package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FFmpegStatus struct {
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Message   string `json:"message"`
}

func (s *Service) FFmpegStatus() FFmpegStatus {
	path, err := exec.LookPath("ffmpeg")
	if err != nil {
		return FFmpegStatus{
			Available: false,
			Path:      "",
			Message:   "未在环境变量 PATH 中找到 ffmpeg，请先安装 ffmpeg 并将其加入 PATH。",
		}
	}
	return FFmpegStatus{
		Available: true,
		Path:      path,
		Message:   "ok",
	}
}

func (s *Service) MediaPlayback(token string) (string, string, error) {
	status := s.FFmpegStatus()
	if !status.Available {
		return "", "", errors.New(status.Message)
	}

	inputPath, inputName, err := s.MediaArtifact(token)
	if err != nil {
		return "", "", err
	}

	outputName := buildPlaybackName(inputName)

	s.mu.RLock()
	existing := strings.TrimSpace(s.mediaPlayback[token])
	s.mu.RUnlock()
	if existing != "" {
		if info, statErr := os.Stat(existing); statErr == nil && info.Size() > 0 {
			return existing, outputName, nil
		}
	}

	outputPath := filepath.Join(filepath.Dir(inputPath), outputName)
	if err := generatePlaybackAsset(status.Path, inputPath, outputPath); err != nil {
		return "", "", err
	}

	s.mu.Lock()
	if s.mediaPlayback == nil {
		s.mediaPlayback = map[string]string{}
	}
	s.mediaPlayback[token] = outputPath
	s.mu.Unlock()

	return outputPath, outputName, nil
}

func buildPlaybackName(inputName string) string {
	base := strings.TrimSuffix(filepath.Base(inputName), filepath.Ext(inputName))
	base = strings.TrimSpace(base)
	if base == "" {
		base = "media"
	}
	return base + ".mp4"
}

func generatePlaybackAsset(ffmpegPath, inputPath, outputPath string) error {
	inputFormat, err := detectPlaybackInputFormat(inputPath)
	if err != nil {
		return err
	}

	if err := os.RemoveAll(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup existing playback asset: %w", err)
	}

	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-y",
		"-fflags", "+genpts",
		"-f", inputFormat,
		"-i", inputPath,
		"-an",
		"-c:v", "libx264",
		"-preset", "veryfast",
		"-pix_fmt", "yuv420p",
		"-movflags", "+faststart",
		outputPath,
	}
	cmd := exec.Command(ffmpegPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return fmt.Errorf("ffmpeg convert failed: %w", err)
		}
		return fmt.Errorf("ffmpeg convert failed: %s", detail)
	}

	info, statErr := os.Stat(outputPath)
	if statErr != nil {
		return fmt.Errorf("ffmpeg output missing: %w", statErr)
	}
	if info.Size() <= 0 {
		return errors.New("ffmpeg output is empty")
	}
	return nil
}

func detectPlaybackInputFormat(path string) (string, error) {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "h264", "264":
		return "h264", nil
	case "h265", "265", "hevc":
		return "hevc", nil
	default:
		return "", fmt.Errorf("unsupported playback input format: %s", filepath.Ext(path))
	}
}
