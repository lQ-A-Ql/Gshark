package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type playbackProfile struct {
	inputFormat string
	outputExt   string
	contentType string
	inputArgs   []string
	outputArgs  []string
}

type FFmpegStatus struct {
	Available       bool   `json:"available"`
	Path            string `json:"path"`
	Message         string `json:"message"`
	CustomPath      string `json:"custom_path,omitempty"`
	UsingCustomPath bool   `json:"using_custom_path,omitempty"`
}

func (s *Service) FFmpegStatus() FFmpegStatus {
	customPath := strings.TrimSpace(os.Getenv(ffmpegEnvVar))
	path, err := resolveFFmpegBinary(customPath)
	if err != nil {
		return FFmpegStatus{
			Available:       false,
			Path:            "",
			Message:         "未检测到 ffmpeg，请先安装 ffmpeg 或在设置中配置其路径。",
			CustomPath:      customPath,
			UsingCustomPath: customPath != "",
		}
	}
	return FFmpegStatus{
		Available:       true,
		Path:            path,
		Message:         "ok",
		CustomPath:      customPath,
		UsingCustomPath: customPath != "",
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

	profile, err := detectPlaybackProfile(inputPath)
	if err != nil {
		return "", "", err
	}
	outputName := buildPlaybackName(inputName, profile.outputExt)

	s.mu.RLock()
	existing := strings.TrimSpace(s.mediaPlayback[token])
	s.mu.RUnlock()
	if existing != "" {
		if info, statErr := os.Stat(existing); statErr == nil && info.Size() > 0 {
			return existing, outputName, nil
		}
	}

	outputPath := filepath.Join(filepath.Dir(inputPath), outputName)
	if err := generatePlaybackAsset(status.Path, inputPath, outputPath, profile); err != nil {
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

func buildPlaybackName(inputName, ext string) string {
	base := strings.TrimSuffix(filepath.Base(inputName), filepath.Ext(inputName))
	base = strings.TrimSpace(base)
	if base == "" {
		base = "media"
	}
	if strings.TrimSpace(ext) == "" {
		ext = ".mp4"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return base + ext
}

func generatePlaybackAsset(ffmpegPath, inputPath, outputPath string, profile playbackProfile) error {
	if err := os.RemoveAll(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup existing playback asset: %w", err)
	}

	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-y",
		"-fflags", "+genpts",
	}
	if profile.inputFormat != "" {
		args = append(args, "-f", profile.inputFormat)
	}
	args = append(args, profile.inputArgs...)
	args = append(args, "-i", inputPath)
	args = append(args, profile.outputArgs...)
	args = append(args, outputPath)
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

func detectPlaybackProfile(path string) (playbackProfile, error) {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "h264", "264":
		return playbackProfile{
			inputFormat: "h264",
			outputExt:   ".mp4",
			contentType: "video/mp4",
			outputArgs: []string{
				"-an",
				"-c:v", "libx264",
				"-preset", "veryfast",
				"-pix_fmt", "yuv420p",
				"-movflags", "+faststart",
			},
		}, nil
	case "h265", "265", "hevc":
		return playbackProfile{
			inputFormat: "hevc",
			outputExt:   ".mp4",
			contentType: "video/mp4",
			outputArgs: []string{
				"-an",
				"-c:v", "libx264",
				"-preset", "veryfast",
				"-pix_fmt", "yuv420p",
				"-movflags", "+faststart",
			},
		}, nil
	case "ulaw":
		return rawAudioPlaybackProfile("mulaw", 8000), nil
	case "alaw":
		return rawAudioPlaybackProfile("alaw", 8000), nil
	case "g722":
		return rawAudioPlaybackProfile("g722", 8000), nil
	case "l16":
		return rawAudioPlaybackProfile("s16be", 44100), nil
	case "aac":
		return compressedAudioPlaybackProfile("aac"), nil
	case "opus":
		return compressedAudioPlaybackProfile("opus"), nil
	case "mpa", "mp3":
		return compressedAudioPlaybackProfile("mp3"), nil
	default:
		return playbackProfile{}, fmt.Errorf("unsupported playback input format: %s", filepath.Ext(path))
	}
}

func rawAudioPlaybackProfile(inputFormat string, sampleRate int) playbackProfile {
	return playbackProfile{
		inputFormat: inputFormat,
		outputExt:   ".m4a",
		contentType: "audio/mp4",
		inputArgs: []string{
			"-ar", fmt.Sprintf("%d", sampleRate),
			"-ac", "1",
		},
		outputArgs: []string{
			"-vn",
			"-c:a", "aac",
			"-b:a", "160k",
			"-movflags", "+faststart",
		},
	}
}

func compressedAudioPlaybackProfile(inputFormat string) playbackProfile {
	return playbackProfile{
		inputFormat: inputFormat,
		outputExt:   ".m4a",
		contentType: "audio/mp4",
		outputArgs: []string{
			"-vn",
			"-c:a", "aac",
			"-b:a", "160k",
			"-movflags", "+faststart",
		},
	}
}

func resolveFFmpegBinary(custom string) (string, error) {
	custom = strings.TrimSpace(custom)
	if custom == "" {
		return exec.LookPath("ffmpeg")
	}

	candidates := []string{custom}
	if info, err := os.Stat(custom); err == nil && info.IsDir() {
		candidates = append(candidates,
			filepath.Join(custom, "ffmpeg.exe"),
			filepath.Join(custom, "ffmpeg"),
		)
	}

	var lastErr error
	for _, candidate := range candidates {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		} else {
			lastErr = err
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		} else if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", exec.ErrNotFound
}
