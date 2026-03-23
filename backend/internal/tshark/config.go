package tshark

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Status struct {
	Available       bool   `json:"available"`
	Path            string `json:"path"`
	Message         string `json:"message"`
	CustomPath      string `json:"custom_path,omitempty"`
	UsingCustomPath bool   `json:"using_custom_path,omitempty"`
}

var (
	binaryMu         sync.RWMutex
	configuredBinary string
)

func SetBinaryPath(path string) {
	binaryMu.Lock()
	defer binaryMu.Unlock()
	configuredBinary = strings.TrimSpace(path)
}

func ConfiguredBinaryPath() string {
	binaryMu.RLock()
	defer binaryMu.RUnlock()
	return configuredBinary
}

func Command(args ...string) (*exec.Cmd, error) {
	binary, err := ResolveBinary()
	if err != nil {
		return nil, err
	}
	return exec.Command(binary, args...), nil
}

func CommandContext(ctx context.Context, args ...string) (*exec.Cmd, error) {
	binary, err := ResolveBinary()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, binary, args...), nil
}

func ResolveBinary() (string, error) {
	custom := ConfiguredBinaryPath()
	if custom != "" {
		resolved, err := resolveCustomBinary(custom)
		if err == nil {
			return resolved, nil
		}
		return resolvePathBinary("tshark")
	}
	return resolvePathBinary("tshark")
}

func CurrentStatus() Status {
	custom := ConfiguredBinaryPath()
	if custom != "" {
		resolved, err := resolveCustomBinary(custom)
		if err == nil {
			return Status{
				Available:       true,
				Path:            resolved,
				Message:         "ok",
				CustomPath:      custom,
				UsingCustomPath: true,
			}
		}

		fallback, fallbackErr := resolvePathBinary("tshark")
		if fallbackErr == nil {
			return Status{
				Available:       true,
				Path:            fallback,
				Message:         fmt.Sprintf("custom tshark path is invalid; falling back to PATH (%s)", err),
				CustomPath:      custom,
				UsingCustomPath: false,
			}
		}

		return Status{
			Available:       false,
			Path:            "",
			Message:         err.Error(),
			CustomPath:      custom,
			UsingCustomPath: true,
		}
	}

	resolved, err := resolvePathBinary("tshark")
	if err != nil {
		return Status{
			Available: false,
			Path:      "",
			Message:   "找不到 tshark QAQ ，需要自行配置正确的路径OVO",
		}
	}
	return Status{
		Available: true,
		Path:      resolved,
		Message:   "ok",
	}
}

func resolvePathBinary(name string) (string, error) {
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("tshark was not found in PATH")
	}
	if !isTSharkBinary(resolved) {
		return "", fmt.Errorf("resolved binary is not tshark: %s", resolved)
	}
	return resolved, nil
}

func resolveCustomBinary(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("custom tshark path is empty")
	}

	var lastErr error
	for _, candidate := range tsharkCandidates(value) {
		resolved, err := resolveCandidate(candidate)
		if err == nil {
			return resolved, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", fmt.Errorf("custom tshark path is invalid: %w", lastErr)
	}
	return "", fmt.Errorf("custom tshark path is invalid")
}

func tsharkCandidates(value string) []string {
	info, err := os.Stat(value)
	if err == nil && info.IsDir() {
		return []string{
			filepath.Join(value, "tshark.exe"),
			filepath.Join(value, "tshark"),
		}
	}
	return []string{value}
}

func resolveCandidate(candidate string) (string, error) {
	value := strings.TrimSpace(candidate)
	if value == "" {
		return "", fmt.Errorf("empty candidate")
	}

	resolved, err := exec.LookPath(value)
	if err == nil {
		if !isTSharkBinary(resolved) {
			return "", fmt.Errorf("%s is not a tshark binary", resolved)
		}
		return resolved, nil
	}

	info, statErr := os.Stat(value)
	if statErr != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s points to a directory", value)
	}
	if !isTSharkBinary(value) {
		return "", fmt.Errorf("%s is not a tshark binary", value)
	}
	return value, nil
}

func isTSharkBinary(path string) bool {
	base := strings.TrimSpace(filepath.Base(path))
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(strings.ToLower(base), strings.ToLower(ext))
	return name == "tshark"
}
