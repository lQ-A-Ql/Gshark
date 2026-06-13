package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestProtocolToolScanErrorsPreserveCauses(t *testing.T) {
	rootCause := errors.New("tshark scan root cause")

	t.Run("ntlm", func(t *testing.T) {
		oldScan := scanNTLMSessionRowsWithDisplayFilter
		t.Cleanup(func() { scanNTLMSessionRowsWithDisplayFilter = oldScan })
		scanNTLMSessionRowsWithDisplayFilter = func(string, []string, string, func([]string)) error {
			return rootCause
		}

		_, err := scanNTLMSessionMaterials(context.Background(), "capture.pcapng")
		if !errors.Is(err, rootCause) {
			t.Fatalf("NTLM scan error does not preserve cause: %v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "NTLM") {
			t.Fatalf("NTLM scan error should keep user-facing operation text, got %v", err)
		}
	})

	t.Run("smb3", func(t *testing.T) {
		oldScan := scanSMB3SessionRowsWithDisplayFilter
		t.Cleanup(func() { scanSMB3SessionRowsWithDisplayFilter = oldScan })
		scanSMB3SessionRowsWithDisplayFilter = func(string, []string, string, func([]string)) error {
			return rootCause
		}

		_, err := scanSMB3SessionCandidates(context.Background(), "capture.pcapng")
		if !errors.Is(err, rootCause) {
			t.Fatalf("SMB3 scan error does not preserve cause: %v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "SMB3") {
			t.Fatalf("SMB3 scan error should keep user-facing operation text, got %v", err)
		}
	})

	t.Run("winrm", func(t *testing.T) {
		oldScan := scanWinRMRowsWithFallbacks
		t.Cleanup(func() { scanWinRMRowsWithFallbacks = oldScan })
		scanWinRMRowsWithFallbacks = func(string, string, []tshark.FieldScanFallback, func([]string)) error {
			return rootCause
		}

		_, err := scanWinRMRowsWithContext(context.Background(), "capture.pcapng", 5985)
		if !errors.Is(err, rootCause) {
			t.Fatalf("WinRM scan error does not preserve cause: %v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "WinRM") {
			t.Fatalf("WinRM scan error should keep user-facing operation text, got %v", err)
		}
	})
}

func TestExternalToolErrorsPreserveCauses(t *testing.T) {
	t.Run("playback ffmpeg detail wraps command error", func(t *testing.T) {
		ffmpegPath := buildFakeFFmpegBinary(t)
		t.Setenv("MEOW_TRAFFIC_FAKE_FFMPEG_MODE", "fail")
		inputPath := filepath.Join(t.TempDir(), "audio.ulaw")
		if err := os.WriteFile(inputPath, []byte("audio"), 0o644); err != nil {
			t.Fatalf("write input: %v", err)
		}

		err := generatePlaybackAsset(context.Background(), ffmpegPath, inputPath, filepath.Join(t.TempDir(), "out.m4a"), rawAudioPlaybackProfile("mulaw", 8000))
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ffmpeg failure to wrap exec.ExitError, got %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "fake ffmpeg failure") {
			t.Fatalf("expected ffmpeg detail to remain visible, got %v", err)
		}
	})

	t.Run("speech ffmpeg wraps command error", func(t *testing.T) {
		ffmpegPath := buildFakeFFmpegBinary(t)
		t.Setenv(ffmpegEnvVar, ffmpegPath)
		t.Setenv("MEOW_TRAFFIC_FAKE_FFMPEG_MODE", "fail")
		inputPath := filepath.Join(t.TempDir(), "audio.ulaw")
		if err := os.WriteFile(inputPath, []byte("audio"), 0o644); err != nil {
			t.Fatalf("write input: %v", err)
		}

		err := convertArtifactToSpeechWav(context.Background(), inputPath, filepath.Join(t.TempDir(), "out.wav"), transcriptionAudioProfile{inputFormat: "mulaw"})
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected speech ffmpeg failure to wrap exec.ExitError, got %T %v", err, err)
		}
	})

	t.Run("vosk runner wraps command error", func(t *testing.T) {
		pythonPath := buildFakePythonBinary(t)
		t.Setenv("MEOW_TRAFFIC_FAKE_PYTHON_MODE", "fail")
		_, err := transcribeAudioFileWithPython(context.Background(), []string{pythonPath}, "model", "audio.wav")
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected Vosk runner failure to wrap exec.ExitError, got %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "fake python failure") {
			t.Fatalf("expected Vosk stderr detail to remain visible, got %v", err)
		}
	})
}

func TestToolRuntimeControllersPreserveFacadeBehavior(t *testing.T) {
	t.Setenv(ffmpegEnvVar, "")
	t.Setenv(pythonEnvVar, "")
	t.Setenv(voskModelEnvVar, "")

	svc := NewService(NopEmitter{})
	got := svc.SetToolRuntimeConfig(model.ToolRuntimeConfig{
		TSharkPath:    " C:/Tools/tshark.exe ",
		FFmpegPath:    " C:/Tools/ffmpeg.exe ",
		PythonPath:    " C:/Tools/python.exe ",
		VoskModelPath: " C:/Models/vosk ",
		YaraEnabled:   true,
		YaraBin:       " C:/Tools/yara.exe ",
		YaraRules:     " C:/Rules/main.yar ",
		YaraTimeoutMS: 30000,
	})

	if got.FFmpegPath != "C:/Tools/ffmpeg.exe" || got.PythonPath != "C:/Tools/python.exe" || got.VoskModelPath != "C:/Models/vosk" {
		t.Fatalf("runtime env config not preserved: %+v", got)
	}
	if got.YaraBin != "C:/Tools/yara.exe" || got.YaraRules != "C:/Rules/main.yar" || got.YaraTimeoutMS != 30000 || !got.YaraEnabled {
		t.Fatalf("runtime yara config not preserved: %+v", got)
	}

	svc.SetTLSConfig(model.TLSConfig{SSLKeyLogFile: "keys.log"})
	if got := svc.TLSConfig(); got.SSLKeyLogFile != "keys.log" {
		t.Fatalf("TLSConfig() = %+v, want configured value", got)
	}
}

func buildFakePythonBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "fake_python.go")
	exe := filepath.Join(dir, "fake_python")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	source := `package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Getenv("MEOW_TRAFFIC_FAKE_PYTHON_MODE") == "fail" {
		fmt.Fprintln(os.Stderr, "fake python failure")
		os.Exit(2)
	}
	fmt.Println(` + "`" + `{"text":"ok","duration_seconds":1,"segments":[]}` + "`" + `)
}
`
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatalf("write fake python source: %v", err)
	}
	if out, err := exec.Command("go", "build", "-o", exe, src).CombinedOutput(); err != nil {
		t.Fatalf("build fake python: %v\n%s", err, string(out))
	}
	return exe
}
