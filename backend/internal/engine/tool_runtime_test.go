package engine

import (
	"os"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestToModelTSharkStatusPreservesCapabilityDiagnostics(t *testing.T) {
	status := tshark.Status{
		Available:       true,
		Path:            "tshark.exe",
		Message:         "ok",
		CustomPath:      "C:/Wireshark/tshark.exe",
		UsingCustomPath: true,
		Capabilities: tshark.Capabilities{
			Version:                 "TShark 4.6.5",
			FieldProfile:            tshark.FieldProfileCompat,
			FieldCount:              4321,
			MissingRequiredFields:   []string{"frame.protocols"},
			MissingOptionalFields:   []string{"usb.capdata"},
			CapabilityMessage:       "optional tshark fields are unavailable; some analyses will degrade",
			CapabilityCheckDegraded: true,
		},
	}

	got := toModelTSharkStatus(status)
	if got.Version != status.Version || got.FieldProfile != status.FieldProfile || got.FieldCount != status.FieldCount {
		t.Fatalf("capability summary not preserved: got=%+v status=%+v", got, status)
	}
	if len(got.MissingRequiredFields) != 1 || got.MissingRequiredFields[0] != "frame.protocols" {
		t.Fatalf("missing required fields not preserved: %+v", got.MissingRequiredFields)
	}
	if len(got.MissingOptionalFields) != 1 || got.MissingOptionalFields[0] != "usb.capdata" {
		t.Fatalf("missing optional fields not preserved: %+v", got.MissingOptionalFields)
	}

	status.MissingOptionalFields[0] = "mutated"
	if got.MissingOptionalFields[0] != "usb.capdata" {
		t.Fatalf("model status must own copied slices, got %+v", got.MissingOptionalFields)
	}
}

func TestToModelFFmpegStatusPreservesRuntimeFields(t *testing.T) {
	status := FFmpegStatus{
		Available:       true,
		Path:            "ffmpeg.exe",
		Message:         "ok",
		CustomPath:      "C:/ffmpeg/bin/ffmpeg.exe",
		UsingCustomPath: true,
	}

	got := toModelFFmpegStatus(status)
	if !got.Available || got.Path != status.Path || got.CustomPath != status.CustomPath || !got.UsingCustomPath {
		t.Fatalf("ffmpeg status not preserved: got=%+v status=%+v", got, status)
	}
}

func TestToolRuntimeConfigReadsEnvironmentOverrides(t *testing.T) {
	t.Setenv(ffmpegEnvVar, " C:/Env/ffmpeg.exe ")
	t.Setenv(pythonEnvVar, " C:/Env/python.exe ")
	t.Setenv(voskModelEnvVar, " C:/Env/vosk-model ")

	svc := NewService(nil, nil)
	got := svc.ToolRuntimeConfig()

	if got.FFmpegPath != "C:/Env/ffmpeg.exe" {
		t.Fatalf("FFmpegPath = %q, want env value", got.FFmpegPath)
	}
	if got.PythonPath != "C:/Env/python.exe" {
		t.Fatalf("PythonPath = %q, want env value", got.PythonPath)
	}
	if got.VoskModelPath != "C:/Env/vosk-model" {
		t.Fatalf("VoskModelPath = %q, want env value", got.VoskModelPath)
	}
}

func TestSetToolRuntimeConfigEmptyValuesUnsetEnvironmentOverrides(t *testing.T) {
	t.Setenv(ffmpegEnvVar, "C:/Env/ffmpeg.exe")
	t.Setenv(pythonEnvVar, "C:/Env/python.exe")
	t.Setenv(voskModelEnvVar, "C:/Env/vosk-model")

	svc := NewService(nil, nil)
	got := svc.SetToolRuntimeConfig(model.ToolRuntimeConfig{
		YaraEnabled:   true,
		YaraTimeoutMS: 25000,
	})

	if got.FFmpegPath != "" || got.PythonPath != "" || got.VoskModelPath != "" {
		t.Fatalf("config after unset = %+v, want empty env-backed paths", got)
	}
	for _, key := range []string{ffmpegEnvVar, pythonEnvVar, voskModelEnvVar} {
		if value, ok := os.LookupEnv(key); ok {
			t.Fatalf("%s still set to %q, want unset", key, value)
		}
	}
}

func TestSetToolRuntimeConfigRoundTripsEnvironmentOverrides(t *testing.T) {
	t.Setenv(ffmpegEnvVar, "")
	t.Setenv(pythonEnvVar, "")
	t.Setenv(voskModelEnvVar, "")

	svc := NewService(nil, nil)
	got := svc.SetToolRuntimeConfig(model.ToolRuntimeConfig{
		FFmpegPath:    " C:/Saved/ffmpeg.exe ",
		PythonPath:    " C:/Saved/python.exe ",
		VoskModelPath: " C:/Saved/vosk-model ",
		YaraEnabled:   true,
		YaraTimeoutMS: 30000,
	})

	if got.FFmpegPath != "C:/Saved/ffmpeg.exe" || os.Getenv(ffmpegEnvVar) != "C:/Saved/ffmpeg.exe" {
		t.Fatalf("ffmpeg env round trip failed: config=%+v env=%q", got, os.Getenv(ffmpegEnvVar))
	}
	if got.PythonPath != "C:/Saved/python.exe" || os.Getenv(pythonEnvVar) != "C:/Saved/python.exe" {
		t.Fatalf("python env round trip failed: config=%+v env=%q", got, os.Getenv(pythonEnvVar))
	}
	if got.VoskModelPath != "C:/Saved/vosk-model" || os.Getenv(voskModelEnvVar) != "C:/Saved/vosk-model" {
		t.Fatalf("vosk env round trip failed: config=%+v env=%q", got, os.Getenv(voskModelEnvVar))
	}
}
