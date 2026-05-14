package engine

import (
	"testing"

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
