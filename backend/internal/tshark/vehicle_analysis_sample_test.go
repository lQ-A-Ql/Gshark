package tshark

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildVehicleAnalysisFromCANSampleIncludesRawData(t *testing.T) {
	if testing.Short() {
		t.Skip("skip sample-backed vehicle regression in short mode")
	}
	if _, err := ResolveBinary(); err != nil {
		t.Skipf("tshark unavailable: %v", err)
	}

	samplePath := filepath.Clean(filepath.Join("..", "..", "..", "CAN.pcapng"))
	if _, err := os.Stat(samplePath); err != nil {
		t.Skipf("sample capture not found: %v", err)
	}

	stats, err := BuildVehicleAnalysisFromFile(samplePath)
	if err != nil {
		t.Fatalf("BuildVehicleAnalysisFromFile() error = %v", err)
	}
	if stats.CAN.TotalFrames <= 0 {
		t.Fatalf("expected CAN frames from sample, got %+v", stats.CAN)
	}
	if len(stats.CAN.Frames) == 0 {
		t.Fatalf("expected CAN frame previews from sample, got none")
	}

	foundRawData := false
	for _, frame := range stats.CAN.Frames {
		if frame.RawData != "" {
			foundRawData = true
			break
		}
	}
	if !foundRawData {
		t.Fatalf("expected at least one CAN frame with raw data, got %+v", stats.CAN.Frames)
	}
}
