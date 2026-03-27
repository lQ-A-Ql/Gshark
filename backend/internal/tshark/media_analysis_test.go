package tshark

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSDPCodecHints(t *testing.T) {
	hints := parseSDPCodecHints([]string{
		"rtpmap:96 H264/90000",
		"fmtp:96 packetization-mode=1; sprop-parameter-sets=Z0IAH5WoFAFuQA==,aM48gA==",
	})

	h264, ok := hints["96"]
	if !ok {
		t.Fatalf("expected payload type 96 in hints")
	}
	if h264.Name != "H264" {
		t.Fatalf("expected H264, got %q", h264.Name)
	}
	if h264.ClockRate != 90000 {
		t.Fatalf("expected clock rate 90000, got %d", h264.ClockRate)
	}
	if h264.Fmtp["packetization-mode"] != "1" {
		t.Fatalf("unexpected fmtp map: %#v", h264.Fmtp)
	}
}

func TestDetectMediaApplicationGameStreamPorts(t *testing.T) {
	app, tags := detectMediaApplication("rtsp setup stream", 48010, 47998)
	if app != "Moonlight / GameStream" {
		t.Fatalf("expected Moonlight / GameStream, got %q", app)
	}
	if !reflect.DeepEqual(tags, []string{"RTP", "GameStream Ports"}) {
		t.Fatalf("unexpected tags: %#v", tags)
	}
}

func TestReconstructH264Stream(t *testing.T) {
	builder := &mediaSessionBuilder{
		Codec: "H264",
		Packets: []rtpPacketRecord{
			{Payload: []byte{0x65, 0xAA, 0xBB}},
			{Payload: []byte{0x7C, 0x85, 0x11, 0x22}},
			{Payload: []byte{0x7C, 0x45, 0x33, 0x44}},
		},
	}

	payload, ext, err := reconstructH264Stream(builder)
	if err != nil {
		t.Fatalf("reconstructH264Stream returned error: %v", err)
	}
	if ext != ".h264" {
		t.Fatalf("expected .h264 extension, got %q", ext)
	}

	expected := []byte{
		0x00, 0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB,
		0x00, 0x00, 0x00, 0x01, 0x65, 0x11, 0x22, 0x33, 0x44,
	}
	if !reflect.DeepEqual(payload, expected) {
		t.Fatalf("unexpected payload:\nwant=%#v\ngot =%#v", expected, payload)
	}
}

func TestBuildMediaAnalysisFromGameStreamSample(t *testing.T) {
	if testing.Short() {
		t.Skip("skip sample-backed media regression in short mode")
	}
	if _, err := ResolveBinary(); err != nil {
		t.Skipf("tshark unavailable: %v", err)
	}

	samplePath := filepath.Clean(filepath.Join("..", "..", "..", "gamestream.pcapng"))
	if _, err := os.Stat(samplePath); err != nil {
		t.Skipf("sample capture not found: %v", err)
	}

	exportDir := t.TempDir()
	stats, artifacts, err := BuildMediaAnalysisFromFile(samplePath, exportDir)
	if err != nil {
		t.Fatalf("BuildMediaAnalysisFromFile() error = %v", err)
	}
	if stats.TotalMediaPackets <= 0 {
		t.Fatalf("expected media packets from sample, got %+v", stats)
	}
	if len(stats.Sessions) == 0 {
		t.Fatalf("expected extracted sessions from sample, got none")
	}

	foundGameStream := false
	artifactNames := map[string]struct{}{}
	artifactCount := 0
	for _, session := range stats.Sessions {
		if session.Application == "Moonlight / GameStream" {
			foundGameStream = true
			if session.Family != "Moonlight / GameStream" {
				t.Fatalf("expected GameStream family label for session %+v", session)
			}
		}
		if session.Artifact == nil {
			continue
		}
		artifactCount++
		if _, exists := artifactNames[session.Artifact.Name]; exists {
			t.Fatalf("artifact name collision detected: %s", session.Artifact.Name)
		}
		artifactNames[session.Artifact.Name] = struct{}{}

		path := artifacts[session.Artifact.Token]
		if path == "" {
			t.Fatalf("missing artifact path for token %s", session.Artifact.Token)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("artifact path is not readable: %v", statErr)
		}
		if info.Size() <= 0 {
			t.Fatalf("artifact %s is empty", path)
		}
		if session.Artifact.SizeBytes <= 0 {
			t.Fatalf("artifact metadata reports invalid size: %+v", session.Artifact)
		}
	}

	if !foundGameStream {
		t.Fatalf("expected Moonlight / GameStream session in sample, got %+v", stats.Applications)
	}
	if artifactCount == 0 {
		t.Fatalf("expected at least one extracted video artifact, got none")
	}
}
