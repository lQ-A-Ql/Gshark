package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildYaraHTTPStreamContentUsesRequestResponseAndFirstPacket(t *testing.T) {
	stream := model.ReassembledStream{
		StreamID: 7,
		Protocol: "HTTP",
		Request:  "GET /shell.jsp HTTP/1.1\r\nHost: demo\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		Chunks: []model.StreamChunk{
			{PacketID: 42, Direction: "server", Body: "ignored response chunk"},
			{PacketID: 11, Direction: "client", Body: "ignored request chunk"},
		},
	}

	content, packetID := buildYaraHTTPStreamContent(stream)
	if packetID != 11 {
		t.Fatalf("packetID = %d, want first chunk packet 11", packetID)
	}
	for _, want := range []string{"=== HTTP REQUEST ===", "GET /shell.jsp", "=== HTTP RESPONSE ===", "HTTP/1.1 200 OK"} {
		if !strings.Contains(content, want) {
			t.Fatalf("HTTP stream content missing %q:\n%s", want, content)
		}
	}
}

func TestBuildYaraHTTPStreamContentFallsBackToReadableChunks(t *testing.T) {
	stream := model.ReassembledStream{
		StreamID: 8,
		Protocol: "HTTP",
		Chunks: []model.StreamChunk{
			{PacketID: 30, Direction: "server", Body: "00:01:02:03"},
			{PacketID: 20, Direction: "client", Body: "65:76:61:6c:28:24:5f:50:4f:53:54:29"},
			{PacketID: 25, Direction: "server", Body: "plain readable body"},
		},
	}

	content, packetID := buildYaraHTTPStreamContent(stream)
	if packetID != 20 {
		t.Fatalf("packetID = %d, want first positive packet id 20", packetID)
	}
	if !strings.Contains(content, "=== CLIENT ===\neval($_POST)") {
		t.Fatalf("expected decoded hex client chunk, got:\n%s", content)
	}
	if !strings.Contains(content, "=== SERVER ===\nplain readable body") {
		t.Fatalf("expected plain server chunk, got:\n%s", content)
	}
	if !strings.Contains(content, "00:01:02:03") {
		t.Fatalf("printable hex-looking chunk should be preserved as text, got:\n%s", content)
	}
}

func TestBuildYaraRawStreamContentDecodesReadableHexAndFiltersNoise(t *testing.T) {
	stream := model.ReassembledStream{
		StreamID: 9,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{PacketID: 99, Direction: "server", Body: "00:ff:01"},
			{PacketID: 51, Direction: "client", Body: "63:6d:64:3d:77:68:6f:61:6d:69"},
			{PacketID: 60, Direction: "server", Body: "HTTP/1.1 200 OK\r\n\r\nroot"},
		},
	}

	content, packetID := buildYaraRawStreamContent(stream)
	if packetID != 51 {
		t.Fatalf("packetID = %d, want first positive packet id 51", packetID)
	}
	if !strings.Contains(content, "cmd=whoami") || !strings.Contains(content, "HTTP/1.1 200 OK") {
		t.Fatalf("expected decoded and plain readable chunks, got:\n%s", content)
	}
	if !strings.Contains(content, "00:ff:01") {
		t.Fatalf("printable hex-looking chunk should be preserved as text, got:\n%s", content)
	}

	empty, emptyPacket := buildYaraRawStreamContent(model.ReassembledStream{StreamID: 1, Protocol: "UDP"})
	if empty != "" || emptyPacket != 0 {
		t.Fatalf("empty raw stream content = %q packet=%d, want zero", empty, emptyPacket)
	}
}

func TestDecodeYaraChunkBodyAndReadabilityBoundaries(t *testing.T) {
	if got := decodeYaraChunkBody(" 68 65 6c 6c 6f 00 "); got != "hello" {
		t.Fatalf("decodeYaraChunkBody(hex) = %q, want hello", got)
	}
	if got := decodeYaraChunkBody("plain text 123"); got != "plain text 123" {
		t.Fatalf("decodeYaraChunkBody(plain) = %q", got)
	}
	if got := decodeYaraChunkBody("00:01:02"); got != "00:01:02" {
		t.Fatalf("decodeYaraChunkBody(printable hex text) = %q, want original", got)
	}
	if looksReadableForYara("") || looksReadableForYara("\x00\x01") {
		t.Fatal("empty/binary content should not be readable for YARA")
	}
	if !looksReadableForYara("abcd") || !looksReadableForYara("!!!!!!!!!1") {
		t.Fatal("printable text should be readable for YARA")
	}
	if got := firstStreamPacketID([]model.StreamChunk{{PacketID: 0}, {PacketID: 12}, {PacketID: 3}}); got != 3 {
		t.Fatalf("firstStreamPacketID() = %d, want 3", got)
	}
	if got := firstStreamPacketID(nil); got != 0 {
		t.Fatalf("firstStreamPacketID(nil) = %d, want 0", got)
	}
}

func TestBuildYaraScanTargetsIncludesObjectsAndMaterializedStreams(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	objectPath := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(objectPath, []byte("object payload"), 0o644); err != nil {
		t.Fatalf("write object: %v", err)
	}

	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{
			ID: 101, Protocol: "HTTP", StreamID: 3,
			SourceIP: "10.0.0.10", SourcePort: 50123, DestIP: "10.0.0.20", DestPort: 80,
			Info:    "POST /shell.php HTTP/1.1",
			Payload: "POST /shell.php HTTP/1.1\r\nHost: demo\r\n\r\ncmd=whoami",
		},
		{
			ID: 102, Protocol: "HTTP", StreamID: 3,
			SourceIP: "10.0.0.20", SourcePort: 80, DestIP: "10.0.0.10", DestPort: 50123,
			Info:    "HTTP/1.1 200 OK",
			Payload: "HTTP/1.1 200 OK\r\n\r\nok",
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.streamCtl.rawStreamIndex[streamCacheKey("TCP", 9)] = model.ReassembledStream{
		StreamID: 9,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{PacketID: 201, Direction: "client", Body: "70:6f:77:65:72:73:68:65:6c:6c"},
		},
	}
	svc.streamCtl.rawStreamIndex[streamCacheKey("UDP", 4)] = model.ReassembledStream{
		StreamID: 4,
		Protocol: "UDP",
		Chunks: []model.StreamChunk{
			{PacketID: 301, Direction: "client", Body: "dns tunnel marker"},
		},
	}

	targets, cleanup, err := svc.buildYaraScanTargetsWithContext(context.Background(), []model.ObjectFile{
		{Name: "dump.bin", Path: objectPath, PacketID: 88, Source: "object"},
		{Name: "ignored.bin", Path: "   ", PacketID: 99, Source: "object"},
	})
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("buildYaraScanTargetsWithContext() error = %v", err)
	}

	objectTarget := findYaraTargetByName(targets, "dump.bin")
	if objectTarget == nil || objectTarget.path != objectPath || objectTarget.packetID != 88 || objectTarget.source != "object" {
		t.Fatalf("object target not preserved: %+v in %+v", objectTarget, targets)
	}

	httpTarget := findYaraTargetByName(targets, "http-stream-3.txt")
	if httpTarget == nil || httpTarget.packetID != 101 || httpTarget.source != "http-stream" {
		t.Fatalf("HTTP stream target missing or wrong: %+v in %+v", httpTarget, targets)
	}
	httpPayload := readYaraTargetFile(t, httpTarget.path)
	if !strings.Contains(httpPayload, "cmd=whoami") || !strings.Contains(httpPayload, "HTTP/1.1 200 OK") {
		t.Fatalf("HTTP stream target content incomplete:\n%s", httpPayload)
	}

	tcpTarget := findYaraTargetByName(targets, "tcp-stream-9.txt")
	if tcpTarget == nil || tcpTarget.packetID != 201 || tcpTarget.source != "tcp-stream" {
		t.Fatalf("TCP stream target missing or wrong: %+v in %+v", tcpTarget, targets)
	}
	if payload := readYaraTargetFile(t, tcpTarget.path); !strings.Contains(payload, "powershell") {
		t.Fatalf("TCP stream target did not decode hex payload:\n%s", payload)
	}

	udpTarget := findYaraTargetByName(targets, "udp-stream-4.txt")
	if udpTarget == nil || udpTarget.packetID != 301 || udpTarget.source != "udp-stream" {
		t.Fatalf("UDP stream target missing or wrong: %+v in %+v", udpTarget, targets)
	}

	streamDir := filepath.Dir(httpTarget.path)
	cleanup()
	if _, statErr := os.Stat(streamDir); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup should remove stream temp dir %q, stat err=%v", streamDir, statErr)
	}
}

func TestBuildYaraScanTargetsTruncatesLargeStreamContent(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	large := strings.Repeat("PAYLOAD!", (maxStreamContentBytes/8)+1024)
	svc.streamCtl.rawStreamIndex[streamCacheKey("TCP", 44)] = model.ReassembledStream{
		StreamID: 44,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{PacketID: 440, Direction: "client", Body: large},
		},
	}

	targets, cleanup, err := svc.buildYaraScanTargetsWithContext(context.Background(), nil)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("buildYaraScanTargetsWithContext() error = %v", err)
	}
	target := findYaraTargetByName(targets, "tcp-stream-44.txt")
	if target == nil {
		t.Fatalf("tcp stream target not found in %+v", targets)
	}
	info, err := os.Stat(target.path)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Size() != maxStreamContentBytes {
		t.Fatalf("target size = %d, want %d", info.Size(), maxStreamContentBytes)
	}
}

func TestYaraStreamContentReturnsEmptyForUnsupportedOrCanceledContext(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	content, packetID := svc.yaraStreamContent(context.Background(), "icmp", 1)
	if content != "" || packetID != 0 {
		t.Fatalf("unsupported yara stream content = %q packet=%d", content, packetID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	content, packetID = svc.yaraStreamContent(ctx, "http", 9)
	if content != "" || packetID != 0 {
		t.Fatalf("canceled HTTP yara stream content = %q packet=%d", content, packetID)
	}
}

func findYaraTargetByName(targets []yaraScanTarget, name string) *yaraScanTarget {
	for i := range targets {
		if targets[i].name == name {
			return &targets[i]
		}
	}
	return nil
}

func readYaraTargetFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read YARA target %q: %v", path, err)
	}
	return string(payload)
}
