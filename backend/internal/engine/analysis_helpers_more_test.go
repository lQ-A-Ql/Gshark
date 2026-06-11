package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

func TestObjectMagicAndMIMEHelpersCoverKnownAndFallbackTypes(t *testing.T) {
	mimeTests := map[string]string{
		"capture.PNG":  "image/png",
		"photo.jpeg":   "image/jpeg",
		"anim.gif":     "image/gif",
		"image.webp":   "image/webp",
		"bitmap.bmp":   "image/bmp",
		"archive.zip":  "application/zip",
		"manual.pdf":   "application/pdf",
		"notes.txt":    "text/plain",
		"index.HTML":   "text/html",
		"payload.bin":  "application/octet-stream",
		"no-extension": "application/octet-stream",
	}
	for name, want := range mimeTests {
		if got := guessMIME(name); got != want {
			t.Fatalf("guessMIME(%q) = %q, want %q", name, got, want)
		}
	}

	magicTests := map[string]string{
		"PNG":          "image/png",
		"JPEG":         "image/jpeg",
		"GIF89a":       "image/gif",
		"RIFF":         "image/webp",
		"BMP":          "image/bmp",
		"ZIP/DOCX":     "application/zip",
		"PDF":          "application/pdf",
		"RAR":          "application/x-rar",
		"7z":           "application/x-7z-compressed",
		"ELF":          "application/x-elf",
		"PE/DOS MZ":    "application/x-dosexec",
		"OLE2 (doc)":   "application/msword",
		"MP3 (ID3)":    "audio/mpeg",
		"FLAC":         "audio/flac",
		"MP4 (ftyp)":   "video/mp4",
		"MKV/WebM":     "video/webm",
		"FLV":          "video/x-flv",
		"OGG":          "application/ogg",
		"custombinary": "",
	}
	for magic, want := range magicTests {
		if got := magicToMIME(magic); got != want {
			t.Fatalf("magicToMIME(%q) = %q, want %q", magic, got, want)
		}
	}

	if got := detectMagic("89504e470d0a1a0a"); got != "PNG" {
		t.Fatalf("detectMagic(PNG) = %q", got)
	}
	if got := detectMagic("zzzz"); got != "" {
		t.Fatalf("detectMagic(invalid) = %q, want empty", got)
	}
	if got := detectMagicFromPayload(" 504b0304 "); got != "ZIP" {
		t.Fatalf("detectMagicFromPayload(ZIP) = %q", got)
	}
	if got := detectMagicFromPayload("123"); got != "" {
		t.Fatalf("detectMagicFromPayload(short) = %q, want empty", got)
	}
}

func TestCheckPNGDetectsCorruptIHDRAndTrailingData(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid.png")
	writeMinimalPNG(t, validPath, false, false)
	if suspicious, reason := checkPNG(validPath); suspicious || reason != "" {
		t.Fatalf("valid PNG flagged suspicious=%v reason=%q", suspicious, reason)
	}

	corruptPath := filepath.Join(dir, "corrupt-crc.png")
	writeMinimalPNG(t, corruptPath, true, false)
	if suspicious, reason := checkPNG(corruptPath); !suspicious || reason == "" {
		t.Fatalf("corrupt IHDR was not flagged suspicious=%v reason=%q", suspicious, reason)
	}

	trailingPath := filepath.Join(dir, "trailing.png")
	writeMinimalPNG(t, trailingPath, false, true)
	if suspicious, reason := checkPNG(trailingPath); !suspicious || reason == "" {
		t.Fatalf("trailing data was not flagged suspicious=%v reason=%q", suspicious, reason)
	}

	shortPath := filepath.Join(dir, "short.png")
	if err := os.WriteFile(shortPath, []byte{0x89, 'P', 'N', 'G'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if suspicious, reason := checkPNG(shortPath); suspicious || reason != "" {
		t.Fatalf("short PNG flagged suspicious=%v reason=%q", suspicious, reason)
	}

	if suspicious, reason := checkPNG(filepath.Join(dir, "missing.png")); suspicious || reason != "" {
		t.Fatalf("missing PNG flagged suspicious=%v reason=%q", suspicious, reason)
	}
}

func TestRawProtocolMatcherIncludesHTTPWhenFollowingTCP(t *testing.T) {
	httpPacket := model.Packet{Protocol: "HTTP"}
	tcpPacket := model.Packet{Protocol: "tcp"}
	udpPacket := model.Packet{Protocol: "UDP"}

	if !matchesRawProtocol(httpPacket, "TCP") {
		t.Fatal("HTTP packet should be included when following a TCP stream")
	}
	if !matchesRawProtocol(tcpPacket, "TCP") {
		t.Fatal("TCP packet should match TCP protocol case-insensitively")
	}
	if matchesRawProtocol(udpPacket, "TCP") {
		t.Fatal("UDP packet should not match TCP protocol")
	}
}

func TestAnalysisStatusAndMetricHelpersCoverErrorAndPercentileBoundaries(t *testing.T) {
	if got := analysisStatusFromError(context.Background(), nil); got != "ok" {
		t.Fatalf("nil err status = %q", got)
	}
	if got := analysisStatusFromError(context.Background(), context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("deadline err status = %q", got)
	}
	if got := analysisStatusFromError(context.Background(), context.Canceled); got != "canceled" {
		t.Fatalf("canceled err status = %q", got)
	}
	if got := analysisStatusFromError(context.Background(), errors.New("boom")); got != "error" {
		t.Fatalf("generic err status = %q", got)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := analysisStatusFromError(canceledCtx, errors.New("wrapped")); got != "canceled" {
		t.Fatalf("canceled context status = %q", got)
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer timeoutCancel()
	<-timeoutCtx.Done()
	if got := analysisStatusFromError(timeoutCtx, errors.New("wrapped")); got != "timeout" {
		t.Fatalf("deadline context status = %q", got)
	}

	if got := durationMilliseconds(-time.Second); got != 0 {
		t.Fatalf("negative duration ms = %d, want 0", got)
	}
	values := appendCappedInt64([]int64{1, 2}, -5, 3)
	values = appendCappedInt64(values, 4, 3)
	if !reflect.DeepEqual(values, []int64{2, 0, 4}) {
		t.Fatalf("appendCappedInt64 values = %+v", values)
	}
	if got := percentileInt64([]int64{30, 10, 40, 20}, 50); got != 20 {
		t.Fatalf("p50 = %d, want 20", got)
	}
	if got := percentileInt64([]int64{30, 10, 40, 20}, 95); got != 40 {
		t.Fatalf("p95 = %d, want 40", got)
	}
	if got := percentileInt64(nil, 95); got != 0 {
		t.Fatalf("empty percentile = %d, want 0", got)
	}

	ordered := []int64{5, -1, 5, 2}
	sortInt64s(ordered)
	if !reflect.DeepEqual(ordered, []int64{-1, 2, 5, 5}) {
		t.Fatalf("sortInt64s = %+v", ordered)
	}
}

func TestAnalysisMetricsRecordWarmupStatusesAndNormalDurations(t *testing.T) {
	metrics := newAnalysisMetrics()
	for _, sample := range []analysisMetricSample{
		{Source: servicecontract.AnalysisRequestSourceWarmup, QueueDepth: 1, WaitMs: 10, DurationMs: 30, Status: "ok"},
		{Source: servicecontract.AnalysisRequestSourceWarmup, QueueDepth: 3, WaitMs: 20, DurationMs: 40, Status: "timeout"},
		{Source: servicecontract.AnalysisRequestSourceWarmup, QueueDepth: 2, WaitMs: 30, DurationMs: 50, Status: "canceled"},
		{Source: servicecontract.AnalysisRequestSourceWarmup, QueueDepth: 2, WaitMs: 40, DurationMs: 60, Status: "error"},
		{Source: servicecontract.AnalysisRequestSourceUser, DurationMs: 70, Status: "ok"},
	} {
		metrics.record(sample)
	}

	snapshot := metrics.snapshot()
	if snapshot.WarmupQueueDepthMax != 3 {
		t.Fatalf("WarmupQueueDepthMax = %d, want 3", snapshot.WarmupQueueDepthMax)
	}
	if snapshot.WarmupFulfilled != 1 || snapshot.WarmupTimeouts != 1 || snapshot.WarmupCanceled != 1 || snapshot.WarmupFailed != 1 {
		t.Fatalf("unexpected warmup counters: %+v", snapshot)
	}
	if snapshot.WarmupWaitP95Ms != 40 || snapshot.WarmupDurationP95Ms != 60 || snapshot.NormalP95Ms != 70 {
		t.Fatalf("unexpected percentile snapshot: %+v", snapshot)
	}
}

func writeMinimalPNG(t *testing.T, path string, corruptCRC bool, trailing bool) {
	t.Helper()

	var out bytes.Buffer
	out.Write([]byte{137, 80, 78, 71, 13, 10, 26, 10})

	ihdrData := []byte{
		0, 0, 0, 1,
		0, 0, 0, 1,
		8, 2, 0, 0, 0,
	}
	writePNGChunk(&out, "IHDR", ihdrData, corruptCRC)
	writePNGChunk(&out, "IEND", nil, false)
	if trailing {
		out.WriteString("not-an-iend!")
	}

	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePNGChunk(out *bytes.Buffer, chunkType string, data []byte, corruptCRC bool) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(data)))
	start := out.Len()
	out.WriteString(chunkType)
	out.Write(data)
	crc := crc32.ChecksumIEEE(out.Bytes()[start:])
	if corruptCRC {
		crc++
	}
	_ = binary.Write(out, binary.BigEndian, crc)
}
