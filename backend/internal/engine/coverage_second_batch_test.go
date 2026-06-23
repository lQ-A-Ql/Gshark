package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestC2DecryptFieldReaderAndRSAHelpers(t *testing.T) {
	line := strings.Join([]string{
		"91",
		"7",
		"2026-06-01T00:00:00Z",
		"10.1.1.10",
		"51000",
		"10.1.1.20",
		"80",
		"POST",
		"/submit?x=" + base64.StdEncoding.EncodeToString([]byte("metadata-123456")),
		"",
		"id=" + base64.StdEncoding.EncodeToString([]byte("cookie-123456")),
		"NTLM " + base64.StdEncoding.EncodeToString([]byte("auth-123456")),
		"41:42:43:44:45:46:47:48",
		"",
		"",
		"",
	}, "\t")

	seen := map[string]struct{}{}
	var out []c2DecryptCandidate
	if err := readCSHTTPFieldCandidates(context.Background(), strings.NewReader(line+"\n\n"), tshark.PlannedFieldScan{}, seen, &out); err != nil {
		t.Fatalf("readCSHTTPFieldCandidates() error = %v", err)
	}
	if len(out) < 4 {
		t.Fatalf("expected body and metadata candidates, got %#v", out)
	}
	if out[0].packet.ID != 91 || out[0].packet.StreamID != 7 || out[0].direction != "client_to_server" {
		t.Fatalf("unexpected first candidate metadata: %#v", out[0])
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readCSHTTPFieldCandidates(ctx, strings.NewReader(line+"\n"), tshark.PlannedFieldScan{}, seen, &out); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readCSHTTPFieldCandidates() error = %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if parsed, err := parseRSAPrivateKey(string(pkcs1)); err != nil || parsed.N.Cmp(key.N) != 0 {
		t.Fatalf("parse PKCS1 RSA key = key:%v err:%v", parsed != nil, err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	if parsed, err := parseRSAPrivateKey(string(pkcs8)); err != nil || parsed.N.Cmp(key.N) != 0 {
		t.Fatalf("parse PKCS8 RSA key = key:%v err:%v", parsed != nil, err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ecdsa) error = %v", err)
	}
	ecdsaBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(ecdsa) error = %v", err)
	}
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaBytes})
	if _, err := parseRSAPrivateKey(string(ecdsaPEM)); err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("expected non-RSA error, got %v", err)
	}
	if _, err := parseRSAPrivateKey("not pem"); err == nil || !strings.Contains(err.Error(), "missing PEM") {
		t.Fatalf("expected missing PEM error, got %v", err)
	}
}

func TestServiceAnalysisWrappersAndMediaEvidence(t *testing.T) {
	oldStats := buildGlobalTrafficStatsFromFileFn
	oldMediaFile := buildMediaAnalysisFromFileWithConfigFn
	oldMediaPacketStream := buildMediaAnalysisFromPacketStreamFn
	oldDetectRTPPorts := tsharkDetectLikelyRTPPortsForTest(t)
	t.Cleanup(func() {
		buildGlobalTrafficStatsFromFileFn = oldStats
		buildMediaAnalysisFromFileWithConfigFn = oldMediaFile
		buildMediaAnalysisFromPacketStreamFn = oldMediaPacketStream
		oldDetectRTPPorts()
	})

	buildGlobalTrafficStatsFromFileFn = func(path string) (model.GlobalTrafficStats, error) {
		if path != "capture.pcapng" {
			t.Fatalf("unexpected stats pcap path: %q", path)
		}
		return model.GlobalTrafficStats{TotalPackets: 3, ProtocolKinds: 2}, nil
	}
	buildMediaAnalysisFromPacketStreamFn = func(context.Context, string, int, tshark.MediaScanConfig, func(int, int, string), func(func(model.Packet) error) error) (model.MediaAnalysis, map[string]string, error) {
		return model.MediaAnalysis{}, nil, errors.New("force file fallback")
	}
	buildMediaAnalysisFromFileWithConfigFn = func(ctx context.Context, path string, exportDir string, cfg tshark.MediaScanConfig, progress func(int, int, string)) (model.MediaAnalysis, map[string]string, error) {
		if path != "capture.pcapng" || strings.TrimSpace(exportDir) == "" {
			t.Fatalf("unexpected media build args path=%q exportDir=%q", path, exportDir)
		}
		progress(1, 1, "done")
		return model.MediaAnalysis{
			TotalMediaPackets: 222,
			Sessions: []model.MediaSession{
				{
					ID: "video-1", MediaType: "video", Application: "RTP", Codec: "H264",
					Source: "10.0.0.1", SourcePort: 5004, Destination: "10.0.0.2", DestinationPort: 5006,
					PacketCount: 101, StartTime: "1.0", EndTime: "2.0",
				},
				{
					ID: "audio-1", MediaType: "audio", Application: "RTP", Codec: "OPUS",
					Source: "10.0.0.3", SourcePort: 5008, Destination: "10.0.0.4", DestinationPort: 5010,
					PacketCount: 4,
				},
			},
		}, map[string]string{"artifact": "path"}, nil
	}

	svc := NewService(NopEmitter{})
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })
	svc.captureCtl.pcap = "capture.pcapng"
	stats, err := svc.GlobalTrafficStats()
	if err != nil {
		t.Fatalf("GlobalTrafficStats() error = %v", err)
	}
	if stats.TotalPackets != 3 || stats.ProtocolKinds != 2 {
		t.Fatalf("unexpected stats wrapper result: %+v", stats)
	}

	media, err := svc.RefreshMediaAnalysis()
	if err != nil {
		t.Fatalf("RefreshMediaAnalysis() error = %v", err)
	}
	if media.TotalMediaPackets != 222 || len(media.Sessions) != 2 {
		t.Fatalf("unexpected media analysis: %+v", media)
	}
	if len(svc.mediaCtl.mediaPlayback) != 0 || len(svc.mediaCtl.mediaSpeech) != 0 {
		t.Fatalf("refresh should reset playback/speech caches")
	}

	svc.captureCtl.mu.Lock()
	svc.mediaCtl.mediaSpeech["audio-1"] = model.MediaTranscription{
		Token: "audio-1", Title: "Call", Text: strings.Repeat("hello ", 60),
		Engine: "vosk", Language: "zh", Segments: []model.MediaTranscriptionSegment{
			{Text: "1"}, {Text: "2"}, {Text: "3"}, {Text: "4"}, {Text: "5"}, {Text: "6"},
		},
	}
	svc.mediaCtl.mediaSpeech["blank"] = model.MediaTranscription{Token: "blank", Text: " "}
	svc.captureCtl.mu.Unlock()

	records, err := svc.gatherMediaEvidence(context.Background())
	if err != nil {
		t.Fatalf("gatherMediaEvidence() error = %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected two sessions plus one transcription evidence, got %+v", records)
	}
	if records[0].Confidence < records[1].Confidence || records[0].Severity == "" {
		t.Fatalf("video session should have stronger populated evidence, got %+v", records)
	}
	if len(records[2].Value) > 203 || !strings.HasSuffix(records[2].Value, "...") {
		t.Fatalf("transcription should be truncated, got len=%d value=%q", len(records[2].Value), records[2].Value)
	}

	if got := truncateString("abcdef", 3); got != "abc..." {
		t.Fatalf("truncateString() = %q", got)
	}
	if got := truncateString("abc", 10); got != "abc" {
		t.Fatalf("truncateString short = %q", got)
	}
}

func TestRuntimeDNP3WinRMAndDecoderBoundaryHelpers(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() {
		tshark.SetBinaryPath("")
		tshark.ClearCapabilityCache()
	})
	tshark.SetBinaryPath("C:/definitely/missing/tshark.exe")
	if got := svc.ToolRuntimeSnapshot(); got.ProbeMode != ToolRuntimeProbeModeFull || got.UpdatedAt == "" {
		t.Fatalf("ToolRuntimeSnapshot wrapper returned bad diagnostics: %+v", got)
	}
	if got := svc.ToolRuntimeSnapshotWithContext(nil); got.ProbeMode != ToolRuntimeProbeModeFull {
		t.Fatalf("ToolRuntimeSnapshotWithContext nil ctx = %+v", got)
	}
	if got := svc.SetTSharkPath(" C:/definitely/missing/tshark.exe "); got.UsingCustomPath && got.Available {
		t.Fatalf("SetTSharkPath should not report invalid custom path as usable: %+v", got)
	}
	_ = svc.SetTSharkPathWithContext(context.Background(), "")
	_ = svc.TSharkStatus()
	_ = svc.TSharkStatusWithContext(context.Background())
	_ = svc.TSharkStatusPath()
	_ = svc.TSharkUsingCustomPath()
	if mode := normalizeToolRuntimeProbeMode("unknown"); mode != ToolRuntimeProbeModeFull {
		t.Fatalf("normalize unknown mode = %q", mode)
	}

	if !onlyNonStandardRTPPorts([]int{6000, 6002}) || onlyNonStandardRTPPorts([]int{6000, 5004}) || onlyNonStandardRTPPorts(nil) {
		t.Fatal("onlyNonStandardRTPPorts boundary behavior changed")
	}
	if got := formatPortList([]int{5004, 6000}); got != "5004, 6000" {
		t.Fatalf("formatPortList() = %q", got)
	}

	for _, tt := range []struct {
		group, variation int
		want             int
	}{
		{1, 2, 8}, {20, 2, 3}, {30, 3, 5}, {40, 2, 3}, {50, 1, 6}, {99, 1, 1},
	} {
		if got := dnp3ValueSize(tt.group, tt.variation); got != tt.want {
			t.Fatalf("dnp3ValueSize(%d,%d) = %d, want %d", tt.group, tt.variation, got, tt.want)
		}
	}
	if got := formatDNP3Value([]byte{0x80}, 1, 1); got != "ON" {
		t.Fatalf("format binary DNP3 value = %q", got)
	}
	if got := formatDNP3Value([]byte{0, 0x34, 0x12}, 20, 2); got != "4660" {
		t.Fatalf("format counter DNP3 value = %q", got)
	}
	if got := dnp3QualifierName(0xff); got != "qualifier 0xFF" {
		t.Fatalf("dnp3QualifierName fallback = %q", got)
	}
	if got := dnp3FunctionCodeName(0x30); got != "Function 0x30" {
		t.Fatalf("dnp3FunctionCodeName fallback = %q", got)
	}

	if isWinRMFieldCompatibilityError(nil) || !isWinRMFieldCompatibilityError(errors.New("Some fields aren't valid: mime_multipart.data")) {
		t.Fatal("WinRM field compatibility detection failed")
	}
	if got := explainWinRMScanError(nil); got != "unknown error" {
		t.Fatalf("nil WinRM scan error = %q", got)
	}
	if got := prettyXMLOrRaw([]byte("  <root/> \n")); got != "<root/>" {
		t.Fatalf("prettyXMLOrRaw XML = %q", got)
	}
	if got := prettyXMLOrRaw(nil); got != "[empty message]" {
		t.Fatalf("prettyXMLOrRaw empty = %q", got)
	}
	token := append([]byte("NTLMSSP\x00"), 1, 0, 0, 0)
	header := "Basic nope, NTLM " + base64.StdEncoding.EncodeToString(token)
	if parsed := parseHTTPAuthToken(header); !reflect.DeepEqual(parsed, token) {
		t.Fatalf("parseHTTPAuthToken() = %#v, want %#v", parsed, token)
	}

	if key := normalizeAESKey([]byte("short")); len(key) != 16 || !strings.HasPrefix(string(key), "short") {
		t.Fatalf("normalizeAESKey short = %#v", key)
	}
	if key := normalizeAESKey([]byte(strings.Repeat("a", 40))); len(key) != 32 {
		t.Fatalf("normalizeAESKey long len = %d", len(key))
	}
	if got := bytesToDisplayText([]byte{'a', 0, 0}); got != "a" {
		t.Fatalf("bytesToDisplayText trimmed = %q", got)
	}
	if got := optionsBoolDefault(map[string]any{"enabled": "true"}, "enabled", false); !got {
		t.Fatal("optionsBoolDefault string true failed")
	}
	if got := optionsIntDefault(map[string]any{"n": "42"}, "n", 1); got != 42 {
		t.Fatalf("optionsIntDefault string = %d", got)
	}
	if _, _, err := decodeCipherInput("xx", "rot13"); err == nil {
		t.Fatal("decodeCipherInput should reject unsupported mode")
	}
	if decoded, mode, err := decodeCipherInput("41424344", "auto"); err != nil || mode != "hex" || string(decoded) != "ABCD" {
		t.Fatalf("decodeCipherInput auto hex = %q %q %v", decoded, mode, err)
	}
}

func tsharkDetectLikelyRTPPortsForTest(t *testing.T) func() {
	t.Helper()
	// buildMediaScanConfig calls tshark.DetectLikelyRTPPorts directly. Keep this
	// helper as a no-op restore hook so the test documents the external boundary.
	return func() {}
}

func TestAnalysisInFlightDoDirectAndFallbackBranches(t *testing.T) {
	group := &analysisInFlightGroup{}
	value, err := group.do(context.Background(), "", func() (any, error) {
		return "direct", nil
	})
	if err != nil || value != "direct" {
		t.Fatalf("direct do() = %v %v", value, err)
	}

	typed, err := doInFlightAnalysis(context.Background(), group, "typed", func() (int, error) {
		return 7, nil
	})
	if err != nil || typed != 7 {
		t.Fatalf("typed doInFlightAnalysis() = %d %v", typed, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := group.do(ctx, "cancel", func() (any, error) { return "never", nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled do() error = %v", err)
	}

	slow := &analysisInFlightGroup{}
	call := &analysisInFlightCall{done: make(chan struct{})}
	call.result = "normal-result"
	close(call.done)
	slow.calls = map[string]*analysisInFlightCall{"normal": call}
	joined := make(chan struct{})
	builderCalled := make(chan struct{}, 1)
	go func() {
		defer close(joined)
		value, err = slow.doWithFallback(context.Background(), "warmup", "normal", func() (any, error) {
			builderCalled <- struct{}{}
			return "wrong", nil
		})
	}()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("fallback join did not complete")
	}
	select {
	case <-builderCalled:
		t.Fatal("fallback call should join normal in-flight work")
	default:
	}
	if err != nil || value != "normal-result" {
		t.Fatalf("fallback join = %v %v", value, err)
	}
}
