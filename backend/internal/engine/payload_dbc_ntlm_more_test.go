package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestPayloadSourceStrongHintAndDecoderHelpers(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{FamilyHint: "antsword_like"},
		{SourceRole: "key_negotiation"},
		{DecoderHints: []string{" BEHINDER "}},
		{DecoderOptionsHint: map[string]any{"decoder": "godzilla"}},
		{Signals: []string{"script-after-base64"}},
	}
	for _, source := range sources {
		if !payloadSourcesHaveStrongWebshellHint([]model.StreamPayloadSource{source}) {
			t.Fatalf("expected strong webshell hint for %+v", source)
		}
	}

	if payloadSourcesHaveStrongWebshellHint([]model.StreamPayloadSource{{Signals: []string{"benign"}}}) {
		t.Fatal("benign source should not be a strong webshell hint")
	}
	if !streamPayloadSourceHasDecoder(model.StreamPayloadSource{DecoderHints: []string{" antSword "}}, "antsword") {
		t.Fatal("expected decoder hint match to be case-insensitive")
	}
	if streamPayloadSourceHasDecoder(model.StreamPayloadSource{DecoderOptionsHint: map[string]any{"decoder": 42}}, "behinder") {
		t.Fatal("non-string decoder option should not match")
	}
}

func TestPayloadSourceHTTPMetaAndStreamBodyFetchRank(t *testing.T) {
	packet := model.Packet{
		ID: 7, Protocol: "TCP", DisplayProtocol: "HTTP",
		DestIP: "203.0.113.10", DestPort: 8080,
		Info:    "POST http://demo.local/upload/shell.php?cmd=id HTTP/1.1",
		Payload: "POST /upload/shell.php?cmd=id HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=eval($_POST[x])",
	}
	meta, ok := parsePayloadSourceHTTPMeta(packet)
	if !ok {
		t.Fatal("expected HTTP meta to parse")
	}
	if meta.method != "POST" || meta.uri != "/upload/shell.php?cmd=id" || meta.host != "demo.local" || meta.contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("unexpected HTTP meta: %+v", meta)
	}
	if !hasHTTPBody(meta.raw) {
		t.Fatalf("expected HTTP body to be detected")
	}
	if !shouldFetchPayloadSourceStreamBody(payloadSourceHTTPMeta{method: "POST", uri: "/shell.php", contentType: "application/x-www-form-urlencoded"}) {
		t.Fatal("high-rank suspicious POST should fetch stream body")
	}
	if shouldFetchPayloadSourceStreamBody(payloadSourceHTTPMeta{method: "GET", uri: "/shell.php"}) {
		t.Fatal("GET should not fetch fallback stream body")
	}
	if rank := payloadSourceStreamBodyFetchRank(payloadSourceHTTPMeta{method: "PATCH", uri: "/cmd/exec", contentType: "text/plain"}); rank <= payloadSourceStreamBodyFallbackMinScore {
		t.Fatalf("expected suspicious PATCH rank above threshold, got %d", rank)
	}

	if value := parseHTTPHeaderValue([]string{"Host: demo", "Content-Type: text/plain", ""}, "content-type"); value != "text/plain" {
		t.Fatalf("parseHTTPHeaderValue() = %q", value)
	}
	if !looksLikeHTTPRequestLine("OPTIONS /api HTTP/1.1") {
		t.Fatal("expected OPTIONS request line to be recognized")
	}
	if method, uri := parseHTTPRequestLine("POST http://example.test/a?b=1 HTTP/1.1"); method != "POST" || uri != "/a?b=1" {
		t.Fatalf("parseHTTPRequestLine() = %q %q", method, uri)
	}
	if _, ok := parsePayloadSourceHTTPMeta(model.Packet{Protocol: "DNS", Info: "query", Payload: ""}); ok {
		t.Fatal("non-HTTP packet should not parse as payload source meta")
	}
}

func TestFetchStreamRequestBodiesFromChunksAndRequestFallback(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	svc.streamCtl.streamCache[streamCacheKey("HTTP", 5)] = model.ReassembledStream{
		StreamID: 5,
		Protocol: "HTTP",
		Chunks: []model.StreamChunk{
			{PacketID: 1, Direction: "server", Body: "HTTP/1.1 200 OK\r\n\r\nignored"},
			{PacketID: 2, Direction: "client", Body: "POST /shell.php HTTP/1.1\r\nHost: demo\r\n\r\ncmd=whoami"},
			{PacketID: 3, Direction: "client", Body: "raw-body"},
		},
	}
	bodies := svc.fetchStreamRequestBodies(5)
	if !reflect.DeepEqual(bodies, []string{"cmd=whoami", "raw-body"}) {
		t.Fatalf("fetchStreamRequestBodies(chunks) = %+v", bodies)
	}

	svc.streamCtl.streamCache[streamCacheKey("HTTP", 6)] = model.ReassembledStream{
		StreamID: 6,
		Protocol: "HTTP",
		Request:  "POST /fallback HTTP/1.1\r\nHost: demo\r\n\r\npass=secret",
	}
	bodies = svc.fetchStreamRequestBodies(6)
	if !reflect.DeepEqual(bodies, []string{"pass=secret"}) {
		t.Fatalf("fetchStreamRequestBodies(request fallback) = %+v", bodies)
	}
	if got := svc.fetchStreamRequestBodies(404); got != nil {
		t.Fatalf("fetchStreamRequestBodies(missing) = %+v, want nil", got)
	}
}

func TestVehicleDBCProfileServiceAddDuplicateAndRemove(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	if got := svc.VehicleDBCProfiles(); got != nil {
		t.Fatalf("empty VehicleDBCProfiles() = %+v, want nil", got)
	}

	dbcPath := writeDBCFile(t, "vehicle.dbc", `VERSION ""

BO_ 291 VehicleStatus: 8 ECU
 SG_ Speed : 0|16@1+ (0.1,0) [0|250] "km/h" Vector__XXX
`)
	profiles, err := svc.AddVehicleDBC("  " + dbcPath + "  ")
	if err != nil {
		t.Fatalf("AddVehicleDBC() error = %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "vehicle" || profiles[0].MessageCount != 1 || profiles[0].SignalCount != 1 {
		t.Fatalf("unexpected DBC profiles after add: %+v", profiles)
	}
	svc.analysisCtl.vehicleAnalysis = &model.VehicleAnalysis{TotalVehiclePackets: 99}
	profiles, err = svc.AddVehicleDBC(dbcPath)
	if err != nil {
		t.Fatalf("duplicate AddVehicleDBC() error = %v", err)
	}
	if len(profiles) != 1 || svc.analysisCtl.vehicleAnalysis.TotalVehiclePackets != 99 {
		t.Fatalf("duplicate DBC add should not invalidate analysis or duplicate profile: profiles=%+v analysis=%+v", profiles, svc.analysisCtl.vehicleAnalysis)
	}

	second := &tshark.DBCDatabase{Path: filepath.Join(t.TempDir(), "manual.dbc"), Name: "manual", MessageCount: 2, SignalCount: 3}
	if got := buildDBCProfilesForService([]*tshark.DBCDatabase{nil, second}); len(got) != 1 || got[0].Name != "manual" {
		t.Fatalf("buildDBCProfilesForService() = %+v", got)
	}

	svc.analysisCtl.vehicleAnalysis = &model.VehicleAnalysis{TotalVehiclePackets: 42}
	profiles = svc.RemoveVehicleDBC(dbcPath)
	if len(profiles) != 0 || svc.analysisCtl.vehicleAnalysis != nil {
		t.Fatalf("RemoveVehicleDBC() profiles=%+v analysis=%+v, want empty and invalidated", profiles, svc.analysisCtl.vehicleAnalysis)
	}
}

func TestVehicleDBCProfileServiceRejectsMissingFile(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	if _, err := svc.AddVehicleDBC(filepath.Join(t.TempDir(), "missing.dbc")); err == nil {
		t.Fatal("expected AddVehicleDBC missing file to fail")
	}
}

func TestNTLMSessionMaterialsScanAndSort(t *testing.T) {
	oldScan := scanNTLMSessionRowsWithDisplayFilter
	t.Cleanup(func() { scanNTLMSessionRowsWithDisplayFilter = oldScan })

	var calls int
	scanNTLMSessionRowsWithDisplayFilter = func(filePath string, fields []string, displayFilter string, onRow func([]string)) error {
		calls++
		if filePath != "capture.pcapng" || displayFilter != "ntlmssp" {
			t.Fatalf("unexpected scan args file=%q filter=%q", filePath, displayFilter)
		}
		if calls == 1 {
			return errors.New("missing optional field")
		}
		rows := [][]string{
			{"12", "t2", "10.0.0.3", "", "10.0.0.4", "", "49152", "445", "SMB2", "Session Setup", "7", "", "", "alice", "ACME", "11223344", "aabbccdd", "eeff0011"},
			{"2", "t1", "10.0.0.4", "", "10.0.0.3", "", "445", "49152", "SMB2", "Challenge", "7", "", "NTLM", "", "", "11223344", "", ""},
			{"5", "t3", "10.0.0.5", "", "10.0.0.6", "", "50000", "5985", "HTTP", "WinRM Authorization", "", "NTLM abc", "", "bob", "DOMAIN", "", "beef", ""},
		}
		for _, row := range rows {
			onRow(row)
		}
		return nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	items, err := svc.ListNTLMSessionMaterialsWithContext(context.Background())
	if err != nil {
		t.Fatalf("ListNTLMSessionMaterialsWithContext() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected fallback scanner to retry once, got %d calls", calls)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 NTLM materials, got %+v", items)
	}
	if items[0].Protocol != "SMB3" || items[0].FrameNumber != "2" || items[0].Direction != "server -> client" || items[0].Complete {
		t.Fatalf("unexpected first sorted SMB challenge item: %+v", items[0])
	}
	if items[1].Protocol != "SMB3" || items[1].FrameNumber != "12" || !items[1].Complete || items[1].UserDisplay != `ACME\alice` || items[1].SessionID != "0x0000000000000007" {
		t.Fatalf("unexpected complete SMB item: %+v", items[1])
	}
	if items[2].Protocol != "WinRM" || items[2].UserDisplay != `DOMAIN\bob` || items[2].Direction != "client -> server" {
		t.Fatalf("unexpected WinRM item: %+v", items[2])
	}
}

func TestNTLMSessionMaterialsErrorsAndHelpers(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	if _, err := svc.ListNTLMSessionMaterials(); err == nil {
		t.Fatal("expected missing capture error")
	}

	oldScan := scanNTLMSessionRowsWithDisplayFilter
	t.Cleanup(func() { scanNTLMSessionRowsWithDisplayFilter = oldScan })
	scanNTLMSessionRowsWithDisplayFilter = func(string, []string, string, func([]string)) error {
		return errors.New("tshark failed")
	}
	svc.captureCtl.pcap = "capture.pcapng"
	if _, err := svc.ListNTLMSessionMaterialsWithContext(context.Background()); err == nil || !strings.Contains(err.Error(), "NTLM") {
		t.Fatalf("expected scan error mentioning NTLM, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanNTLMSessionMaterials(ctx, "capture.pcapng"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled NTLM scan, got %v", err)
	}

	if got := detectNTLMProtocol(ntlmSessionScanRow{displayProtocol: "HTTP", info: "NTLM"}); got != "HTTP" {
		t.Fatalf("detectNTLMProtocol(HTTP) = %q", got)
	}
	if got := detectNTLMProtocol(ntlmSessionScanRow{}); got != "NTLM" {
		t.Fatalf("detectNTLMProtocol(default) = %q", got)
	}
	if got := detectNTLMDirection(ntlmSessionScanRow{wwwAuthenticate: "NTLM"}); got != "server -> client" {
		t.Fatalf("detectNTLMDirection(challenge) = %q", got)
	}
	if got := formatNTLMUser("", "DOMAIN"); got != "DOMAIN" {
		t.Fatalf("formatNTLMUser(domain only) = %q", got)
	}
	if got := buildNTLMTransportLabel("", "445"); !strings.Contains(got, "?") || !strings.Contains(got, "445") {
		t.Fatalf("buildNTLMTransportLabel() = %q", got)
	}
	if got := joinNonEmpty(" / ", " a ", "", "b"); got != "a / b" {
		t.Fatalf("joinNonEmpty() = %q", got)
	}
}

func writeDBCFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write dbc: %v", err)
	}
	return path
}
