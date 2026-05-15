package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
)

func TestCaptureStatusContract(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	rec := httptest.NewRecorder()

	server.handleCaptureStatus(rec, httptest.NewRequest(http.MethodGet, "/api/capture/status", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "file_path", "has_capture", "packet_count")
	requireJSONString(t, payload, "file_path")
	requireJSONBool(t, payload, "has_capture")
	requireJSONNumber(t, payload, "packet_count")
}

func TestPacketsPageContract(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	rec := httptest.NewRecorder()

	server.handlePacketsPage(rec, httptest.NewRequest(http.MethodGet, "/api/packets/page?cursor=0&limit=50", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "items", "next_cursor", "total", "has_more", "filtering")
	requireJSONArray(t, payload, "items")
	requireJSONNumber(t, payload, "next_cursor")
	requireJSONNumber(t, payload, "total")
	requireJSONBool(t, payload, "has_more")
	requireJSONBool(t, payload, "filtering")
}

func TestStreamIndexContract(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	rec := httptest.NewRecorder()

	server.handleStreamIndex(rec, httptest.NewRequest(http.MethodGet, "/api/streams/index?protocol=tcp", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "protocol", "total", "ids")
	if got := payload["protocol"]; got != "TCP" {
		t.Fatalf("protocol = %#v, want TCP", got)
	}
	requireJSONNumber(t, payload, "total")
	requireJSONArray(t, payload, "ids")
}

func TestEvidenceContractEmptyCapture(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	rec := httptest.NewRecorder()

	server.handleEvidence(rec, httptest.NewRequest(http.MethodGet, "/api/evidence", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "records", "total")
	requireJSONArray(t, payload, "records")
	requireJSONNumber(t, payload, "total")
}

func TestEvidenceContractModuleFilter(t *testing.T) {
	analysis := &contractEvidenceAnalysisService{}
	server := &Server{analysis: analysis}
	rec := httptest.NewRecorder()

	server.handleEvidence(rec, httptest.NewRequest(http.MethodGet, "/api/evidence?modules=c2,%20usb,,", nil))

	requireStatus(t, rec, http.StatusOK)
	if got := strings.Join(analysis.modules, ","); got != "c2,usb" {
		t.Fatalf("modules = %q, want c2,usb", got)
	}
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "records", "total", "notes")
	if got := payload["total"]; got != float64(1) {
		t.Fatalf("total = %#v, want 1", got)
	}
	records := requireJSONArray(t, payload, "records")
	if len(records) != 1 {
		t.Fatalf("records = %#v, want one record", records)
	}
	record, ok := records[0].(map[string]any)
	if !ok {
		t.Fatalf("record = %#v, want object", records[0])
	}
	requireJSONKeys(t, record, "id", "module", "source_type", "summary", "severity")
	if record["id"] != "ev-1" || record["module"] != "c2" || record["severity"] != "high" {
		t.Fatalf("unexpected evidence record: %#v", record)
	}
	notes := requireJSONArray(t, payload, "notes")
	if len(notes) != 1 || notes[0] != "contract" {
		t.Fatalf("notes = %#v, want [contract]", notes)
	}
}

func TestToolRuntimeConfigContract(t *testing.T) {
	server := &Server{toolRuntime: contractToolRuntimeService{}}
	rec := httptest.NewRecorder()

	server.handleToolRuntimeConfig(rec, httptest.NewRequest(http.MethodGet, "/api/tools/runtime-config", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "config", "tshark", "ffmpeg", "speech", "yara")
	config := requireJSONNestedObject(t, payload, "config")
	requireJSONKeys(t, config, "tshark_path", "ffmpeg_path", "python_path", "vosk_model_path", "yara_enabled", "yara_bin", "yara_rules", "yara_timeout_ms")
	tshark := requireJSONNestedObject(t, payload, "tshark")
	requireJSONKeys(t, tshark, "available", "path", "message")
	ffmpeg := requireJSONNestedObject(t, payload, "ffmpeg")
	requireJSONKeys(t, ffmpeg, "available", "path", "message")
	speech := requireJSONNestedObject(t, payload, "speech")
	requireJSONKeys(t, speech, "available", "engine", "language", "python_available", "ffmpeg_available", "vosk_available", "model_available", "message")
	yara := requireJSONNestedObject(t, payload, "yara")
	requireJSONKeys(t, yara, "available", "enabled", "message", "using_custom_bin", "using_custom_rules", "timeout_ms")
}

func TestGlobalTrafficStatsContract(t *testing.T) {
	server := &Server{analysis: contractAnalysisService{}}
	rec := httptest.NewRecorder()

	server.handleGlobalTrafficStats(rec, httptest.NewRequest(http.MethodGet, "/api/stats/traffic/global", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "total_packets", "protocol_kinds", "timeline", "protocol_dist", "top_talkers", "top_hostnames", "top_domains", "top_src_ips", "top_dst_ips", "top_computer_names", "top_dest_ports", "top_src_ports")
	requireJSONNumber(t, payload, "total_packets")
	requireJSONNumber(t, payload, "protocol_kinds")
	requireJSONArray(t, payload, "timeline")
	requireJSONArray(t, payload, "protocol_dist")
	requireJSONArray(t, payload, "top_talkers")
}

func TestPacketInlineContractRejectsInvalidID(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	tests := []struct {
		name   string
		path   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{name: "locate", path: "/api/packets/locate?id=bad", handle: server.handlePacketLocate},
		{name: "raw", path: "/api/packet/raw?id=bad", handle: server.handlePacketRaw},
		{name: "layers", path: "/api/packet/layers?id=bad", handle: server.handlePacketLayers},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handle(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			requireStatus(t, rec, http.StatusBadRequest)
			payload := decodeJSONMap(t, rec)
			requireJSONKeys(t, payload, "error")
			requireJSONString(t, payload, "error")
		})
	}
}

func TestPacketDetailContract(t *testing.T) {
	server := &Server{capture: contractCaptureService{}}
	rec := httptest.NewRecorder()

	server.handlePacket(rec, httptest.NewRequest(http.MethodGet, "/api/packet?id=7", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "id", "timestamp", "source_ip", "dest_ip", "protocol", "length", "info", "payload", "stream_id")
	requireJSONNumber(t, payload, "id")
	requireJSONString(t, payload, "protocol")
	requireJSONNumber(t, payload, "length")
}

func TestPacketLocateContract(t *testing.T) {
	server := &Server{capture: contractCaptureService{}}
	rec := httptest.NewRecorder()

	server.handlePacketLocate(rec, httptest.NewRequest(http.MethodGet, "/api/packets/locate?id=7&limit=50", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "packet_id", "cursor", "total", "found")
	requireJSONNumber(t, payload, "packet_id")
	requireJSONNumber(t, payload, "cursor")
	requireJSONNumber(t, payload, "total")
	requireJSONBool(t, payload, "found")
}

func TestPacketRawContract(t *testing.T) {
	server := &Server{capture: contractCaptureService{}}
	rec := httptest.NewRecorder()

	server.handlePacketRaw(rec, httptest.NewRequest(http.MethodGet, "/api/packet/raw?id=7", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "packet_id", "raw_hex")
	requireJSONNumber(t, payload, "packet_id")
	requireJSONString(t, payload, "raw_hex")
}

func TestPacketLayersContract(t *testing.T) {
	server := &Server{capture: contractCaptureService{}}
	rec := httptest.NewRecorder()

	server.handlePacketLayers(rec, httptest.NewRequest(http.MethodGet, "/api/packet/layers?id=7", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "packet_id", "layers")
	requireJSONNumber(t, payload, "packet_id")
	requireJSONObject(t, payload, "layers")
}

func TestIndustrialAnalysisContract(t *testing.T) {
	server := &Server{analysis: contractAnalysisService{}}
	rec := httptest.NewRecorder()

	server.handleIndustrialAnalysis(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/industrial", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "total_industrial_packets", "protocols", "conversations", "modbus", "details", "notes", "report")
	requireJSONNumber(t, payload, "total_industrial_packets")
	requireJSONArray(t, payload, "protocols")
	requireJSONArray(t, payload, "conversations")
	requireJSONObject(t, payload, "modbus")
	requireJSONArray(t, payload, "details")
	requireJSONArray(t, payload, "notes")
	requireJSONObject(t, payload, "report")
}

func TestVehicleAnalysisContract(t *testing.T) {
	server := &Server{analysis: contractAnalysisService{}}
	rec := httptest.NewRecorder()

	server.handleVehicleAnalysis(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/vehicle", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "total_vehicle_packets", "protocols", "conversations", "can", "j1939", "doip", "uds", "recommendations", "report")
	requireJSONNumber(t, payload, "total_vehicle_packets")
	requireJSONArray(t, payload, "protocols")
	requireJSONArray(t, payload, "conversations")
	requireJSONObject(t, payload, "can")
	requireJSONObject(t, payload, "j1939")
	requireJSONObject(t, payload, "doip")
	requireJSONObject(t, payload, "uds")
	requireJSONArray(t, payload, "recommendations")
	requireJSONObject(t, payload, "report")
}

func TestUSBAnalysisContract(t *testing.T) {
	server := &Server{analysis: contractAnalysisService{}}
	rec := httptest.NewRecorder()

	server.handleUSBAnalysis(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/usb", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "total_usb_packets", "keyboard_packets", "mouse_packets", "other_usb_packets", "hid_packets", "mass_storage_packets", "protocols", "records", "hid", "mass_storage", "other", "notes", "report")
	requireJSONNumber(t, payload, "total_usb_packets")
	requireJSONNumber(t, payload, "keyboard_packets")
	requireJSONNumber(t, payload, "mouse_packets")
	requireJSONNumber(t, payload, "other_usb_packets")
	requireJSONNumber(t, payload, "hid_packets")
	requireJSONNumber(t, payload, "mass_storage_packets")
	requireJSONArray(t, payload, "protocols")
	requireJSONArray(t, payload, "records")
	requireJSONObject(t, payload, "hid")
	requireJSONObject(t, payload, "mass_storage")
	requireJSONObject(t, payload, "other")
	requireJSONArray(t, payload, "notes")
	requireJSONObject(t, payload, "report")
}

func TestC2AnalysisContract(t *testing.T) {
	server := &Server{analysis: contractAnalysisService{}}
	rec := httptest.NewRecorder()

	server.handleC2Analysis(rec, httptest.NewRequest(http.MethodGet, "/api/c2-analysis", nil))

	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "total_matched_packets", "families", "conversations", "cs", "vshell", "notes")
	requireJSONNumber(t, payload, "total_matched_packets")
	requireJSONArray(t, payload, "families")
	requireJSONArray(t, payload, "conversations")
	requireJSONObject(t, payload, "cs")
	requireJSONObject(t, payload, "vshell")
	requireJSONArray(t, payload, "notes")
}

type contractCaptureService struct{}

func (contractCaptureService) BeginCaptureLoad(ctx context.Context) (int64, context.Context) {
	return 1, ctx
}

func (contractCaptureService) LoadPCAPWithRun(context.Context, model.ParseOptions, int64) error {
	return nil
}

func (contractCaptureService) PrepareCaptureReplacement() {}

func (contractCaptureService) StopStreaming() bool { return false }

func (contractCaptureService) ClearCapture() error { return nil }

func (contractCaptureService) CaptureStatus() model.CaptureStatus { return model.CaptureStatus{} }

func (contractCaptureService) CurrentCapturePath() string { return "" }

func (contractCaptureService) Packets() []model.Packet { return []model.Packet{contractPacket()} }

func (contractCaptureService) PacketsPageWithState(int, int, string) ([]model.Packet, int, int, bool, error) {
	return []model.Packet{contractPacket()}, 1, 1, false, nil
}

func (contractCaptureService) PacketPageCursorWithError(int64, int, string) (int, int, bool, error) {
	return 0, 1, true, nil
}

func (contractCaptureService) Packet(int64) (model.Packet, error) { return contractPacket(), nil }

func (contractCaptureService) PacketRawHex(int64) (string, error) { return "45000000", nil }

func (contractCaptureService) PacketLayers(int64) (map[string]any, error) {
	return map[string]any{"frame": map[string]any{"frame.number": "7"}}, nil
}

func (contractCaptureService) StreamIDs(string) []int64 { return []int64{3} }

func (contractCaptureService) HTTPStream(context.Context, int64) model.ReassembledStream {
	return model.ReassembledStream{}
}

func (contractCaptureService) RawStream(context.Context, string, int64) model.ReassembledStream {
	return model.ReassembledStream{}
}

func (contractCaptureService) RawStreamPage(context.Context, string, int64, int, int) (model.ReassembledStream, int, int) {
	return model.ReassembledStream{}, 0, 0
}

func (contractCaptureService) UpdateStreamPayloads(context.Context, string, int64, []model.StreamChunkPatch) (model.ReassembledStream, error) {
	return model.ReassembledStream{}, nil
}

func (contractCaptureService) ListStreamPayloadSources(int) ([]model.StreamPayloadSource, error) {
	return []model.StreamPayloadSource{}, nil
}

func contractPacket() model.Packet {
	return model.Packet{
		ID:        7,
		Timestamp: "2026-05-14T23:25:00+08:00",
		SourceIP:  "10.0.0.1",
		DestIP:    "10.0.0.2",
		Protocol:  "HTTP",
		Length:    64,
		Info:      "GET /demo",
		Payload:   "demo",
		StreamID:  3,
	}
}

type contractAnalysisService struct{}

func (contractAnalysisService) GlobalTrafficStats() (model.GlobalTrafficStats, error) {
	return contractAnalysisService{}.GlobalTrafficStatsWithContext(context.Background())
}

func (contractAnalysisService) GlobalTrafficStatsWithContext(context.Context) (model.GlobalTrafficStats, error) {
	return model.GlobalTrafficStats{
		TotalPackets:  1,
		ProtocolKinds: 1,
		Timeline:      []model.TrafficBucket{{Label: "2026-05-14T23:25:00+08:00", Count: 1}},
		ProtocolDist:  []model.TrafficBucket{{Label: "HTTP", Count: 1}},
		TopTalkers:    []model.TrafficBucket{{Label: "10.0.0.1 -> 10.0.0.2", Count: 1}},
		TopHostnames:  []model.TrafficBucket{},
		TopDomains:    []model.TrafficBucket{},
		TopSrcIPs:     []model.TrafficBucket{{Label: "10.0.0.1", Count: 1}},
		TopDstIPs:     []model.TrafficBucket{{Label: "10.0.0.2", Count: 1}},
		TopDestPorts:  []model.TrafficBucket{{Label: "80", Count: 1}},
		TopSrcPorts:   []model.TrafficBucket{},
	}, nil
}

func (contractAnalysisService) IndustrialAnalysis() (model.IndustrialAnalysis, error) {
	return contractAnalysisService{}.IndustrialAnalysisWithContext(context.Background())
}

func (contractAnalysisService) IndustrialAnalysisWithContext(context.Context) (model.IndustrialAnalysis, error) {
	return model.IndustrialAnalysis{
		TotalIndustrialPackets: 1,
		Protocols:              []model.TrafficBucket{{Label: "modbus", Count: 1}},
		Conversations:          []model.AnalysisConversation{{Label: "10.0.0.1 -> 10.0.0.2", Count: 1}},
		Details:                []model.IndustrialProtocolDetail{},
		Notes:                  []string{"contract"},
		Report:                 contractReport(),
	}, nil
}

func (contractAnalysisService) VehicleAnalysis() (model.VehicleAnalysis, error) {
	return contractAnalysisService{}.VehicleAnalysisWithContext(context.Background())
}

func (contractAnalysisService) VehicleAnalysisWithContext(context.Context) (model.VehicleAnalysis, error) {
	return model.VehicleAnalysis{
		TotalVehiclePackets: 1,
		Protocols:           []model.TrafficBucket{{Label: "can", Count: 1}},
		Conversations:       []model.AnalysisConversation{},
		Recommendations:     []string{"review diagnostic traffic"},
		Report:              contractReport(),
	}, nil
}

func (contractAnalysisService) VehicleDBCProfiles() []model.DBCProfile { return []model.DBCProfile{} }

func (contractAnalysisService) AddVehicleDBC(string) ([]model.DBCProfile, error) {
	return []model.DBCProfile{}, nil
}

func (contractAnalysisService) RemoveVehicleDBC(string) []model.DBCProfile {
	return []model.DBCProfile{}
}

func (contractAnalysisService) USBAnalysis() (model.USBAnalysis, error) {
	return contractAnalysisService{}.USBAnalysisWithContext(context.Background())
}

func (contractAnalysisService) USBAnalysisWithContext(context.Context) (model.USBAnalysis, error) {
	return model.USBAnalysis{
		TotalUSBPackets: 1,
		Protocols:       []model.TrafficBucket{{Label: "usb", Count: 1}},
		Records:         []model.USBPacketRecord{},
		Notes:           []string{"contract"},
		Report:          contractReport(),
	}, nil
}

func (contractAnalysisService) C2SampleAnalysis(context.Context) (model.C2SampleAnalysis, error) {
	return model.C2SampleAnalysis{
		TotalMatchedPackets: 1,
		Families:            []model.TrafficBucket{{Label: "cs", Count: 1}},
		Conversations:       []model.AnalysisConversation{},
		CS:                  model.C2FamilyAnalysis{Candidates: []model.C2IndicatorRecord{}, Notes: []string{"contract"}},
		VShell:              model.C2FamilyAnalysis{Candidates: []model.C2IndicatorRecord{}, Notes: []string{}},
		Notes:               []string{"contract"},
	}, nil
}

func (contractAnalysisService) C2Decrypt(context.Context, model.C2DecryptRequest) (model.C2DecryptResult, error) {
	return model.C2DecryptResult{}, nil
}

func (contractAnalysisService) APTAnalysis(context.Context) (model.APTAnalysis, error) {
	return model.APTAnalysis{}, nil
}

func (contractAnalysisService) GatherEvidence(context.Context, model.EvidenceFilter) (model.EvidenceResponse, error) {
	return model.EvidenceResponse{Records: []model.EvidenceRecord{}, Total: 0}, nil
}

type contractEvidenceAnalysisService struct {
	contractAnalysisService
	modules []string
}

func (s *contractEvidenceAnalysisService) GatherEvidence(_ context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error) {
	s.modules = append([]string(nil), filter.Modules...)
	return model.EvidenceResponse{
		Records: []model.EvidenceRecord{
			{
				ID:         "ev-1",
				Module:     "c2",
				SourceType: "stream",
				Summary:    "contract evidence",
				Severity:   "high",
			},
		},
		Total: 1,
		Notes: []string{"contract"},
	}, nil
}

type contractToolRuntimeService struct{}

func (contractToolRuntimeService) TSharkStatus() model.TSharkToolStatus {
	return model.TSharkToolStatus{Available: true, Path: "tshark", Message: "ok"}
}

func (contractToolRuntimeService) SetTSharkPath(string) model.TSharkToolStatus {
	return contractToolRuntimeService{}.TSharkStatus()
}

func (contractToolRuntimeService) TSharkStatusPath() string { return "tshark" }

func (contractToolRuntimeService) TSharkUsingCustomPath() bool { return false }

func (contractToolRuntimeService) ToolRuntimeSnapshot() model.ToolRuntimeSnapshot {
	return model.ToolRuntimeSnapshot{
		Config: model.ToolRuntimeConfig{
			TSharkPath:    "tshark",
			FFmpegPath:    "ffmpeg",
			PythonPath:    "python",
			VoskModelPath: "model",
			YaraEnabled:   true,
			YaraBin:       "yara",
			YaraRules:     "rules.yar",
			YaraTimeoutMS: 25000,
		},
		TShark: model.TSharkToolStatus{Available: true, Path: "tshark", Message: "ok"},
		FFmpeg: model.FFmpegToolStatus{Available: true, Path: "ffmpeg", Message: "ok"},
		Speech: model.SpeechToTextStatus{Available: true, Engine: "vosk", Language: "auto", PythonAvailable: true, FFmpegAvailable: true, VoskAvailable: true, ModelAvailable: true, Message: "ok"},
		Yara:   model.YaraToolStatus{Available: true, Enabled: true, Message: "ok", TimeoutMS: 25000},
	}
}

func (contractToolRuntimeService) SetToolRuntimeConfig(model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	return contractToolRuntimeService{}.ToolRuntimeSnapshot().Config
}

func (contractToolRuntimeService) FFmpegStatus() model.FFmpegToolStatus {
	return model.FFmpegToolStatus{Available: true, Path: "ffmpeg", Message: "ok"}
}

func (contractToolRuntimeService) TLSConfig() model.TLSConfig { return model.TLSConfig{} }

func (contractToolRuntimeService) SetTLSConfig(model.TLSConfig) {}

func contractReport() model.InvestigationReport {
	return model.InvestigationReport{
		Summary: []model.InvestigationReportItem{{Title: "Contract", Summary: "shape guard", Severity: "info"}},
	}
}

func decodeJSONMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON object: %v body=%s", err, rec.Body.String())
	}
	return payload
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, want, rec.Body.String())
	}
}

func requireJSONKeys(t *testing.T, payload map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing JSON key %q in payload %#v", key, payload)
		}
	}
}

func requireExactJSONKeys(t *testing.T, payload map[string]any, keys ...string) {
	t.Helper()
	requireJSONKeys(t, payload, keys...)
	if len(payload) != len(keys) {
		t.Fatalf("payload keys = %#v, want exactly %#v", payload, keys)
	}
}

func requireJSONString(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].(string); !ok {
		t.Fatalf("JSON key %q = %#v, want string", key, payload[key])
	}
}

func requireJSONBool(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].(bool); !ok {
		t.Fatalf("JSON key %q = %#v, want bool", key, payload[key])
	}
}

func requireJSONNumber(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].(float64); !ok {
		t.Fatalf("JSON key %q = %#v, want JSON number", key, payload[key])
	}
}

func requireJSONArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("JSON key %q = %#v, want array", key, payload[key])
	}
	return value
}

func requireJSONObject(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].(map[string]any); !ok {
		t.Fatalf("JSON key %q = %#v, want object", key, payload[key])
	}
}

func requireJSONNestedObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("JSON key %q = %#v, want object", key, payload[key])
	}
	return value
}
