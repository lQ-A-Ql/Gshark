package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	return model.GlobalTrafficStats{}, nil
}

func (contractAnalysisService) GlobalTrafficStatsWithContext(context.Context) (model.GlobalTrafficStats, error) {
	return model.GlobalTrafficStats{}, nil
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

func requireJSONArray(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].([]any); !ok {
		t.Fatalf("JSON key %q = %#v, want array", key, payload[key])
	}
}

func requireJSONObject(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key].(map[string]any); !ok {
		t.Fatalf("JSON key %q = %#v, want object", key, payload[key])
	}
}
