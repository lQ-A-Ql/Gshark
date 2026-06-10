package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestJSONRPCMethodContracts(t *testing.T) {
	server := newTestMCPServer(t, nil)
	tests := []struct {
		name      string
		body      string
		wantKey   string
		wantError bool
	}{
		{name: "initialize", body: `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, wantKey: "protocolVersion"},
		{name: "tools/list", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, wantKey: "tools"},
		{name: "resources/list", body: `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`, wantKey: "resources"},
		{name: "resources/templates/list", body: `{"jsonrpc":"2.0","id":4,"method":"resources/templates/list"}`, wantKey: "resourceTemplates"},
		{name: "prompts/list", body: `{"jsonrpc":"2.0","id":5,"method":"prompts/list"}`, wantKey: "prompts"},
		{name: "unknown", body: `{"jsonrpc":"2.0","id":6,"method":"does/not/exist"}`, wantError: true},
		{name: "invalid params", body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":[]}`, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := callMCP(t, server, tt.body)
			requireMCPHTTPStatus(t, rec, http.StatusOK)
			payload := decodeMCPMap(t, rec)
			if tt.wantError {
				errObj := requireMCPObject(t, payload, "error")
				if _, ok := errObj["code"].(float64); !ok {
					t.Fatalf("error code = %#v, want number", errObj["code"])
				}
				return
			}
			result := requireMCPObject(t, payload, "result")
			if _, ok := result[tt.wantKey]; !ok {
				t.Fatalf("result missing %q: %#v", tt.wantKey, result)
			}
		})
	}

	parseErr := callMCP(t, server, `{bad json`)
	requireMCPHTTPStatus(t, parseErr, http.StatusBadRequest)
}

func TestResourceReadContracts(t *testing.T) {
	server := newTestMCPServer(t, nil)
	tests := []string{
		"meow://runtime/snapshot",
		"meow://capture/status",
		"meow://analysis/evidence",
		"meow://catalog/misc-modules",
		"meow://audit/recent",
		"meow://packet/7",
		"meow://stream/tcp/3",
	}

	for _, uri := range tests {
		t.Run(uri, func(t *testing.T) {
			rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"`+uri+`"}}`)
			requireMCPHTTPStatus(t, rec, http.StatusOK)
			payload := decodeMCPMap(t, rec)
			result := requireMCPObject(t, payload, "result")
			contents := requireMCPArray(t, result, "contents")
			if len(contents) != 1 {
				t.Fatalf("contents len = %d, want 1", len(contents))
			}
		})
	}

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"meow://stream/icmp/3"}}`)
	payload := decodeMCPMap(t, rec)
	errObj := requireMCPObject(t, payload, "error")
	if errObj["code"] != float64(-32602) {
		t.Fatalf("error code = %#v, want -32602", errObj["code"])
	}
}

func TestPromptGetContracts(t *testing.T) {
	server := newTestMCPServer(t, nil)
	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"triage_capture","arguments":{"focus":"c2"}}}`)
	requireMCPHTTPStatus(t, rec, http.StatusOK)
	payload := decodeMCPMap(t, rec)
	result := requireMCPObject(t, payload, "result")
	messages := requireMCPArray(t, result, "messages")
	if len(messages) == 0 {
		t.Fatal("messages is empty")
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"unknown","arguments":{}}}`)
	errObj := requireMCPObject(t, decodeMCPMap(t, rec), "error")
	if errObj["code"] != float64(-32602) {
		t.Fatalf("error code = %#v, want -32602", errObj["code"])
	}
}

func TestToolCallSuccessParsesTypedArguments(t *testing.T) {
	toolAnalysis := &testMCPToolAnalysis{}
	streamDecode := &testMCPStreamDecode{}
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.ToolAnalysis = toolAnalysis
		deps.StreamDecode = streamDecode.decode
	})

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tooling.winrm_decrypt","arguments":{"port":"5985","auth_mode":"password","password":"secret","preview_lines":25,"include_error_frames":"true","extract_command_output":1}}}`)
	requireToolCallOK(t, rec)
	if toolAnalysis.lastWinRM.Port != 5985 || toolAnalysis.lastWinRM.AuthMode != "password" || !toolAnalysis.lastWinRM.IncludeErrorFrames || !toolAnalysis.lastWinRM.ExtractCommandOutput {
		t.Fatalf("WinRM request parsed incorrectly: %+v", toolAnalysis.lastWinRM)
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stream.decode","arguments":{"decoder":"base64","payload":"aGVsbG8=","options":{"mode":"strict"}}}}`)
	requireToolCallOK(t, rec)
	if streamDecode.last.Decoder != "base64" || streamDecode.last.Payload != "aGVsbG8=" {
		t.Fatalf("stream decode request = %+v", streamDecode.last)
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analysis.evidence","arguments":{"modules":[" c2 ","","usb"]}}}`)
	result := requireToolCallOK(t, rec)
	sc := requireMCPObject(t, result, "structuredContent")
	if got := sc["modules"]; got == nil {
		t.Fatalf("structuredContent missing modules: %#v", sc)
	}
}

func TestToolCallErrorPayloadAndUnknownTool(t *testing.T) {
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.Capture = &testMCPCapture{packetPageErr: errors.New("packet page failed")}
	})

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"capture.packet_page","arguments":{"limit":1}}}`)
	payload := decodeMCPMap(t, rec)
	errObj := requireMCPObject(t, payload, "error")
	if !strings.Contains(errObj["message"].(string), "packet page failed") {
		t.Fatalf("error message = %#v, want service error", errObj["message"])
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"missing.tool","arguments":{}}}`)
	errObj = requireMCPObject(t, decodeMCPMap(t, rec), "error")
	if errObj["code"] != float64(-32602) {
		t.Fatalf("error code = %#v, want -32602", errObj["code"])
	}
}

func TestToolCallTruncatesLongPayload(t *testing.T) {
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.Evidence = func(context.Context, []string) (any, error) {
			return map[string]any{"blob": strings.Repeat("x", 210000)}, nil
		}
	})

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analysis.evidence","arguments":{}}}`)
	result := requireToolCallOK(t, rec)
	content := requireMCPArray(t, result, "content")
	node, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] = %#v, want object", content[0])
	}
	text := node["text"].(string)
	if !strings.Contains(text, "...<truncated>") {
		t.Fatalf("text was not truncated, len=%d", len(text))
	}
}

func newTestMCPServer(t *testing.T, mutate func(*Dependencies)) *Server {
	t.Helper()
	deps := Dependencies{
		Capture:      &testMCPCapture{},
		Detection:    testMCPDetection{},
		Analysis:     &testMCPAnalysis{},
		Media:        testMCPMedia{},
		ToolRuntime:  testMCPRuntime{},
		ToolAnalysis: &testMCPToolAnalysis{},
		Evidence: func(_ context.Context, modules []string) (any, error) {
			return map[string]any{"modules": modules, "total": len(modules)}, nil
		},
		MiscModules: func() []model.MiscModuleManifest {
			return []model.MiscModuleManifest{{ID: "demo", Title: "Demo"}}
		},
		AuditLogs: func(limit int) []model.AuditEntry {
			return []model.AuditEntry{{Action: "demo", Status: http.StatusOK}}
		},
		AuthEnabled: func() bool { return false },
		StreamDecode: func(req StreamDecodeRequest) (any, error) {
			return map[string]any{"decoder": req.Decoder, "payload": req.Payload}, nil
		},
	}
	if mutate != nil {
		mutate(&deps)
	}
	return NewServer(deps)
}

func callMCP(t *testing.T, server *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body)))
	return rec
}

func decodeMCPMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON: %v body=%s", err, rec.Body.String())
	}
	return payload
}

func requireMCPHTTPStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, want, rec.Body.String())
	}
}

func requireMCPObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object in payload %#v", key, payload[key], payload)
	}
	return value
}

func requireMCPArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array in payload %#v", key, payload[key], payload)
	}
	return value
}

func requireToolCallOK(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	requireMCPHTTPStatus(t, rec, http.StatusOK)
	payload := decodeMCPMap(t, rec)
	if errObj, ok := payload["error"]; ok {
		t.Fatalf("unexpected MCP error: %#v", errObj)
	}
	result := requireMCPObject(t, payload, "result")
	if result["isError"] != false {
		t.Fatalf("isError = %#v, want false", result["isError"])
	}
	return result
}

type testMCPCapture struct {
	packetPageErr error
}

func (s *testMCPCapture) CaptureStatus() model.CaptureStatus {
	return model.CaptureStatus{FilePath: "demo.pcap", HasCapture: true, PacketCount: 2}
}

func (s *testMCPCapture) PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error) {
	if s.packetPageErr != nil {
		return nil, 0, 0, false, s.packetPageErr
	}
	return []model.Packet{{ID: 1, Protocol: "TCP"}}, cursor + limit, 1, false, nil
}

func (s *testMCPCapture) Packet(packetID int64) (model.Packet, error) {
	return model.Packet{ID: packetID, Protocol: "TCP"}, nil
}

func (s *testMCPCapture) PacketRawHex(int64) (string, error) { return "45000000", nil }

func (s *testMCPCapture) PacketLayers(int64) (map[string]any, error) {
	return map[string]any{"frame": map[string]any{"frame.number": "7"}}, nil
}

func (s *testMCPCapture) StreamIDs(string) []int64 { return []int64{1, 3} }

func (s *testMCPCapture) HTTPStream(context.Context, int64) model.ReassembledStream {
	return model.ReassembledStream{Protocol: "HTTP", Chunks: []model.StreamChunk{{Direction: "client", Body: "GET /"}}}
}

func (s *testMCPCapture) RawStream(_ context.Context, protocol string, streamID int64) model.ReassembledStream {
	return model.ReassembledStream{Protocol: protocol, StreamID: streamID, Chunks: []model.StreamChunk{{Direction: "client", Body: "01:02"}}}
}

func (s *testMCPCapture) RawStreamPage(context.Context, string, int64, int, int) (model.ReassembledStream, int, int) {
	return model.ReassembledStream{Protocol: "TCP"}, 1, 1
}

func (s *testMCPCapture) ListStreamPayloadSources(int) ([]model.StreamPayloadSource, error) {
	return []model.StreamPayloadSource{{ID: "src-1", Payload: "cmd=whoami", PacketID: 1}}, nil
}

type testMCPDetection struct{}

func (testMCPDetection) ThreatHuntWithContext(context.Context, []string) []model.ThreatHit {
	return []model.ThreatHit{{ID: 1, Rule: "demo"}}
}

func (testMCPDetection) ObjectsWithContext(context.Context) []model.ObjectFile {
	return []model.ObjectFile{{ID: 1, Name: "object.bin"}}
}

func (testMCPDetection) GetHuntingRuntimeConfig() model.HuntingRuntimeConfig {
	return model.HuntingRuntimeConfig{Prefixes: []string{"flag{"}}
}

type testMCPAnalysis struct {
	lastUSBOptions model.USBAnalysisOptions
}

func (s *testMCPAnalysis) GlobalTrafficStatsWithContext(context.Context) (model.GlobalTrafficStats, error) {
	return model.GlobalTrafficStats{TotalPackets: 1}, nil
}

func (s *testMCPAnalysis) IndustrialAnalysisWithContext(context.Context) (model.IndustrialAnalysis, error) {
	return model.IndustrialAnalysis{TotalIndustrialPackets: 1}, nil
}

func (s *testMCPAnalysis) VehicleAnalysisWithContext(context.Context) (model.VehicleAnalysis, error) {
	return model.VehicleAnalysis{TotalVehiclePackets: 1}, nil
}

func (s *testMCPAnalysis) USBAnalysisWithOptions(_ context.Context, opts model.USBAnalysisOptions) (model.USBAnalysis, error) {
	s.lastUSBOptions = opts
	return model.USBAnalysis{TotalUSBPackets: 1, HIDSourceMode: string(opts.HIDSourceMode), HIDEventLimit: opts.HIDEventLimit}, nil
}

func (s *testMCPAnalysis) C2SampleAnalysis(context.Context) (model.C2SampleAnalysis, error) {
	return model.C2SampleAnalysis{TotalMatchedPackets: 1}, nil
}

func (s *testMCPAnalysis) C2Decrypt(context.Context, model.C2DecryptRequest) (model.C2DecryptResult, error) {
	return model.C2DecryptResult{Family: "cs", Status: "ok"}, nil
}

func (s *testMCPAnalysis) APTAnalysis(context.Context) (model.APTAnalysis, error) {
	return model.APTAnalysis{}, nil
}

type testMCPMedia struct{}

func (testMCPMedia) MediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{Sessions: []model.MediaSession{{ID: "media-1"}}}, nil
}

type testMCPRuntime struct{}

func (testMCPRuntime) ToolRuntimeSnapshotWithOptions(context.Context, model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot {
	return model.ToolRuntimeSnapshot{TShark: model.TSharkToolStatus{Available: true, Path: "tshark", Message: "ok"}}
}

type testMCPToolAnalysis struct {
	lastWinRM model.WinRMDecryptRequest
}

func (s *testMCPToolAnalysis) ListNTLMSessionMaterialsWithContext(context.Context) ([]model.NTLMSessionMaterial, error) {
	return []model.NTLMSessionMaterial{}, nil
}

func (s *testMCPToolAnalysis) HTTPLoginAnalysis(context.Context) (model.HTTPLoginAnalysis, error) {
	return model.HTTPLoginAnalysis{}, nil
}

func (s *testMCPToolAnalysis) SMTPAnalysis(context.Context) (model.SMTPAnalysis, error) {
	return model.SMTPAnalysis{}, nil
}

func (s *testMCPToolAnalysis) MySQLAnalysis(context.Context) (model.MySQLAnalysis, error) {
	return model.MySQLAnalysis{}, nil
}

func (s *testMCPToolAnalysis) ShiroRememberMeAnalysis(context.Context, model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	return model.ShiroRememberMeAnalysis{}, nil
}

func (s *testMCPToolAnalysis) ListSMB3SessionCandidatesWithContext(context.Context) ([]model.SMB3SessionCandidate, error) {
	return []model.SMB3SessionCandidate{}, nil
}

func (s *testMCPToolAnalysis) RunWinRMDecryptWithContext(_ context.Context, req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error) {
	s.lastWinRM = req
	return model.WinRMDecryptResult{Port: req.Port, AuthMode: req.AuthMode, Message: "ok"}, nil
}

func (s *testMCPToolAnalysis) UDPTunnelAnalysis(context.Context) (model.UDPTunnelAnalysis, error) {
	return model.UDPTunnelAnalysis{}, nil
}

func (s *testMCPToolAnalysis) BruteforceAnalysis(context.Context) (model.BruteforceAnalysis, error) {
	return model.BruteforceAnalysis{}, nil
}

type testMCPStreamDecode struct {
	last StreamDecodeRequest
}

func (s *testMCPStreamDecode) decode(req StreamDecodeRequest) (any, error) {
	s.last = req
	return map[string]any{"decoder": req.Decoder, "payload": req.Payload}, nil
}
