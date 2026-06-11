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

func TestToolCallCaptureRuntimeAndDetectionBranches(t *testing.T) {
	capture := &testMCPCapture{}
	detection := &testMCPDetection{}
	runtime := &testMCPRuntime{}
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.Capture = capture
		deps.Detection = detection
		deps.ToolRuntime = runtime
	})

	tests := []struct {
		name string
		body string
	}{
		{name: "runtime", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"runtime.snapshot","arguments":{"mode":"full"}}}`},
		{name: "capture status", body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"capture.status","arguments":{}}}`},
		{name: "packet page", body: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capture.packet_page","arguments":{"cursor":5,"limit":"7","filter":"tcp"}}}`},
		{name: "packet", body: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"capture.packet","arguments":{"packet_id":"9"}}}`},
		{name: "raw hex", body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"capture.packet_raw_hex","arguments":{"packet_id":10}}}`},
		{name: "layers", body: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"capture.packet_layers","arguments":{"packet_id":11}}}`},
		{name: "stream ids", body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"capture.stream_ids","arguments":{"protocol":"udp"}}}`},
		{name: "http stream", body: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"stream.http","arguments":{"stream_id":12}}}`},
		{name: "raw stream", body: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"stream.raw","arguments":{"protocol":"tcp","stream_id":13}}}`},
		{name: "raw page", body: `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"stream.raw_page","arguments":{"protocol":"udp","stream_id":14,"cursor":3,"limit":4}}}`},
		{name: "payload sources", body: `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"stream.payload_sources","arguments":{"limit":2}}}`},
		{name: "threat hunting", body: `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"threat.hunting_hits","arguments":{"prefixes":[" flag{ ","","token="]}}}`},
		{name: "objects", body: `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"objects.list","arguments":{}}}`},
		{name: "filter count", body: `{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"capture.filter_count","arguments":{"filter":"http"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireToolCallOK(t, callMCP(t, server, tt.body))
		})
	}

	if runtime.lastOptions.Mode != "full" {
		t.Fatalf("runtime mode = %q, want full", runtime.lastOptions.Mode)
	}
	if capture.lastPage.cursor != 0 || capture.lastPage.limit != 1 || capture.lastPage.filter != "http" {
		t.Fatalf("last page call = %+v, want filter_count cursor=0 limit=1 filter=http", capture.lastPage)
	}
	if capture.lastPacketID != 9 || capture.lastRawHexID != 10 || capture.lastLayersID != 11 {
		t.Fatalf("packet ids = packet %d raw %d layers %d", capture.lastPacketID, capture.lastRawHexID, capture.lastLayersID)
	}
	if capture.lastStreamIDsProtocol != "UDP" || capture.lastHTTPStreamID != 12 {
		t.Fatalf("stream ids/http calls = protocol %q http %d", capture.lastStreamIDsProtocol, capture.lastHTTPStreamID)
	}
	if capture.lastRawStream.protocol != "TCP" || capture.lastRawStream.streamID != 13 {
		t.Fatalf("raw stream call = %+v", capture.lastRawStream)
	}
	if capture.lastRawPage.protocol != "UDP" || capture.lastRawPage.streamID != 14 || capture.lastRawPage.cursor != 3 || capture.lastRawPage.limit != 4 {
		t.Fatalf("raw page call = %+v", capture.lastRawPage)
	}
	if capture.lastPayloadSourceLimit != 2 {
		t.Fatalf("payload source limit = %d, want 2", capture.lastPayloadSourceLimit)
	}
	if len(detection.lastPrefixes) != 2 || detection.lastPrefixes[0] != "flag{" || detection.lastPrefixes[1] != "token=" {
		t.Fatalf("prefixes = %+v, want trimmed non-empty prefixes", detection.lastPrefixes)
	}

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"capture.filter_count","arguments":{}}}`)
	errObj := requireMCPObject(t, decodeMCPMap(t, rec), "error")
	if errObj["code"] != float64(-32602) || !strings.Contains(errObj["message"].(string), "filter is required") {
		t.Fatalf("filter_count error = %+v", errObj)
	}
}

func TestToolCallAnalysisAndToolingBranches(t *testing.T) {
	analysis := &testMCPAnalysis{}
	toolAnalysis := &testMCPToolAnalysis{}
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.Analysis = analysis
		deps.ToolAnalysis = toolAnalysis
	})

	tests := []struct {
		name string
		body string
	}{
		{name: "traffic", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analysis.traffic","arguments":{}}}`},
		{name: "industrial", body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analysis.industrial","arguments":{}}}`},
		{name: "vehicle", body: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analysis.vehicle","arguments":{}}}`},
		{name: "usb", body: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"analysis.usb","arguments":{"hid_source":"btatt","hid_event_limit":"1234"}}}`},
		{name: "c2 overview", body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"analysis.c2_overview","arguments":{}}}`},
		{name: "apt", body: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"analysis.apt","arguments":{}}}`},
		{name: "c2 candidates", body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"c2.candidates","arguments":{"family":"all","min_confidence":60,"limit":2}}}`},
		{name: "c2 decrypt", body: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"c2.decrypt","arguments":{"family":"vshell","scope":{"stream_ids":[3],"use_candidates":true},"vshell":{"vkey":"vk","salt":"salt"},"cs":{"key_mode":"raw","aes_key":"aa"}}}}`},
		{name: "ntlm", body: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"tooling.ntlm_sessions","arguments":{}}}`},
		{name: "http login", body: `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"tooling.http_login","arguments":{}}}`},
		{name: "smtp", body: `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"tooling.smtp","arguments":{}}}`},
		{name: "mysql", body: `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"tooling.mysql","arguments":{}}}`},
		{name: "shiro", body: `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"tooling.shiro","arguments":{"candidate_keys":["k1","k2"]}}}`},
		{name: "smb3", body: `{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"tooling.smb3_candidates","arguments":{}}}`},
		{name: "udp tunnel", body: `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"tooling.udp_tunnel","arguments":{}}}`},
		{name: "bruteforce", body: `{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"tooling.bruteforce","arguments":{}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireToolCallOK(t, callMCP(t, server, tt.body))
		})
	}

	if analysis.lastUSBOptions.HIDSourceMode != model.USBHIDSourceBTATT || analysis.lastUSBOptions.HIDEventLimit != 1234 {
		t.Fatalf("USB options = %+v", analysis.lastUSBOptions)
	}
	if analysis.lastC2Decrypt.Family != "vshell" || !analysis.lastC2Decrypt.Scope.UseCandidates || len(analysis.lastC2Decrypt.Scope.StreamIDs) != 1 || analysis.lastC2Decrypt.VShell.VKey != "vk" || analysis.lastC2Decrypt.CS.AESKey != "aa" {
		t.Fatalf("C2 decrypt request = %+v", analysis.lastC2Decrypt)
	}
	if len(toolAnalysis.lastShiro.CandidateKeys) != 2 || toolAnalysis.lastShiro.CandidateKeys[0] != "k1" {
		t.Fatalf("Shiro request = %+v", toolAnalysis.lastShiro)
	}

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"analysis.usb","arguments":{"hid_source":"bad-mode"}}}`)
	errObj := requireMCPObject(t, decodeMCPMap(t, rec), "error")
	if errObj["code"] != float64(-32602) || !strings.Contains(errObj["message"].(string), "invalid hid_source") {
		t.Fatalf("USB invalid source error = %+v", errObj)
	}
}

func TestToolCallMediaAndCandidateFiltering(t *testing.T) {
	media := &testMCPMedia{}
	server := newTestMCPServer(t, func(deps *Dependencies) {
		deps.Media = media
	})

	rec := callMCP(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"media.sessions","arguments":{}}}`)
	result := requireToolCallOK(t, rec)
	sc := requireMCPObject(t, result, "structuredContent")
	if sc["total"] != float64(1) {
		t.Fatalf("media total = %#v, want 1", sc["total"])
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"c2.candidates","arguments":{"family":"cs","min_confidence":80,"limit":10}}}`)
	result = requireToolCallOK(t, rec)
	sc = requireMCPObject(t, result, "structuredContent")
	if sc["family"] != "cs" || sc["total"] != float64(1) {
		t.Fatalf("cs candidates result = %+v", sc)
	}

	rec = callMCP(t, server, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"c2.candidates","arguments":{"family":"vshell","min_confidence":50,"limit":1}}}`)
	result = requireToolCallOK(t, rec)
	sc = requireMCPObject(t, result, "structuredContent")
	if sc["family"] != "vshell" || sc["total"] != float64(1) {
		t.Fatalf("vshell candidates result = %+v", sc)
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
		Detection:    &testMCPDetection{},
		Analysis:     &testMCPAnalysis{},
		Media:        testMCPMedia{},
		ToolRuntime:  &testMCPRuntime{},
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
	lastPage      struct {
		cursor int
		limit  int
		filter string
	}
	lastPacketID          int64
	lastRawHexID          int64
	lastLayersID          int64
	lastStreamIDsProtocol string
	lastHTTPStreamID      int64
	lastRawStream         struct {
		protocol string
		streamID int64
	}
	lastRawPage struct {
		protocol string
		streamID int64
		cursor   int
		limit    int
	}
	lastPayloadSourceLimit int
}

func (s *testMCPCapture) CaptureStatus() model.CaptureStatus {
	return model.CaptureStatus{FilePath: "demo.pcap", HasCapture: true, PacketCount: 2}
}

func (s *testMCPCapture) PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error) {
	s.lastPage.cursor = cursor
	s.lastPage.limit = limit
	s.lastPage.filter = filter
	if s.packetPageErr != nil {
		return nil, 0, 0, false, s.packetPageErr
	}
	return []model.Packet{{ID: 1, Protocol: "TCP"}}, cursor + limit, 1, false, nil
}

func (s *testMCPCapture) Packet(packetID int64) (model.Packet, error) {
	s.lastPacketID = packetID
	return model.Packet{ID: packetID, Protocol: "TCP"}, nil
}

func (s *testMCPCapture) PacketRawHex(packetID int64) (string, error) {
	s.lastRawHexID = packetID
	return "45000000", nil
}

func (s *testMCPCapture) PacketLayers(packetID int64) (map[string]any, error) {
	s.lastLayersID = packetID
	return map[string]any{"frame": map[string]any{"frame.number": "7"}}, nil
}

func (s *testMCPCapture) StreamIDs(protocol string) []int64 {
	s.lastStreamIDsProtocol = protocol
	return []int64{1, 3}
}

func (s *testMCPCapture) HTTPStream(_ context.Context, streamID int64) model.ReassembledStream {
	s.lastHTTPStreamID = streamID
	return model.ReassembledStream{StreamID: streamID, Protocol: "HTTP", Chunks: []model.StreamChunk{{Direction: "client", Body: "GET /"}}}
}

func (s *testMCPCapture) RawStream(_ context.Context, protocol string, streamID int64) model.ReassembledStream {
	s.lastRawStream.protocol = protocol
	s.lastRawStream.streamID = streamID
	return model.ReassembledStream{Protocol: protocol, StreamID: streamID, Chunks: []model.StreamChunk{{Direction: "client", Body: "01:02"}}}
}

func (s *testMCPCapture) RawStreamPage(_ context.Context, protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int) {
	s.lastRawPage.protocol = protocol
	s.lastRawPage.streamID = streamID
	s.lastRawPage.cursor = cursor
	s.lastRawPage.limit = limit
	return model.ReassembledStream{Protocol: protocol, StreamID: streamID}, cursor + limit, 1
}

func (s *testMCPCapture) ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error) {
	s.lastPayloadSourceLimit = limit
	return []model.StreamPayloadSource{{ID: "src-1", Payload: "cmd=whoami", PacketID: 1}}, nil
}

type testMCPDetection struct {
	lastPrefixes []string
}

func (s *testMCPDetection) ThreatHuntWithContext(_ context.Context, prefixes []string) []model.ThreatHit {
	s.lastPrefixes = append([]string(nil), prefixes...)
	return []model.ThreatHit{{ID: 1, Rule: "demo"}}
}

func (*testMCPDetection) ObjectsWithContext(context.Context) []model.ObjectFile {
	return []model.ObjectFile{{ID: 1, Name: "object.bin"}}
}

func (*testMCPDetection) GetHuntingRuntimeConfig() model.HuntingRuntimeConfig {
	return model.HuntingRuntimeConfig{Prefixes: []string{"flag{"}}
}

type testMCPAnalysis struct {
	lastUSBOptions model.USBAnalysisOptions
	lastC2Decrypt  model.C2DecryptRequest
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
	return model.C2SampleAnalysis{
		TotalMatchedPackets: 3,
		CS: model.C2FamilyAnalysis{Candidates: []model.C2IndicatorRecord{
			{Family: "cs", IndicatorValue: "low", Confidence: 40},
			{Family: "cs", IndicatorValue: "high", Confidence: 85},
		}},
		VShell: model.C2FamilyAnalysis{Candidates: []model.C2IndicatorRecord{
			{Family: "vshell", IndicatorValue: "mid", Confidence: 55},
			{Family: "vshell", IndicatorValue: "high", Confidence: 90},
		}},
	}, nil
}

func (s *testMCPAnalysis) C2Decrypt(_ context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error) {
	s.lastC2Decrypt = req
	return model.C2DecryptResult{Family: req.Family, Status: "ok"}, nil
}

func (s *testMCPAnalysis) APTAnalysis(context.Context) (model.APTAnalysis, error) {
	return model.APTAnalysis{}, nil
}

type testMCPMedia struct{}

func (testMCPMedia) MediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{Sessions: []model.MediaSession{{ID: "media-1"}}}, nil
}

type testMCPRuntime struct {
	lastOptions model.ToolRuntimeProbeOptions
}

func (s *testMCPRuntime) ToolRuntimeSnapshotWithOptions(_ context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot {
	s.lastOptions = opts
	return model.ToolRuntimeSnapshot{ProbeMode: opts.Mode, TShark: model.TSharkToolStatus{Available: true, Path: "tshark", Message: "ok"}}
}

type testMCPToolAnalysis struct {
	lastWinRM model.WinRMDecryptRequest
	lastShiro model.ShiroRememberMeRequest
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

func (s *testMCPToolAnalysis) ShiroRememberMeAnalysis(_ context.Context, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	s.lastShiro = req
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
