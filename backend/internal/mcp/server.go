package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

const protocolVersion = "2025-06-18"

type Dependencies struct {
	Capture      CaptureService
	Detection    DetectionService
	Analysis     AnalysisService
	Media        MediaService
	ToolRuntime  ToolRuntimeService
	ToolAnalysis ToolAnalysisService
	Evidence     func(ctx context.Context, modules []string) (any, error)
	MiscModules  func() []model.MiscModuleManifest
	AuditLogs    func(limit int) []model.AuditEntry
	AuthEnabled  func() bool
	StreamDecode func(req StreamDecodeRequest) (any, error)
}

// StreamDecodeRequest mirrors the engine decode request for MCP callers.
type StreamDecodeRequest struct {
	Decoder string         `json:"decoder"`
	Payload string         `json:"payload"`
	Options map[string]any `json:"options"`
}

type CaptureService interface {
	CaptureStatus() model.CaptureStatus
	PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error)
	Packet(packetID int64) (model.Packet, error)
	PacketRawHex(packetID int64) (string, error)
	PacketLayers(packetID int64) (map[string]any, error)
	StreamIDs(protocol string) []int64
	HTTPStream(ctx context.Context, streamID int64) model.ReassembledStream
	RawStream(ctx context.Context, protocol string, streamID int64) model.ReassembledStream
	RawStreamPage(ctx context.Context, protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int)
	ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error)
}

type DetectionService interface {
	ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit
	ObjectsWithContext(ctx context.Context) []model.ObjectFile
	GetHuntingRuntimeConfig() model.HuntingRuntimeConfig
}

type AnalysisService interface {
	GlobalTrafficStatsWithContext(ctx context.Context) (model.GlobalTrafficStats, error)
	IndustrialAnalysisWithContext(ctx context.Context) (model.IndustrialAnalysis, error)
	VehicleAnalysisWithContext(ctx context.Context) (model.VehicleAnalysis, error)
	USBAnalysisWithOptions(ctx context.Context, opts model.USBAnalysisOptions) (model.USBAnalysis, error)
	C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error)
	C2Decrypt(ctx context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error)
	APTAnalysis(ctx context.Context) (model.APTAnalysis, error)
}

type MediaService interface {
	MediaAnalysis() (model.MediaAnalysis, error)
}

type ToolRuntimeService interface {
	ToolRuntimeSnapshotWithOptions(ctx context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot
}

type ToolAnalysisService interface {
	ListNTLMSessionMaterialsWithContext(ctx context.Context) ([]model.NTLMSessionMaterial, error)
	HTTPLoginAnalysis(ctx context.Context) (model.HTTPLoginAnalysis, error)
	SMTPAnalysis(ctx context.Context) (model.SMTPAnalysis, error)
	MySQLAnalysis(ctx context.Context) (model.MySQLAnalysis, error)
	ShiroRememberMeAnalysis(ctx context.Context, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error)
	ListSMB3SessionCandidatesWithContext(ctx context.Context) ([]model.SMB3SessionCandidate, error)
	RunWinRMDecryptWithContext(ctx context.Context, req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error)
	UDPTunnelAnalysis(ctx context.Context) (model.UDPTunnelAnalysis, error)
	BruteforceAnalysis(ctx context.Context) (model.BruteforceAnalysis, error)
}

type Server struct {
	deps Dependencies
}

func NewServer(deps Dependencies) *Server {
	return &Server{deps: deps}
}

type requestEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type responseEnvelope struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req requestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, responseEnvelope{
			JSONRPC: "2.0",
			Error:   &mcpError{Code: -32700, Message: "parse error"},
		})
		return
	}
	result, rpcErr := s.handle(r.Context(), req)
	resp := responseEnvelope{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handle(ctx context.Context, req requestEnvelope) (any, *mcpError) {
	switch strings.TrimSpace(req.Method) {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"listChanged": false, "subscribe": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "meow-traffic-local-mcp",
				"title":   "meow~traffic Local MCP",
				"version": "0.1.0",
			},
			"instructions": "Local read-only traffic analysis MCP for meow~traffic. Use tools for deep queries and resources for compact context snapshots.",
		}, nil
	case "initialized":
		return map[string]any{}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.tools()}, nil
	case "tools/call":
		return s.callTool(ctx, req.Params)
	case "resources/list":
		return map[string]any{"resources": s.resources()}, nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": s.resourceTemplates()}, nil
	case "resources/read":
		return s.readResource(ctx, req.Params)
	case "prompts/list":
		return map[string]any{"prompts": s.prompts()}, nil
	case "prompts/get":
		return s.getPrompt(req.Params)
	default:
		return nil, &mcpError{Code: -32601, Message: "method not found"}
	}
}

func (s *Server) tools() []map[string]any {
	tools := []map[string]any{
		s.newTool("runtime.snapshot", "Get aggregated runtime tool status.", runtimeSnapshotInputSchema(), true, true),
		s.newTool("capture.status", "Get current capture status.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("capture.packet_page", "List packets page by cursor and filter.", map[string]any{
			"type": "object",
			"properties": map[string]any{
				"cursor": map[string]any{"type": "integer", "minimum": 0},
				"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
				"filter": map[string]any{"type": "string"},
			},
		}, true, true),
		s.newTool("capture.packet", "Get a single packet by id.", objectSchema(map[string]any{
			"packet_id": map[string]any{"type": "integer", "minimum": 1},
		}, []string{"packet_id"}), true, true),
		s.newTool("capture.packet_raw_hex", "Get packet raw hex by id.", objectSchema(map[string]any{
			"packet_id": map[string]any{"type": "integer", "minimum": 1},
		}, []string{"packet_id"}), true, true),
		s.newTool("capture.packet_layers", "Get decoded packet layers by id.", objectSchema(map[string]any{
			"packet_id": map[string]any{"type": "integer", "minimum": 1},
		}, []string{"packet_id"}), true, true),
		s.newTool("capture.stream_ids", "List stream ids for protocol.", objectSchema(map[string]any{
			"protocol": map[string]any{"type": "string", "enum": []string{"HTTP", "TCP", "UDP"}},
		}, []string{"protocol"}), true, true),
		s.newTool("stream.http", "Get reassembled HTTP stream.", objectSchema(map[string]any{
			"stream_id": map[string]any{"type": "integer", "minimum": 0},
		}, []string{"stream_id"}), true, true),
		s.newTool("stream.raw", "Get reassembled TCP/UDP stream.", objectSchema(map[string]any{
			"protocol":  map[string]any{"type": "string", "enum": []string{"TCP", "UDP"}},
			"stream_id": map[string]any{"type": "integer", "minimum": 0},
		}, []string{"protocol", "stream_id"}), true, true),
		s.newTool("stream.raw_page", "Get paged TCP/UDP stream chunks.", objectSchema(map[string]any{
			"protocol":  map[string]any{"type": "string", "enum": []string{"TCP", "UDP"}},
			"stream_id": map[string]any{"type": "integer", "minimum": 0},
			"cursor":    map[string]any{"type": "integer", "minimum": 0},
			"limit":     map[string]any{"type": "integer", "minimum": 1, "maximum": 4096},
		}, []string{"protocol", "stream_id"}), true, true),
		s.newTool("stream.payload_sources", "List suspicious payload sources.", objectSchema(map[string]any{
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
		}, nil), true, true),
		s.newTool("analysis.traffic", "Get global traffic stats.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("analysis.industrial", "Get industrial analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("analysis.vehicle", "Get vehicle analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("analysis.usb", "Get USB analysis.", objectSchema(map[string]any{
			"hid_source":      map[string]any{"type": "string", "enum": []string{"auto", "usbhid", "capdata", "btatt", "raw"}},
			"hid_event_limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200000},
		}, nil), true, true),
		s.newTool("analysis.c2_overview", "Get C2 sample analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("analysis.apt", "Get APT analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("analysis.evidence", "Get unified evidence records.", objectSchema(map[string]any{
			"modules": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
		}, nil), true, true),
		s.newTool("tooling.ntlm_sessions", "List NTLM session materials.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.http_login", "Get HTTP login analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.smtp", "Get SMTP analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.mysql", "Get MySQL analysis.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.shiro", "Get Shiro rememberMe analysis.", objectSchema(map[string]any{
			"candidate_keys": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
		}, nil), true, true),
		s.newTool("tooling.smb3_candidates", "List SMB3 session candidates.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.udp_tunnel", "Detect UDP tunneling (DNS tunnels, generic UDP tunnels).", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.bruteforce", "Detect port scanning and directory bruteforce attacks.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),

		// --- Expanded tools (high priority) ---
		s.newTool("threat.hunting_hits", "Run threat hunting and return hits (YARA + prefix pattern matching).", objectSchema(map[string]any{
			"prefixes": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional prefix strings to search for in packet payloads. Empty uses configured defaults.",
			},
		}, nil), true, false),
		s.newTool("c2.candidates", "List C2 candidate streams with confidence scores.", objectSchema(map[string]any{
			"family":         map[string]any{"type": "string", "enum": []string{"cs", "vshell", "all"}},
			"min_confidence": map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
			"limit":          map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
		}, nil), true, true),
		s.newTool("objects.list", "List extracted objects/files from current capture.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
		s.newTool("tooling.winrm_decrypt", "Decrypt WinRM session using NTLM credentials.", objectSchema(map[string]any{
			"port":                   map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
			"auth_mode":              map[string]any{"type": "string", "enum": []string{"password", "nt_hash"}},
			"password":               map[string]any{"type": "string"},
			"nt_hash":                map[string]any{"type": "string"},
			"preview_lines":          map[string]any{"type": "integer", "minimum": 1, "maximum": 2000},
			"include_error_frames":   map[string]any{"type": "boolean"},
			"extract_command_output": map[string]any{"type": "boolean"},
		}, []string{"port", "auth_mode"}), false, false),

		// --- Expanded tools (medium priority) ---
		s.newTool("capture.filter_count", "Count packets matching a display filter without returning packet data.", objectSchema(map[string]any{
			"filter": map[string]any{"type": "string"},
		}, []string{"filter"}), true, true),
		s.newTool("stream.decode", "Run stream decoder (base64/behinder/antsword/godzilla/auto) on payload.", objectSchema(map[string]any{
			"decoder": map[string]any{"type": "string", "enum": []string{"base64", "behinder", "antsword", "godzilla", "auto"}},
			"payload": map[string]any{"type": "string", "description": "Raw payload text to decode."},
			"options": map[string]any{"type": "object", "description": "Decoder-specific options (key, pass, cipherMode, etc)."},
		}, []string{"decoder", "payload"}), true, true),
		s.newTool("c2.decrypt", "Decrypt C2 traffic with provided key/config.", objectSchema(map[string]any{
			"family": map[string]any{"type": "string", "enum": []string{"cs", "vshell"}},
			"scope":  map[string]any{"type": "object", "description": "Scope filter: packet_ids, stream_ids, use_candidates, use_aggregates."},
			"vshell": map[string]any{"type": "object", "description": "VShell options: vkey, salt, mode."},
			"cs":     map[string]any{"type": "object", "description": "CobaltStrike options: key_mode, aes_key, hmac_key, aes_rand, rsa_private_key, transform_mode."},
		}, []string{"family"}), false, false),
		s.newTool("media.sessions", "List media sessions (RTP/RTSP audio/video) from current capture.", map[string]any{"type": "object", "properties": map[string]any{}}, true, true),
	}
	sort.SliceStable(tools, func(i, j int) bool {
		return tools[i]["name"].(string) < tools[j]["name"].(string)
	})
	return tools
}

func (s *Server) resources() []map[string]any {
	return []map[string]any{
		{"uri": "meow://runtime/snapshot", "name": "Runtime Snapshot", "description": "Compact runtime dependency snapshot.", "mimeType": "application/json"},
		{"uri": "meow://capture/status", "name": "Capture Status", "description": "Current capture status.", "mimeType": "application/json"},
		{"uri": "meow://analysis/evidence", "name": "Evidence Summary", "description": "Current evidence response summary.", "mimeType": "application/json"},
		{"uri": "meow://catalog/misc-modules", "name": "MISC Modules", "description": "Available builtin/custom MISC modules.", "mimeType": "application/json"},
		{"uri": "meow://audit/recent", "name": "Recent Audit", "description": "Recent backend audit entries.", "mimeType": "application/json"},
	}
}

func (s *Server) resourceTemplates() []map[string]any {
	return []map[string]any{
		{"uriTemplate": "meow://packet/{id}", "name": "Packet", "description": "Read packet by id.", "mimeType": "application/json"},
		{"uriTemplate": "meow://stream/{protocol}/{id}", "name": "Stream", "description": "Read HTTP/TCP/UDP stream by protocol and id.", "mimeType": "application/json"},
	}
}

func (s *Server) prompts() []map[string]any {
	return []map[string]any{
		{
			"name":        "triage_capture",
			"title":       "Triage Capture",
			"description": "Summarize suspicious protocols, conversations, evidence and next pivots.",
			"arguments": []map[string]any{
				{"name": "focus", "required": false, "description": "Optional focus area such as c2, webshell, vehicle, industrial."},
			},
		},
		{
			"name":        "inspect_suspicious_stream",
			"title":       "Inspect Suspicious Stream",
			"description": "Review one suspicious stream with payload-source and packet context.",
			"arguments": []map[string]any{
				{"name": "protocol", "required": true, "description": "HTTP, TCP or UDP."},
				{"name": "stream_id", "required": true, "description": "Stream identifier."},
			},
		},
		{
			"name":        "summarize_evidence",
			"title":       "Summarize Evidence",
			"description": "Turn current evidence response into an investigation summary.",
			"arguments": []map[string]any{
				{"name": "modules", "required": false, "description": "Optional comma-separated modules to focus on."},
			},
		},
	}
}

func (s *Server) getPrompt(params json.RawMessage) (any, *mcpError) {
	var input struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := decodeParams(params, &input); err != nil {
		return nil, invalidParams(err)
	}
	switch input.Name {
	case "triage_capture":
		focus := strings.TrimSpace(stringValue(input.Arguments["focus"]))
		text := "Review runtime snapshot, capture status, traffic stats, evidence, suspicious payload sources, and protocol/tool analyses relevant to this capture. Highlight top risks, confidence, false-positive caveats, and next pivots."
		if focus != "" {
			text += " Focus area: " + focus + "."
		}
		return map[string]any{"description": "Capture triage prompt", "messages": promptMessages(text)}, nil
	case "inspect_suspicious_stream":
		protocol := strings.TrimSpace(stringValue(input.Arguments["protocol"]))
		streamID := stringValue(input.Arguments["stream_id"])
		text := fmt.Sprintf("Inspect suspicious %s stream %s. Use stream content, related payload-source candidates, and packet-level context to explain likely protocol behavior, suspicious markers, and follow-up pivots.", protocol, streamID)
		return map[string]any{"description": "Suspicious stream inspection prompt", "messages": promptMessages(text)}, nil
	case "summarize_evidence":
		modules := strings.TrimSpace(stringValue(input.Arguments["modules"]))
		text := "Summarize current evidence records into a concise investigation narrative with severity, confidence, and caveats."
		if modules != "" {
			text += " Focus modules: " + modules + "."
		}
		return map[string]any{"description": "Evidence summary prompt", "messages": promptMessages(text)}, nil
	default:
		return nil, &mcpError{Code: -32602, Message: "unknown prompt"}
	}
}

func (s *Server) readResource(ctx context.Context, params json.RawMessage) (any, *mcpError) {
	var input struct {
		URI string `json:"uri"`
	}
	if err := decodeParams(params, &input); err != nil {
		return nil, invalidParams(err)
	}
	uri := strings.TrimSpace(input.URI)
	content, err := s.resourceContent(ctx, uri)
	if err != nil {
		return nil, &mcpError{Code: -32602, Message: err.Error()}
	}
	return map[string]any{
		"contents": []map[string]any{
			{
				"uri":      uri,
				"mimeType": "application/json",
				"text":     marshalPretty(content),
			},
		},
	}, nil
}

func (s *Server) resourceContent(ctx context.Context, uri string) (any, error) {
	switch uri {
	case "meow://runtime/snapshot":
		return s.deps.ToolRuntime.ToolRuntimeSnapshotWithOptions(ctx, model.ToolRuntimeProbeOptions{Mode: "fast"}), nil
	case "meow://capture/status":
		return s.deps.Capture.CaptureStatus(), nil
	case "meow://analysis/evidence":
		return s.deps.Evidence(ctx, nil)
	case "meow://catalog/misc-modules":
		return s.deps.MiscModules(), nil
	case "meow://audit/recent":
		return s.deps.AuditLogs(20), nil
	}
	if strings.HasPrefix(uri, "meow://packet/") {
		id, err := strconv.ParseInt(strings.TrimPrefix(uri, "meow://packet/"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid packet resource uri")
		}
		return s.deps.Capture.Packet(id)
	}
	if strings.HasPrefix(uri, "meow://stream/") {
		parsed, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("invalid stream resource uri")
		}
		parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid stream resource uri")
		}
		protocol := strings.ToUpper(strings.TrimSpace(parts[0]))
		id, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid stream resource uri")
		}
		if protocol == "HTTP" {
			return s.deps.Capture.HTTPStream(ctx, id), nil
		}
		if protocol == "TCP" || protocol == "UDP" {
			return s.deps.Capture.RawStream(ctx, protocol, id), nil
		}
		return nil, fmt.Errorf("unsupported stream protocol")
	}
	return nil, fmt.Errorf("unknown resource")
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, *mcpError) {
	var input struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := decodeParams(params, &input); err != nil {
		return nil, invalidParams(err)
	}
	payload, err := s.toolResult(ctx, input.Name, input.Arguments)
	if err != nil {
		return nil, &mcpError{Code: -32602, Message: err.Error()}
	}
	text := marshalPretty(payload)
	return map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": truncateText(text, 200000),
			},
		},
		"structuredContent": payload,
		"isError":           false,
	}, nil
}

func (s *Server) toolResult(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case "runtime.snapshot":
		mode := strings.TrimSpace(stringValue(args["mode"]))
		if mode == "" {
			mode = "fast"
		}
		return s.deps.ToolRuntime.ToolRuntimeSnapshotWithOptions(ctx, model.ToolRuntimeProbeOptions{Mode: mode}), nil
	case "capture.status":
		return s.deps.Capture.CaptureStatus(), nil
	case "capture.packet_page":
		cursor := int(numberValue(args["cursor"]))
		limit := int(numberValue(args["limit"]))
		if limit <= 0 {
			limit = 50
		}
		filter := strings.TrimSpace(stringValue(args["filter"]))
		items, nextCursor, total, hasMore, err := s.deps.Capture.PacketsPageWithState(cursor, limit, filter)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"items":       items,
			"next_cursor": nextCursor,
			"total":       total,
			"has_more":    hasMore,
			"filtering":   filter != "",
		}, nil
	case "capture.packet":
		return s.deps.Capture.Packet(int64(numberValue(args["packet_id"])))
	case "capture.packet_raw_hex":
		packetID := int64(numberValue(args["packet_id"]))
		rawHex, err := s.deps.Capture.PacketRawHex(packetID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"packet_id": packetID, "raw_hex": rawHex}, nil
	case "capture.packet_layers":
		return s.deps.Capture.PacketLayers(int64(numberValue(args["packet_id"])))
	case "capture.stream_ids":
		protocol := strings.ToUpper(strings.TrimSpace(stringValue(args["protocol"])))
		return map[string]any{"protocol": protocol, "ids": s.deps.Capture.StreamIDs(protocol), "total": len(s.deps.Capture.StreamIDs(protocol))}, nil
	case "stream.http":
		return s.deps.Capture.HTTPStream(ctx, int64(numberValue(args["stream_id"]))), nil
	case "stream.raw":
		return s.deps.Capture.RawStream(ctx, strings.ToUpper(strings.TrimSpace(stringValue(args["protocol"]))), int64(numberValue(args["stream_id"]))), nil
	case "stream.raw_page":
		stream, nextCursor, total := s.deps.Capture.RawStreamPage(ctx, strings.ToUpper(strings.TrimSpace(stringValue(args["protocol"]))), int64(numberValue(args["stream_id"])), int(numberValue(args["cursor"])), int(numberValue(args["limit"])))
		return map[string]any{"stream": stream, "next_cursor": nextCursor, "total": total}, nil
	case "stream.payload_sources":
		limit := int(numberValue(args["limit"]))
		if limit <= 0 {
			limit = 50
		}
		return s.deps.Capture.ListStreamPayloadSources(limit)
	case "analysis.traffic":
		return s.deps.Analysis.GlobalTrafficStatsWithContext(ctx)
	case "analysis.industrial":
		return s.deps.Analysis.IndustrialAnalysisWithContext(ctx)
	case "analysis.vehicle":
		return s.deps.Analysis.VehicleAnalysisWithContext(ctx)
	case "analysis.usb":
		opts := model.USBAnalysisOptions{}
		if raw := strings.TrimSpace(stringValue(args["hid_source"])); raw != "" {
			mode, ok := model.NormalizeUSBHIDSourceMode(raw)
			if !ok {
				return nil, fmt.Errorf("invalid hid_source")
			}
			opts.HIDSourceMode = mode
		}
		if limit := int(numberValue(args["hid_event_limit"])); limit > 0 {
			opts.HIDEventLimit = limit
		}
		return s.deps.Analysis.USBAnalysisWithOptions(ctx, opts)
	case "analysis.c2_overview":
		return s.deps.Analysis.C2SampleAnalysis(ctx)
	case "analysis.apt":
		return s.deps.Analysis.APTAnalysis(ctx)
	case "analysis.evidence":
		var modules []string
		for _, item := range stringSliceValue(args["modules"]) {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				modules = append(modules, trimmed)
			}
		}
		return s.deps.Evidence(ctx, modules)
	case "tooling.ntlm_sessions":
		return s.deps.ToolAnalysis.ListNTLMSessionMaterialsWithContext(ctx)
	case "tooling.http_login":
		return s.deps.ToolAnalysis.HTTPLoginAnalysis(ctx)
	case "tooling.smtp":
		return s.deps.ToolAnalysis.SMTPAnalysis(ctx)
	case "tooling.mysql":
		return s.deps.ToolAnalysis.MySQLAnalysis(ctx)
	case "tooling.shiro":
		return s.deps.ToolAnalysis.ShiroRememberMeAnalysis(ctx, model.ShiroRememberMeRequest{CandidateKeys: stringSliceValue(args["candidate_keys"])})
	case "tooling.smb3_candidates":
		return s.deps.ToolAnalysis.ListSMB3SessionCandidatesWithContext(ctx)
	case "tooling.udp_tunnel":
		return s.deps.ToolAnalysis.UDPTunnelAnalysis(ctx)
	case "tooling.bruteforce":
		return s.deps.ToolAnalysis.BruteforceAnalysis(ctx)

	// --- Expanded tools (high priority) ---
	case "threat.hunting_hits":
		var prefixes []string
		for _, item := range stringSliceValue(args["prefixes"]) {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				prefixes = append(prefixes, trimmed)
			}
		}
		hits := s.deps.Detection.ThreatHuntWithContext(ctx, prefixes)
		return map[string]any{
			"hits":  hits,
			"total": len(hits),
		}, nil
	case "c2.candidates":
		analysis, err := s.deps.Analysis.C2SampleAnalysis(ctx)
		if err != nil {
			return nil, err
		}
		family := strings.ToLower(strings.TrimSpace(stringValue(args["family"])))
		if family == "" {
			family = "all"
		}
		minConfidence := int(numberValue(args["min_confidence"]))
		limit := int(numberValue(args["limit"]))
		if limit <= 0 {
			limit = 100
		}
		var candidates []model.C2IndicatorRecord
		switch family {
		case "cs":
			candidates = analysis.CS.Candidates
		case "vshell":
			candidates = analysis.VShell.Candidates
		default:
			candidates = append(candidates, analysis.CS.Candidates...)
			candidates = append(candidates, analysis.VShell.Candidates...)
		}
		if minConfidence > 0 {
			filtered := make([]model.C2IndicatorRecord, 0, len(candidates))
			for _, c := range candidates {
				if c.Confidence >= minConfidence {
					filtered = append(filtered, c)
				}
			}
			candidates = filtered
		}
		if len(candidates) > limit {
			candidates = candidates[:limit]
		}
		return map[string]any{
			"family":     family,
			"candidates": candidates,
			"total":      len(candidates),
		}, nil
	case "objects.list":
		objects := s.deps.Detection.ObjectsWithContext(ctx)
		return map[string]any{
			"objects": objects,
			"total":   len(objects),
		}, nil
	case "tooling.winrm_decrypt":
		req := model.WinRMDecryptRequest{
			Port:                 int(numberValue(args["port"])),
			AuthMode:             strings.TrimSpace(stringValue(args["auth_mode"])),
			Password:             strings.TrimSpace(stringValue(args["password"])),
			NTHash:               strings.TrimSpace(stringValue(args["nt_hash"])),
			PreviewLines:         int(numberValue(args["preview_lines"])),
			IncludeErrorFrames:   boolValue(args["include_error_frames"]),
			ExtractCommandOutput: boolValue(args["extract_command_output"]),
		}
		return s.deps.ToolAnalysis.RunWinRMDecryptWithContext(ctx, req)

	// --- Expanded tools (medium priority) ---
	case "capture.filter_count":
		filter := strings.TrimSpace(stringValue(args["filter"]))
		if filter == "" {
			return nil, fmt.Errorf("filter is required")
		}
		_, _, total, pending, err := s.deps.Capture.PacketsPageWithState(0, 1, filter)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"filter":  filter,
			"count":   total,
			"pending": pending,
		}, nil
	case "stream.decode":
		decoder := strings.TrimSpace(stringValue(args["decoder"]))
		payload := stringValue(args["payload"])
		var options map[string]any
		if raw, ok := args["options"].(map[string]any); ok {
			options = raw
		}
		if s.deps.StreamDecode == nil {
			return nil, fmt.Errorf("stream decode not available")
		}
		return s.deps.StreamDecode(StreamDecodeRequest{
			Decoder: decoder,
			Payload: payload,
			Options: options,
		})
	case "c2.decrypt":
		var req model.C2DecryptRequest
		req.Family = strings.TrimSpace(stringValue(args["family"]))
		if scopeRaw, ok := args["scope"].(map[string]any); ok {
			scopeBytes, _ := json.Marshal(scopeRaw)
			_ = json.Unmarshal(scopeBytes, &req.Scope)
		}
		if vshellRaw, ok := args["vshell"].(map[string]any); ok {
			vshellBytes, _ := json.Marshal(vshellRaw)
			_ = json.Unmarshal(vshellBytes, &req.VShell)
		}
		if csRaw, ok := args["cs"].(map[string]any); ok {
			csBytes, _ := json.Marshal(csRaw)
			_ = json.Unmarshal(csBytes, &req.CS)
		}
		return s.deps.Analysis.C2Decrypt(ctx, req)
	case "media.sessions":
		analysis, err := s.deps.Media.MediaAnalysis()
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"sessions": analysis.Sessions,
			"total":    len(analysis.Sessions),
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool")
	}
}

func (s *Server) newTool(name, description string, inputSchema map[string]any, readOnly, idempotent bool) map[string]any {
	return map[string]any{
		"name":        name,
		"description": description,
		"inputSchema": inputSchema,
		"annotations": map[string]any{
			"readOnlyHint":   readOnly,
			"idempotentHint": idempotent,
		},
	}
}

func runtimeSnapshotInputSchema() map[string]any {
	return objectSchema(map[string]any{
		"mode": map[string]any{"type": "string", "enum": []string{"fast", "full"}},
	}, nil)
}

func objectSchema(properties map[string]any, required []string) map[string]any {
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func promptMessages(text string) []map[string]any {
	return []map[string]any{
		{
			"role": "user",
			"content": []map[string]any{
				{
					"type": "text",
					"text": text,
				},
			},
		},
	}
}

func invalidParams(err error) *mcpError {
	return &mcpError{Code: -32602, Message: "invalid params: " + err.Error()}
}

func decodeParams(raw json.RawMessage, dest any) error {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.Unmarshal([]byte(`{}`), dest)
	}
	return json.Unmarshal(raw, dest)
}

func marshalPretty(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func numberValue(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	default:
		return 0
	}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func stringSliceValue(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, stringValue(item))
	}
	return out
}

func truncateText(text string, max int) string {
	if max <= 0 || len(text) <= max {
		return text
	}
	return text[:max] + "\n...<truncated>"
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(strings.TrimSpace(v)) == "true"
	case float64:
		return v != 0
	default:
		return false
	}
}
