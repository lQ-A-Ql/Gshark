package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestPacketFilterExpressionHelpersCoverComparisonsAndContains(t *testing.T) {
	packet := model.Packet{
		ID:              42,
		SourceIP:        "10.0.0.10",
		SourcePort:      51515,
		DestIP:          "198.51.100.20",
		DestPort:        8080,
		Protocol:        "HTTP",
		DisplayProtocol: "HTTP/JSON",
		Length:          512,
		Info:            "POST /login HTTP/1.1",
		Payload:         `{"username":"alice","token":"secret"}`,
	}

	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{name: "empty", filter: "", want: true},
		{name: "and contains", filter: `http and payload contains "alice"`, want: true},
		{name: "or", filter: `dns or http.request.method == POST`, want: true},
		{name: "not", filter: `http and not ip.dst == 203.0.113.1`, want: true},
		{name: "ip addr", filter: `ip.addr contains 198.51`, want: true},
		{name: "protocol display", filter: `_ws.col.protocol contains json`, want: true},
		{name: "frame len", filter: `frame.len >= 512`, want: true},
		{name: "frame number", filter: `frame.number < 50`, want: true},
		{name: "port", filter: `port == 8080`, want: true},
		{name: "payload fallback compare", filter: `payload == {"username":"alice","token":"secret"}`, want: true},
		{name: "negative method", filter: `http.request.method == GET`, want: false},
		{name: "negative port", filter: `udp.port == 53`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := compilePacketFilter(tt.filter)
			got := true
			if predicate != nil {
				got = predicate(packet)
			}
			if got != tt.want {
				t.Fatalf("compilePacketFilter(%q)(packet) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}

	if got := splitFilter(packetFilterAndRE, " http and  tcp  and "); !reflect.DeepEqual(got, []string{"http", "tcp"}) {
		t.Fatalf("splitFilter() = %+v", got)
	}
	if got := normalizePacketFilterValue(` "quoted value" `); got != "quoted value" {
		t.Fatalf("normalizePacketFilterValue() = %q", got)
	}
	if got := httpStatusCode(model.Packet{Info: "404 Not Found"}); got != 404 {
		t.Fatalf("httpStatusCode() = %d", got)
	}
	if got := httpMethod(model.Packet{Info: "TRACE /debug"}); got != "" {
		t.Fatalf("httpMethod unsupported = %q", got)
	}
	if compareString("a", ">", "b") || compareInt(1, "bad", 1) || compareInt64(1, "bad", 1) {
		t.Fatal("unsupported comparison operators should return false")
	}
	if got := parseFilterInt("bad"); got != 0 {
		t.Fatalf("parseFilterInt bad = %d", got)
	}
	if got := parseFilterInt64("bad"); got != 0 {
		t.Fatalf("parseFilterInt64 bad = %d", got)
	}
}

func TestStreamPayloadUpdatesRebuildHTTPBodiesAndValidateInputs(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	httpKey := streamCacheKey("HTTP", 7)
	svc.streamCtl.streamCache[httpKey] = model.ReassembledStream{
		StreamID: 7,
		Protocol: "HTTP",
		Chunks: []model.StreamChunk{
			{PacketID: 1, Direction: "client", Body: "GET /old\r\n"},
			{PacketID: 2, Direction: "server", Body: "HTTP/1.1 200 OK\r\n"},
			{PacketID: 3, Direction: "client", Body: "Host: old\r\n"},
		},
		Request:  "GET /old\r\nHost: old\r\n",
		Response: "HTTP/1.1 200 OK\r\n",
	}

	updated, err := svc.UpdateStreamPayloads(context.Background(), "http", 7, []model.StreamChunkPatch{
		{Index: -1, Body: "ignored"},
		{Index: 0, Body: "POST /new\r\n"},
		{Index: 2, Body: "Host: new\r\n"},
	})
	if err != nil {
		t.Fatalf("UpdateStreamPayloads(HTTP) error = %v", err)
	}
	if updated.Request != "POST /new\r\nHost: new\r\n" || updated.Response != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("HTTP bodies were not rebuilt: request=%q response=%q chunks=%+v", updated.Request, updated.Response, updated.Chunks)
	}
	if updated.LoadMeta == nil || !updated.LoadMeta.CacheHit || updated.LoadMeta.OverrideCount != 2 {
		t.Fatalf("expected cache load meta with override count, got %+v", updated.LoadMeta)
	}

	rawKey := streamCacheKey("TCP", 9)
	svc.streamCtl.rawStreamIndex[rawKey] = model.ReassembledStream{
		StreamID: 9,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{PacketID: 1, Direction: "client", Body: "aa"},
			{PacketID: 2, Direction: "server", Body: "bb"},
		},
	}
	raw, err := svc.UpdateStreamPayloads(context.Background(), "tcp", 9, []model.StreamChunkPatch{{Index: 1, Body: "cc"}})
	if err != nil {
		t.Fatalf("UpdateStreamPayloads(TCP) error = %v", err)
	}
	if len(raw.Chunks) != 2 || raw.Chunks[1].Body != "cc" || raw.LoadMeta == nil || !raw.LoadMeta.IndexHit || raw.LoadMeta.OverrideCount != 1 {
		t.Fatalf("raw stream override = %+v", raw)
	}

	if _, err := svc.UpdateStreamPayloads(context.Background(), "icmp", 1, []model.StreamChunkPatch{{Index: 0, Body: "x"}}); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("unsupported protocol err = %v", err)
	}
	if _, err := svc.UpdateStreamPayloads(context.Background(), "tcp", -1, []model.StreamChunkPatch{{Index: 0, Body: "x"}}); err == nil || !strings.Contains(err.Error(), "invalid stream id") {
		t.Fatalf("invalid stream id err = %v", err)
	}
	if _, err := svc.UpdateStreamPayloads(context.Background(), "tcp", 1, []model.StreamChunkPatch{{Index: -1, Body: "x"}}); err == nil || !strings.Contains(err.Error(), "no valid patches") {
		t.Fatalf("no valid patches err = %v", err)
	}
}

func TestServiceToolConfigAndStreamIDs(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	hunting := svc.SetHuntingRuntimeConfig(model.HuntingRuntimeConfig{
		Prefixes:      []string{" flag{ ", "FLAG{", "", "token="},
		YaraEnabled:   true,
		YaraBin:       " yara ",
		YaraRules:     " rules.yar ",
		YaraTimeoutMS: 5000,
	})
	if !reflect.DeepEqual(hunting.Prefixes, []string{"flag{", "token="}) || !hunting.YaraEnabled || hunting.YaraBin != "yara" || hunting.YaraRules != "rules.yar" || hunting.YaraTimeoutMS != 5000 {
		t.Fatalf("SetHuntingRuntimeConfig() = %+v", hunting)
	}

	svc.SetTLSConfig(model.TLSConfig{SSLKeyLogFile: "keys.log", RSAPrivateKey: "rsa.pem", TargetIPPort: "10.0.0.1:443"})
	if got := svc.TLSConfig(); got.SSLKeyLogFile != "keys.log" || got.RSAPrivateKey != "rsa.pem" || got.TargetIPPort != "10.0.0.1:443" {
		t.Fatalf("TLSConfig() = %+v", got)
	}

	status := svc.MCPStatus(true)
	if status.Enabled || !status.AuthRequired || !status.ReadOnly || status.Endpoint == "" || status.Transport != "streamable-http" {
		t.Fatalf("default MCPStatus() = %+v", status)
	}
	cfg := svc.SetMCPConfig(model.MCPConfig{Enabled: true})
	if !cfg.Enabled || !svc.MCPConfig().Enabled || !svc.MCPStatus(false).Enabled {
		t.Fatalf("MCP config/status not enabled: cfg=%+v status=%+v", cfg, svc.MCPStatus(false))
	}

	svc.streamCtl.rawStreamIndex[streamCacheKey("TCP", 5)] = model.ReassembledStream{StreamID: 5, Protocol: "TCP"}
	svc.streamCtl.rawStreamIndex[streamCacheKey("UDP", 3)] = model.ReassembledStream{StreamID: 3, Protocol: "UDP"}
	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", StreamID: 1},
		{ID: 2, Protocol: "TLS", StreamID: 2},
		{ID: 3, Protocol: "DNS", StreamID: 3},
		{ID: 4, Protocol: "UDP", StreamID: 4},
		{ID: 5, Protocol: "ICMP", StreamID: -1},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	if got := svc.StreamIDs("http"); !reflect.DeepEqual(got, []int64{1}) {
		t.Fatalf("HTTP StreamIDs() = %+v", got)
	}
	if got := svc.StreamIDs("tcp"); !reflect.DeepEqual(got, []int64{1, 2, 5}) {
		t.Fatalf("TCP StreamIDs() = %+v", got)
	}
	if got := svc.StreamIDs("udp"); !reflect.DeepEqual(got, []int64{3, 4}) {
		t.Fatalf("UDP StreamIDs() = %+v", got)
	}
	if got := svc.StreamIDs("icmp"); len(got) != 0 {
		t.Fatalf("unsupported StreamIDs() = %+v", got)
	}
}

func TestPacketLookupAndRawHelpersReturnExpectedErrors(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	if _, err := svc.Packet(0); err == nil || !strings.Contains(err.Error(), "invalid packet id") {
		t.Fatalf("Packet(0) err = %v", err)
	}
	if _, err := svc.Packet(99); err == nil || !strings.Contains(err.Error(), "packet not found") {
		t.Fatalf("Packet(99) err = %v", err)
	}
	if err := svc.captureCtl.packetStore.Append([]model.Packet{{ID: 7, Protocol: "TCP", Info: "demo"}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	packet, err := svc.Packet(7)
	if err != nil || packet.ID != 7 {
		t.Fatalf("Packet(7) = %+v err=%v", packet, err)
	}
	if _, err := svc.PacketRawHex(7); err == nil || !strings.Contains(err.Error(), "no capture loaded") {
		t.Fatalf("PacketRawHex no capture err = %v", err)
	}
	if _, err := svc.PacketLayers(7); err == nil || !strings.Contains(err.Error(), "no capture loaded") {
		t.Fatalf("PacketLayers no capture err = %v", err)
	}
}
