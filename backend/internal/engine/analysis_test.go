package engine

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func makePacket(id int64, info, payload, protocol, srcIP string, destPort int) model.Packet {
	return model.Packet{
		ID:       id,
		Info:     info,
		Payload:  payload,
		Protocol: protocol,
		SourceIP: srcIP,
		DestIP:   "10.0.0.1",
		DestPort: destPort,
	}
}

func TestHuntThreats_NoHardcodedOWASPRules(t *testing.T) {
	packets := []model.Packet{
		makePacket(1, "POST /cmd", "whoami && cat /etc/passwd", "HTTP", "192.168.1.1", 80),
		makePacket(2, "POST /comment", "<script>alert(1)</script>", "HTTP", "192.168.1.2", 80),
	}
	hits := HuntThreats(packets, nil)
	for _, h := range hits {
		if h.Category == "OWASP" || h.Category == "Sensitive" {
			t.Fatalf("expected HuntThreats to skip hardcoded OWASP/Sensitive checks, got %+v", h)
		}
	}
}

func TestHuntThreats_FlagSniffing(t *testing.T) {
	packets := []model.Packet{
		makePacket(1, "TCP data", "flag{test_flag_123}", "TCP", "192.168.1.1", 9000),
	}
	hits := HuntThreats(packets, []string{"flag{"})
	found := false
	for _, h := range hits {
		if h.Rule == "Flag 嗅探" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected flag sniffing hit")
	}
}

func TestHuntThreats_FlagBase64(t *testing.T) {
	// "flag{" base64 = "ZmxhZ3s="
	packets := []model.Packet{
		makePacket(1, "TCP data", "payload ZmxhZ3s= more data", "TCP", "192.168.1.1", 9000),
	}
	hits := HuntThreats(packets, []string{"flag{"})
	found := false
	for _, h := range hits {
		if h.Rule == "Flag Base64 变体" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected flag base64 variant hit")
	}
}

func TestHuntThreats_Anomaly404(t *testing.T) {
	packets := make([]model.Packet, 0, 20)
	for i := int64(1); i <= 20; i++ {
		packets = append(packets, makePacket(i, "HTTP 404 Not Found", "", "HTTP", "192.168.1.100", 80))
	}
	hits := HuntThreats(packets, nil)
	found := false
	for _, h := range hits {
		if h.Rule == "异常扫描行为" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected anomaly scan hit for 20x 404 from same IP")
	}
}

func TestHuntThreats_NoFalsePositiveOnNormal(t *testing.T) {
	packets := []model.Packet{
		makePacket(1, "GET /api/data", "normal response data", "HTTP", "192.168.1.1", 80),
		makePacket(2, "DNS query", "A www.example.com", "DNS", "192.168.1.1", 53),
	}
	hits := HuntThreats(packets, nil)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on normal traffic, got %d: %+v", len(hits), hits)
	}
}

func TestDetectNonStandardPortFlows(t *testing.T) {
	packets := []model.Packet{
		makePacket(1, "HTTP GET /test", "payload", "HTTP", "192.168.1.1", 9999),
	}
	hits := DetectNonStandardPortFlows(packets)
	if len(hits) == 0 {
		t.Error("expected non-standard port hit for HTTP on port 9999")
	}
}

func TestExtractObjects(t *testing.T) {
	packets := []model.Packet{
		makePacket(1, "POST /upload", "content-type: image/png\nfilename=\"test.png\"", "HTTP", "192.168.1.1", 80),
		makePacket(2, "TCP data", "some data", "TCP", "192.168.1.1", 9000),
	}
	objects := ExtractObjects(packets)
	if len(objects) == 0 {
		t.Error("expected at least one extracted object from HTTP packet with filename")
	}
}

func TestReassembleRawStream(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, StreamID: 5, Protocol: "TCP", SourceIP: "192.168.1.1", SourcePort: 50000, DestIP: "10.0.0.1", DestPort: 80, Payload: "client hello"},
		{ID: 2, StreamID: 5, Protocol: "TCP", SourceIP: "10.0.0.1", SourcePort: 80, DestIP: "192.168.1.1", DestPort: 50000, Payload: "server hello"},
		{ID: 3, StreamID: 99, Protocol: "TCP", SourceIP: "192.168.1.1", SourcePort: 50001, DestIP: "10.0.0.2", DestPort: 8080, Payload: "other stream"},
	}
	stream := ReassembleRawStream(packets, "TCP", 5)
	if len(stream.Chunks) != 2 {
		t.Errorf("expected 2 chunks in stream 5, got %d", len(stream.Chunks))
	}
	if stream.Chunks[0].Direction != "client" {
		t.Errorf("expected first chunk direction 'client', got %q", stream.Chunks[0].Direction)
	}
	if stream.Chunks[1].Direction != "server" {
		t.Errorf("expected second chunk direction 'server', got %q", stream.Chunks[1].Direction)
	}
}
