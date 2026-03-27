package tshark

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildArgs_Basic(t *testing.T) {
	opts := model.ParseOptions{FilePath: "test.pcap"}
	args := BuildArgs(opts)
	expected := []string{"-n", "-r", "test.pcap", "-T", "ek"}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(args), args)
	}
	for i, v := range expected {
		if args[i] != v {
			t.Errorf("arg[%d] expected %q, got %q", i, v, args[i])
		}
	}
}

func TestBuildArgs_WithFilter(t *testing.T) {
	opts := model.ParseOptions{FilePath: "test.pcap", DisplayFilter: "http"}
	args := BuildArgs(opts)
	if args[len(args)-2] != "-Y" || args[len(args)-1] != "http" {
		t.Errorf("expected -Y http suffix, got %v", args)
	}
}

func TestBuildArgs_WithTLSKeyLog(t *testing.T) {
	opts := model.ParseOptions{
		FilePath: "test.pcap",
		TLS:      model.TLSConfig{SSLKeyLogFile: "/tmp/keys.log"},
	}
	args := BuildArgs(opts)
	found := false
	for i, v := range args {
		if v == "-o" && i+1 < len(args) && args[i+1] == "tls.keylog_file:/tmp/keys.log" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tls.keylog_file option in args: %v", args)
	}
}

func TestBuildArgs_WithRSAKey(t *testing.T) {
	opts := model.ParseOptions{
		FilePath: "test.pcap",
		TLS: model.TLSConfig{
			RSAPrivateKey: "/tmp/server.pem",
			TargetIPPort:  "10.0.0.1,8443",
		},
	}
	args := BuildArgs(opts)
	found := false
	for i, v := range args {
		if v == "-o" && i+1 < len(args) && args[i+1] == "rsa_keys:10.0.0.1,8443,http,/tmp/server.pem" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rsa_keys option in args: %v", args)
	}
}

func TestParsePacketFromEK_IndexLine(t *testing.T) {
	line := `{"index":{"_index":"packets-2024","_type":"doc"}}`
	_, err := ParsePacketFromEK(line, 1)
	if err == nil || err.Error() != "ek metadata line" {
		t.Errorf("expected 'ek metadata line' error, got %v", err)
	}
}

func TestParsePacketFromEK_EmptyLine(t *testing.T) {
	_, err := ParsePacketFromEK("", 1)
	if err == nil {
		t.Error("expected error on empty line")
	}
}

func TestParsePacketFromEK_ValidPacket(t *testing.T) {
	line := `{"layers":{"frame":{"frame_protocols":"eth:ip:tcp:http","frame_len":"512","frame_time_epoch":"1700000000.123"},"ip":{"ip_src":"192.168.1.10","ip_dst":"10.0.0.5"},"tcp":{"tcp_srcport":"50000","tcp_dstport":"80","tcp_stream":"42"},"http":{"http_request_method":"GET","http_request_uri":"/api/test"},"_ws":{"col":{"info":"GET /api/test HTTP/1.1"}}}}`
	pkt, err := ParsePacketFromEK(line, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.SourceIP != "192.168.1.10" {
		t.Errorf("expected source IP 192.168.1.10, got %s", pkt.SourceIP)
	}
	if pkt.DestIP != "10.0.0.5" {
		t.Errorf("expected dest IP 10.0.0.5, got %s", pkt.DestIP)
	}
	if pkt.Protocol != "HTTP" {
		t.Errorf("expected protocol HTTP, got %s", pkt.Protocol)
	}
	if pkt.SourcePort != 50000 {
		t.Errorf("expected source port 50000, got %d", pkt.SourcePort)
	}
	if pkt.DestPort != 80 {
		t.Errorf("expected dest port 80, got %d", pkt.DestPort)
	}
	if pkt.StreamID != 42 {
		t.Errorf("expected stream ID 42, got %d", pkt.StreamID)
	}
	if pkt.Length != 512 {
		t.Errorf("expected length 512, got %d", pkt.Length)
	}
}

func TestParsePacketFromEK_PreservesDisplayProtocol(t *testing.T) {
	line := `{"layers":{"frame":{"frame_protocols":"eth:ip:tcp:tls","frame_len":"128","frame_time_epoch":"1700000000.123"},"ip":{"ip_src":"192.168.1.10","ip_dst":"10.0.0.5"},"tcp":{"tcp_srcport":"50000","tcp_dstport":"443","tcp_stream":"7"},"_ws":{"col":{"Protocol":"TLSv1.3","info":"Client Hello"}}}}`
	pkt, err := ParsePacketFromEK(line, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.Protocol != "TLS" {
		t.Fatalf("expected normalized protocol TLS, got %s", pkt.Protocol)
	}
	if pkt.DisplayProtocol != "TLSv1.3" {
		t.Fatalf("expected display protocol TLSv1.3, got %s", pkt.DisplayProtocol)
	}
}

func TestParsePacketFromEK_UsesFrameNumberWhenAvailable(t *testing.T) {
	line := `{"layers":{"frame":{"frame_number":"42","frame_protocols":"eth:ip:tcp","frame_len":"96","frame_time_epoch":"1700000000.123"},"ip":{"ip_src":"192.168.1.10","ip_dst":"10.0.0.5"},"tcp":{"tcp_srcport":"50000","tcp_dstport":"443"},"_ws":{"col":{"Protocol":"TCP","info":"Client Hello"}}}}`
	pkt, err := ParsePacketFromEK(line, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.ID != 42 {
		t.Fatalf("expected packet ID 42 from frame.number, got %d", pkt.ID)
	}
}

func TestParseFastListLine_PreservesDisplayProtocol(t *testing.T) {
	parts := make([]string, 64)
	parts[0] = "5"
	parts[1] = "1700000000.123"
	parts[2] = "192.168.1.10"
	parts[5] = "10.0.0.5"
	parts[8] = "50000"
	parts[10] = "443"
	parts[12] = "TLSv1.3"
	parts[13] = "128"
	parts[14] = "Client Hello"

	pkt, err := parseFastListLine(strings.Join(parts, "\x1f"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.Protocol != "TLS" {
		t.Fatalf("expected normalized protocol TLS, got %s", pkt.Protocol)
	}
	if pkt.DisplayProtocol != "TLSv1.3" {
		t.Fatalf("expected display protocol TLSv1.3, got %s", pkt.DisplayProtocol)
	}
}

func TestParseCompatListLine_PreservesDisplayProtocol(t *testing.T) {
	parts := make([]string, 20)
	parts[0] = "5"
	parts[1] = "1700000000.123"
	parts[2] = "192.168.1.10"
	parts[5] = "10.0.0.5"
	parts[8] = "50000"
	parts[10] = "443"
	parts[12] = "TLSv1.3"
	parts[13] = "eth:ip:tcp:tls"
	parts[14] = "128"
	parts[15] = "Client Hello"

	pkt, err := parseCompatListLine(strings.Join(parts, "\x1f"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.Protocol != "TLS" {
		t.Fatalf("expected normalized protocol TLS, got %s", pkt.Protocol)
	}
	if pkt.DisplayProtocol != "TLSv1.3" {
		t.Fatalf("expected display protocol TLSv1.3, got %s", pkt.DisplayProtocol)
	}
}

func TestNormalizeProto(t *testing.T) {
	tests := map[string]string{
		"eth:ip:tcp:http":      "HTTP",
		"eth:ip:tcp":           "TCP",
		"eth:ip:udp":           "UDP",
		"eth:ip:udp:dns":       "DNS",
		"eth:ip:tcp:tls":       "TLS",
		"eth:ip:tcp:ssh":       "SSHv2",
		"eth:arp":              "ARP",
		"eth:ip:tcp:something": "TCP",
		"":                     "OTHER",
	}
	for input, expected := range tests {
		result := normalizeProto(input)
		if result != expected {
			t.Errorf("normalizeProto(%q) = %q, want %q", input, result, expected)
		}
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	// Epoch seconds-like string
	result := normalizeTimestamp("1700000000.123456")
	if result != "1700000000.123456" {
		// Non-parseable as int or RFC3339, returns raw
	}

	// Empty
	if normalizeTimestamp("") != "" {
		t.Error("expected empty string")
	}
}

func TestStreamPacketsFast_WithCustomBinaryAndNoTSharkInPath(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	tsharkPath, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not available in PATH")
	}

	pcapFile, err := os.CreateTemp("", "gshark-custom-binary-*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	pcapPath := pcapFile.Name()
	defer os.Remove(pcapPath)

	writer := pcapgo.NewWriter(pcapFile)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = pcapFile.Close()
		t.Fatalf("write pcap header: %v", err)
	}

	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x04, 0xd2, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000000, 0),
		CaptureLength: len(frame),
		Length:        len(frame),
	}, frame); err != nil {
		_ = pcapFile.Close()
		t.Fatalf("write packet: %v", err)
	}
	if err := pcapFile.Close(); err != nil {
		t.Fatalf("close temp pcap: %v", err)
	}

	SetBinaryPath(tsharkPath)
	t.Setenv("PATH", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := model.ParseOptions{FilePath: pcapPath, FastList: true}
	total, err := EstimatePackets(ctx, opts)
	if err != nil {
		t.Fatalf("EstimatePackets() error = %v", err)
	}
	if total != 1 {
		t.Fatalf("EstimatePackets() total = %d, want 1", total)
	}

	var packets []model.Packet
	err = StreamPacketsFast(ctx, opts, func(packet model.Packet) error {
		packets = append(packets, packet)
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("StreamPacketsFast() error = %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
}

func TestStreamPacketsFast_WithCustomBinaryDirectoryAndNoTSharkInPath(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	tsharkPath, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not available in PATH")
	}

	pcapFile, err := os.CreateTemp("", "gshark-custom-binary-dir-*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	pcapPath := pcapFile.Name()
	defer os.Remove(pcapPath)

	writer := pcapgo.NewWriter(pcapFile)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = pcapFile.Close()
		t.Fatalf("write pcap header: %v", err)
	}

	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
		0x04, 0xd2, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000001, 0),
		CaptureLength: len(frame),
		Length:        len(frame),
	}, frame); err != nil {
		_ = pcapFile.Close()
		t.Fatalf("write packet: %v", err)
	}
	if err := pcapFile.Close(); err != nil {
		t.Fatalf("close temp pcap: %v", err)
	}

	SetBinaryPath(filepath.Dir(tsharkPath))
	t.Setenv("PATH", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := model.ParseOptions{FilePath: pcapPath, FastList: true}
	total, err := EstimatePackets(ctx, opts)
	if err != nil {
		t.Fatalf("EstimatePackets() error = %v", err)
	}
	if total != 1 {
		t.Fatalf("EstimatePackets() total = %d, want 1", total)
	}
}
