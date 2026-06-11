package tshark

import (
	"context"
	"strings"
	"testing"
)

func TestReassembleHTTPStreamFromFileContextUsesFakeTSharkRows(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	t.Cleanup(ClearCapabilityCache)

	stream, err := ReassembleHTTPStreamFromFileContext(context.Background(), "sample.pcap", 9)
	if err != nil {
		t.Fatalf("ReassembleHTTPStreamFromFileContext() error = %v", err)
	}

	if stream.Protocol != "HTTP" || stream.StreamID != 9 {
		t.Fatalf("stream identity = %+v", stream)
	}
	if stream.From != "192.0.2.10" || stream.To != "198.51.100.20" {
		t.Fatalf("stream endpoints = from %q to %q", stream.From, stream.To)
	}
	if len(stream.Chunks) != 2 {
		t.Fatalf("chunks = %+v, want client and server chunks", stream.Chunks)
	}
	if stream.Chunks[0].PacketID != 301 || stream.Chunks[0].Direction != "client" || !strings.Contains(stream.Chunks[0].Body, "GET /a") || !strings.Contains(stream.Chunks[0].Body, "Host: example") {
		t.Fatalf("client chunk = %+v", stream.Chunks[0])
	}
	if stream.Chunks[1].PacketID != 303 || stream.Chunks[1].Direction != "server" || !strings.Contains(stream.Chunks[1].Body, "HTTP/1.1 200 OK") {
		t.Fatalf("server chunk = %+v", stream.Chunks[1])
	}
	if !strings.Contains(stream.Request, "GET /a") || !strings.Contains(stream.Response, "HTTP/1.1 200 OK") {
		t.Fatalf("request/response = %q / %q", stream.Request, stream.Response)
	}
}

func TestReassembleRawStreamFromFileContextUsesFakeTSharkRows(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	t.Cleanup(ClearCapabilityCache)

	tcp, err := ReassembleRawStreamFromFileContext(context.Background(), "sample.pcap", "tcp", 9)
	if err != nil {
		t.Fatalf("ReassembleRawStreamFromFileContext(TCP) error = %v", err)
	}
	if tcp.Protocol != "TCP" || tcp.From != "192.0.2.10" || tcp.To != "198.51.100.20" {
		t.Fatalf("tcp stream metadata = %+v", tcp)
	}
	if len(tcp.Chunks) != 2 {
		t.Fatalf("tcp chunks = %+v, want client/server chunks", tcp.Chunks)
	}
	if tcp.Chunks[0].Direction != "client" || !strings.HasPrefix(tcp.Chunks[0].Body, "47:45:54") || !strings.Contains(tcp.Chunks[0].Body, "48:6f:73:74") {
		t.Fatalf("tcp client chunk = %+v", tcp.Chunks[0])
	}
	if tcp.Chunks[1].Direction != "server" || !strings.Contains(tcp.Chunks[1].Body, "32:30:30") {
		t.Fatalf("tcp server chunk = %+v", tcp.Chunks[1])
	}

	udp, err := ReassembleRawStreamFromFileContext(context.Background(), "sample.pcap", "udp", 2)
	if err != nil {
		t.Fatalf("ReassembleRawStreamFromFileContext(UDP) error = %v", err)
	}
	if udp.Protocol != "UDP" || udp.From != "203.0.113.10" || udp.To != "203.0.113.53" {
		t.Fatalf("udp stream metadata = %+v", udp)
	}
	if len(udp.Chunks) != 2 {
		t.Fatalf("udp chunks = %+v, want client/server chunks", udp.Chunks)
	}
	if udp.Chunks[0].Direction != "client" || udp.Chunks[0].Body != "01:02:03:04:05:06" {
		t.Fatalf("udp client chunk = %+v", udp.Chunks[0])
	}
	if udp.Chunks[1].Direction != "server" || udp.Chunks[1].Body != "aa:bb" {
		t.Fatalf("udp server chunk = %+v", udp.Chunks[1])
	}
}

func TestReassembleRawStreamRejectsUnsupportedProtocol(t *testing.T) {
	stream, err := ReassembleRawStreamFromFileContext(context.Background(), "sample.pcap", "icmp", 1)
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("err = %v, want unsupported protocol", err)
	}
	if stream.Protocol != "ICMP" || stream.StreamID != 1 {
		t.Fatalf("stream metadata on error = %+v", stream)
	}
}

func TestStreamFollowPayloadHelpers(t *testing.T) {
	if got := decodeHexPayloadToText("48:69,20:21,abc,zz"); got != "Hi !" {
		t.Fatalf("decodeHexPayloadToText() = %q, want Hi !", got)
	}
	if got := normalizePayloadHex("01:02, 0304,abc,zz"); got != "01:02:03:04" {
		t.Fatalf("normalizePayloadHex() = %q", got)
	}
	if got := joinFollowChunkBodies("aa:bb", "cc"); got != "aa:bb:cc" {
		t.Fatalf("joinFollowChunkBodies() = %q", got)
	}
	if got := joinFollowChunkBodies("", "cc"); got != "cc" {
		t.Fatalf("joinFollowChunkBodies empty left = %q", got)
	}
	if got := joinFollowChunkBodies("aa", ""); got != "aa" {
		t.Fatalf("joinFollowChunkBodies empty right = %q", got)
	}
}
