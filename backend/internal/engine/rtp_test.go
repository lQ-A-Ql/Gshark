package engine

import (
	"encoding/binary"
	"testing"
)

// buildRTPPacket builds a minimal RTP packet byte slice.
func buildRTPPacket(ssrc uint32, seq uint16, ts uint32, pt uint8, marker bool, payload []byte) []byte {
	buf := make([]byte, 12+len(payload))
	buf[0] = 0x80 // V=2, P=0, X=0, CC=0
	markerBit := uint8(0)
	if marker {
		markerBit = 0x80
	}
	buf[1] = markerBit | (pt & 0x7F)
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	copy(buf[12:], payload)
	return buf
}

// buildRTPPacketWithCSRC builds an RTP packet with CSRC entries.
func buildRTPPacketWithCSRC(ssrc uint32, seq uint16, ts uint32, pt uint8, csrcs []uint32) []byte {
	csrcCount := len(csrcs)
	buf := make([]byte, 12+csrcCount*4)
	buf[0] = 0x80 | uint8(csrcCount&0x0F) // V=2, CC=csrcCount
	buf[1] = pt & 0x7F
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	for i, c := range csrcs {
		binary.BigEndian.PutUint32(buf[12+i*4:], c)
	}
	return buf
}

// buildRTPPacketWithExt builds an RTP packet with a profile extension header.
func buildRTPPacketWithExt(ssrc uint32, seq uint16, ts uint32, pt uint8, extData []byte) []byte {
	// Extension header: 2 bytes profile, 2 bytes length (in 32-bit words).
	extWords := (len(extData) + 3) / 4
	padded := make([]byte, extWords*4)
	copy(padded, extData)

	buf := make([]byte, 12+4+len(padded))
	buf[0] = 0x90 // V=2, P=0, X=1, CC=0
	buf[1] = pt & 0x7F
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	// Extension header: profile-specific (0xBEDE = one-byte header)
	binary.BigEndian.PutUint16(buf[12:14], 0xBEDE)
	binary.BigEndian.PutUint16(buf[14:16], uint16(extWords))
	copy(buf[16:], padded)
	return buf
}

// buildPaddedRTPPacket builds an RTP packet with padding.
func buildPaddedRTPPacket(ssrc uint32, seq uint16, ts uint32, pt uint8, payload []byte, padLen int) []byte {
	buf := make([]byte, 12+len(payload)+padLen)
	buf[0] = 0xA0 // V=2, P=1, X=0, CC=0
	buf[1] = pt & 0x7F
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	copy(buf[12:], payload)
	// Padding bytes (last byte = padLen).
	for i := len(buf) - padLen; i < len(buf)-1; i++ {
		buf[i] = 0
	}
	buf[len(buf)-1] = byte(padLen)
	return buf
}

func TestParseRTPHeader_Basic(t *testing.T) {
	raw := buildRTPPacket(0xDEADBEEF, 42, 160000, 0, false, []byte("hello"))
	h, offset, err := ParseRTPHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Version != 2 {
		t.Errorf("version = %d, want 2", h.Version)
	}
	if h.Padding {
		t.Error("padding should be false")
	}
	if h.Extension {
		t.Error("extension should be false")
	}
	if h.CSRCCount != 0 {
		t.Errorf("CSRCCount = %d, want 0", h.CSRCCount)
	}
	if h.Marker {
		t.Error("marker should be false")
	}
	if h.PayloadType != 0 {
		t.Errorf("PayloadType = %d, want 0", h.PayloadType)
	}
	if h.SeqNum != 42 {
		t.Errorf("SeqNum = %d, want 42", h.SeqNum)
	}
	if h.Timestamp != 160000 {
		t.Errorf("Timestamp = %d, want 160000", h.Timestamp)
	}
	if h.SSRC != 0xDEADBEEF {
		t.Errorf("SSRC = 0x%08X, want 0xDEADBEEF", h.SSRC)
	}
	if offset != 12 {
		t.Errorf("offset = %d, want 12", offset)
	}
}

func TestParseRTPHeader_WithCSRC(t *testing.T) {
	csrcs := []uint32{0x11111111, 0x22222222, 0x33333333}
	raw := buildRTPPacketWithCSRC(0xAABBCCDD, 100, 320000, 8, csrcs)
	h, offset, err := ParseRTPHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.CSRCCount != 3 {
		t.Errorf("CSRCCount = %d, want 3", h.CSRCCount)
	}
	if len(h.CSRC) != 3 {
		t.Fatalf("len(CSRC) = %d, want 3", len(h.CSRC))
	}
	for i, want := range csrcs {
		if h.CSRC[i] != want {
			t.Errorf("CSRC[%d] = 0x%08X, want 0x%08X", i, h.CSRC[i], want)
		}
	}
	if offset != 12+3*4 {
		t.Errorf("offset = %d, want %d", offset, 12+3*4)
	}
}

func TestParseRTPHeader_WithExtension(t *testing.T) {
	extPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	raw := buildRTPPacketWithExt(0x12345678, 50, 48000, 18, extPayload)
	h, offset, err := ParseRTPHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.Extension {
		t.Error("extension should be true")
	}
	// 5 bytes → 2 32-bit words → 4 + 2*4 = 12 bytes extension.
	expectedOffset := 12 + 4 + 8 // header + ext header + 2 words
	if offset != expectedOffset {
		t.Errorf("offset = %d, want %d", offset, expectedOffset)
	}
}

func TestParseRTPHeader_TooShort(t *testing.T) {
	short := []byte{0x80, 0x00, 0x00}
	_, _, err := ParseRTPHeader(short)
	if err != errRTPTooShort {
		t.Errorf("expected errRTPTooShort, got %v", err)
	}
}

func TestParseRTPHeader_BadVersion(t *testing.T) {
	buf := make([]byte, 12)
	buf[0] = 0x00 // V=0
	_, _, err := ParseRTPHeader(buf)
	if err != errRTPVersion {
		t.Errorf("expected errRTPVersion, got %v", err)
	}
}

func TestParseRTPPacket_Basic(t *testing.T) {
	payload := []byte("audio-frame-data")
	raw := buildRTPPacket(0xABCD1234, 7, 640, 0, true, payload)
	pkt, err := ParseRTPPacket(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pkt.Header.Marker {
		t.Error("marker should be true")
	}
	if len(pkt.Payload) != len(payload) {
		t.Errorf("payload length = %d, want %d", len(pkt.Payload), len(payload))
	}
	for i, b := range payload {
		if pkt.Payload[i] != b {
			t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, pkt.Payload[i], b)
		}
	}
}

func TestParseRTPPacket_Padding(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	padLen := 3
	raw := buildPaddedRTPPacket(0x11111111, 10, 800, 0, payload, padLen)
	pkt, err := ParseRTPPacket(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pkt.Header.Padding {
		t.Error("padding should be true")
	}
	// Payload should have padding stripped.
	if len(pkt.Payload) != len(payload) {
		t.Errorf("payload length = %d, want %d (padding stripped)", len(pkt.Payload), len(payload))
	}
}

func TestIdentifyCodec_StaticTypes(t *testing.T) {
	tests := []struct {
		pt     uint8
		want   string
		wantCR int
	}{
		{0, "PCMU", 8000},
		{8, "PCMA", 8000},
		{9, "G722", 8000},
		{18, "G729", 8000},
		{14, "MPA", 90000},
		{33, "MP2T", 90000},
	}
	for _, tt := range tests {
		info := IdentifyCodec(tt.pt)
		if info.Name != tt.want {
			t.Errorf("IdentifyCodec(%d).Name = %q, want %q", tt.pt, info.Name, tt.want)
		}
		if info.ClockRate != tt.wantCR {
			t.Errorf("IdentifyCodec(%d).ClockRate = %d, want %d", tt.pt, info.ClockRate, tt.wantCR)
		}
	}
}

func TestIdentifyCodec_DynamicType(t *testing.T) {
	info := IdentifyCodec(96)
	if info.Name != "dynamic" {
		t.Errorf("IdentifyCodec(96).Name = %q, want %q", info.Name, "dynamic")
	}
}

func TestIdentifyCodec_UnknownType(t *testing.T) {
	info := IdentifyCodec(50)
	if info.Name != "unknown" {
		t.Errorf("IdentifyCodec(50).Name = %q, want %q", info.Name, "unknown")
	}
}

func TestExtractRTPStreamsFromPackets_MultipleSSRC(t *testing.T) {
	packets := [][]byte{
		buildRTPPacket(0xAAAA0001, 1, 160, 0, false, []byte{0x01}),
		buildRTPPacket(0xAAAA0001, 2, 320, 0, false, []byte{0x02}),
		buildRTPPacket(0xAAAA0001, 3, 480, 0, false, []byte{0x03}),
		buildRTPPacket(0xBBBB0002, 100, 8000, 8, false, []byte{0x10}),
		buildRTPPacket(0xBBBB0002, 101, 8160, 8, false, []byte{0x11}),
	}
	result := ExtractRTPStreamsFromPackets(packets)

	if result.TotalParsed != 5 {
		t.Errorf("TotalParsed = %d, want 5", result.TotalParsed)
	}
	if result.TotalRejected != 0 {
		t.Errorf("TotalRejected = %d, want 0", result.TotalRejected)
	}
	if len(result.Streams) != 2 {
		t.Fatalf("len(Streams) = %d, want 2", len(result.Streams))
	}

	// Streams are sorted by SSRC.
	if result.Streams[0].SSRC != 0xAAAA0001 {
		t.Errorf("Stream[0].SSRC = 0x%08X, want 0xAAAA0001", result.Streams[0].SSRC)
	}
	if result.Streams[1].SSRC != 0xBBBB0002 {
		t.Errorf("Stream[1].SSRC = 0x%08X, want 0xBBBB0002", result.Streams[1].SSRC)
	}

	// Check codec identification.
	if result.Streams[0].Codec.Name != "PCMU" {
		t.Errorf("Stream[0].Codec = %s, want PCMU", result.Streams[0].Codec.Name)
	}
	if result.Streams[1].Codec.Name != "PCMA" {
		t.Errorf("Stream[1].Codec = %s, want PCMA", result.Streams[1].Codec.Name)
	}
}

func TestExtractRTPStreamsFromPackets_InvalidPacketsRejected(t *testing.T) {
	packets := [][]byte{
		{0x00, 0x01, 0x02},             // too short
		{0x00, 0x01, 0x02, 0x03, 0x04}, // too short
		buildRTPPacket(0x11111111, 1, 160, 0, false, []byte{0x01}),
	}
	result := ExtractRTPStreamsFromPackets(packets)
	if result.TotalParsed != 1 {
		t.Errorf("TotalParsed = %d, want 1", result.TotalParsed)
	}
	if result.TotalRejected != 2 {
		t.Errorf("TotalRejected = %d, want 2", result.TotalRejected)
	}
}

func TestCalculateStreamStats_NoLoss(t *testing.T) {
	s := &RTPStream{
		SSRC: 0x12345678,
		Packets: []*RTPPacket{
			{Header: RTPHeader{SeqNum: 100, Timestamp: 16000}},
			{Header: RTPHeader{SeqNum: 101, Timestamp: 16160}},
			{Header: RTPHeader{SeqNum: 102, Timestamp: 16320}},
			{Header: RTPHeader{SeqNum: 103, Timestamp: 16480}},
			{Header: RTPHeader{SeqNum: 104, Timestamp: 16640}},
		},
	}
	CalculateStreamStats(s)
	if s.Stats.PacketCount != 5 {
		t.Errorf("PacketCount = %d, want 5", s.Stats.PacketCount)
	}
	if s.Stats.LostPackets != 0 {
		t.Errorf("LostPackets = %d, want 0", s.Stats.LostPackets)
	}
	if s.Stats.OutOfOrder != 0 {
		t.Errorf("OutOfOrder = %d, want 0", s.Stats.OutOfOrder)
	}
	if s.Stats.MinSeq != 100 {
		t.Errorf("MinSeq = %d, want 100", s.Stats.MinSeq)
	}
	if s.Stats.MaxSeq != 104 {
		t.Errorf("MaxSeq = %d, want 104", s.Stats.MaxSeq)
	}
}

func TestCalculateStreamStats_WithLoss(t *testing.T) {
	// Packets 100,101,102,104,105 — missing 103.
	s := &RTPStream{
		SSRC: 0xAABBCCDD,
		Packets: []*RTPPacket{
			{Header: RTPHeader{SeqNum: 100, Timestamp: 16000}},
			{Header: RTPHeader{SeqNum: 101, Timestamp: 16160}},
			{Header: RTPHeader{SeqNum: 102, Timestamp: 16320}},
			{Header: RTPHeader{SeqNum: 104, Timestamp: 16640}},
			{Header: RTPHeader{SeqNum: 105, Timestamp: 16800}},
		},
	}
	CalculateStreamStats(s)
	if s.Stats.LostPackets != 1 {
		t.Errorf("LostPackets = %d, want 1", s.Stats.LostPackets)
	}
	if s.Stats.ExpectedPackets != 6 {
		t.Errorf("ExpectedPackets = %d, want 6", s.Stats.ExpectedPackets)
	}
}

func TestCalculateStreamStats_OutOfOrder(t *testing.T) {
	// Packets arrive: 100, 102, 101 (101 is out of order).
	s := &RTPStream{
		SSRC: 0x11223344,
		Packets: []*RTPPacket{
			{Header: RTPHeader{SeqNum: 100, Timestamp: 16000}},
			{Header: RTPHeader{SeqNum: 102, Timestamp: 16320}},
			{Header: RTPHeader{SeqNum: 101, Timestamp: 16160}},
		},
	}
	CalculateStreamStats(s)
	if s.Stats.OutOfOrder != 1 {
		t.Errorf("OutOfOrder = %d, want 1", s.Stats.OutOfOrder)
	}
}

func TestCalculateStreamStats_Duplicate(t *testing.T) {
	s := &RTPStream{
		SSRC: 0x55667788,
		Packets: []*RTPPacket{
			{Header: RTPHeader{SeqNum: 100, Timestamp: 16000}},
			{Header: RTPHeader{SeqNum: 100, Timestamp: 16000}}, // dup
			{Header: RTPHeader{SeqNum: 101, Timestamp: 16160}},
		},
	}
	CalculateStreamStats(s)
	if s.Stats.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", s.Stats.Duplicates)
	}
}

func TestCalculateStreamStats_SinglePacket(t *testing.T) {
	s := &RTPStream{
		SSRC: 0x99AABBCC,
		Packets: []*RTPPacket{
			{Header: RTPHeader{SeqNum: 500, Timestamp: 80000}},
		},
	}
	CalculateStreamStats(s)
	if s.Stats.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", s.Stats.PacketCount)
	}
	if s.Stats.LostPackets != 0 {
		t.Errorf("LostPackets = %d, want 0", s.Stats.LostPackets)
	}
	if s.Stats.OutOfOrder != 0 {
		t.Errorf("OutOfOrder = %d, want 0", s.Stats.OutOfOrder)
	}
}

func TestCalculateStreamStats_Empty(t *testing.T) {
	s := &RTPStream{SSRC: 0}
	CalculateStreamStats(s)
	if s.Stats.PacketCount != 0 {
		t.Errorf("PacketCount = %d, want 0", s.Stats.PacketCount)
	}
}

func TestExtractRTPStreamsFromInfo(t *testing.T) {
	packets := []RTPPacketInfo{
		{SSRC: 0xAAA, PayloadType: 0, SeqNum: 1, Timestamp: 160, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 10000, DstPort: 20000},
		{SSRC: 0xAAA, PayloadType: 0, SeqNum: 2, Timestamp: 320, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 10000, DstPort: 20000},
		{SSRC: 0xBBB, PayloadType: 8, SeqNum: 50, Timestamp: 8000, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SrcPort: 30000, DstPort: 40000},
	}
	result := ExtractRTPStreamsFromInfo(packets)
	if result.TotalParsed != 3 {
		t.Errorf("TotalParsed = %d, want 3", result.TotalParsed)
	}
	if len(result.Streams) != 2 {
		t.Fatalf("len(Streams) = %d, want 2", len(result.Streams))
	}
	// First stream (sorted by SSRC).
	s0 := result.Streams[0]
	if s0.SSRC != 0xAAA {
		t.Errorf("Stream[0].SSRC = 0x%X, want 0xAAA", s0.SSRC)
	}
	if s0.SrcIP != "10.0.0.1" {
		t.Errorf("Stream[0].SrcIP = %q, want %q", s0.SrcIP, "10.0.0.1")
	}
	if s0.Codec.Name != "PCMU" {
		t.Errorf("Stream[0].Codec = %s, want PCMU", s0.Codec.Name)
	}
	if s0.Stats.PacketCount != 2 {
		t.Errorf("Stream[0].PacketCount = %d, want 2", s0.Stats.PacketCount)
	}
}

func TestCountReorderAndDups(t *testing.T) {
	tests := []struct {
		name    string
		seqs    []uint16
		reorder int
		dups    int
	}{
		{"ordered", []uint16{1, 2, 3, 4, 5}, 0, 0},
		{"one reorder", []uint16{1, 3, 2, 4, 5}, 1, 0},
		{"one dup", []uint16{1, 2, 2, 3}, 0, 1},
		{"two dups", []uint16{1, 1, 1, 2}, 0, 2},
		{"reorder + dup", []uint16{1, 3, 2, 3, 4}, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reorder, dups := countReorderAndDups(tt.seqs)
			if reorder != tt.reorder {
				t.Errorf("reorder = %d, want %d", reorder, tt.reorder)
			}
			if dups != tt.dups {
				t.Errorf("dups = %d, want %d", dups, tt.dups)
			}
		})
	}
}

func TestSeqNumLess(t *testing.T) {
	if !seqNumLess(100, 101) {
		t.Error("100 < 101 should be true")
	}
	if seqNumLess(101, 100) {
		t.Error("101 < 100 should be false")
	}
	// Wrap-around: 65535 < 0 in circular space.
	if !seqNumLess(65535, 0) {
		t.Error("65535 < 0 (wrap) should be true")
	}
	if seqNumLess(0, 65535) {
		t.Error("0 < 65535 (wrap) should be false")
	}
}

func TestFormatSSRC(t *testing.T) {
	got := formatSSRC(0xDEADBEEF)
	want := "0xdeadbeef"
	if got != want {
		t.Errorf("formatSSRC(0xDEADBEEF) = %q, want %q", got, want)
	}
	got2 := formatSSRC(0)
	want2 := "0x00000000"
	if got2 != want2 {
		t.Errorf("formatSSRC(0) = %q, want %q", got2, want2)
	}
}

func TestRTPPacketInfo_ExtractAndStats(t *testing.T) {
	// Build 100 sequential packets with 5 gaps (at seq 10,20,30,40,50).
	packets := make([]RTPPacketInfo, 0, 95)
	for i := uint16(0); i < 105; i++ {
		if i == 10 || i == 20 || i == 30 || i == 40 || i == 50 {
			continue // simulate loss
		}
		packets = append(packets, RTPPacketInfo{
			SSRC:        0x12340001,
			PayloadType: 0,
			SeqNum:      i,
			Timestamp:   uint32(i) * 160,
		})
	}
	result := ExtractRTPStreamsFromInfo(packets)
	if len(result.Streams) != 1 {
		t.Fatalf("len(Streams) = %d, want 1", len(result.Streams))
	}
	s := result.Streams[0]
	if s.Stats.PacketCount != 100 {
		t.Errorf("PacketCount = %d, want 100", s.Stats.PacketCount)
	}
	if s.Stats.LostPackets != 5 {
		t.Errorf("LostPackets = %d, want 5", s.Stats.LostPackets)
	}
	if s.Stats.ExpectedPackets != 105 {
		t.Errorf("ExpectedPackets = %d, want 105", s.Stats.ExpectedPackets)
	}
}

func TestExtractRTPStreamsFromPackets_WithCSRCAndExt(t *testing.T) {
	// Verify packets with CSRC and extension headers are parsed correctly.
	packets := [][]byte{
		buildRTPPacketWithCSRC(0xCC000001, 1, 160, 9, []uint32{0x11}),
		buildRTPPacketWithExt(0xCC000001, 2, 320, 9, []byte{0xAA, 0xBB}),
		buildRTPPacket(0xCC000001, 3, 480, 9, false, []byte{0x01}),
	}
	result := ExtractRTPStreamsFromPackets(packets)
	if result.TotalParsed != 3 {
		t.Errorf("TotalParsed = %d, want 3", result.TotalParsed)
	}
	if result.TotalRejected != 0 {
		t.Errorf("TotalRejected = %d, want 0", result.TotalRejected)
	}
	if len(result.Streams) != 1 {
		t.Fatalf("len(Streams) = %d, want 1", len(result.Streams))
	}
	if result.Streams[0].Codec.Name != "G722" {
		t.Errorf("Codec = %s, want G722", result.Streams[0].Codec.Name)
	}
}
