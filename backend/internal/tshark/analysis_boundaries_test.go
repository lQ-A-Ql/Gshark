package tshark

import (
	"context"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestIndustrialDetailBuilderAggregatesMissingAndKnownFields(t *testing.T) {
	builder := newIndustrialDetailBuilder("S7comm")
	builder.Add(7, "2026-05-01T00:00:00Z", "10.0.0.1", "10.0.0.2", "Job / Read Var", "DB 1 / DB / Byte 4", "Success", "value", "summary")
	builder.Add(8, "", "", "10.0.0.2", "", "", "", "", "fallback")

	detail, conversations := builder.Build()
	if detail.Name != "S7comm" || detail.TotalFrames != 2 || len(detail.Records) != 2 {
		t.Fatalf("detail = %+v, want two S7comm records", detail)
	}
	if detail.Operations[0].Label != "Job / Read Var" || detail.Targets[0].Label != "DB 1 / DB / Byte 4" {
		t.Fatalf("unexpected buckets operations=%+v targets=%+v", detail.Operations, detail.Targets)
	}
	if conversations["S7comm|unknown -> 10.0.0.2"].Count != 1 {
		t.Fatalf("missing fallback conversation bucket: %+v", conversations)
	}
}

func TestIndustrialProtocolDetailLabelHelpers(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "s7 target", got: formatS7Target("1", "0x84", "4"), want: "DB 1 / DB / Byte 4"},
		{name: "s7 unknown area", got: s7AreaName("0x99"), want: "Area 0X99"},
		{name: "dnp3 known app", got: dnp3AppFunctionName("4"), want: "Operate"},
		{name: "dnp3 unknown app", got: dnp3AppFunctionName("0x77"), want: "App Func 0X77"},
		{name: "cip known service", got: cipServiceName("0x4C"), want: "Read Tag"},
		{name: "cip unknown service", got: cipServiceName("0x99"), want: "Service 0X99"},
		{name: "iec104 known cause", got: iec104CauseName("6"), want: "Activation"},
		{name: "iec104 unknown cause", got: iec104CauseName("99"), want: "Cause 99"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestIndustrialRulesCoverUnknownQuantityExceptionAndBurstBoundaries(t *testing.T) {
	bitCount := 2
	stats := model.IndustrialAnalysis{
		Modbus: model.ModbusAnalysis{
			Transactions: []model.ModbusTransaction{
				{PacketID: 10, Kind: "request", Source: "master", Destination: "slave", FunctionCode: 99, FunctionName: "Vendor", Reference: "40001", Summary: "vendor fc"},
				{PacketID: 11, Kind: "request", Source: "master", Destination: "slave", FunctionCode: 3, FunctionName: "Read Holding", Reference: "40001", Quantity: "126"},
				{PacketID: 12, Kind: "request", Source: "master", Destination: "slave", FunctionCode: 15, FunctionName: "Write Coils", Reference: "00001", Quantity: "3", BitRange: &model.ModbusBitRange{Count: &bitCount}},
				{PacketID: 13, Kind: "exception", Source: "slave", Destination: "master", FunctionCode: 3, ExceptionCode: 2, Reference: "40001"},
				{PacketID: 14, Kind: "request", Source: "other-master", Destination: "slave", FunctionCode: 3, Reference: "40001"},
			},
		},
		SuspiciousWrites: []model.ModbusSuspiciousWrite{
			{Target: "40002", FunctionCode: 16, FunctionName: "Write Multiple", WriteCount: 8, Sources: []string{"master"}, SamplePacketID: 20},
		},
	}

	hits := buildIndustrialRuleHits(stats)
	if len(hits) < 6 {
		t.Fatalf("hits = %+v, want multiple rule hits", hits)
	}
	if hits[0].Level != industrialRuleLevelHigh {
		t.Fatalf("first hit level = %q, want high after severity sort; hits=%+v", hits[0].Level, hits)
	}
	wantRules := []string{"未知功能码", "数量越界", "长度不一致", "异常响应", "高频写入"}
	for _, rule := range wantRules {
		if !hasIndustrialRule(hits, rule) {
			t.Fatalf("missing rule %q in hits %+v", rule, hits)
		}
	}
}

func TestVehicleCANPayloadHelpersHandleBoundaries(t *testing.T) {
	service, detail := decodeOBDPayload("")
	if service != "OBD-II" || detail != "" {
		t.Fatalf("empty OBD payload = %q/%q, want fallback", service, detail)
	}

	service, detail = decodeOBDPayload("GG")
	if service != "Mode 00 OBD Service" || detail != "GG" {
		t.Fatalf("bad OBD payload = %q/%q, want safe unknown mode preview", service, detail)
	}

	if got := isoTPFrameType("0x30", "0x1", "0x2"); got != "FC Overflow" {
		t.Fatalf("flow control frame = %q, want FC Overflow", got)
	}
	if got := isoTPFrameType("0x99", "", ""); got != "PCI 0X99" {
		t.Fatalf("unknown ISO-TP frame = %q, want PCI 0X99", got)
	}
	if got := canopenFunctionName("0x99"); got != "Function 0X99" {
		t.Fatalf("unknown CANopen function = %q", got)
	}
	if got := canopenObjectIndex("0x2000", "0x01"); got != "Index 0X2000:01" {
		t.Fatalf("CANopen object index = %q", got)
	}
	if got := boolLabel(false, "Reply"); got != "" {
		t.Fatalf("boolLabel(false) = %q, want empty", got)
	}
}

func TestDBCDecodeBoundaries(t *testing.T) {
	if got := parseCANIdentifier("0x123"); got != 0x123 {
		t.Fatalf("parseCANIdentifier hex = %d, want 0x123", got)
	}
	if got := parseCANIdentifier("not-a-can-id"); got != 0 {
		t.Fatalf("parseCANIdentifier bad = %d, want 0", got)
	}

	msg := &DBCMessageDef{
		ID:     0x123,
		Name:   "Boundary",
		Length: 8,
		Signals: []DBCSignalDef{
			{Name: "BadLength", StartBit: 0, Length: 65, LittleEndian: true},
			{Name: "OutOfRange", StartBit: 80, Length: 8, LittleEndian: true},
			{Name: "Signed", StartBit: 0, Length: 8, LittleEndian: true, Signed: true, Factor: 1, Offset: 0},
		},
	}
	signals := decodeDBCSignals(msg, []byte{0xff})
	if len(signals) != 1 || signals[0].Name != "Signed" || signals[0].Value != "-1" {
		t.Fatalf("signals = %+v, want only signed in-range signal", signals)
	}

	if _, ok := readDBCBit([]byte{0x01}, -1); ok {
		t.Fatal("readDBCBit accepted negative bit index")
	}
	if value := formatDBCSignalValue(0, DBCSignalDef{Length: 8, Factor: 0.5, Offset: 1}); value != "1" {
		t.Fatalf("formatted DBC value = %q, want 1", value)
	}
}

func TestStreamFollowHelpersHandleEmptyInvalidAndMergedChunks(t *testing.T) {
	stream := model.ReassembledStream{}
	AppendStreamChunk(&stream, 1, "client", "")
	if len(stream.Chunks) != 0 {
		t.Fatalf("empty append created chunks: %+v", stream.Chunks)
	}
	AppendStreamChunk(&stream, 1, "client", "GET ")
	AppendStreamChunk(&stream, 2, "client", "/")
	AppendStreamChunk(&stream, 3, "server", "OK")
	if len(stream.Chunks) != 2 || stream.Chunks[0].Body != "GET /" || stream.Chunks[1].Direction != "server" {
		t.Fatalf("merged text chunks = %+v", stream.Chunks)
	}

	if got := decodeHexPayloadToText("4869, bad, 21"); got != "Hi!" {
		t.Fatalf("decodeHexPayloadToText = %q, want Hi!", got)
	}
	if got := normalizePayloadHex("4869,zz,21,0"); got != "48:69:21" {
		t.Fatalf("normalizePayloadHex = %q, want 48:69:21", got)
	}

	raw := model.ReassembledStream{}
	appendRawFollowChunk(&raw, 1, "client", "48:69")
	appendRawFollowChunk(&raw, 2, "client", "21")
	if len(raw.Chunks) != 1 || raw.Chunks[0].Body != "48:69:21" {
		t.Fatalf("raw chunks = %+v, want merged hex body", raw.Chunks)
	}
	if got := joinFollowChunkBodies("", "aa"); got != "aa" {
		t.Fatalf("join left empty = %q, want aa", got)
	}
}

func TestStreamFollowRejectsUnsupportedProtocolBeforeExternalCommand(t *testing.T) {
	stream, err := ReassembleRawStreamFromFileContext(context.Background(), "missing.pcap", "icmp", 1)
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("err = %v, want unsupported protocol", err)
	}
	if stream.Protocol != "ICMP" || len(stream.Chunks) != 0 {
		t.Fatalf("stream = %+v, want initialized empty ICMP stream", stream)
	}
}

func hasIndustrialRule(hits []model.IndustrialRuleHit, rule string) bool {
	for _, hit := range hits {
		if hit.Rule == rule {
			return true
		}
	}
	return false
}
