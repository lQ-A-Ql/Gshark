package tshark

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildModbusBitRangeReadCoilsResponseUsesRequestContext(t *testing.T) {
	ctx, ok := buildModbusBitContext(1, "17", "10")
	if !ok {
		t.Fatalf("buildModbusBitContext() did not return a request context")
	}

	bitRange := buildModbusBitRange(1, "response", "", "", "4D 01", "", "", ctx)
	if bitRange == nil {
		t.Fatalf("buildModbusBitRange() returned nil")
	}
	if bitRange.Type != "coil" {
		t.Fatalf("bitRange.Type = %q, want %q", bitRange.Type, "coil")
	}
	if bitRange.Start == nil || *bitRange.Start != 17 {
		t.Fatalf("bitRange.Start = %#v, want 17", bitRange.Start)
	}
	if bitRange.Count == nil || *bitRange.Count != 10 {
		t.Fatalf("bitRange.Count = %#v, want 10", bitRange.Count)
	}
	expected := []bool{true, false, true, true, false, false, true, false, true, false}
	if len(bitRange.Values) != len(expected) {
		t.Fatalf("len(bitRange.Values) = %d, want %d", len(bitRange.Values), len(expected))
	}
	for idx, want := range expected {
		if bitRange.Values[idx] != want {
			t.Fatalf("bitRange.Values[%d] = %v, want %v", idx, bitRange.Values[idx], want)
		}
	}
	if bitRange.Preview != "线圈 17-26 -> 1 0 1 1 0 0 1 0 1 0" {
		t.Fatalf("bitRange.Preview = %q", bitRange.Preview)
	}
}

func TestBuildModbusBitRangeWriteSingleCoil(t *testing.T) {
	bitRange := buildModbusBitRange(5, "request", "7", "", "FF 00", "", "", modbusBitContext{})
	if bitRange == nil {
		t.Fatalf("buildModbusBitRange() returned nil")
	}
	if bitRange.Preview != "线圈 7 = ON" {
		t.Fatalf("bitRange.Preview = %q, want %q", bitRange.Preview, "线圈 7 = ON")
	}
	if len(bitRange.Values) != 1 || !bitRange.Values[0] {
		t.Fatalf("bitRange.Values = %#v, want [true]", bitRange.Values)
	}
}

func TestBuildModbusBitRangeWriteMultipleCoilsRequest(t *testing.T) {
	bitRange := buildModbusBitRange(15, "request", "32", "10", "CD 01", "", "", modbusBitContext{})
	if bitRange == nil {
		t.Fatalf("buildModbusBitRange() returned nil")
	}
	if bitRange.Type != "coil" {
		t.Fatalf("bitRange.Type = %q, want %q", bitRange.Type, "coil")
	}
	if bitRange.Start == nil || *bitRange.Start != 32 {
		t.Fatalf("bitRange.Start = %#v, want 32", bitRange.Start)
	}
	if bitRange.Count == nil || *bitRange.Count != 10 {
		t.Fatalf("bitRange.Count = %#v, want 10", bitRange.Count)
	}
	expected := []bool{true, false, true, true, false, false, true, true, true, false}
	if len(bitRange.Values) != len(expected) {
		t.Fatalf("len(bitRange.Values) = %d, want %d", len(bitRange.Values), len(expected))
	}
	for idx, want := range expected {
		if bitRange.Values[idx] != want {
			t.Fatalf("bitRange.Values[%d] = %v, want %v", idx, bitRange.Values[idx], want)
		}
	}
	if bitRange.Preview != "线圈 32-41 -> 1 0 1 1 0 0 1 1 1 0" {
		t.Fatalf("bitRange.Preview = %q", bitRange.Preview)
	}
}

func TestBuildModbusBitRangeUsesExplicitBitFields(t *testing.T) {
	ctx, ok := buildModbusBitContext(1, "100", "4")
	if !ok {
		t.Fatalf("buildModbusBitContext() did not return a request context")
	}

	bitRange := buildModbusBitRange(1, "response", "", "", "", "100,101,102,103", "1,0,1,1", ctx)
	if bitRange == nil {
		t.Fatalf("buildModbusBitRange() returned nil")
	}
	if bitRange.Preview != "线圈 100-103 -> 1 0 1 1" {
		t.Fatalf("bitRange.Preview = %q", bitRange.Preview)
	}
}

func TestDecodeModbusInputTextFromObjectString(t *testing.T) {
	got := decodeModbusInputText("  station-ready\r\n", "", "", "")
	if got != "station-ready" {
		t.Fatalf("decodeModbusInputText() = %q, want station-ready", got)
	}
}

func TestDecodeModbusInputTextFromHexBytes(t *testing.T) {
	got := decodeModbusInputText("", "68:65:6c:6c:6f:20:6d:6f:64:62:75:73:00", "", "")
	if got != "hello modbus" {
		t.Fatalf("decodeModbusInputText() = %q, want hello modbus", got)
	}
}

func TestDecodeModbusInputTextFromCompactHexBytes(t *testing.T) {
	got := decodeModbusInputText("", "68656c6c6f206d6f64627573", "", "")
	if got != "hello modbus" {
		t.Fatalf("decodeModbusInputText() = %q, want hello modbus", got)
	}
}

func TestDecodeModbusInputTextFromRegisterValues(t *testing.T) {
	got := decodeModbusInputText("", "", "26725,27756,28416", "")
	if got != "hello" {
		t.Fatalf("decodeModbusInputText() = %q, want hello", got)
	}
}

func TestDecodeModbusInputTextIgnoresBinaryNoise(t *testing.T) {
	got := decodeModbusInputText("", "00:01:02:ff:00", "0,1,2", "")
	if got != "" {
		t.Fatalf("decodeModbusInputText() = %q, want empty", got)
	}
}

func TestBuildModbusDecodedInputsFromSequentialASCIIWrites(t *testing.T) {
	inputs := buildModbusDecodedInputs([]model.ModbusTransaction{
		{PacketID: 10, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, FunctionName: "写多寄存器", Kind: "request", Reference: "Ref 40001", RegisterValues: "104"},
		{PacketID: 11, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, FunctionName: "写多寄存器", Kind: "request", Reference: "Ref 40001", RegisterValues: "105"},
		{PacketID: 12, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, FunctionName: "写多寄存器", Kind: "request", Reference: "Ref 40001", RegisterValues: "33"},
		{PacketID: 13, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, FunctionName: "写多寄存器", Kind: "request", Reference: "Ref 40001", RegisterValues: "33"},
	}, nil)

	if len(inputs) != 1 {
		t.Fatalf("len(inputs) = %d, want 1", len(inputs))
	}
	if inputs[0].Text != "hi!!" {
		t.Fatalf("inputs[0].Text = %q, want hi!!", inputs[0].Text)
	}
	if inputs[0].Encoding != "ascii->utf-8" {
		t.Fatalf("inputs[0].Encoding = %q, want ascii->utf-8", inputs[0].Encoding)
	}
	if inputs[0].StartPacketID != 10 || inputs[0].EndPacketID != 13 {
		t.Fatalf("packet range = %d-%d, want 10-13", inputs[0].StartPacketID, inputs[0].EndPacketID)
	}
}

func TestBuildModbusDecodedInputsDecodesNestedHexText(t *testing.T) {
	inputs := buildModbusDecodedInputs([]model.ModbusTransaction{
		{PacketID: 20, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "54"},
		{PacketID: 21, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "54"},
		{PacketID: 22, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "54"},
		{PacketID: 23, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "99"},
		{PacketID: 24, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "54"},
		{PacketID: 25, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "49"},
		{PacketID: 26, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "54"},
		{PacketID: 27, Source: "10.0.0.1", Destination: "10.0.0.2", UnitID: 1, FunctionCode: 16, Kind: "request", Reference: "Ref 40001", RegisterValues: "55"},
	}, nil)

	if len(inputs) != 1 {
		t.Fatalf("len(inputs) = %d, want 1", len(inputs))
	}
	if inputs[0].Text != "flag" {
		t.Fatalf("inputs[0].Text = %q, want flag", inputs[0].Text)
	}
	if inputs[0].RawText != "666c6167" {
		t.Fatalf("inputs[0].RawText = %q, want 666c6167", inputs[0].RawText)
	}
	if inputs[0].Encoding != "ascii-hex->utf-8" {
		t.Fatalf("inputs[0].Encoding = %q, want ascii-hex->utf-8", inputs[0].Encoding)
	}
}

func TestBuildModbusFunctionMutationRuleHits(t *testing.T) {
	hits := buildModbusFunctionMutationRuleHits([]model.ModbusTransaction{
		{
			PacketID:     10,
			Time:         "1.000000",
			Source:       "10.0.0.10",
			Destination:  "10.0.0.20",
			FunctionCode: 3,
			FunctionName: "读保持寄存器",
			Kind:         "request",
			Reference:    "40001",
		},
		{
			PacketID:     11,
			Time:         "1.100000",
			Source:       "10.0.0.10",
			Destination:  "10.0.0.20",
			FunctionCode: 16,
			FunctionName: "写多个寄存器",
			Kind:         "request",
			Reference:    "40001",
		},
	})

	if len(hits) != 1 {
		t.Fatalf("len(hits) = %d, want 1", len(hits))
	}
	if hits[0].Rule != "功能码突变" {
		t.Fatalf("hits[0].Rule = %q, want 功能码突变", hits[0].Rule)
	}
	if hits[0].Level != "warning" {
		t.Fatalf("hits[0].Level = %q, want warning", hits[0].Level)
	}
	if hits[0].PacketID != 11 {
		t.Fatalf("hits[0].PacketID = %d, want 11", hits[0].PacketID)
	}
}

func TestBuildModbusFunctionMutationRuleHitsIgnoresStableOrDifferentTargets(t *testing.T) {
	hits := buildModbusFunctionMutationRuleHits([]model.ModbusTransaction{
		{
			PacketID:     10,
			Source:       "10.0.0.10",
			Destination:  "10.0.0.20",
			FunctionCode: 3,
			FunctionName: "读保持寄存器",
			Kind:         "request",
			Reference:    "40001",
		},
		{
			PacketID:     11,
			Source:       "10.0.0.10",
			Destination:  "10.0.0.20",
			FunctionCode: 3,
			FunctionName: "读保持寄存器",
			Kind:         "request",
			Reference:    "40002",
		},
		{
			PacketID:     12,
			Source:       "10.0.0.10",
			Destination:  "10.0.0.21",
			FunctionCode: 16,
			FunctionName: "写多个寄存器",
			Kind:         "request",
			Reference:    "40001",
		},
	})

	if len(hits) != 0 {
		t.Fatalf("len(hits) = %d, want 0", len(hits))
	}
}
