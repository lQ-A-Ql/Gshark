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
