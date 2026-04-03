package tshark

import "testing"

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
