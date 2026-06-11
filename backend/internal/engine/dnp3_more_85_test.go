package engine

import (
	"reflect"
	"strings"
	"testing"
)

func TestDNP3FunctionAndQualifierTablesCoverKnownBranches(t *testing.T) {
	functions := map[int]string{
		dnp3FCConfirm:          "Confirm",
		dnp3FCRead:             "Read",
		dnp3FCWrite:            "Write",
		dnp3FCSelect:           "Select",
		dnp3FCOperate:          "Operate",
		dnp3FCDirectOperate:    "Direct Operate",
		dnp3FCDirectOperateNAK: "Direct Operate No ACK",
		dnp3FCFreeze:           "Freeze",
		dnp3FCFreezeNAK:        "Freeze No ACK",
		dnp3FCFreezeClear:      "Freeze Clear",
		dnp3FCFreezeClearNAK:   "Freeze Clear No ACK",
		dnp3FCColdRestart:      "Cold Restart",
		dnp3FCWarmRestart:      "Warm Restart",
		dnp3FCInitData:         "Initialize Data",
		dnp3FCInitApp:          "Initialize Application",
		dnp3FCStartApp:         "Start Application",
		dnp3FCStopApp:          "Stop Application",
		dnp3FCSaveConfig:       "Save Configuration",
		dnp3FCEnableUnsol:      "Enable Unsolicited",
		dnp3FCDisableUnsol:     "Disable Unsolicited",
		dnp3FCAssignClass:      "Assign Class",
		dnp3FCDelayMeasure:     "Delay Measurement",
		dnp3FCRecordTime:       "Record Current Time",
		dnp3FCOpenFile:         "Open File",
		dnp3FCCloseFile:        "Close File",
		dnp3FCDeleteFile:       "Delete File",
		dnp3FCGetFileInfo:      "Get File Info",
		dnp3FCAuthFile:         "Authenticate File",
		dnp3FCAbortFile:        "Abort File",
		dnp3FCResponse:         "Response",
		dnp3FCUnsolicitedResp:  "Unsolicited Response",
	}
	for code, want := range functions {
		if got := dnp3FunctionCodeName(code); got != want {
			t.Fatalf("dnp3FunctionCodeName(0x%02X) = %q, want %q", code, got, want)
		}
	}
	if got := dnp3FunctionCodeName(0x90); got != "Response 0x90" {
		t.Fatalf("response fallback = %q", got)
	}
	if got := dnp3FunctionCodeName(0x55); got != "Function 0x55" {
		t.Fatalf("request fallback = %q", got)
	}

	qualifiers := map[byte]string{
		0x00: "1-byte start/stop",
		0x01: "1-byte start/count",
		0x06: "no range, count",
		0x07: "1-byte count",
		0x08: "2-byte count",
		0x17: "2-byte start/count",
		0x28: "2-byte start/stop",
		0x3B: "free-format",
	}
	for qp, want := range qualifiers {
		if got := dnp3QualifierName(qp); got != want {
			t.Fatalf("dnp3QualifierName(0x%02X) = %q, want %q", qp, got, want)
		}
	}
	if got := dnp3QualifierName(0x44); got != "qualifier 0x44" {
		t.Fatalf("unknown qualifier = %q", got)
	}
}

func TestDNP3IINValueSizeAndFormattingBranches(t *testing.T) {
	allFlags := formatDNP3IIN([2]byte{0xFF, 0x3F})
	for _, want := range []string{
		"All_Stations",
		"Class1_Data",
		"Class2_Data",
		"Class3_Data",
		"Need_Time",
		"Local_Control",
		"Device_Trouble",
		"Device_Restart",
		"Function_Not_Supported",
		"Object_Not_Supported",
		"Parameter_Error",
		"Event_Buffer_Overflow",
		"Already_Executing",
		"Config_Corrupt",
	} {
		if !strings.Contains(allFlags, want) {
			t.Fatalf("formatDNP3IIN all flags missing %q in %q", want, allFlags)
		}
	}

	sizeCases := []struct {
		group, variation int
		want             int
	}{
		{1, 2, 8},
		{20, 1, 5},
		{20, 2, 3},
		{20, 6, 3},
		{30, 1, 5},
		{30, 2, 3},
		{30, 3, 5},
		{30, 4, 3},
		{40, 1, 5},
		{40, 2, 3},
		{40, 3, 5},
		{50, 1, 6},
		{999, 1, 1},
	}
	for _, tt := range sizeCases {
		if got := dnp3ValueSize(tt.group, tt.variation); got != tt.want {
			t.Fatalf("dnp3ValueSize(%d,%d) = %d, want %d", tt.group, tt.variation, got, tt.want)
		}
	}

	valueCases := []struct {
		value            []byte
		group, variation int
		want             string
	}{
		{[]byte{0x80}, 1, 1, "ON"},
		{[]byte{0x00}, 3, 1, "OFF"},
		{[]byte{0x01, 0x34, 0x12}, 20, 2, "4660"},
		{[]byte{0x01, 0x78, 0x56, 0x34, 0x12}, 21, 1, "305419896"},
		{[]byte{0x01, 0xFE, 0xFF}, 30, 2, "-2"},
		{[]byte{0x01, 0x78, 0x56, 0x34, 0x12}, 40, 1, "305419896"},
		{[]byte{0xAA, 0xBB}, 99, 1, "0xaabb"},
	}
	for _, tt := range valueCases {
		if got := formatDNP3Value(tt.value, tt.group, tt.variation); got != tt.want {
			t.Fatalf("formatDNP3Value(%v,%d,%d) = %q, want %q", tt.value, tt.group, tt.variation, got, tt.want)
		}
	}
}

func TestParseDNP3ObjectsQualifierBranchesAndSummarySorting(t *testing.T) {
	objects := parseDNP3Objects([]byte{
		20, 2, 0x17,
		0x02, 0x00,
		0x03, 0x00,
		0x01, 0x10, 0x00,
		0x01, 0x20, 0x00,
		0x01, 0x30, 0x00,
	})
	if len(objects) != 3 || objects[0].PointIndex != 2 || objects[2].Value != "48" {
		t.Fatalf("2-byte start/count objects = %+v", objects)
	}

	rangeObjects := parseDNP3Objects([]byte{
		1, 1, 0x28,
		0x05, 0x00,
		0x02, 0x00,
		0x80, 0x00,
	})
	if len(rangeObjects) != 2 || rangeObjects[0].PointIndex != 5 || rangeObjects[1].Value != "OFF" {
		t.Fatalf("2-byte range objects = %+v", rangeObjects)
	}

	for _, raw := range [][]byte{
		{1, 1, 0x70},
		{1, 1, 0x17, 0x01},
		{1, 1, 0x01, 0x00},
	} {
		if got := parseDNP3Objects(raw); len(got) != 0 {
			t.Fatalf("truncated/unknown object parse = %+v, want empty", got)
		}
	}

	if got := buildDNP3Summary("request", "Read", nil, 2, 1); got != "request Read / addr 1->2" {
		t.Fatalf("summary without objects = %q", got)
	}
	buckets := topBucketsDNP3(map[string]int{"b": 2, "a": 2, "c": 3})
	want := []string{"c", "a", "b"}
	got := []string{buckets[0].Label, buckets[1].Label, buckets[2].Label}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topBucketsDNP3 order = %+v, want %+v", got, want)
	}
}
