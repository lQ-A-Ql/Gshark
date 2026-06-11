package tshark

import (
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestVehicleCANLabelTablesCoverKnownAndFallbackValues(t *testing.T) {
	for mode, want := range map[int]string{
		0x01: "Current Data",
		0x02: "Freeze Frame",
		0x03: "Stored DTC",
		0x04: "Clear DTC",
		0x05: "O2 Sensor Test",
		0x06: "On-Board Monitoring",
		0x07: "Pending DTC",
		0x08: "Control Operation",
		0x09: "Vehicle Information",
		0x0A: "Permanent DTC",
		0x7F: "OBD Service",
	} {
		if got := obdModeName(mode); got != want {
			t.Fatalf("obdModeName(0x%02X) = %q, want %q", mode, got, want)
		}
	}

	for _, tt := range []struct {
		mode int
		pid  string
		want string
	}{
		{0x09, "02", "VIN"},
		{0x09, "04", "Calibration ID"},
		{0x09, "0a", "ECU Name"},
		{0x01, "00", "Supported PIDs 00-20"},
		{0x01, "05", "Coolant Temperature"},
		{0x01, "0c", "Engine RPM"},
		{0x01, "0D", "Vehicle Speed"},
		{0x01, "0F", "Intake Air Temperature"},
		{0x01, "10", "MAF Air Flow Rate"},
		{0x01, "11", "Throttle Position"},
		{0x01, "2f", "Fuel Tank Level"},
		{0x01, "42", "Control Module Voltage"},
		{0x01, "99", ""},
	} {
		if got := obdPIDName(tt.mode, tt.pid); got != tt.want {
			t.Fatalf("obdPIDName(0x%02X,%q) = %q, want %q", tt.mode, tt.pid, got, tt.want)
		}
	}

	for raw, want := range map[string]string{
		"0x0":  "NMT",
		"0x1":  "SYNC/EMCY",
		"0x2":  "TIME",
		"0x3":  "PDO1 Tx",
		"0x4":  "PDO1 Rx",
		"0x5":  "PDO2 Tx",
		"0x6":  "PDO2 Rx",
		"0x7":  "PDO3 Tx",
		"0x8":  "PDO3 Rx",
		"0x9":  "PDO4 Tx",
		"0xA":  "PDO4 Rx",
		"0xB":  "SDO Tx",
		"0xC":  "SDO Rx",
		"0xE":  "NMT Error Control",
		"":     "NMT",
		"0x99": "Function 0X99",
	} {
		if got := canopenFunctionName(raw); got != want {
			t.Fatalf("canopenFunctionName(%q) = %q, want %q", raw, got, want)
		}
	}

	if got := canopenObjectIndex("", ""); got != "" {
		t.Fatalf("canopenObjectIndex empty = %q", got)
	}
	if got := canopenObjectIndex("0x2000", ""); got != "Index 0X2000" {
		t.Fatalf("canopenObjectIndex main = %q", got)
	}
	if got := canopenObjectIndex("0x2000", "0x01"); got != "Index 0X2000:01" {
		t.Fatalf("canopenObjectIndex sub = %q", got)
	}
	if got := boolLabel(true, "Reply"); got != "Reply" {
		t.Fatalf("boolLabel true = %q", got)
	}
	if got := boolLabel(false, "Reply"); got != "" {
		t.Fatalf("boolLabel false = %q", got)
	}
}

func TestUSBKeyboardLabelAndTextTables(t *testing.T) {
	for _, tt := range []struct {
		key   string
		shift bool
		want  string
	}{
		{"A", false, "a"},
		{"A", true, "A"},
		{"1", false, "1"},
		{"1", true, "!"},
		{"0", true, ")"},
		{"Space", false, " "},
		{"Tab", false, "\t"},
		{"Enter", false, "\n"},
		{"-", true, "_"},
		{"=", true, "+"},
		{"[", true, "{"},
		{"]", true, "}"},
		{"\\", true, "|"},
		{";", true, ":"},
		{"'", true, "\""},
		{",", true, "<"},
		{".", true, ">"},
		{"/", true, "?"},
		{"`", true, "~"},
		{"Esc", false, ""},
	} {
		if got := keyboardTextToken(tt.key, tt.shift); got != tt.want {
			t.Fatalf("keyboardTextToken(%q,%v) = %q, want %q", tt.key, tt.shift, got, tt.want)
		}
	}

	for code, want := range map[int]string{
		0:  "",
		4:  "A",
		29: "Z",
		30: "1",
		38: "9",
		39: "0",
		40: "Enter",
		41: "Esc",
		42: "Backspace",
		43: "Tab",
		44: "Space",
		45: "-",
		46: "=",
		47: "[",
		48: "]",
		49: "\\",
		51: ";",
		52: "'",
		53: "`",
		54: ",",
		55: ".",
		56: "/",
		57: "CapsLock",
		58: "F1",
		69: "F12",
		79: "Right",
		80: "Left",
		81: "Down",
		82: "Up",
	} {
		if got := keyboardKeyLabel(code); got != want {
			t.Fatalf("keyboardKeyLabel(%d) = %q, want %q", code, got, want)
		}
	}
	if got := keyboardKeyLabel(250); got != "Keycode(250)" {
		t.Fatalf("keyboardKeyLabel fallback = %q", got)
	}
}

func TestUSBSetupAndMassStorageOperationTables(t *testing.T) {
	for raw, want := range map[string]string{
		"0":    "GET_STATUS",
		"0x01": "CLEAR_FEATURE",
		"0x03": "SET_FEATURE",
		"0x05": "SET_ADDRESS",
		"0x06": "GET_DESCRIPTOR",
		"0x07": "SET_DESCRIPTOR",
		"0x08": "GET_CONFIGURATION",
		"0x09": "SET_CONFIGURATION",
		"10":   "GET_INTERFACE",
		"11":   "SET_INTERFACE",
		"12":   "SYNCH_FRAME",
		"":     "",
		"0xff": "0XFF",
	} {
		if got := normalizeUSBSetupRequest(raw); got != want {
			t.Fatalf("normalizeUSBSetupRequest(%q) = %q, want %q", raw, got, want)
		}
	}

	for opcode, want := range map[int]string{
		0x08: "READ(6)",
		0x0A: "WRITE(6)",
		0x12: "INQUIRY",
		0x1A: "MODE SENSE(6)",
		0x1B: "START STOP UNIT",
		0x23: "READ FORMAT CAPACITIES",
		0x25: "READ CAPACITY(10)",
		0x28: "READ(10)",
		0x2A: "WRITE(10)",
		0x35: "SYNCHRONIZE CACHE(10)",
		0x5A: "MODE SENSE(10)",
		0x88: "READ(16)",
		0x8A: "WRITE(16)",
		-1:   "",
		0xFE: "OPCODE(0xFE)",
	} {
		if got := usbMassStorageCommandLabel(opcode); got != want {
			t.Fatalf("usbMassStorageCommandLabel(0x%X) = %q, want %q", opcode, got, want)
		}
	}

	for _, tt := range []struct {
		info usbMassStoragePacketInfo
		want string
	}{
		{usbMassStoragePacketInfo{}, ""},
		{usbMassStoragePacketInfo{Device: "Disk"}, ""},
		{usbMassStoragePacketInfo{Endpoint: "EP 1", Tag: "0x00000001"}, "EP 1|tag|0x00000001"},
		{usbMassStoragePacketInfo{Device: "Disk", RequestFrame: 7}, "Disk|req|7"},
		{usbMassStoragePacketInfo{Device: "Disk", ResponseFrame: 8}, "Disk|resp|8"},
	} {
		if got := buildUSBMassStorageOperationKey(tt.info); got != tt.want {
			t.Fatalf("buildUSBMassStorageOperationKey(%+v) = %q, want %q", tt.info, got, tt.want)
		}
	}
}

func TestUSBMassStorageMergeAppendAndFlushBranches(t *testing.T) {
	op := &model.USBMassStorageOperation{Status: "unknown"}
	mergeUSBMassStorageOperation(op, usbMassStoragePacketInfo{
		Device: "Disk", Endpoint: "EP 1", LUN: "LUN 0", Command: "READ(10)",
		Direction: "IN", Status: "ok", TransferLength: 512, RequestFrame: 1,
		ResponseFrame: 2, LatencyMs: 3.5, DataResidue: 4, Summary: "merged",
	})
	if op.Device != "Disk" || op.Status != "ok" || op.ResponseFrame != 2 || op.Summary != "merged" {
		t.Fatalf("mergeUSBMassStorageOperation() = %+v", op)
	}

	var analysis model.USBMassStorageAnalysis
	appendUSBMassStorageOperation(&analysis, model.USBMassStorageOperation{Operation: "read", RequestFrame: 10})
	appendUSBMassStorageOperation(&analysis, model.USBMassStorageOperation{Operation: "write", ResponseFrame: 11})
	appendUSBMassStorageOperation(&analysis, model.USBMassStorageOperation{Operation: "other", PacketID: 12})
	if len(analysis.ReadOperations) != 1 || analysis.ReadOperations[0].PacketID != 10 {
		t.Fatalf("read operations = %+v", analysis.ReadOperations)
	}
	if len(analysis.WriteOperations) != 1 || analysis.WriteOperations[0].PacketID != 11 {
		t.Fatalf("write operations = %+v", analysis.WriteOperations)
	}

	pending := map[string]*model.USBMassStorageOperation{
		"b": {Operation: "write", PacketID: 2, Summary: "b"},
		"a": {Operation: "read", PacketID: 1, Summary: "a"},
	}
	flushUSBMassStorageOperations(pending, &analysis)
	if len(analysis.ReadOperations) != 2 || len(analysis.WriteOperations) != 2 {
		t.Fatalf("flush operations read=%+v write=%+v", analysis.ReadOperations, analysis.WriteOperations)
	}

	info := usbMassStoragePacketInfo{
		PacketID: 1, Device: "Disk", Tag: "0x1", Operation: "read", Command: "READ(10)",
		TransferLength: 512, Direction: "IN", RequestFrame: 1,
	}
	pending = map[string]*model.USBMassStorageOperation{}
	analysis = model.USBMassStorageAnalysis{}
	consumeUSBMassStorageOperation(info, pending, &analysis)
	if len(pending) != 1 || len(analysis.ReadOperations) != 0 {
		t.Fatalf("pending after request = pending=%+v analysis=%+v", pending, analysis)
	}
	info.IsCompletion = true
	info.ResponseFrame = 2
	info.Status = "ok"
	consumeUSBMassStorageOperation(info, pending, &analysis)
	if len(pending) != 0 || len(analysis.ReadOperations) != 1 {
		t.Fatalf("completion after consume = pending=%+v analysis=%+v", pending, analysis)
	}

	info = usbMassStoragePacketInfo{PacketID: 3, Device: "", Endpoint: "", Operation: "write", Command: "WRITE(10)"}
	consumeUSBMassStorageOperation(info, pending, &analysis)
	if len(analysis.WriteOperations) != 1 || analysis.WriteOperations[0].PacketID != 3 {
		t.Fatalf("keyless operation append = %+v", analysis.WriteOperations)
	}

	if summary := buildUSBMassStorageSummary("", "other", "", 0, ""); summary != "Mass Storage operation" {
		t.Fatalf("empty-ish summary = %q, want Mass Storage operation", summary)
	}
	if got := fmt.Sprint(analysis.ReadOperations[0].PacketID); got != "1" {
		t.Fatalf("read operation packet id string = %q", got)
	}
}
