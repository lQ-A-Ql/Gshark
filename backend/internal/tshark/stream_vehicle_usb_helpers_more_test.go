package tshark

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestStreamClientServerSelectionUsesEphemeralPortHeuristics(t *testing.T) {
	if !IsLikelyClientPort(51515, 443) {
		t.Fatal("ephemeral source port should be treated as likely client")
	}
	if !IsLikelyClientPort(2048, 80) {
		t.Fatal("high source port talking to well-known peer should be likely client")
	}
	if !IsLikelyClientPort(51515, 0) {
		t.Fatal("ephemeral candidate should be likely client when peer port is unknown")
	}
	if IsLikelyClientPort(0, 80) {
		t.Fatal("zero candidate port should not be likely client")
	}
	if IsLikelyClientPort(443, 51515) {
		t.Fatal("well-known service port should not be likely client against ephemeral peer")
	}

	client, server := SelectClientServerHosts("10.0.0.10", 51515, "10.0.0.20", 443)
	if client != "10.0.0.10" || server != "10.0.0.20" {
		t.Fatalf("src ephemeral selection = %s/%s", client, server)
	}
	client, server = SelectClientServerHosts("10.0.0.20", 443, "10.0.0.10", 51515)
	if client != "10.0.0.10" || server != "10.0.0.20" {
		t.Fatalf("dst ephemeral selection = %s/%s", client, server)
	}
	client, server = SelectClientServerHosts("10.0.0.30", 1234, "10.0.0.40", 2345)
	if client != "10.0.0.30" || server != "10.0.0.40" {
		t.Fatalf("fallback selection = %s/%s", client, server)
	}
}

func TestCANPayloadLengthAndCANopenServiceBoundaries(t *testing.T) {
	parts := makeCANPayloadParts()
	parts[15] = "4096"
	parts[16] = "128"
	parts[13] = "8"
	parts[14] = "4"
	parts[7] = "2"
	if got := resolveISOTPLength(parts); got != 4096 {
		t.Fatalf("resolveISOTPLength priority = %d, want 4096", got)
	}
	parts[15] = ""
	if got := resolveISOTPLength(parts); got != 128 {
		t.Fatalf("resolveISOTPLength fallback = %d, want 128", got)
	}
	if got := resolveISOTPLength(makeCANPayloadParts()); got != 0 {
		t.Fatalf("resolveISOTPLength empty = %d", got)
	}

	frameTests := map[string]string{
		"0x0":  "Single Frame",
		"0x10": "First Frame",
		"0x20": "Consecutive Frame 0X2",
		"0x99": "PCI 0X99",
		"":     "",
	}
	for raw, want := range frameTests {
		got := isoTPFrameType(raw, "0x2", "")
		if got != want {
			t.Fatalf("isoTPFrameType(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := flowControlLabel("0x0", "8", "10"); got != "FC Continue To Send / BS 8 / STmin 10" {
		t.Fatalf("flowControlLabel CTS = %q", got)
	}
	if got := flowControlLabel("0x1", "", ""); got != "FC Wait" {
		t.Fatalf("flowControlLabel wait = %q", got)
	}
	if got := flowControlLabel("0x2", "", ""); got != "FC Overflow" {
		t.Fatalf("flowControlLabel overflow = %q", got)
	}

	canopen := makeCANPayloadParts()
	canopen[30] = "0xB"
	if got := canopenServiceLabel(canopen); got != "SDO Tx" {
		t.Fatalf("CANopen base service = %q", got)
	}
	canopen[33] = "0x2000"
	if got := canopenServiceLabel(canopen); got != "SDO Tx / SDO" {
		t.Fatalf("CANopen SDO service = %q", got)
	}
	canopen[33] = ""
	canopen[36] = "0x1000"
	if got := canopenServiceLabel(canopen); got != "SDO Tx / Emergency" {
		t.Fatalf("CANopen emergency service = %q", got)
	}
	canopen[36] = ""
	canopen[32] = "01:02"
	if got := canopenServiceLabel(canopen); got != "SDO Tx / PDO" {
		t.Fatalf("CANopen PDO service = %q", got)
	}
}

func TestOBDAndCANopenLabelMapsCoverKnownFallbacks(t *testing.T) {
	service, detail := decodeOBDPayload("41 0C 1A F8")
	if service != "Mode 01 Current Data Response" || !strings.Contains(detail, "Engine RPM") || !strings.Contains(detail, "Data 1A F8") {
		t.Fatalf("decodeOBDPayload response = %q / %q", service, detail)
	}
	if got := obdModeName(0x09); got != "Vehicle Information" {
		t.Fatalf("obdModeName = %q", got)
	}
	if got := obdPIDName(0x09, "02"); got != "VIN" {
		t.Fatalf("obdPIDName VIN = %q", got)
	}
	if got := parseHexByte("0x0C"); got != 12 {
		t.Fatalf("parseHexByte = %d", got)
	}
	if got := parseHexByte("12"); got != 18 {
		t.Fatalf("parseHexByte bare hex = %d, want 18", got)
	}
	if got := parseHexByte("not-number"); got != 0 {
		t.Fatalf("parseHexByte bad = %d", got)
	}

	functions := map[string]string{
		"0x0": "NMT",
		"0x1": "SYNC/EMCY",
		"0x3": "PDO1 Tx",
		"0xC": "SDO Rx",
		"0xE": "NMT Error Control",
	}
	for raw, want := range functions {
		if got := canopenFunctionName(raw); got != want {
			t.Fatalf("canopenFunctionName(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestUSBHIDSourceAndPayloadBoundaryHelpers(t *testing.T) {
	candidates := orderedUSBHIDSourceCandidates(map[string]struct{}{
		"usb.frame.data":       {},
		"usbhid.data":          {},
		"ignored":              {},
		"usb.control.Response": {},
	})
	if !reflect.DeepEqual(candidates, []string{"usbhid.data", "usb.control.Response", "usb.frame.data"}) {
		t.Fatalf("orderedUSBHIDSourceCandidates = %+v", candidates)
	}

	selected := topUSBHIDSelectedSource(map[string]int{
		"usb.capdata": 2,
		"usbhid.data": 2,
		"btatt.value": 5,
	})
	if selected != "btatt.value" {
		t.Fatalf("topUSBHIDSelectedSource = %q", selected)
	}

	notes := buildUSBHIDSourceNotes(model.USBHIDSourceRaw, candidates, selected)
	if len(notes) != 4 {
		t.Fatalf("expected mode, selected, candidates and manual-mode notes, got %+v", notes)
	}

	record := model.USBPacketRecord{TransferType: "Interrupt"}
	if !candidatesMayCarryHID(record, []usbHIDPayloadCandidate{{Mode: model.USBHIDSourceRaw, Raw: "00:01"}}) {
		t.Fatal("interrupt payload candidate should be accepted as possible HID")
	}
	if candidatesMayCarryHID(model.USBPacketRecord{TransferType: "Bulk"}, []usbHIDPayloadCandidate{{Mode: model.USBHIDSourceRaw, Raw: "00:01"}}) {
		t.Fatal("bulk payload candidate should not be accepted without HID hints")
	}
	if !candidatesMayCarryHID(model.USBPacketRecord{}, []usbHIDPayloadCandidate{{Mode: model.USBHIDSourceBTATT, Raw: "00:01"}}) {
		t.Fatal("BTATT mode should be accepted as possible HID")
	}
	if candidatesMayCarryHID(record, []usbHIDPayloadCandidate{{Mode: model.USBHIDSourceRaw, Raw: ""}}) {
		t.Fatal("empty payload candidate should not be accepted")
	}
	if !candidatesAreEmpty([]usbHIDPayloadCandidate{{Raw: ""}, {Raw: " "}}) {
		t.Fatal("blank candidates should be considered empty")
	}
	if candidatesAreEmpty([]usbHIDPayloadCandidate{{Raw: "00"}}) {
		t.Fatal("non-empty candidate should not be considered empty")
	}
}

func TestUSBKeyboardAndMouseBoundaryHelpers(t *testing.T) {
	if !isLikelyKeyboardBootReport([]byte{0x02, 0x00, 0x04, 0x05, 0, 0, 0, 0}) {
		t.Fatal("valid keyboard boot report was not recognized")
	}
	if isLikelyKeyboardBootReport([]byte{0x00, 0x01, 0x04, 0, 0, 0, 0, 0}) {
		t.Fatal("keyboard report with non-zero reserved byte should be rejected")
	}
	buttons, x, y, wheel, horizontal := parseMouseBootPayload([]byte{0x03, 0x7f, 0xff, 0x01, 0xfe})
	if !reflect.DeepEqual(buttons, []string{"Left", "Right"}) || x != 127 || y != -1 || wheel != 1 || horizontal != -2 {
		t.Fatalf("parseMouseBootPayload = buttons=%+v x=%d y=%d wheel=%d horizontal=%d", buttons, x, y, wheel, horizontal)
	}
	if !looksLikeMouseBootPayload([]byte{0x00, 0x01, 0x00}) {
		t.Fatal("mouse movement boot payload should be recognized")
	}
	if looksLikeMouseBootPayload([]byte{0xf8, 0x01, 0x00}) {
		t.Fatal("reserved mouse button bits should be rejected")
	}
	if !looksLikeMouseReportIDPayload([]byte{0x01, 0x00, 0x01, 0x00}) {
		t.Fatal("mouse report-id payload should be recognized")
	}

	parsed := parseUSBMousePayloadLayouts([]byte{0x01, 0x00, 0x01, 0x00}, false)
	if len(parsed) == 0 || parsed[0].layout == "" {
		t.Fatalf("expected parsed mouse report-id payload, got %+v", parsed)
	}
	if score := scoreUSBMousePayloadCandidate(usbMouseParsedPayload{buttons: []string{"Left"}, xDelta: 1}, usbHIDHint{Mouse: true}); score != 12 {
		t.Fatalf("mouse score = %d, want 12", score)
	}
	if got := keyboardModifiersFromMask(0x22); !reflect.DeepEqual(got, []string{"Left Shift", "Right Shift"}) {
		t.Fatalf("keyboardModifiersFromMask = %+v", got)
	}
	if !looksLikeBluetoothHIDRecord(model.USBPacketRecord{Protocol: "btatt", Summary: "value"}, "00") {
		t.Fatal("BTATT protocol record should be recognized as Bluetooth HID")
	}
}

func TestUSBNormalizationAndMassStorageHelpers(t *testing.T) {
	if got := normalizeUSBProtocolLabel("usb.capdata"); got != "USB.CAPDATA" {
		t.Fatalf("normalizeUSBProtocolLabel = %q", got)
	}
	if got := normalizeUSBTransferType("0x03"); got != "Bulk" {
		t.Fatalf("normalizeUSBTransferType = %q", got)
	}
	if got := normalizeUSBTransferType("vendor"); got != "VENDOR" {
		t.Fatalf("normalizeUSBTransferType vendor = %q", got)
	}
	if got := normalizeUSBUrbType("c"); got != "Complete" {
		t.Fatalf("normalizeUSBUrbType = %q", got)
	}
	if got := normalizeUSBStatus("0"); got != "ok" {
		t.Fatalf("normalizeUSBStatus = %q", got)
	}
	if got := normalizeUSBStatus(""); got != "unknown" {
		t.Fatalf("normalizeUSBStatus empty = %q", got)
	}
	if got := normalizeUSBDirection("", "0x81"); got != "IN" {
		t.Fatalf("normalizeUSBDirection endpoint IN = %q", got)
	}
	if got := normalizeUSBDirection("out", "0x81"); got != "OUT" {
		t.Fatalf("normalizeUSBDirection explicit OUT = %q", got)
	}
	if got := normalizeUSBSetupRequest("0x06"); got != "GET_DESCRIPTOR" {
		t.Fatalf("normalizeUSBSetupRequest = %q", got)
	}
	if got := buildUSBEndpointLabel("1", "2", "0x81", "IN"); got != "Bus 1 / Device 2 / EP 0x81 (IN)" {
		t.Fatalf("buildUSBEndpointLabel = %q", got)
	}
	if got := buildUSBSetupSummary("GET_DESCRIPTOR", "0x0100", "0", "64"); got != "GET_DESCRIPTOR wValue=0x0100 wIndex=0 wLength=64" {
		t.Fatalf("buildUSBSetupSummary = %q", got)
	}
	if got := previewUSBPayload("48:65:6c:6c:6f"); got != "Hello" {
		t.Fatalf("previewUSBPayload = %q", got)
	}
	if got := decodeLooseHexToText("00:ff:00"); got != "" {
		t.Fatalf("decodeLooseHexToText binary = %q, want empty", got)
	}

	if got := normalizeUSBMassStorageTag("255"); got != "0x000000FF" {
		t.Fatalf("normalizeUSBMassStorageTag decimal = %q", got)
	}
	if got := normalizeUSBMassStorageTag("0x10"); got != "0x00000010" {
		t.Fatalf("normalizeUSBMassStorageTag hex = %q", got)
	}
	if got := normalizeUSBMassStorageLUN("0x02"); got != "LUN 2" {
		t.Fatalf("normalizeUSBMassStorageLUN = %q", got)
	}
	if got := usbMassStorageDirectionFromFlags(0x80); got != "IN" {
		t.Fatalf("usbMassStorageDirectionFromFlags = %q", got)
	}
	if got := parseUSBMassStorageOpcode("2A"); got != 0x2A {
		t.Fatalf("parseUSBMassStorageOpcode = %d", got)
	}
	if got := usbMassStorageCommandLabel(0x2A); got != "WRITE(10)" {
		t.Fatalf("usbMassStorageCommandLabel = %q", got)
	}
	if got := usbMassStorageOperationFromOpcode(0x28); got != "read" {
		t.Fatalf("usbMassStorageOperationFromOpcode = %q", got)
	}
	if got := normalizeUSBMassStorageStatus("", "1", 1); got != "failed" {
		t.Fatalf("normalizeUSBMassStorageStatus = %q", got)
	}
	summary := buildUSBMassStorageSummary("WRITE(10)", "write", "LUN 0", 4096, "failed")
	for _, part := range []string{"WRITE(10)", "op=write", "LUN 0", "len=4096", "status=failed"} {
		if !strings.Contains(summary, part) {
			t.Fatalf("summary %q missing %q", summary, part)
		}
	}
}

func TestUSBNotesAndScalarHelpers(t *testing.T) {
	massEmpty := buildUSBMassStorageNotes(model.USBMassStorageAnalysis{}, 0, 0)
	if len(massEmpty) != 1 || !strings.Contains(massEmpty[0], "Mass Storage") {
		t.Fatalf("empty mass-storage notes = %+v", massEmpty)
	}
	massNotes := buildUSBMassStorageNotes(model.USBMassStorageAnalysis{
		TotalPackets: 2,
		ReadPackets:  1,
		WritePackets: 1,
		Devices:      []model.TrafficBucket{{Label: "Disk A", Count: 2}},
	}, 1, 1)
	if len(massNotes) != 5 {
		t.Fatalf("mass-storage notes = %+v, want all populated branches", massNotes)
	}

	otherEmpty := buildUSBOtherNotes(model.USBOtherAnalysis{})
	if len(otherEmpty) != 1 {
		t.Fatalf("empty other notes = %+v", otherEmpty)
	}
	otherNotes := buildUSBOtherNotes(model.USBOtherAnalysis{
		TotalPackets:   3,
		ControlPackets: 1,
		Devices:        []model.TrafficBucket{{Label: "Device A", Count: 2}},
	})
	if len(otherNotes) != 2 {
		t.Fatalf("other notes = %+v, want control and device notes", otherNotes)
	}
	otherFallback := buildUSBOtherNotes(model.USBOtherAnalysis{TotalPackets: 1})
	if len(otherFallback) != 1 {
		t.Fatalf("other fallback notes = %+v", otherFallback)
	}

	analysisNotes := buildUSBAnalysisNotes(model.USBAnalysis{
		TotalUSBPackets:    5,
		HIDPackets:         1,
		MassStoragePackets: 1,
		OtherUSBPackets:    1,
		Devices:            []model.TrafficBucket{{Label: "Bus 1 / Device 2", Count: 3}},
		TransferTypes:      []model.TrafficBucket{{Label: "Bulk", Count: 2}},
		Records:            []model.USBPacketRecord{{PacketID: 1}, {PacketID: 2}},
	}, map[string]int{"ok": 2, "unknown": 1})
	if len(analysisNotes) != 8 {
		t.Fatalf("analysis notes = %+v, want all populated branches", analysisNotes)
	}
	emptyAnalysisNotes := buildUSBAnalysisNotes(model.USBAnalysis{}, nil)
	if len(emptyAnalysisNotes) != 1 {
		t.Fatalf("empty analysis notes = %+v", emptyAnalysisNotes)
	}

	if got := parseFlexibleUSBInt("0x10"); got != 16 {
		t.Fatalf("parseFlexibleUSBInt hex = %d", got)
	}
	if got := parseFlexibleUSBInt("10"); got != 10 {
		t.Fatalf("parseFlexibleUSBInt decimal = %d", got)
	}
	if got := parseFlexibleUSBInt("2a"); got != 42 {
		t.Fatalf("parseFlexibleUSBInt bare hex = %d", got)
	}
	if got := parseFlexibleUSBInt("zz"); got != 0 {
		t.Fatalf("parseFlexibleUSBInt bad = %d", got)
	}
	if got := parseUSBFloat("1.25"); got != 1.25 {
		t.Fatalf("parseUSBFloat = %f", got)
	}
	if got := parseUSBFloat("bad"); got != 0 {
		t.Fatalf("parseUSBFloat bad = %f", got)
	}
	if got := maxInt(4, 7); got != 7 {
		t.Fatalf("maxInt = %d", got)
	}
}

func makeCANPayloadParts() []string {
	return make([]string, len(canPayloadAnalysisFields))
}
