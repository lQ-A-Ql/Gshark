package tshark

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildUSBKeyboardEventStateDiff(t *testing.T) {
	record := model.USBPacketRecord{PacketID: 1, Time: "1.000000", BusID: "1", DeviceAddress: "2", Endpoint: "EP 0x81 (IN)"}
	first, ok := buildUSBKeyboardEvent(record, usbKeyboardState{}, usbKeyboardSnapshot{
		DeviceKey: "EP 0x81 (IN)",
		Modifiers: []string{},
		Keys:      []string{"A"},
	})
	if !ok {
		t.Fatalf("expected first key press to produce an event")
	}
	if got := first.PressedKeys; len(got) != 1 || got[0] != "A" {
		t.Fatalf("unexpected pressed keys: %#v", got)
	}
	if first.Text != "a" {
		t.Fatalf("expected lowercase printable text, got %q", first.Text)
	}

	if _, ok := buildUSBKeyboardEvent(record, usbKeyboardState{Keys: []string{"A"}}, usbKeyboardSnapshot{
		DeviceKey: "EP 0x81 (IN)",
		Modifiers: []string{},
		Keys:      []string{"A"},
	}); ok {
		t.Fatalf("expected identical key snapshot to be deduplicated")
	}

	release, ok := buildUSBKeyboardEvent(record, usbKeyboardState{Keys: []string{"A"}}, usbKeyboardSnapshot{
		DeviceKey: "EP 0x81 (IN)",
		Modifiers: []string{},
		Keys:      []string{},
	})
	if !ok {
		t.Fatalf("expected release snapshot to produce an event")
	}
	if got := release.ReleasedKeys; len(got) != 1 || got[0] != "A" {
		t.Fatalf("unexpected released keys: %#v", got)
	}
}

func TestBuildUSBKeyboardEventCtrlComboSuppressesPrintableText(t *testing.T) {
	record := model.USBPacketRecord{PacketID: 2, Time: "2.000000", BusID: "1", DeviceAddress: "2", Endpoint: "EP 0x81 (IN)"}
	event, ok := buildUSBKeyboardEvent(record, usbKeyboardState{}, usbKeyboardSnapshot{
		DeviceKey: "EP 0x81 (IN)",
		Modifiers: []string{"Left Ctrl"},
		Keys:      []string{"C"},
	})
	if !ok {
		t.Fatalf("expected ctrl+c to produce an event")
	}
	if event.Text != "" {
		t.Fatalf("expected ctrl+c not to emit printable text, got %q", event.Text)
	}
	if got := event.PressedModifiers; len(got) != 1 || got[0] != "Left Ctrl" {
		t.Fatalf("unexpected pressed modifiers: %#v", got)
	}
}

func TestBuildUSBMouseEventReleaseWithoutMovement(t *testing.T) {
	record := model.USBPacketRecord{PacketID: 3, Time: "3.000000", BusID: "1", DeviceAddress: "3", Endpoint: "EP 0x82 (IN)"}
	event, _, ok := buildUSBMouseEvent(record, usbMouseState{
		Buttons: []string{"Left"},
		X:       10,
		Y:       5,
	}, usbMouseSnapshot{
		DeviceKey: "EP 0x82 (IN)",
		Buttons:   []string{},
	})
	if !ok {
		t.Fatalf("expected pure button release to produce a mouse event")
	}
	if got := event.ReleasedButtons; len(got) != 1 || got[0] != "Left" {
		t.Fatalf("unexpected released buttons: %#v", got)
	}
}

func TestBuildUSBMassStoragePacketInfoReadAndWriteClassification(t *testing.T) {
	readParts := make([]string, usbFieldCount)
	readParts[usbFieldMassStorageCBWTag] = "0x00000001"
	readParts[usbFieldMassStorageCBWDataTransferLength] = "512"
	readParts[usbFieldMassStorageCBWFlags] = "0x80"
	readParts[usbFieldMassStorageCBWLUN] = "0"
	record := model.USBPacketRecord{
		PacketID:      10,
		Time:          "10.000000",
		BusID:         "1",
		DeviceAddress: "7",
		Endpoint:      "EP 0x81 (IN)",
		TransferType:  "Bulk",
	}
	readInfo := buildUSBMassStoragePacketInfo(record, readParts, buildCBWHex(0x1, 512, 0x80, 0x00, []byte{0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0}), "READ(10)")
	if !readInfo.Active {
		t.Fatalf("expected read info to be active")
	}
	if readInfo.Operation != "read" {
		t.Fatalf("expected read operation, got %q", readInfo.Operation)
	}
	if readInfo.Command != "READ(10)" {
		t.Fatalf("expected READ(10) command, got %q", readInfo.Command)
	}

	writeParts := make([]string, usbFieldCount)
	writeParts[usbFieldMassStorageCBWTag] = "0x00000002"
	writeParts[usbFieldMassStorageCBWDataTransferLength] = "1024"
	writeParts[usbFieldMassStorageCBWFlags] = "0x00"
	writeParts[usbFieldMassStorageCBWLUN] = "1"
	writeInfo := buildUSBMassStoragePacketInfo(record, writeParts, "", "Bulk-Only Transport")
	if !writeInfo.Active {
		t.Fatalf("expected write info to be active")
	}
	if writeInfo.Operation != "write" {
		t.Fatalf("expected write fallback classification, got %q", writeInfo.Operation)
	}
}

func TestConsumeUSBMassStorageOperationAggregatesRequestAndResponse(t *testing.T) {
	pending := make(map[string]*model.USBMassStorageOperation)
	analysis := model.USBMassStorageAnalysis{}

	consumeUSBMassStorageOperation(usbMassStoragePacketInfo{
		PacketID:       11,
		Time:           "11.000000",
		Active:         true,
		IsCommand:      true,
		Tag:            "0x00000001",
		Device:         "Disk A",
		Endpoint:       "EP 0x81 (IN)",
		LUN:            "LUN 0",
		Command:        "READ(10)",
		Operation:      "read",
		TransferLength: 512,
		Direction:      "IN",
		RequestFrame:   11,
		Summary:        "READ(10)",
	}, pending, &analysis)

	consumeUSBMassStorageOperation(usbMassStoragePacketInfo{
		PacketID:      12,
		Time:          "11.050000",
		Active:        true,
		IsCompletion:  true,
		Tag:           "0x00000001",
		Device:        "Disk A",
		Endpoint:      "EP 0x81 (IN)",
		LUN:           "LUN 0",
		Command:       "READ(10)",
		Operation:     "read",
		Direction:     "IN",
		Status:        "ok",
		ResponseFrame: 12,
		LatencyMs:     1.25,
		DataResidue:   0,
		Summary:       "READ(10) / status=ok",
	}, pending, &analysis)

	if len(analysis.ReadOperations) != 1 {
		t.Fatalf("expected one aggregated read operation, got %d", len(analysis.ReadOperations))
	}
	op := analysis.ReadOperations[0]
	if op.RequestFrame != 11 || op.ResponseFrame != 12 {
		t.Fatalf("unexpected frames: req=%d resp=%d", op.RequestFrame, op.ResponseFrame)
	}
	if op.LatencyMs != 1.25 {
		t.Fatalf("unexpected latency: %f", op.LatencyMs)
	}
}

func TestAppendUSBOtherRecordAddsControlRequests(t *testing.T) {
	analysis := model.USBAnalysis{}
	record := model.USBPacketRecord{
		PacketID:     99,
		TransferType: "Control",
		SetupRequest: "GET_DESCRIPTOR wValue=0x0100",
		Summary:      "GET_DESCRIPTOR",
	}

	appendUSBOtherRecord(&analysis, record)

	if analysis.OtherUSBPackets != 1 || analysis.Other.TotalPackets != 1 {
		t.Fatalf("unexpected other counts: top=%d nested=%d", analysis.OtherUSBPackets, analysis.Other.TotalPackets)
	}
	if analysis.Other.ControlPackets != 1 {
		t.Fatalf("expected one control packet, got %d", analysis.Other.ControlPackets)
	}
	if len(analysis.Other.ControlRecords) != 1 {
		t.Fatalf("expected control record to be stored")
	}
}

func buildCBWHex(tag uint32, transferLength uint32, flags byte, lun byte, cdb []byte) string {
	payload := make([]byte, 31)
	binary.LittleEndian.PutUint32(payload[0:4], 0x43425355)
	binary.LittleEndian.PutUint32(payload[4:8], tag)
	binary.LittleEndian.PutUint32(payload[8:12], transferLength)
	payload[12] = flags
	payload[13] = lun
	payload[14] = byte(len(cdb))
	copy(payload[15:], cdb)

	parts := make([]string, 0, len(payload))
	for _, b := range payload {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

func TestDetectUSBKeyboardSnapshotFromRawBootPayload(t *testing.T) {
	record := model.USBPacketRecord{
		Endpoint:     "Bus 2 / Device 2 / EP 0x81 (IN)",
		TransferType: "Interrupt",
	}

	snapshot, ok := detectUSBKeyboardSnapshot(record, make([]string, usbFieldCount), "0200040000000000", usbHIDHint{})
	if !ok {
		t.Fatalf("expected raw 8-byte boot report to be detected as keyboard")
	}
	if !strings.EqualFold(strings.Join(snapshot.Modifiers, ","), "Left Shift") {
		t.Fatalf("unexpected modifiers: %#v", snapshot.Modifiers)
	}
	if len(snapshot.Keys) != 1 || snapshot.Keys[0] != "A" {
		t.Fatalf("unexpected keys: %#v", snapshot.Keys)
	}
}

func TestDetectUSBKeyboardSnapshotRawReleaseWithHint(t *testing.T) {
	record := model.USBPacketRecord{
		Endpoint:     "Bus 2 / Device 2 / EP 0x81 (IN)",
		TransferType: "Interrupt",
	}

	snapshot, ok := detectUSBKeyboardSnapshot(record, make([]string, usbFieldCount), "0000000000000000", usbHIDHint{Keyboard: true})
	if !ok {
		t.Fatalf("expected all-zero boot report to keep keyboard endpoint state")
	}
	if len(snapshot.Modifiers) != 0 || len(snapshot.Keys) != 0 {
		t.Fatalf("release snapshot should be empty, got modifiers=%#v keys=%#v", snapshot.Modifiers, snapshot.Keys)
	}
}
