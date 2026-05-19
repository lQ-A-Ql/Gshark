package tshark

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestUSBAnalysisFieldsMatchParserWidth(t *testing.T) {
	if len(usbAnalysisFields) != usbFieldCount {
		t.Fatalf("usbAnalysisFields len = %d, want %d", len(usbAnalysisFields), usbFieldCount)
	}
	if usbAnalysisFields[usbFieldFrameNumber] != "frame.number" {
		t.Fatalf("unexpected frame number field: %q", usbAnalysisFields[usbFieldFrameNumber])
	}
	if usbAnalysisFields[usbFieldProtocol] != "_ws.col.Protocol" {
		t.Fatalf("unexpected protocol field: %q", usbAnalysisFields[usbFieldProtocol])
	}
	if usbAnalysisFields[usbFieldInfo] != "_ws.col.Info" {
		t.Fatalf("unexpected info field: %q", usbAnalysisFields[usbFieldInfo])
	}
	if usbAnalysisFields[usbFieldSCSIStatus] != "scsi.status" {
		t.Fatalf("unexpected final field: %q", usbAnalysisFields[usbFieldSCSIStatus])
	}
	if usbAnalysisFields[usbFieldBTATTValue] != "btatt.value" {
		t.Fatalf("unexpected Bluetooth HID field: %q", usbAnalysisFields[usbFieldBTATTValue])
	}
}

func TestUSBAnalysisRawScanCacheDeduplicatesInFlightRequests(t *testing.T) {
	oldRunner := usbAnalysisScanRunner
	t.Cleanup(func() {
		usbAnalysisScanRunner = oldRunner
		ClearUSBAnalysisRawScanCache()
	})
	ClearUSBAnalysisRawScanCache()

	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	usbAnalysisScanRunner = func(filePath string) (usbAnalysisRawScan, error) {
		atomic.AddInt32(&calls, 1)
		close(started)
		<-release
		return usbAnalysisRawScan{Rows: [][]string{make([]string, usbFieldCount)}}, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, err := loadUSBAnalysisRawScan("sample.pcapng")
		results <- err
	}()
	go func() {
		defer wg.Done()
		_, err := loadUSBAnalysisRawScan("sample.pcapng")
		results <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected first raw scan to start")
	}
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("unexpected raw scan error: %v", err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one scan invocation, got %d", got)
	}
}

func TestClearUSBAnalysisRawScanCacheInvalidatesEntries(t *testing.T) {
	oldRunner := usbAnalysisScanRunner
	t.Cleanup(func() {
		usbAnalysisScanRunner = oldRunner
		ClearUSBAnalysisRawScanCache()
	})
	ClearUSBAnalysisRawScanCache()

	var calls int32
	usbAnalysisScanRunner = func(filePath string) (usbAnalysisRawScan, error) {
		atomic.AddInt32(&calls, 1)
		return usbAnalysisRawScan{Rows: [][]string{make([]string, usbFieldCount)}}, nil
	}

	if _, err := loadUSBAnalysisRawScan("sample.pcapng"); err != nil {
		t.Fatalf("first load error = %v", err)
	}
	ClearUSBAnalysisRawScanCache()
	if _, err := loadUSBAnalysisRawScan("sample.pcapng"); err != nil {
		t.Fatalf("second load error = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected cache invalidation to force a second scan, got %d", got)
	}
}

func TestUSBAnalysisRawScanCacheDoesNotPersistFailures(t *testing.T) {
	oldRunner := usbAnalysisScanRunner
	t.Cleanup(func() {
		usbAnalysisScanRunner = oldRunner
		ClearUSBAnalysisRawScanCache()
	})
	ClearUSBAnalysisRawScanCache()

	var calls int32
	usbAnalysisScanRunner = func(filePath string) (usbAnalysisRawScan, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return usbAnalysisRawScan{}, errors.New("temporary scan failure")
		}
		return usbAnalysisRawScan{Rows: [][]string{make([]string, usbFieldCount)}}, nil
	}

	if _, err := loadUSBAnalysisRawScan("sample.pcapng"); err == nil {
		t.Fatal("expected first load to fail")
	}
	if _, err := loadUSBAnalysisRawScan("sample.pcapng"); err != nil {
		t.Fatalf("expected second load to retry and succeed, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected failed load to be evicted and retried, got %d calls", got)
	}
}

func TestUSBHIDBluetoothRecordsAreAccepted(t *testing.T) {
	if !looksLikeUSBRecord("BTATT", "", "", "", "", "") {
		t.Fatalf("expected BTATT records to enter USB HID analysis")
	}
	if got := normalizeUSBProtocolLabel("btatt"); got != "BTATT" {
		t.Fatalf("unexpected Bluetooth protocol label: %q", got)
	}
}

func TestBuildPlannedFieldArgsForUSBAnalysisSkipsMissingOptionalFields(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	fields := append([]string{}, requiredCapabilityFields...)
	fields = append(fields,
		"usb.bus_id",
		"usb.device_address",
		"usbms.dCBWTag",
		"scsi.status",
	)
	binary := writeFakeTShark(t, "TShark 4.6.5", fields)
	SetBinaryPath(binary)

	planned, err := BuildPlannedFieldArgs([]string{"-n", "-r", "usb.pcap", "-T", "fields"}, usbAnalysisFields)
	if err != nil {
		t.Fatalf("BuildPlannedFieldArgs() error = %v", err)
	}
	if !slices.Contains(planned.MissingOptional, "usbhid.data") {
		t.Fatalf("expected usbhid.data to be optional missing, got %#v", planned.MissingOptional)
	}
	if slices.Contains(planned.TSharkFields, "usbhid.data") {
		t.Fatalf("missing optional field should not be emitted to tshark args: %#v", planned.TSharkFields)
	}

	scanned := make([]string, len(planned.TSharkFields))
	for idx, field := range planned.TSharkFields {
		scanned[idx] = field
	}
	projected := planned.ProjectRow(scanned)
	if len(projected) != usbFieldCount {
		t.Fatalf("projected len = %d, want %d", len(projected), usbFieldCount)
	}
	if projected[usbFieldBusID] != "usb.bus_id" {
		t.Fatalf("expected usb.bus_id projection, got %q", projected[usbFieldBusID])
	}
	if projected[usbFieldHIDData] != "" {
		t.Fatalf("missing HID data should project empty column, got %q", projected[usbFieldHIDData])
	}
	if projected[usbFieldSCSIStatus] != "scsi.status" {
		t.Fatalf("expected scsi.status projection, got %q", projected[usbFieldSCSIStatus])
	}
}

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

func TestDetectUSBMouseSnapshotKeepsEmptyInterruptFramesWithHint(t *testing.T) {
	record := model.USBPacketRecord{
		PacketID:      4,
		TransferType:  "Interrupt",
		BusID:         "1",
		DeviceAddress: "3",
		Endpoint:      "Bus 1 / Device 3 / EP 0x81 (IN)",
	}

	snapshot, ok := detectUSBMouseSnapshot(record, make([]string, usbFieldCount), nil, usbHIDHint{Mouse: true})
	if !ok {
		t.Fatalf("expected empty completion frame to stay classified as mouse HID after a mouse hint")
	}
	if !snapshot.KeepState || len(snapshot.Buttons) != 0 || snapshot.XDelta != 0 || snapshot.YDelta != 0 || snapshot.WheelVertical != 0 || snapshot.WheelHorizontal != 0 {
		t.Fatalf("expected empty mouse snapshot, got %+v", snapshot)
	}

	_, nextState, eventOK := buildUSBMouseEvent(record, usbMouseState{Buttons: []string{"Left"}, X: 10, Y: 5}, snapshot)
	if eventOK {
		t.Fatalf("expected empty completion frame not to produce a mouse event")
	}
	if nextState.X != 10 || nextState.Y != 5 || len(nextState.Buttons) != 1 || nextState.Buttons[0] != "Left" {
		t.Fatalf("unexpected next mouse state: %+v", nextState)
	}
}

func TestDetectUSBMouseSnapshotFromReportIDPayload(t *testing.T) {
	record := model.USBPacketRecord{
		PacketID:      5,
		TransferType:  "Interrupt",
		BusID:         "1",
		DeviceAddress: "3",
		Endpoint:      "Bus 1 / Device 3 / EP 0x81 (IN)",
	}

	parts := make([]string, usbFieldCount)
	parts[usbFieldHIDData] = "09:01:FE:00"
	snapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{Mouse: true})
	if !ok {
		t.Fatalf("expected report-id mouse payload to be detected")
	}
	if len(snapshot.Buttons) != 1 || snapshot.Buttons[0] != "Left" || snapshot.XDelta != -2 || snapshot.YDelta != 0 {
		t.Fatalf("unexpected report-id mouse snapshot: %+v", snapshot)
	}
	if snapshot.Source != "usbhid.data" || snapshot.Layout != "report-id-4" {
		t.Fatalf("unexpected report-id source/layout: %+v", snapshot)
	}
}

func TestDetectUSBMouseSnapshotKeepsZeroReleasePayloadWithHint(t *testing.T) {
	record := model.USBPacketRecord{
		PacketID:      6,
		TransferType:  "Interrupt",
		BusID:         "1",
		DeviceAddress: "3",
		Endpoint:      "Bus 1 / Device 3 / EP 0x81 (IN)",
	}
	parts := make([]string, usbFieldCount)
	parts[usbFieldHIDData] = "00:00:00:00"

	snapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{Mouse: true})
	if !ok {
		t.Fatalf("expected zero mouse release payload to stay classified as mouse")
	}
	event, nextState, eventOK := buildUSBMouseEvent(record, usbMouseState{Buttons: []string{"Left"}, X: 4, Y: 5}, snapshot)
	if !eventOK {
		t.Fatalf("expected zero release payload to produce release event")
	}
	if len(event.ReleasedButtons) != 1 || event.ReleasedButtons[0] != "Left" || nextState.X != 4 || nextState.Y != 5 {
		t.Fatalf("unexpected zero release event=%+v state=%+v", event, nextState)
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

func TestUSBHIDEventLimitTracksTotalsAndTruncation(t *testing.T) {
	analysis := model.USBAnalysis{}
	limit := model.MinUSBHIDEventLimit
	for i := 0; i < limit+1; i++ {
		appendUSBKeyboardEvent(&analysis, model.USBKeyboardEvent{PacketID: int64(i + 1)}, limit)
		appendUSBMouseEvent(&analysis, model.USBMouseEvent{PacketID: int64(i + 1)}, limit)
	}

	if analysis.HIDKeyboardEventsTotal != limit+1 || analysis.HIDMouseEventsTotal != limit+1 {
		t.Fatalf("unexpected HID totals: keyboard=%d mouse=%d", analysis.HIDKeyboardEventsTotal, analysis.HIDMouseEventsTotal)
	}
	if len(analysis.KeyboardEvents) != limit || len(analysis.HID.KeyboardEvents) != limit {
		t.Fatalf("keyboard event slices should be truncated to %d, got top=%d nested=%d", limit, len(analysis.KeyboardEvents), len(analysis.HID.KeyboardEvents))
	}
	if len(analysis.MouseEvents) != limit || len(analysis.HID.MouseEvents) != limit {
		t.Fatalf("mouse event slices should be truncated to %d, got top=%d nested=%d", limit, len(analysis.MouseEvents), len(analysis.HID.MouseEvents))
	}
	if !analysis.HIDEventsTruncated {
		t.Fatal("expected HID events truncated metadata")
	}
	notes := buildUSBHIDNotes(analysis)
	if !strings.Contains(strings.Join(notes, " "), "已按上限截断") {
		t.Fatalf("expected HID notes to mention truncation, got %#v", notes)
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

	parts := make([]string, usbFieldCount)
	parts[usbFieldCapData] = "0200040000000000"
	snapshot, ok := detectUSBKeyboardSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{})
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

	parts := make([]string, usbFieldCount)
	parts[usbFieldCapData] = "0000000000000000"
	snapshot, ok := detectUSBKeyboardSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{Keyboard: true})
	if !ok {
		t.Fatalf("expected all-zero boot report to keep keyboard endpoint state")
	}
	if len(snapshot.Modifiers) != 0 || len(snapshot.Keys) != 0 {
		t.Fatalf("release snapshot should be empty, got modifiers=%#v keys=%#v", snapshot.Modifiers, snapshot.Keys)
	}
}

func TestDetectUSBKeyboardSnapshotFromBluetoothPrefixedPayload(t *testing.T) {
	record := model.USBPacketRecord{
		Protocol: "BTATT",
		Summary:  "Bluetooth HID Report",
	}

	parts := make([]string, usbFieldCount)
	parts[usbFieldBTATTValue] = "a10200040000000000"
	snapshot, ok := detectUSBKeyboardSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{})
	if !ok {
		t.Fatalf("expected prefixed Bluetooth keyboard payload to be detected")
	}
	if len(snapshot.Keys) != 1 || snapshot.Keys[0] != "A" {
		t.Fatalf("unexpected Bluetooth keys: %#v", snapshot.Keys)
	}
}

func TestDetectUSBMouseSnapshotFromEightByteOffsetPayload(t *testing.T) {
	record := model.USBPacketRecord{
		PacketID:      6,
		TransferType:  "Interrupt",
		BusID:         "1",
		DeviceAddress: "3",
		Endpoint:      "Bus 1 / Device 3 / EP 0x81 (IN)",
	}

	parts := make([]string, usbFieldCount)
	parts[usbFieldHIDData] = "00:01:FE:00:02:00:00:00"
	snapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{})
	if !ok {
		t.Fatalf("expected 8-byte offset mouse payload to be detected")
	}
	if len(snapshot.Buttons) != 1 || snapshot.Buttons[0] != "Left" || snapshot.XDelta != -2 || snapshot.YDelta != 2 {
		t.Fatalf("unexpected offset mouse snapshot: %+v", snapshot)
	}
	if snapshot.Source != "usbhid.data" || snapshot.Layout != "github-8" {
		t.Fatalf("unexpected offset source/layout: %+v", snapshot)
	}
}

func TestDetectUSBMouseSnapshotSourceModeUsesSelectedCandidate(t *testing.T) {
	record := model.USBPacketRecord{
		PacketID:      7,
		TransferType:  "Interrupt",
		BusID:         "1",
		DeviceAddress: "3",
		Endpoint:      "Bus 1 / Device 3 / EP 0x81 (IN)",
	}
	parts := make([]string, usbFieldCount)
	parts[usbFieldHIDData] = "01:05:00:00"
	parts[usbFieldCapData] = "02:00:07:00"

	autoSnapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceAuto), usbHIDHint{})
	if !ok {
		t.Fatalf("expected auto mouse candidate")
	}
	if autoSnapshot.Source != "usbhid.data" || autoSnapshot.Buttons[0] != "Left" || autoSnapshot.XDelta != 5 {
		t.Fatalf("auto should prefer usbhid.data on comparable candidates, got %+v", autoSnapshot)
	}

	capSnapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceCapData), usbHIDHint{})
	if !ok {
		t.Fatalf("expected capdata mouse candidate")
	}
	if capSnapshot.Source != "usb.capdata" || capSnapshot.Buttons[0] != "Right" || capSnapshot.YDelta != 7 {
		t.Fatalf("forced capdata should use usb.capdata, got %+v", capSnapshot)
	}
}

func TestDetectUSBMouseSnapshotLayouts(t *testing.T) {
	record := model.USBPacketRecord{TransferType: "Interrupt", Endpoint: "EP 0x81 (IN)"}
	tests := []struct {
		name   string
		raw    string
		layout string
		x      int
		y      int
		button string
	}{
		{name: "github4", raw: "01:02:FE:00", layout: "boot-4", x: 2, y: -2, button: "Left"},
		{name: "github6", raw: "00:02:04:FC:00:00", layout: "github-6", x: 4, y: -4, button: "Right"},
		{name: "github8", raw: "00:01:FE:00:02:00:00:00", layout: "github-8", x: -2, y: 2, button: "Left"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := make([]string, usbFieldCount)
			parts[usbFieldHIDData] = tt.raw
			snapshot, ok := detectUSBMouseSnapshot(record, parts, buildUSBHIDPayloadCandidates(parts, model.USBHIDSourceUSBHID), usbHIDHint{})
			if !ok {
				t.Fatalf("expected mouse snapshot")
			}
			if snapshot.Layout != tt.layout || snapshot.XDelta != tt.x || snapshot.YDelta != tt.y || len(snapshot.Buttons) != 1 || snapshot.Buttons[0] != tt.button {
				t.Fatalf("unexpected snapshot: %+v", snapshot)
			}
		})
	}
}

func TestUSBHIDSourceModeRejectsUnknownValue(t *testing.T) {
	if _, ok := model.NormalizeUSBHIDSourceMode("unknown"); ok {
		t.Fatalf("expected unknown hid source to be rejected")
	}
	if mode, ok := model.NormalizeUSBHIDSourceMode("USBHID"); !ok || mode != model.USBHIDSourceUSBHID {
		t.Fatalf("expected case-insensitive usbhid mode, got %q ok=%v", mode, ok)
	}
}

func TestUSBMouseTrafficSampleRegression(t *testing.T) {
	sample := os.Getenv("GSHARK_USB_MOUSE_SAMPLE")
	if strings.TrimSpace(sample) == "" {
		t.Skip("set GSHARK_USB_MOUSE_SAMPLE to run local mouse traffic regression")
	}

	analysis, err := BuildUSBAnalysisFromFile(sample)
	if err != nil {
		t.Fatalf("BuildUSBAnalysisFromFile() error = %v", err)
	}
	if analysis.MousePackets == 0 {
		t.Fatalf("expected mouse events in sample, got none")
	}
	if analysis.OtherUSBPackets >= analysis.HIDPackets/10 {
		t.Fatalf("expected mouse HID completion frames to stay out of Other USB, got hid=%d other=%d mouse=%d", analysis.HIDPackets, analysis.OtherUSBPackets, analysis.MousePackets)
	}
}
