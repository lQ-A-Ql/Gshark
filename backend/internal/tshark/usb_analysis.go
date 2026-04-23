package tshark

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

const usbRecordLimit = 2000

const (
	usbFieldFrameNumber = iota
	usbFieldFrameTime
	usbFieldProtocol
	usbFieldBusID
	usbFieldDeviceAddress
	usbFieldEndpointAddress
	usbFieldEndpointDirection
	usbFieldIRPDirection
	usbFieldTransferType
	usbFieldURBType
	usbFieldURBStatus
	usbFieldDataLength
	usbFieldSetupRequest
	usbFieldSetupValue
	usbFieldSetupIndex
	usbFieldSetupLength
	usbFieldFrameData
	usbFieldControlResponse
	usbFieldCapData
	usbFieldHIDData
	usbFieldKeyboardKey1
	usbFieldKeyboardKey2
	usbFieldKeyboardKey3
	usbFieldKeyboardKey4
	usbFieldKeyboardKey5
	usbFieldKeyboardKey6
	usbFieldKeyboardLeftCtrl
	usbFieldKeyboardLeftShift
	usbFieldKeyboardLeftAlt
	usbFieldKeyboardLeftGUI
	usbFieldKeyboardRightCtrl
	usbFieldKeyboardRightShift
	usbFieldKeyboardRightAlt
	usbFieldKeyboardRightGUI
	usbFieldMouseLeft
	usbFieldMouseRight
	usbFieldMouseMiddle
	usbFieldMouseButton4
	usbFieldMouseButton5
	usbFieldMouseButton6
	usbFieldMouseButton7
	usbFieldMouseButton8
	usbFieldMouseXDelta
	usbFieldMouseYDelta
	usbFieldMouseWheelVertical
	usbFieldMouseWheelHorizontal
	usbFieldInfo
	usbFieldMassStorageCBWSignature
	usbFieldMassStorageCBWTag
	usbFieldMassStorageCBWDataTransferLength
	usbFieldMassStorageCBWFlags
	usbFieldMassStorageCBWLUN
	usbFieldMassStorageCBWCBLength
	usbFieldMassStorageCSWSignature
	usbFieldMassStorageCSWStatus
	usbFieldMassStorageCSWDataResidue
	usbFieldSCSIOpcode
	usbFieldSCSILUN
	usbFieldSCSIRequestFrame
	usbFieldSCSIResponseFrame
	usbFieldSCSITime
	usbFieldSCSIStatus
)

const usbFieldCount = usbFieldSCSIStatus + 1

type usbKeyboardState struct {
	Modifiers []string
	Keys      []string
}

type usbMouseState struct {
	Buttons []string
	X       int
	Y       int
}

type usbHIDHint struct {
	Keyboard bool
	Mouse    bool
}

type usbKeyboardSnapshot struct {
	DeviceKey string
	Modifiers []string
	Keys      []string
}

type usbMouseSnapshot struct {
	DeviceKey       string
	Buttons         []string
	XDelta          int
	YDelta          int
	WheelVertical   int
	WheelHorizontal int
}

type usbMassStorageCBW struct {
	Valid          bool
	Tag            uint32
	TransferLength int
	Flags          byte
	LUN            byte
	CDB            []byte
}

type usbMassStoragePacketInfo struct {
	PacketID       int64
	Time           string
	Active         bool
	IsControl      bool
	IsCommand      bool
	IsCompletion   bool
	Tag            string
	Device         string
	Endpoint       string
	LUN            string
	Command        string
	Operation      string
	TransferLength int
	Direction      string
	Status         string
	DataResidue    int
	RequestFrame   int64
	ResponseFrame  int64
	LatencyMs      float64
	Summary        string
}

func BuildUSBAnalysisFromFile(filePath string) (model.USBAnalysis, error) {
	analysis := model.USBAnalysis{}

	args := []string{
		"-n",
		"-r", filePath,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-E", "quote=n",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "_ws.col.Protocol",
		"-e", "usb.bus_id",
		"-e", "usb.device_address",
		"-e", "usb.endpoint_address",
		"-e", "usb.endpoint_address.direction",
		"-e", "usb.irp_info.direction",
		"-e", "usb.transfer_type",
		"-e", "usb.urb_type",
		"-e", "usb.urb_status",
		"-e", "usb.data_len",
		"-e", "usb.setup.bRequest",
		"-e", "usb.setup.wValue",
		"-e", "usb.setup.wIndex",
		"-e", "usb.setup.wLength",
		"-e", "usb.frame.data",
		"-e", "usb.control.Response",
		"-e", "usb.capdata",
		"-e", "usbhid.data",
		"-e", "usbhid.boot_report.keyboard.keycode_1",
		"-e", "usbhid.boot_report.keyboard.keycode_2",
		"-e", "usbhid.boot_report.keyboard.keycode_3",
		"-e", "usbhid.boot_report.keyboard.keycode_4",
		"-e", "usbhid.boot_report.keyboard.keycode_5",
		"-e", "usbhid.boot_report.keyboard.keycode_6",
		"-e", "usbhid.boot_report.keyboard.modifier.left_ctrl",
		"-e", "usbhid.boot_report.keyboard.modifier.left_shift",
		"-e", "usbhid.boot_report.keyboard.modifier.left_alt",
		"-e", "usbhid.boot_report.keyboard.modifier.left_gui",
		"-e", "usbhid.boot_report.keyboard.modifier.right_ctrl",
		"-e", "usbhid.boot_report.keyboard.modifier.right_shift",
		"-e", "usbhid.boot_report.keyboard.modifier.right_alt",
		"-e", "usbhid.boot_report.keyboard.modifier.right_gui",
		"-e", "usbhid.boot_report.mouse.button.left",
		"-e", "usbhid.boot_report.mouse.button.right",
		"-e", "usbhid.boot_report.mouse.button.middle",
		"-e", "usbhid.boot_report.mouse.button.4",
		"-e", "usbhid.boot_report.mouse.button.5",
		"-e", "usbhid.boot_report.mouse.button.6",
		"-e", "usbhid.boot_report.mouse.button.7",
		"-e", "usbhid.boot_report.mouse.button.8",
		"-e", "usbhid.boot_report.mouse.x_displacement",
		"-e", "usbhid.boot_report.mouse.y_displacement",
		"-e", "usbhid.boot_report.mouse.scroll_wheel.vertical",
		"-e", "usbhid.boot_report.mouse.scroll_wheel.horizontal",
		"-e", "_ws.col.Info",
		"-e", "usbms.dCBWSignature",
		"-e", "usbms.dCBWTag",
		"-e", "usbms.dCBWDataTransferLength",
		"-e", "usbms.dCBWFlags",
		"-e", "usbms.dCBWLUN",
		"-e", "usbms.dCBWCBLength",
		"-e", "usbms.dCSWSignature",
		"-e", "usbms.dCSWStatus",
		"-e", "usbms.dCSWDataResidue",
		"-e", "scsi.spc.opcode",
		"-e", "scsi.lun",
		"-e", "scsi.request_frame",
		"-e", "scsi.response_frame",
		"-e", "scsi.time",
		"-e", "scsi.status",
	}

	cmd, err := Command(args...)
	if err != nil {
		return analysis, fmt.Errorf("resolve tshark: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return analysis, fmt.Errorf("create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return analysis, fmt.Errorf("start tshark: %w", err)
	}

	protocolMap := make(map[string]int)
	transferMap := make(map[string]int)
	directionMap := make(map[string]int)
	deviceMap := make(map[string]int)
	endpointMap := make(map[string]int)
	setupMap := make(map[string]int)
	statusMap := make(map[string]int)
	hidDeviceMap := make(map[string]int)
	massDeviceMap := make(map[string]int)
	massLUNMap := make(map[string]int)
	massCommandMap := make(map[string]int)
	otherDeviceMap := make(map[string]int)
	otherEndpointMap := make(map[string]int)
	otherSetupMap := make(map[string]int)
	keyboardStates := make(map[string]usbKeyboardState)
	mouseStates := make(map[string]usbMouseState)
	hidHints := make(map[string]usbHIDHint)
	pendingMassStorage := make(map[string]*model.USBMassStorageOperation)
	residueOperations := 0
	massStorageErrorStatuses := 0

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < usbFieldCount {
			continue
		}

		protocol := normalizeUSBProtocolLabel(safeTrim(parts, usbFieldProtocol))
		busID := safeTrim(parts, usbFieldBusID)
		deviceAddress := safeTrim(parts, usbFieldDeviceAddress)
		endpointRaw := safeTrim(parts, usbFieldEndpointAddress)
		endpointDirection := FirstNonEmpty(safeTrim(parts, usbFieldEndpointDirection), safeTrim(parts, usbFieldIRPDirection))
		transferType := normalizeUSBTransferType(safeTrim(parts, usbFieldTransferType))
		urbType := normalizeUSBUrbType(safeTrim(parts, usbFieldURBType))
		status := normalizeUSBStatus(safeTrim(parts, usbFieldURBStatus))
		dataLength := parseUSBInt(safeTrim(parts, usbFieldDataLength))
		setupRequest := normalizeUSBSetupRequest(safeTrim(parts, usbFieldSetupRequest))
		setupValue := safeTrim(parts, usbFieldSetupValue)
		setupIndex := safeTrim(parts, usbFieldSetupIndex)
		setupLength := safeTrim(parts, usbFieldSetupLength)
		payloadRaw := FirstNonEmpty(safeTrim(parts, usbFieldCapData), safeTrim(parts, usbFieldHIDData), safeTrim(parts, usbFieldControlResponse), safeTrim(parts, usbFieldFrameData))
		info := safeTrim(parts, usbFieldInfo)

		if !looksLikeUSBRecord(protocol, busID, deviceAddress, endpointRaw, transferType, urbType) {
			continue
		}

		analysis.TotalUSBPackets++

		if protocol != "" {
			protocolMap[protocol]++
		}
		if transferType != "" {
			transferMap[transferType]++
		}

		direction := normalizeUSBDirection(endpointDirection, endpointRaw)
		if direction != "" {
			directionMap[direction]++
		}

		deviceLabel := buildUSBDeviceLabel(busID, deviceAddress)
		if deviceLabel != "" {
			deviceMap[deviceLabel]++
		}
		endpointLabel := buildUSBEndpointLabel(busID, deviceAddress, endpointRaw, direction)
		if endpointLabel != "" {
			endpointMap[endpointLabel]++
		}
		if setupRequest != "" {
			setupMap[setupRequest]++
		}
		if status != "" {
			statusMap[status]++
		}

		record := model.USBPacketRecord{
			PacketID:       parseUSBInt64(safeTrim(parts, usbFieldFrameNumber)),
			Time:           normalizeTimestamp(safeTrim(parts, usbFieldFrameTime)),
			Protocol:       protocol,
			BusID:          busID,
			DeviceAddress:  deviceAddress,
			Endpoint:       endpointLabel,
			Direction:      direction,
			TransferType:   transferType,
			URBType:        urbType,
			Status:         status,
			DataLength:     dataLength,
			SetupRequest:   buildUSBSetupSummary(setupRequest, setupValue, setupIndex, setupLength),
			PayloadPreview: previewUSBPayload(payloadRaw),
			Summary:        FirstNonEmpty(info, transferType, protocol, "USB packet"),
		}

		if len(analysis.Records) < usbRecordLimit {
			analysis.Records = append(analysis.Records, record)
		}

		massStorageInfo := buildUSBMassStoragePacketInfo(record, parts, payloadRaw, info)
		if massStorageInfo.Active {
			analysis.MassStoragePackets++
			analysis.MassStorage.TotalPackets++
			if massStorageInfo.IsControl {
				analysis.MassStorage.ControlPackets++
			}
			if massStorageInfo.Device != "" {
				massDeviceMap[massStorageInfo.Device]++
			}
			if massStorageInfo.LUN != "" {
				massLUNMap[massStorageInfo.LUN]++
			}
			if massStorageInfo.Command != "" {
				massCommandMap[massStorageInfo.Command]++
			}
			if massStorageInfo.DataResidue > 0 {
				residueOperations++
			}
			if massStorageInfo.Status != "" && massStorageInfo.Status != "ok" && massStorageInfo.Status != "good" && massStorageInfo.Status != "unknown" {
				massStorageErrorStatuses++
			}
			consumeUSBMassStorageOperation(massStorageInfo, pendingMassStorage, &analysis.MassStorage)
			continue
		}

		deviceKey := firstNonEmptyTrim(record.Endpoint, deviceLabel)
		keyboardSnapshot, keyboardDetected := detectUSBKeyboardSnapshot(record, parts, payloadRaw, hidHints[deviceKey])
		mouseSnapshot, mouseDetected := detectUSBMouseSnapshot(record, parts, payloadRaw, hidHints[deviceKey])

		if keyboardDetected {
			analysis.HIDPackets++
			previous := keyboardStates[keyboardSnapshot.DeviceKey]
			if keyboardEvent, ok := buildUSBKeyboardEvent(record, previous, keyboardSnapshot); ok {
				analysis.KeyboardPackets++
				if len(analysis.KeyboardEvents) < usbRecordLimit {
					analysis.KeyboardEvents = append(analysis.KeyboardEvents, keyboardEvent)
				}
				if len(analysis.HID.KeyboardEvents) < usbRecordLimit {
					analysis.HID.KeyboardEvents = append(analysis.HID.KeyboardEvents, keyboardEvent)
				}
			}
			keyboardStates[keyboardSnapshot.DeviceKey] = usbKeyboardState{Modifiers: copyStrings(keyboardSnapshot.Modifiers), Keys: copyStrings(keyboardSnapshot.Keys)}
			hint := hidHints[keyboardSnapshot.DeviceKey]
			hint.Keyboard = true
			hidHints[keyboardSnapshot.DeviceKey] = hint
			if deviceLabel != "" {
				hidDeviceMap[deviceLabel]++
			}
			continue
		}

		if mouseDetected {
			analysis.HIDPackets++
			previous := mouseStates[mouseSnapshot.DeviceKey]
			mouseEvent, nextState, ok := buildUSBMouseEvent(record, previous, mouseSnapshot)
			if ok {
				analysis.MousePackets++
				if len(analysis.MouseEvents) < usbRecordLimit {
					analysis.MouseEvents = append(analysis.MouseEvents, mouseEvent)
				}
				if len(analysis.HID.MouseEvents) < usbRecordLimit {
					analysis.HID.MouseEvents = append(analysis.HID.MouseEvents, mouseEvent)
				}
			}
			mouseStates[mouseSnapshot.DeviceKey] = nextState
			hint := hidHints[mouseSnapshot.DeviceKey]
			hint.Mouse = true
			hidHints[mouseSnapshot.DeviceKey] = hint
			if deviceLabel != "" {
				hidDeviceMap[deviceLabel]++
			}
			continue
		}

		appendUSBOtherRecord(&analysis, record)
		if deviceLabel != "" {
			otherDeviceMap[deviceLabel]++
		}
		if endpointLabel != "" {
			otherEndpointMap[endpointLabel]++
		}
		if setupRequest != "" {
			otherSetupMap[setupRequest]++
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return analysis, fmt.Errorf("scan tshark output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return analysis, fmt.Errorf("wait tshark: %w", err)
	}

	analysis.Protocols = topBuckets(protocolMap, 0)
	analysis.TransferTypes = topBuckets(transferMap, 0)
	analysis.Directions = topBuckets(directionMap, 0)
	analysis.Devices = topBuckets(deviceMap, 0)
	analysis.Endpoints = topBuckets(endpointMap, 0)
	analysis.SetupRequests = topBuckets(setupMap, 0)
	flushUSBMassStorageOperations(pendingMassStorage, &analysis.MassStorage)
	analysis.HID.Devices = topBuckets(hidDeviceMap, 0)
	analysis.HID.Notes = buildUSBHIDNotes(analysis)
	analysis.MassStorage.Devices = topBuckets(massDeviceMap, 0)
	analysis.MassStorage.LUNs = topBuckets(massLUNMap, 0)
	analysis.MassStorage.Commands = topBuckets(massCommandMap, 0)
	analysis.MassStorage.ReadPackets = len(analysis.MassStorage.ReadOperations)
	analysis.MassStorage.WritePackets = len(analysis.MassStorage.WriteOperations)
	analysis.MassStorage.Notes = buildUSBMassStorageNotes(analysis.MassStorage, residueOperations, massStorageErrorStatuses)
	analysis.Other.Devices = topBuckets(otherDeviceMap, 0)
	analysis.Other.Endpoints = topBuckets(otherEndpointMap, 0)
	analysis.Other.SetupRequests = topBuckets(otherSetupMap, 0)
	analysis.Other.Notes = buildUSBOtherNotes(analysis.Other)
	analysis.Notes = buildUSBAnalysisNotes(analysis, statusMap)
	return analysis, nil
}

func detectUSBKeyboardSnapshot(record model.USBPacketRecord, parts []string, payloadRaw string, hint usbHIDHint) (usbKeyboardSnapshot, bool) {
	deviceKey := firstNonEmptyTrim(record.Endpoint, buildUSBDeviceLabel(record.BusID, record.DeviceAddress))
	modifiers := buildKeyboardModifiers(parts)
	keys := buildKeyboardKeys(parts)
	if len(modifiers) > 0 || len(keys) > 0 {
		return usbKeyboardSnapshot{DeviceKey: deviceKey, Modifiers: modifiers, Keys: keys}, true
	}
	if record.TransferType != "Interrupt" {
		return usbKeyboardSnapshot{}, false
	}

	// Many USB CTF captures are plain usbmon/USBPcap frames. TShark keeps the
	// boot report bytes in usb.capdata and never promotes them to usbhid.* fields.
	// Keyboard boot reports are 8 bytes: modifier, reserved, then six keycodes.
	payload := decodeLooseHexToBytes(payloadRaw)
	if len(payload) >= 8 && len(payload) <= 16 {
		modifiers, keys = parseKeyboardBootPayload(payload[:8])
		if len(modifiers) > 0 || len(keys) > 0 || hint.Keyboard || isLikelyKeyboardBootReport(payload[:8]) {
			return usbKeyboardSnapshot{DeviceKey: deviceKey, Modifiers: modifiers, Keys: keys}, true
		}
	}
	return usbKeyboardSnapshot{}, false
}

func buildUSBKeyboardEvent(record model.USBPacketRecord, previous usbKeyboardState, current usbKeyboardSnapshot) (model.USBKeyboardEvent, bool) {
	pressedModifiers := diffOrdered(current.Modifiers, previous.Modifiers)
	releasedModifiers := diffOrdered(previous.Modifiers, current.Modifiers)
	pressedKeys := diffOrdered(current.Keys, previous.Keys)
	releasedKeys := diffOrdered(previous.Keys, current.Keys)
	if len(pressedModifiers) == 0 && len(releasedModifiers) == 0 && len(pressedKeys) == 0 && len(releasedKeys) == 0 {
		return model.USBKeyboardEvent{}, false
	}
	text := buildKeyboardText(current.Modifiers, pressedKeys)
	return model.USBKeyboardEvent{
		PacketID:          record.PacketID,
		Time:              record.Time,
		Device:            buildUSBDeviceLabel(record.BusID, record.DeviceAddress),
		Endpoint:          record.Endpoint,
		Modifiers:         copyStrings(current.Modifiers),
		Keys:              copyStrings(current.Keys),
		PressedModifiers:  pressedModifiers,
		ReleasedModifiers: releasedModifiers,
		PressedKeys:       pressedKeys,
		ReleasedKeys:      releasedKeys,
		Text:              text,
		Summary:           buildKeyboardSummary(current.Modifiers, current.Keys, pressedModifiers, releasedModifiers, pressedKeys, releasedKeys, text),
	}, true
}

func detectUSBMouseSnapshot(record model.USBPacketRecord, parts []string, payloadRaw string, hint usbHIDHint) (usbMouseSnapshot, bool) {
	deviceKey := firstNonEmptyTrim(record.Endpoint, buildUSBDeviceLabel(record.BusID, record.DeviceAddress))
	buttons := buildMouseButtons(parts)
	xDelta := parseUSBSignedInt(safeTrim(parts, usbFieldMouseXDelta))
	yDelta := parseUSBSignedInt(safeTrim(parts, usbFieldMouseYDelta))
	wheelVertical := parseUSBSignedInt(safeTrim(parts, usbFieldMouseWheelVertical))
	wheelHorizontal := parseUSBSignedInt(safeTrim(parts, usbFieldMouseWheelHorizontal))
	if len(buttons) > 0 || xDelta != 0 || yDelta != 0 || wheelVertical != 0 || wheelHorizontal != 0 {
		return usbMouseSnapshot{DeviceKey: deviceKey, Buttons: buttons, XDelta: xDelta, YDelta: yDelta, WheelVertical: wheelVertical, WheelHorizontal: wheelHorizontal}, true
	}
	if record.TransferType != "Interrupt" || hint.Keyboard {
		return usbMouseSnapshot{}, false
	}

	// Same raw usb.capdata fallback as keyboard: common boot mouse reports are
	// button bitmask, X, Y, optional vertical wheel and optional horizontal wheel.
	payload := decodeLooseHexToBytes(payloadRaw)
	if len(payload) >= 3 && len(payload) <= 5 {
		buttons, xDelta, yDelta, wheelVertical, wheelHorizontal = parseMouseBootPayload(payload)
		if len(buttons) > 0 || xDelta != 0 || yDelta != 0 || wheelVertical != 0 || wheelHorizontal != 0 || hint.Mouse {
			return usbMouseSnapshot{DeviceKey: deviceKey, Buttons: buttons, XDelta: xDelta, YDelta: yDelta, WheelVertical: wheelVertical, WheelHorizontal: wheelHorizontal}, true
		}
	}
	return usbMouseSnapshot{}, false
}

func buildUSBMouseEvent(record model.USBPacketRecord, previous usbMouseState, current usbMouseSnapshot) (model.USBMouseEvent, usbMouseState, bool) {
	nextState := usbMouseState{
		Buttons: copyStrings(current.Buttons),
		X:       previous.X + current.XDelta,
		Y:       previous.Y + current.YDelta,
	}
	pressedButtons := diffOrdered(current.Buttons, previous.Buttons)
	releasedButtons := diffOrdered(previous.Buttons, current.Buttons)
	if len(pressedButtons) == 0 && len(releasedButtons) == 0 && current.XDelta == 0 && current.YDelta == 0 && current.WheelVertical == 0 && current.WheelHorizontal == 0 {
		return model.USBMouseEvent{}, nextState, false
	}

	return model.USBMouseEvent{
		PacketID:        record.PacketID,
		Time:            record.Time,
		Device:          buildUSBDeviceLabel(record.BusID, record.DeviceAddress),
		Endpoint:        record.Endpoint,
		Buttons:         copyStrings(current.Buttons),
		PressedButtons:  pressedButtons,
		ReleasedButtons: releasedButtons,
		XDelta:          current.XDelta,
		YDelta:          current.YDelta,
		WheelVertical:   current.WheelVertical,
		WheelHorizontal: current.WheelHorizontal,
		PositionX:       nextState.X,
		PositionY:       nextState.Y,
		Summary:         buildMouseSummary(current.Buttons, pressedButtons, releasedButtons, current.XDelta, current.YDelta, current.WheelVertical, current.WheelHorizontal),
	}, nextState, true
}

func buildKeyboardModifiers(parts []string) []string {
	modifiers := make([]string, 0, 8)
	specs := []struct {
		index int
		label string
	}{
		{usbFieldKeyboardLeftCtrl, "Left Ctrl"},
		{usbFieldKeyboardLeftShift, "Left Shift"},
		{usbFieldKeyboardLeftAlt, "Left Alt"},
		{usbFieldKeyboardLeftGUI, "Left GUI"},
		{usbFieldKeyboardRightCtrl, "Right Ctrl"},
		{usbFieldKeyboardRightShift, "Right Shift"},
		{usbFieldKeyboardRightAlt, "Right Alt"},
		{usbFieldKeyboardRightGUI, "Right GUI"},
	}
	for _, spec := range specs {
		if parseUSBBool(safeTrim(parts, spec.index)) {
			modifiers = append(modifiers, spec.label)
		}
	}
	return modifiers
}

func buildKeyboardKeys(parts []string) []string {
	keys := make([]string, 0, 6)
	seen := make(map[string]struct{})
	for i := usbFieldKeyboardKey1; i <= usbFieldKeyboardKey6; i++ {
		label := keyboardKeyLabel(parseUSBInt(safeTrim(parts, i)))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		keys = append(keys, label)
	}
	return keys
}

func parseKeyboardBootPayload(payload []byte) ([]string, []string) {
	if len(payload) < 8 {
		return nil, nil
	}
	modifiers := keyboardModifiersFromMask(payload[0])
	keys := make([]string, 0, 6)
	seen := make(map[string]struct{})
	for _, code := range payload[2:8] {
		label := keyboardKeyLabel(int(code))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		keys = append(keys, label)
	}
	return modifiers, keys
}

func keyboardModifiersFromMask(mask byte) []string {
	labels := []string{"Left Ctrl", "Left Shift", "Left Alt", "Left GUI", "Right Ctrl", "Right Shift", "Right Alt", "Right GUI"}
	modifiers := make([]string, 0, len(labels))
	for bit, label := range labels {
		if mask&(1<<bit) != 0 {
			modifiers = append(modifiers, label)
		}
	}
	return modifiers
}

func isLikelyKeyboardBootReport(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	// The second byte is reserved in the HID boot keyboard report. This also
	// lets all-zero release/idle frames keep the endpoint classified as keyboard.
	if payload[1] != 0x00 {
		return false
	}
	for _, code := range payload[2:8] {
		if code == 0x00 {
			continue
		}
		if keyboardKeyLabel(int(code)) == "" {
			return false
		}
	}
	return true
}

func parseMouseBootPayload(payload []byte) ([]string, int, int, int, int) {
	if len(payload) < 3 {
		return nil, 0, 0, 0, 0
	}
	buttonLabels := []string{"Left", "Right", "Middle", "Button 4", "Button 5", "Button 6", "Button 7", "Button 8"}
	buttons := make([]string, 0, len(buttonLabels))
	for bit, label := range buttonLabels {
		if payload[0]&(1<<bit) != 0 {
			buttons = append(buttons, label)
		}
	}
	wheelVertical := 0
	wheelHorizontal := 0
	if len(payload) >= 4 {
		wheelVertical = int(int8(payload[3]))
	}
	if len(payload) >= 5 {
		wheelHorizontal = int(int8(payload[4]))
	}
	return buttons, int(int8(payload[1])), int(int8(payload[2])), wheelVertical, wheelHorizontal
}

func buildKeyboardSummary(currentModifiers, currentKeys, pressedModifiers, releasedModifiers, pressedKeys, releasedKeys []string, text string) string {
	parts := make([]string, 0, 4)
	if len(pressedModifiers) > 0 || len(pressedKeys) > 0 {
		pressed := append(copyStrings(pressedModifiers), pressedKeys...)
		parts = append(parts, "press "+strings.Join(pressed, " + "))
	}
	if len(releasedModifiers) > 0 || len(releasedKeys) > 0 {
		released := append(copyStrings(releasedModifiers), releasedKeys...)
		parts = append(parts, "release "+strings.Join(released, " + "))
	}
	if len(currentModifiers) > 0 || len(currentKeys) > 0 {
		current := append(copyStrings(currentModifiers), currentKeys...)
		parts = append(parts, "current="+strings.Join(current, " + "))
	}
	if text != "" {
		parts = append(parts, "text="+strconv.Quote(text))
	}
	if len(parts) == 0 {
		return "Keyboard event"
	}
	return strings.Join(parts, " / ")
}

func buildKeyboardText(modifiers, keys []string) string {
	if len(keys) == 0 || hasNonShiftModifier(modifiers) {
		return ""
	}
	shift := hasShiftModifier(modifiers)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		rendered := keyboardTextToken(key, shift)
		if rendered == "" {
			continue
		}
		parts = append(parts, rendered)
	}
	return strings.Join(parts, "")
}

func hasShiftModifier(modifiers []string) bool {
	for _, modifier := range modifiers {
		if strings.Contains(modifier, "Shift") {
			return true
		}
	}
	return false
}

func hasNonShiftModifier(modifiers []string) bool {
	for _, modifier := range modifiers {
		if !strings.Contains(modifier, "Shift") {
			return true
		}
	}
	return false
}

func keyboardTextToken(key string, shift bool) string {
	if len(key) == 1 && key[0] >= 'A' && key[0] <= 'Z' {
		if shift {
			return key
		}
		return strings.ToLower(key)
	}

	if len(key) == 1 && key[0] >= '0' && key[0] <= '9' {
		if !shift {
			return key
		}
		shiftedDigits := map[string]string{
			"1": "!",
			"2": "@",
			"3": "#",
			"4": "$",
			"5": "%",
			"6": "^",
			"7": "&",
			"8": "*",
			"9": "(",
			"0": ")",
		}
		return shiftedDigits[key]
	}

	switch key {
	case "Space":
		return " "
	case "Tab":
		return "\t"
	case "Enter":
		return "\n"
	case "-":
		if shift {
			return "_"
		}
		return "-"
	case "=":
		if shift {
			return "+"
		}
		return "="
	case "[":
		if shift {
			return "{"
		}
		return "["
	case "]":
		if shift {
			return "}"
		}
		return "]"
	case "\\":
		if shift {
			return "|"
		}
		return "\\"
	case ";":
		if shift {
			return ":"
		}
		return ";"
	case "'":
		if shift {
			return "\""
		}
		return "'"
	case ",":
		if shift {
			return "<"
		}
		return ","
	case ".":
		if shift {
			return ">"
		}
		return "."
	case "/":
		if shift {
			return "?"
		}
		return "/"
	case "`":
		if shift {
			return "~"
		}
		return "`"
	default:
		return ""
	}
}

func keyboardKeyLabel(code int) string {
	switch {
	case code >= 4 && code <= 29:
		return string(rune('A' + code - 4))
	case code >= 30 && code <= 38:
		return strconv.Itoa(code - 29)
	case code == 39:
		return "0"
	}

	switch code {
	case 0:
		return ""
	case 40:
		return "Enter"
	case 41:
		return "Esc"
	case 42:
		return "Backspace"
	case 43:
		return "Tab"
	case 44:
		return "Space"
	case 45:
		return "-"
	case 46:
		return "="
	case 47:
		return "["
	case 48:
		return "]"
	case 49:
		return "\\"
	case 51:
		return ";"
	case 52:
		return "'"
	case 53:
		return "`"
	case 54:
		return ","
	case 55:
		return "."
	case 56:
		return "/"
	case 57:
		return "CapsLock"
	case 58:
		return "F1"
	case 59:
		return "F2"
	case 60:
		return "F3"
	case 61:
		return "F4"
	case 62:
		return "F5"
	case 63:
		return "F6"
	case 64:
		return "F7"
	case 65:
		return "F8"
	case 66:
		return "F9"
	case 67:
		return "F10"
	case 68:
		return "F11"
	case 69:
		return "F12"
	case 79:
		return "Right"
	case 80:
		return "Left"
	case 81:
		return "Down"
	case 82:
		return "Up"
	default:
		return fmt.Sprintf("Keycode(%d)", code)
	}
}

func buildMouseButtons(parts []string) []string {
	buttons := make([]string, 0, 8)
	specs := []struct {
		index int
		label string
	}{
		{usbFieldMouseLeft, "Left"},
		{usbFieldMouseRight, "Right"},
		{usbFieldMouseMiddle, "Middle"},
		{usbFieldMouseButton4, "Button4"},
		{usbFieldMouseButton5, "Button5"},
		{usbFieldMouseButton6, "Button6"},
		{usbFieldMouseButton7, "Button7"},
		{usbFieldMouseButton8, "Button8"},
	}
	for _, spec := range specs {
		if parseUSBBool(safeTrim(parts, spec.index)) {
			buttons = append(buttons, spec.label)
		}
	}
	return buttons
}

func buildMouseSummary(currentButtons, pressedButtons, releasedButtons []string, xDelta, yDelta, wheelVertical, wheelHorizontal int) string {
	parts := make([]string, 0, 4)
	if len(pressedButtons) > 0 {
		parts = append(parts, "press="+strings.Join(pressedButtons, ", "))
	}
	if len(releasedButtons) > 0 {
		parts = append(parts, "release="+strings.Join(releasedButtons, ", "))
	}
	if xDelta != 0 || yDelta != 0 {
		parts = append(parts, fmt.Sprintf("move=(%+d,%+d)", xDelta, yDelta))
	}
	if wheelVertical != 0 || wheelHorizontal != 0 {
		parts = append(parts, fmt.Sprintf("wheel=(v=%+d,h=%+d)", wheelVertical, wheelHorizontal))
	}
	if len(currentButtons) > 0 {
		parts = append(parts, "current="+strings.Join(currentButtons, ", "))
	}
	if len(parts) == 0 {
		return "Mouse event"
	}
	return strings.Join(parts, " / ")
}

func parseUSBBool(raw string) bool {
	value := strings.TrimSpace(strings.ToLower(raw))
	return value == "1" || value == "true" || value == "yes"
}

func parseUSBSignedInt(raw string) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0
	}
	if parsed, err := strconv.Atoi(value); err == nil {
		return parsed
	}
	return 0
}

func looksLikeUSBRecord(protocol, busID, deviceAddress, endpointRaw, transferType, urbType string) bool {
	if strings.Contains(strings.ToLower(protocol), "usb") {
		return true
	}
	return busID != "" || deviceAddress != "" || endpointRaw != "" || transferType != "" || urbType != ""
}

func normalizeUSBProtocolLabel(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "USB"
	}
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(strings.ToLower(value), "hci_usb"):
		return "HCI_USB"
	case strings.Contains(strings.ToLower(value), "mausb"):
		return "MAUSB"
	case strings.Contains(strings.ToLower(value), "ippusb"):
		return "IPPUSB"
	case strings.Contains(strings.ToLower(value), "usb"):
		return upper
	default:
		return upper
	}
}

func normalizeUSBTransferType(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "0", "0x00", "isochronous":
		return "Isochronous"
	case "1", "0x01", "interrupt":
		return "Interrupt"
	case "2", "0x02", "control":
		return "Control"
	case "3", "0x03", "bulk":
		return "Bulk"
	case "":
		return ""
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func normalizeUSBUrbType(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "s":
		return "Submit"
	case "c":
		return "Complete"
	case "e":
		return "Error"
	case "":
		return ""
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func normalizeUSBStatus(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "unknown"
	}
	if parsed, err := strconv.Atoi(value); err == nil && parsed == 0 {
		return "ok"
	}
	return value
}

func normalizeUSBDirection(raw string, endpointRaw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "0", "out":
		return "OUT"
	case "1", "0x01", "128", "0x80", "in":
		return "IN"
	}
	if parsed, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(endpointRaw)), "0x"), 16, 64); err == nil {
		if parsed&0x80 != 0 {
			return "IN"
		}
		return "OUT"
	}
	return ""
}

func normalizeUSBSetupRequest(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "0", "0x00":
		return "GET_STATUS"
	case "1", "0x01":
		return "CLEAR_FEATURE"
	case "3", "0x03":
		return "SET_FEATURE"
	case "5", "0x05":
		return "SET_ADDRESS"
	case "6", "0x06":
		return "GET_DESCRIPTOR"
	case "7", "0x07":
		return "SET_DESCRIPTOR"
	case "8", "0x08":
		return "GET_CONFIGURATION"
	case "9", "0x09":
		return "SET_CONFIGURATION"
	case "10", "0x0a":
		return "GET_INTERFACE"
	case "11", "0x0b":
		return "SET_INTERFACE"
	case "12", "0x0c":
		return "SYNCH_FRAME"
	case "":
		return ""
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func buildUSBDeviceLabel(busID, deviceAddress string) string {
	if busID == "" && deviceAddress == "" {
		return ""
	}
	if busID == "" {
		return "Device " + deviceAddress
	}
	if deviceAddress == "" {
		return "Bus " + busID
	}
	return "Bus " + busID + " / Device " + deviceAddress
}

func buildUSBEndpointLabel(busID, deviceAddress, endpointRaw, direction string) string {
	endpoint := strings.TrimSpace(endpointRaw)
	if endpoint == "" {
		return buildUSBDeviceLabel(busID, deviceAddress)
	}
	label := buildUSBDeviceLabel(busID, deviceAddress)
	if label != "" {
		label += " / "
	}
	if direction != "" {
		return fmt.Sprintf("%sEP %s (%s)", label, endpoint, direction)
	}
	return label + "EP " + endpoint
}

func buildUSBSetupSummary(request, value, index, length string) string {
	if request == "" {
		return ""
	}
	parts := []string{request}
	if value != "" {
		parts = append(parts, "wValue="+value)
	}
	if index != "" {
		parts = append(parts, "wIndex="+index)
	}
	if length != "" {
		parts = append(parts, "wLength="+length)
	}
	return strings.Join(parts, " ")
}

func previewUSBPayload(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.Contains(value, ":") || strings.Contains(value, " ") {
		if decoded := decodeLooseHexToText(value); decoded != "" {
			return decoded
		}
	}
	if len(value) > 96 {
		return value[:96] + "..."
	}
	return value
}

func decodeLooseHexToText(raw string) string {
	decoded := decodeLooseHexToBytes(raw)
	if len(decoded) == 0 {
		return ""
	}
	printable := 0
	for _, b := range decoded {
		if b == '\r' || b == '\n' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	if len(decoded) == 0 || printable*100/len(decoded) < 75 {
		return ""
	}
	text := strings.TrimSpace(string(decoded))
	if len(text) > 96 {
		return text[:96] + "..."
	}
	return text
}

func decodeLooseHexToBytes(raw string) []byte {
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(strings.TrimSpace(raw))
	if len(cleaned) == 0 || len(cleaned)%2 != 0 {
		return nil
	}
	decoded := make([]byte, 0, len(cleaned)/2)
	for i := 0; i < len(cleaned); i += 2 {
		value, err := strconv.ParseUint(cleaned[i:i+2], 16, 8)
		if err != nil {
			return nil
		}
		decoded = append(decoded, byte(value))
	}
	return decoded
}

func buildUSBMassStoragePacketInfo(record model.USBPacketRecord, parts []string, payloadRaw, info string) usbMassStoragePacketInfo {
	cbwSignatureRaw := safeTrim(parts, usbFieldMassStorageCBWSignature)
	cbwTagRaw := safeTrim(parts, usbFieldMassStorageCBWTag)
	cbwTransferLength := parseFlexibleUSBInt(safeTrim(parts, usbFieldMassStorageCBWDataTransferLength))
	cbwFlagsRaw := safeTrim(parts, usbFieldMassStorageCBWFlags)
	cbwLUNRaw := safeTrim(parts, usbFieldMassStorageCBWLUN)
	cbwCBLength := parseFlexibleUSBInt(safeTrim(parts, usbFieldMassStorageCBWCBLength))
	cswSignatureRaw := safeTrim(parts, usbFieldMassStorageCSWSignature)
	cswStatusRaw := safeTrim(parts, usbFieldMassStorageCSWStatus)
	cswStatus := parseFlexibleUSBInt(cswStatusRaw)
	cswResidue := parseFlexibleUSBInt(safeTrim(parts, usbFieldMassStorageCSWDataResidue))
	scsiOpcodeRaw := safeTrim(parts, usbFieldSCSIOpcode)
	scsiLUNRaw := safeTrim(parts, usbFieldSCSILUN)
	scsiRequestFrame := parseUSBInt64(safeTrim(parts, usbFieldSCSIRequestFrame))
	scsiResponseFrame := parseUSBInt64(safeTrim(parts, usbFieldSCSIResponseFrame))
	scsiTime := parseUSBFloat(safeTrim(parts, usbFieldSCSITime))
	scsiStatus := safeTrim(parts, usbFieldSCSIStatus)
	infoLower := strings.ToLower(info)
	protocolLower := strings.ToLower(record.Protocol)

	active := cbwSignatureRaw != "" || cbwTagRaw != "" || cswSignatureRaw != "" || scsiOpcodeRaw != "" || scsiLUNRaw != "" || scsiRequestFrame > 0 || scsiResponseFrame > 0 || strings.Contains(protocolLower, "usbms") || strings.Contains(protocolLower, "scsi") || strings.Contains(infoLower, "mass storage") || strings.Contains(infoLower, "scsi")
	if !active {
		return usbMassStoragePacketInfo{}
	}

	cbw := parseUSBMassStorageCBW(payloadRaw)
	tag := normalizeUSBMassStorageTag(cbwTagRaw)
	if tag == "" && cbw.Valid {
		tag = normalizeUSBMassStorageTag(fmt.Sprintf("0x%08X", cbw.Tag))
	}

	lun := firstNonEmptyTrim(normalizeUSBMassStorageLUN(scsiLUNRaw), normalizeUSBMassStorageLUN(cbwLUNRaw))
	if lun == "" && cbw.Valid {
		lun = normalizeUSBMassStorageLUN(strconv.Itoa(int(cbw.LUN)))
	}

	direction := record.Direction
	if direction == "" && cbwFlagsRaw != "" {
		direction = usbMassStorageDirectionFromFlags(byte(parseFlexibleUSBInt(cbwFlagsRaw)))
	}
	if direction == "" && cbw.Valid {
		direction = usbMassStorageDirectionFromFlags(cbw.Flags)
	}

	if cbw.Valid {
		cbwTransferLength = maxInt(cbwTransferLength, cbw.TransferLength)
	}

	opcode := parseUSBMassStorageOpcode(scsiOpcodeRaw)
	if opcode < 0 && cbw.Valid && len(cbw.CDB) > 0 {
		opcode = int(cbw.CDB[0])
	}
	command := usbMassStorageCommandLabel(opcode)
	if command == "" && cbw.Valid && cbwCBLength > 0 {
		command = fmt.Sprintf("CDB(%d)", cbwCBLength)
	}
	operation := usbMassStorageOperationFromOpcode(opcode)
	if operation == "other" && cbwTransferLength > 0 {
		if direction == "IN" {
			operation = "read"
		} else if direction == "OUT" {
			operation = "write"
		}
	}

	status := normalizeUSBMassStorageStatus(scsiStatus, cswStatusRaw, cswStatus)
	requestFrame := scsiRequestFrame
	responseFrame := scsiResponseFrame
	isCommand := cbw.Valid || scsiOpcodeRaw != ""
	isCompletion := cswSignatureRaw != "" || strings.TrimSpace(cswStatusRaw) != "" || scsiRequestFrame > 0 || scsiTime > 0
	if isCommand && requestFrame == 0 {
		requestFrame = record.PacketID
	}
	if isCompletion && responseFrame == 0 {
		responseFrame = record.PacketID
	}
	if requestFrame == 0 && scsiRequestFrame > 0 {
		requestFrame = scsiRequestFrame
	}
	if responseFrame == 0 && scsiResponseFrame > 0 {
		responseFrame = scsiResponseFrame
	}

	transferLength := cbwTransferLength
	if transferLength == 0 {
		transferLength = record.DataLength
	}

	return usbMassStoragePacketInfo{
		PacketID:       record.PacketID,
		Time:           record.Time,
		Active:         true,
		IsControl:      record.TransferType == "Control" || strings.Contains(infoLower, "get max lun"),
		IsCommand:      isCommand,
		IsCompletion:   isCompletion,
		Tag:            tag,
		Device:         buildUSBDeviceLabel(record.BusID, record.DeviceAddress),
		Endpoint:       record.Endpoint,
		LUN:            lun,
		Command:        command,
		Operation:      operation,
		TransferLength: transferLength,
		Direction:      direction,
		Status:         status,
		DataResidue:    cswResidue,
		RequestFrame:   requestFrame,
		ResponseFrame:  responseFrame,
		LatencyMs:      scsiTime * 1000,
		Summary:        buildUSBMassStorageSummary(command, operation, lun, transferLength, status),
	}
}

func parseUSBMassStorageCBW(raw string) usbMassStorageCBW {
	payload := decodeLooseHexToBytes(raw)
	if len(payload) < 31 {
		return usbMassStorageCBW{}
	}
	if binary.LittleEndian.Uint32(payload[:4]) != 0x43425355 {
		return usbMassStorageCBW{}
	}
	cdbLength := int(payload[14] & 0x1F)
	if cdbLength > 16 {
		cdbLength = 16
	}
	cdb := make([]byte, 0, cdbLength)
	if cdbLength > 0 && len(payload) >= 15+cdbLength {
		cdb = append(cdb, payload[15:15+cdbLength]...)
	}
	return usbMassStorageCBW{
		Valid:          true,
		Tag:            binary.LittleEndian.Uint32(payload[4:8]),
		TransferLength: int(binary.LittleEndian.Uint32(payload[8:12])),
		Flags:          payload[12],
		LUN:            payload[13],
		CDB:            cdb,
	}
}

func consumeUSBMassStorageOperation(info usbMassStoragePacketInfo, pending map[string]*model.USBMassStorageOperation, analysis *model.USBMassStorageAnalysis) {
	if info.Operation != "read" && info.Operation != "write" {
		return
	}
	key := buildUSBMassStorageOperationKey(info)
	if key == "" {
		appendUSBMassStorageOperation(analysis, model.USBMassStorageOperation{
			PacketID:       info.PacketID,
			Time:           info.Time,
			Device:         info.Device,
			Endpoint:       info.Endpoint,
			LUN:            info.LUN,
			Command:        info.Command,
			Operation:      info.Operation,
			TransferLength: info.TransferLength,
			Direction:      info.Direction,
			Status:         info.Status,
			RequestFrame:   info.RequestFrame,
			ResponseFrame:  info.ResponseFrame,
			LatencyMs:      info.LatencyMs,
			DataResidue:    info.DataResidue,
			Summary:        info.Summary,
		})
		return
	}

	op := pending[key]
	if op == nil {
		packetID := info.PacketID
		if info.RequestFrame > 0 {
			packetID = info.RequestFrame
		}
		op = &model.USBMassStorageOperation{
			PacketID:       packetID,
			Time:           info.Time,
			Device:         info.Device,
			Endpoint:       info.Endpoint,
			LUN:            info.LUN,
			Command:        info.Command,
			Operation:      info.Operation,
			TransferLength: info.TransferLength,
			Direction:      info.Direction,
			Status:         info.Status,
			RequestFrame:   info.RequestFrame,
			ResponseFrame:  info.ResponseFrame,
			LatencyMs:      info.LatencyMs,
			DataResidue:    info.DataResidue,
			Summary:        info.Summary,
		}
		pending[key] = op
	} else {
		mergeUSBMassStorageOperation(op, info)
	}

	if info.IsCompletion || (info.ResponseFrame > 0 && op.RequestFrame > 0) {
		appendUSBMassStorageOperation(analysis, *op)
		delete(pending, key)
	}
}

func buildUSBMassStorageOperationKey(info usbMassStoragePacketInfo) string {
	deviceKey := firstNonEmptyTrim(info.Device, info.Endpoint)
	if deviceKey == "" {
		return ""
	}
	if info.Tag != "" {
		return deviceKey + "|tag|" + info.Tag
	}
	if info.RequestFrame > 0 {
		return fmt.Sprintf("%s|req|%d", deviceKey, info.RequestFrame)
	}
	if info.ResponseFrame > 0 {
		return fmt.Sprintf("%s|resp|%d", deviceKey, info.ResponseFrame)
	}
	return ""
}

func mergeUSBMassStorageOperation(op *model.USBMassStorageOperation, info usbMassStoragePacketInfo) {
	if op.Device == "" {
		op.Device = info.Device
	}
	if op.Endpoint == "" {
		op.Endpoint = info.Endpoint
	}
	if op.LUN == "" {
		op.LUN = info.LUN
	}
	if op.Command == "" {
		op.Command = info.Command
	}
	if op.Direction == "" {
		op.Direction = info.Direction
	}
	if op.Status == "" || op.Status == "unknown" {
		op.Status = info.Status
	}
	if op.TransferLength == 0 {
		op.TransferLength = info.TransferLength
	}
	if op.RequestFrame == 0 {
		op.RequestFrame = info.RequestFrame
	}
	if info.ResponseFrame > 0 {
		op.ResponseFrame = info.ResponseFrame
	}
	if info.LatencyMs > 0 {
		op.LatencyMs = info.LatencyMs
	}
	if info.DataResidue > 0 {
		op.DataResidue = info.DataResidue
	}
	if info.Summary != "" {
		op.Summary = info.Summary
	}
}

func appendUSBMassStorageOperation(analysis *model.USBMassStorageAnalysis, op model.USBMassStorageOperation) {
	if op.PacketID == 0 {
		if op.RequestFrame > 0 {
			op.PacketID = op.RequestFrame
		} else if op.ResponseFrame > 0 {
			op.PacketID = op.ResponseFrame
		}
	}
	if op.Summary == "" {
		op.Summary = buildUSBMassStorageSummary(op.Command, op.Operation, op.LUN, op.TransferLength, op.Status)
	}
	switch op.Operation {
	case "read":
		if len(analysis.ReadOperations) < usbRecordLimit {
			analysis.ReadOperations = append(analysis.ReadOperations, op)
		}
	case "write":
		if len(analysis.WriteOperations) < usbRecordLimit {
			analysis.WriteOperations = append(analysis.WriteOperations, op)
		}
	}
}

func flushUSBMassStorageOperations(pending map[string]*model.USBMassStorageOperation, analysis *model.USBMassStorageAnalysis) {
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appendUSBMassStorageOperation(analysis, *pending[key])
	}
}

func normalizeUSBMassStorageTag(raw string) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "0x") {
		if parsed, err := strconv.ParseUint(strings.TrimPrefix(trimmed, "0x"), 16, 32); err == nil {
			return fmt.Sprintf("0x%08X", parsed)
		}
	}
	if parsed, err := strconv.ParseUint(trimmed, 10, 32); err == nil {
		return fmt.Sprintf("0x%08X", parsed)
	}
	if parsed, err := strconv.ParseUint(trimmed, 16, 32); err == nil {
		return fmt.Sprintf("0x%08X", parsed)
	}
	return strings.ToUpper(trimmed)
}

func normalizeUSBMassStorageLUN(raw string) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("LUN %d", parseFlexibleUSBInt(trimmed))
}

func usbMassStorageDirectionFromFlags(flags byte) string {
	if flags&0x80 != 0 {
		return "IN"
	}
	return "OUT"
}

func parseUSBMassStorageOpcode(raw string) int {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return -1
	}
	if strings.HasPrefix(trimmed, "0x") {
		if parsed, err := strconv.ParseInt(strings.TrimPrefix(trimmed, "0x"), 16, 64); err == nil {
			return int(parsed)
		}
	}
	if parsed, err := strconv.Atoi(trimmed); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseInt(trimmed, 16, 64); err == nil {
		return int(parsed)
	}
	return -1
}

func usbMassStorageCommandLabel(opcode int) string {
	switch opcode {
	case 0x08:
		return "READ(6)"
	case 0x0A:
		return "WRITE(6)"
	case 0x12:
		return "INQUIRY"
	case 0x1A:
		return "MODE SENSE(6)"
	case 0x1B:
		return "START STOP UNIT"
	case 0x23:
		return "READ FORMAT CAPACITIES"
	case 0x25:
		return "READ CAPACITY(10)"
	case 0x28:
		return "READ(10)"
	case 0x2A:
		return "WRITE(10)"
	case 0x35:
		return "SYNCHRONIZE CACHE(10)"
	case 0x5A:
		return "MODE SENSE(10)"
	case 0x88:
		return "READ(16)"
	case 0x8A:
		return "WRITE(16)"
	default:
		if opcode < 0 {
			return ""
		}
		return fmt.Sprintf("OPCODE(0x%02X)", opcode)
	}
}

func usbMassStorageOperationFromOpcode(opcode int) string {
	switch opcode {
	case 0x08, 0x28, 0x88:
		return "read"
	case 0x0A, 0x2A, 0x8A:
		return "write"
	default:
		return "other"
	}
}

func normalizeUSBMassStorageStatus(scsiStatus, cswStatusRaw string, cswStatus int) string {
	status := strings.TrimSpace(strings.ToLower(scsiStatus))
	if status != "" {
		return status
	}
	if strings.TrimSpace(cswStatusRaw) == "" {
		return ""
	}
	switch cswStatus {
	case 0:
		return "ok"
	case 1:
		return "failed"
	case 2:
		return "phase_error"
	default:
		return "unknown"
	}
}

func buildUSBMassStorageSummary(command, operation, lun string, transferLength int, status string) string {
	parts := make([]string, 0, 5)
	if command != "" {
		parts = append(parts, command)
	}
	if operation != "" && operation != "other" {
		parts = append(parts, "op="+operation)
	}
	if lun != "" {
		parts = append(parts, lun)
	}
	if transferLength > 0 {
		parts = append(parts, fmt.Sprintf("len=%d", transferLength))
	}
	if status != "" {
		parts = append(parts, "status="+status)
	}
	if len(parts) == 0 {
		return "Mass Storage operation"
	}
	return strings.Join(parts, " / ")
}

func buildUSBHIDNotes(analysis model.USBAnalysis) []string {
	notes := make([]string, 0, 4)
	if analysis.KeyboardPackets > 0 {
		notes = append(notes, fmt.Sprintf("识别到 %d 条键盘行为事件。", analysis.KeyboardPackets))
	}
	if analysis.MousePackets > 0 {
		notes = append(notes, fmt.Sprintf("识别到 %d 条鼠标行为事件。", analysis.MousePackets))
	}
	if len(analysis.HID.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("最活跃 HID 设备为 %s。", analysis.HID.Devices[0].Label))
	}
	if len(notes) == 0 {
		return []string{"当前抓包未识别到可展示的 HID 行为事件。"}
	}
	return notes
}

func buildUSBMassStorageNotes(analysis model.USBMassStorageAnalysis, residueCount, errorStatuses int) []string {
	notes := make([]string, 0, 5)
	if analysis.TotalPackets == 0 {
		return []string{"当前抓包未识别到 USB Mass Storage / SCSI 流量。"}
	}
	if analysis.ReadPackets > 0 {
		notes = append(notes, fmt.Sprintf("识别到 %d 条存储读请求。", analysis.ReadPackets))
	}
	if analysis.WritePackets > 0 {
		notes = append(notes, fmt.Sprintf("识别到 %d 条存储写请求。", analysis.WritePackets))
	}
	if len(analysis.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("最活跃存储设备为 %s。", analysis.Devices[0].Label))
	}
	if residueCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条带有 Data Residue 的存储事务。", residueCount))
	}
	if errorStatuses > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条非正常 Mass Storage 状态。", errorStatuses))
	}
	return notes
}

func buildUSBOtherNotes(analysis model.USBOtherAnalysis) []string {
	notes := make([]string, 0, 3)
	if analysis.TotalPackets == 0 {
		return []string{"当前抓包未识别到其他 USB 流量。"}
	}
	if analysis.ControlPackets > 0 {
		notes = append(notes, fmt.Sprintf("其中 %d 条为控制请求。", analysis.ControlPackets))
	}
	if len(analysis.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("最活跃其他 USB 设备为 %s。", analysis.Devices[0].Label))
	}
	if len(notes) == 0 {
		notes = append(notes, fmt.Sprintf("其余 USB 包共 %d 条。", analysis.TotalPackets))
	}
	return notes
}

func appendUSBOtherRecord(analysis *model.USBAnalysis, record model.USBPacketRecord) {
	analysis.OtherUSBPackets++
	analysis.Other.TotalPackets++
	if record.TransferType == "Control" || record.SetupRequest != "" {
		analysis.Other.ControlPackets++
		if len(analysis.Other.ControlRecords) < usbRecordLimit {
			analysis.Other.ControlRecords = append(analysis.Other.ControlRecords, record)
		}
	}
	if len(analysis.OtherRecords) < usbRecordLimit {
		analysis.OtherRecords = append(analysis.OtherRecords, record)
	}
	if len(analysis.Other.Records) < usbRecordLimit {
		analysis.Other.Records = append(analysis.Other.Records, record)
	}
}

func buildUSBAnalysisNotes(analysis model.USBAnalysis, statusMap map[string]int) []string {
	notes := make([]string, 0, 8)
	if analysis.TotalUSBPackets == 0 {
		return []string{"当前抓包中未检测到 USB 相关流量。"}
	}
	if analysis.HIDPackets > 0 {
		notes = append(notes, fmt.Sprintf("HID 域包含 %d 条行为事件，已拆分为键盘与鼠标子页。", analysis.HIDPackets))
	}
	if analysis.MassStoragePackets > 0 {
		notes = append(notes, fmt.Sprintf("Mass Storage 域包含 %d 条相关包，可进一步审阅读写请求。", analysis.MassStoragePackets))
	}
	if analysis.OtherUSBPackets > 0 {
		notes = append(notes, fmt.Sprintf("其他域包含 %d 条 USB 包，已拆分为概览、控制请求与原始记录。", analysis.OtherUSBPackets))
	}
	if len(analysis.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("当前最活跃的 USB 设备是 %s。", analysis.Devices[0].Label))
	}
	if len(analysis.TransferTypes) > 0 {
		notes = append(notes, fmt.Sprintf("主要传输类型为 %s，共 %d 条。", analysis.TransferTypes[0].Label, analysis.TransferTypes[0].Count))
	}
	if statusMap["ok"] > 0 {
		notes = append(notes, fmt.Sprintf("状态正常的 USB URB 有 %d 条。", statusMap["ok"]))
	}
	errorCount := analysis.TotalUSBPackets - statusMap["ok"] - statusMap["unknown"]
	if errorCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条非正常 USB 传输状态，建议优先检查异常 URB。", errorCount))
	}
	if analysis.TotalUSBPackets > len(analysis.Records) {
		notes = append(notes, fmt.Sprintf("通用记录列表已截断为前 %d 条，但顶部统计覆盖全部 USB 包。", len(analysis.Records)))
	}
	return notes
}

func diffOrdered(source, target []string) []string {
	set := make(map[string]struct{}, len(target))
	for _, item := range target {
		set[item] = struct{}{}
	}
	out := make([]string, 0, len(source))
	for _, item := range source {
		if _, ok := set[item]; ok {
			continue
		}
		out = append(out, item)
	}
	return out
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func parseFlexibleUSBInt(raw string) int {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return 0
	}
	if strings.HasPrefix(trimmed, "0x") {
		if parsed, err := strconv.ParseInt(strings.TrimPrefix(trimmed, "0x"), 16, 64); err == nil {
			return int(parsed)
		}
	}
	if parsed, err := strconv.Atoi(trimmed); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseInt(trimmed, 16, 64); err == nil {
		return int(parsed)
	}
	return 0
}

func parseUSBFloat(raw string) float64 {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0
	}
	return value
}

func firstNonEmptyTrim(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func parseUSBInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return value
}

func parseUSBInt64(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
