package tshark

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

const usbRecordLimit = 2000

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
	keyboardSignatureByDevice := make(map[string]string)
	mousePositionByDevice := make(map[string][2]int)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 46 {
			continue
		}

		protocol := normalizeUSBProtocolLabel(safeTrim(parts, 2))
		busID := safeTrim(parts, 3)
		deviceAddress := safeTrim(parts, 4)
		endpointRaw := safeTrim(parts, 5)
		endpointDirection := firstNonEmpty(safeTrim(parts, 6), safeTrim(parts, 7))
		transferType := normalizeUSBTransferType(safeTrim(parts, 8))
		urbType := normalizeUSBUrbType(safeTrim(parts, 9))
		status := normalizeUSBStatus(safeTrim(parts, 10))
		dataLength := parseUSBInt(safeTrim(parts, 11))
		setupRequest := normalizeUSBSetupRequest(safeTrim(parts, 12))
		setupValue := safeTrim(parts, 13)
		setupIndex := safeTrim(parts, 14)
		setupLength := safeTrim(parts, 15)
		payloadRaw := firstNonEmpty(safeTrim(parts, 16), safeTrim(parts, 17), safeTrim(parts, 18))
		info := safeTrim(parts, 45)

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
			PacketID:       parseUSBInt64(safeTrim(parts, 0)),
			Time:           normalizeTimestamp(safeTrim(parts, 1)),
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
			Summary:        firstNonEmpty(info, transferType, protocol, "USB packet"),
		}

		if len(analysis.Records) < usbRecordLimit {
			analysis.Records = append(analysis.Records, record)
		}

		if keyboardEvent, ok := buildUSBKeyboardEvent(record, parts, keyboardSignatureByDevice); ok {
			analysis.KeyboardPackets++
			if len(analysis.KeyboardEvents) < usbRecordLimit {
				analysis.KeyboardEvents = append(analysis.KeyboardEvents, keyboardEvent)
			}
			continue
		}

		if mouseEvent, ok := buildUSBMouseEvent(record, parts, mousePositionByDevice); ok {
			analysis.MousePackets++
			if len(analysis.MouseEvents) < usbRecordLimit {
				analysis.MouseEvents = append(analysis.MouseEvents, mouseEvent)
			}
			continue
		}

		analysis.OtherUSBPackets++
		if len(analysis.OtherRecords) < usbRecordLimit {
			analysis.OtherRecords = append(analysis.OtherRecords, record)
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
	analysis.Notes = buildUSBAnalysisNotes(analysis, statusMap)
	return analysis, nil
}

func buildUSBKeyboardEvent(record model.USBPacketRecord, parts []string, signatureByDevice map[string]string) (model.USBKeyboardEvent, bool) {
	modifiers := buildKeyboardModifiers(parts)
	keys := buildKeyboardKeys(parts)
	deviceKey := record.Endpoint
	if deviceKey == "" {
		deviceKey = buildUSBDeviceLabel(record.BusID, record.DeviceAddress)
	}

	if len(modifiers) == 0 && len(keys) == 0 {
		signatureByDevice[deviceKey] = ""
		return model.USBKeyboardEvent{}, false
	}

	signature := buildKeyboardSignature(modifiers, keys)
	if signatureByDevice[deviceKey] == signature {
		return model.USBKeyboardEvent{}, false
	}
	signatureByDevice[deviceKey] = signature

	text := buildKeyboardText(modifiers, keys)
	summary := buildKeyboardSummary(modifiers, keys, text)

	return model.USBKeyboardEvent{
		PacketID:  record.PacketID,
		Time:      record.Time,
		Device:    buildUSBDeviceLabel(record.BusID, record.DeviceAddress),
		Endpoint:  record.Endpoint,
		Modifiers: modifiers,
		Keys:      keys,
		Text:      text,
		Summary:   summary,
	}, true
}

func buildUSBMouseEvent(record model.USBPacketRecord, parts []string, positionByDevice map[string][2]int) (model.USBMouseEvent, bool) {
	buttons := buildMouseButtons(parts)
	xDelta := parseUSBSignedInt(safeTrim(parts, 41))
	yDelta := parseUSBSignedInt(safeTrim(parts, 42))
	wheelVertical := parseUSBSignedInt(safeTrim(parts, 43))
	wheelHorizontal := parseUSBSignedInt(safeTrim(parts, 44))

	if len(buttons) == 0 && xDelta == 0 && yDelta == 0 && wheelVertical == 0 && wheelHorizontal == 0 {
		return model.USBMouseEvent{}, false
	}

	deviceKey := record.Endpoint
	if deviceKey == "" {
		deviceKey = buildUSBDeviceLabel(record.BusID, record.DeviceAddress)
	}

	position := positionByDevice[deviceKey]
	position[0] += xDelta
	position[1] += yDelta
	positionByDevice[deviceKey] = position

	return model.USBMouseEvent{
		PacketID:        record.PacketID,
		Time:            record.Time,
		Device:          buildUSBDeviceLabel(record.BusID, record.DeviceAddress),
		Endpoint:        record.Endpoint,
		Buttons:         buttons,
		XDelta:          xDelta,
		YDelta:          yDelta,
		WheelVertical:   wheelVertical,
		WheelHorizontal: wheelHorizontal,
		PositionX:       position[0],
		PositionY:       position[1],
		Summary:         buildMouseSummary(buttons, xDelta, yDelta, wheelVertical, wheelHorizontal),
	}, true
}

func buildKeyboardModifiers(parts []string) []string {
	modifiers := make([]string, 0, 8)
	specs := []struct {
		index int
		label string
	}{
		{25, "Left Ctrl"},
		{26, "Left Shift"},
		{27, "Left Alt"},
		{28, "Left GUI"},
		{29, "Right Ctrl"},
		{30, "Right Shift"},
		{31, "Right Alt"},
		{32, "Right GUI"},
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
	for i := 19; i <= 24; i++ {
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

func buildKeyboardSignature(modifiers, keys []string) string {
	if len(modifiers) == 0 && len(keys) == 0 {
		return ""
	}
	all := make([]string, 0, len(modifiers)+len(keys))
	all = append(all, modifiers...)
	all = append(all, keys...)
	return strings.Join(all, "|")
}

func buildKeyboardSummary(modifiers, keys []string, text string) string {
	combo := append([]string{}, modifiers...)
	combo = append(combo, keys...)
	if len(combo) == 0 {
		return "Keyboard event"
	}
	if text != "" && text != strings.Join(keys, " ") {
		return strings.Join(combo, " + ") + " => " + text
	}
	return strings.Join(combo, " + ")
}

func buildKeyboardText(modifiers, keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	shift := false
	for _, modifier := range modifiers {
		if strings.Contains(modifier, "Shift") {
			shift = true
			break
		}
	}
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
		{33, "Left"},
		{34, "Right"},
		{35, "Middle"},
		{36, "Button4"},
		{37, "Button5"},
		{38, "Button6"},
		{39, "Button7"},
		{40, "Button8"},
	}
	for _, spec := range specs {
		if parseUSBBool(safeTrim(parts, spec.index)) {
			buttons = append(buttons, spec.label)
		}
	}
	return buttons
}

func buildMouseSummary(buttons []string, xDelta, yDelta, wheelVertical, wheelHorizontal int) string {
	parts := make([]string, 0, 4)
	if xDelta != 0 || yDelta != 0 {
		parts = append(parts, fmt.Sprintf("move (%+d, %+d)", xDelta, yDelta))
	}
	if wheelVertical != 0 || wheelHorizontal != 0 {
		parts = append(parts, fmt.Sprintf("wheel (v=%+d, h=%+d)", wheelVertical, wheelHorizontal))
	}
	if len(buttons) > 0 {
		parts = append(parts, "buttons="+strings.Join(buttons, ", "))
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
	if strings.Contains(value, ":") {
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
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(strings.TrimSpace(raw))
	if len(cleaned) == 0 || len(cleaned)%2 != 0 {
		return ""
	}
	decoded := make([]byte, 0, len(cleaned)/2)
	for i := 0; i < len(cleaned); i += 2 {
		value, err := strconv.ParseUint(cleaned[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		decoded = append(decoded, byte(value))
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

func buildUSBAnalysisNotes(analysis model.USBAnalysis, statusMap map[string]int) []string {
	notes := make([]string, 0, 8)
	if analysis.TotalUSBPackets == 0 {
		return []string{"当前抓包中未检测到 USB 相关流量。"}
	}
	if analysis.KeyboardPackets > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条键盘 HID 输入事件，可在“键盘”标签页查看按键序列。", analysis.KeyboardPackets))
	}
	if analysis.MousePackets > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条鼠标 HID 事件，可在“鼠标”标签页查看轨迹与按钮活动。", analysis.MousePackets))
	}
	if analysis.OtherUSBPackets > 0 {
		notes = append(notes, fmt.Sprintf("其余 USB 事件共 %d 条，集中展示在“其余 USB”标签页。", analysis.OtherUSBPackets))
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
