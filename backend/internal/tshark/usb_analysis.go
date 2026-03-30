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

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 18 {
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
		info := safeTrim(parts, 19)

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

		if len(analysis.Records) >= usbRecordLimit {
			continue
		}

		analysis.Records = append(analysis.Records, model.USBPacketRecord{
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
		})
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
	if parsed, err := strconv.Atoi(value); err == nil {
		if parsed == 0 {
			return "ok"
		}
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
	return "EP " + endpoint
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
	notes := make([]string, 0, 6)
	if analysis.TotalUSBPackets == 0 {
		return []string{"当前抓包中未检测到 USB 相关流量。"}
	}
	if len(analysis.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("共识别到 %d 个活跃 USB 设备视角，最活跃对象为 %s。", len(analysis.Devices), analysis.Devices[0].Label))
	}
	if len(analysis.TransferTypes) > 0 {
		notes = append(notes, fmt.Sprintf("主要传输类型为 %s，共 %d 条。", analysis.TransferTypes[0].Label, analysis.TransferTypes[0].Count))
	}
	if statusMap["ok"] > 0 {
		notes = append(notes, fmt.Sprintf("状态正常的 USB URB 有 %d 条。", statusMap["ok"]))
	}
	errorCount := analysis.TotalUSBPackets - statusMap["ok"] - statusMap["unknown"]
	if errorCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条非正常 USB 传输状态，建议优先审计异常 URB。", errorCount))
	}
	if len(analysis.SetupRequests) > 0 {
		notes = append(notes, fmt.Sprintf("控制请求中最常见的是 %s。", analysis.SetupRequests[0].Label))
	}
	if analysis.TotalUSBPackets > len(analysis.Records) {
		notes = append(notes, fmt.Sprintf("明细表已截断为前 %d 条 USB 记录，顶部统计仍覆盖全部 USB 包。", len(analysis.Records)))
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
