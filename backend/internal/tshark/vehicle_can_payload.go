package tshark

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func scanCANPayloadAnalysis(filePath string) ([]model.TrafficBucket, []model.CANPayloadRecord, error) {
	fields := []string{
		"frame.number",
		"frame.time_epoch",
		"frame.protocols",
		"_ws.col.Protocol",
		"_ws.col.Info",
		"can.bus_id",
		"can.id",
		"can.len",
		"data.data",
		"iso15765.address",
		"iso15765.target_address",
		"iso15765.source_address",
		"iso15765.message_type",
		"iso15765.data_length_8bit",
		"iso15765.data_length_4bit",
		"iso15765.frame_length_32bit",
		"iso15765.frame_length_12bit",
		"iso15765.sequence_number",
		"iso15765.flow_status",
		"iso15765.flow_control.bs",
		"iso15765.flow_control.stmin",
		"iso15765.segment_data",
		"uds.sid",
		"uds.subfunction",
		"uds.reply",
		"uds.err.code",
		"uds.rdbi.data_identifier",
		"uds.rdtci.dtc_id",
		"obdii.padding",
		"canopen.cob_id",
		"canopen.function_code",
		"canopen.node_id",
		"canopen.pdo.data.bytes",
		"canopen.sdo.main_idx",
		"canopen.sdo.sub_idx",
		"canopen.sdo.data.bytes",
		"canopen.em.err_code",
		"canopen.sdo.abort_code",
	}

	protocolMap := make(map[string]int)
	records := make([]model.CANPayloadRecord, 0, 128)

	err := scanFieldRows(filePath, fields, func(parts []string) {
		protoPath := strings.ToLower(safeTrim(parts, 2))
		displayProto := strings.ToLower(safeTrim(parts, 3))
		info := safeTrim(parts, 4)
		busID := formatHex(safeTrim(parts, 5))
		identifier := formatHex(safeTrim(parts, 6))
		length := parseInt(safeTrim(parts, 7))
		rawData := firstNonEmpty(
			normalizeHexBytes(safeTrim(parts, 21)),
			normalizeHexBytes(safeTrim(parts, 35)),
			normalizeHexBytes(safeTrim(parts, 32)),
			normalizeHexBytes(safeTrim(parts, 8)),
		)

		hasISOTP := safeTrim(parts, 12) != "" || safeTrim(parts, 21) != "" || strings.Contains(protoPath, "iso15765")
		hasUDS := safeTrim(parts, 22) != "" || strings.Contains(protoPath, "uds")
		hasOBD := safeTrim(parts, 28) != "" || strings.Contains(protoPath, "obd-ii") || strings.Contains(displayProto, "obd")
		hasCANopen := safeTrim(parts, 29) != "" || safeTrim(parts, 30) != "" || strings.Contains(protoPath, "canopen")
		if !hasISOTP && !hasUDS && !hasOBD && !hasCANopen {
			return
		}

		packetID := parseInt64(safeTrim(parts, 0))
		packetTime := normalizeTimestamp(safeTrim(parts, 1))
		sourceAddress := firstNonEmpty(formatHex(safeTrim(parts, 11)), formatHex(safeTrim(parts, 9)))
		targetAddress := formatHex(safeTrim(parts, 10))

		if hasISOTP {
			protocolMap["ISO-TP"]++
		}
		if hasCANopen {
			protocolMap["CANopen"]++
			records = append(records, model.CANPayloadRecord{
				PacketID:      packetID,
				Time:          packetTime,
				BusID:         busID,
				Identifier:    firstNonEmpty(identifier, formatHex(safeTrim(parts, 29))),
				Protocol:      "CANopen",
				FrameType:     canopenFunctionName(safeTrim(parts, 30)),
				SourceAddress: "",
				TargetAddress: nonEmptyPrefixed("Node", formatHex(safeTrim(parts, 31))),
				Service:       canopenServiceLabel(parts),
				Detail:        compactJoin(" / ", canopenObjectIndex(safeTrim(parts, 33), safeTrim(parts, 34)), firstNonEmpty(nonEmptyPrefixed("Abort", formatHex(safeTrim(parts, 37))), nonEmptyPrefixed("EMCY", formatHex(safeTrim(parts, 36))))),
				Length:        length,
				RawData:       rawData,
				Summary:       info,
			})
			return
		}

		if hasUDS {
			sid := formatHex(safeTrim(parts, 22))
			service := compactJoin(" ", sid, udsServiceName(sid))
			protocolMap["UDS"]++
			records = append(records, model.CANPayloadRecord{
				PacketID:      packetID,
				Time:          packetTime,
				BusID:         busID,
				Identifier:    identifier,
				Protocol:      "UDS",
				FrameType:     isoTPFrameType(safeTrim(parts, 12), safeTrim(parts, 17), safeTrim(parts, 18)),
				SourceAddress: sourceAddress,
				TargetAddress: targetAddress,
				Service:       service,
				Detail: compactJoin(" / ",
					nonEmptyPrefixed("Sub", formatHex(safeTrim(parts, 23))),
					nonEmptyPrefixed("DID", formatHex(safeTrim(parts, 26))),
					nonEmptyPrefixed("DTC", formatHex(safeTrim(parts, 27))),
					nonEmptyPrefixed("NRC", formatHex(safeTrim(parts, 25))),
					boolLabel(parseTruthy(safeTrim(parts, 24)), "Reply"),
				),
				Length:  resolveISOTPLength(parts),
				RawData: rawData,
				Summary: info,
			})
			return
		}

		if hasOBD {
			service, detail := decodeOBDPayload(firstNonEmpty(safeTrim(parts, 21), safeTrim(parts, 8)))
			protocolMap["OBD-II"]++
			records = append(records, model.CANPayloadRecord{
				PacketID:      packetID,
				Time:          packetTime,
				BusID:         busID,
				Identifier:    identifier,
				Protocol:      "OBD-II",
				FrameType:     isoTPFrameType(safeTrim(parts, 12), safeTrim(parts, 17), safeTrim(parts, 18)),
				SourceAddress: sourceAddress,
				TargetAddress: targetAddress,
				Service:       service,
				Detail:        detail,
				Length:        resolveISOTPLength(parts),
				RawData:       rawData,
				Summary:       info,
			})
			return
		}

		if hasISOTP {
			records = append(records, model.CANPayloadRecord{
				PacketID:      packetID,
				Time:          packetTime,
				BusID:         busID,
				Identifier:    identifier,
				Protocol:      "ISO-TP",
				FrameType:     isoTPFrameType(safeTrim(parts, 12), safeTrim(parts, 17), safeTrim(parts, 18)),
				SourceAddress: sourceAddress,
				TargetAddress: targetAddress,
				Service:       compactJoin(" / ", nonEmptyPrefixed("Len", firstNonEmpty(safeTrim(parts, 13), safeTrim(parts, 14), safeTrim(parts, 15), safeTrim(parts, 16))), flowControlLabel(safeTrim(parts, 18), safeTrim(parts, 19), safeTrim(parts, 20))),
				Detail:        compactJoin(" / ", nonEmptyPrefixed("Seq", formatHex(safeTrim(parts, 17))), nonEmptyPrefixed("Addr", formatHex(safeTrim(parts, 9)))),
				Length:        resolveISOTPLength(parts),
				RawData:       rawData,
				Summary:       info,
			})
		}
	})
	if err != nil {
		return nil, nil, err
	}

	return topBuckets(protocolMap, 0), records, nil
}

func resolveISOTPLength(parts []string) int {
	for _, idx := range []int{15, 16, 13, 14, 7} {
		if value := parseInt(safeTrim(parts, idx)); value > 0 {
			return value
		}
	}
	return 0
}

func isoTPFrameType(messageType, sequenceNumber, flowStatus string) string {
	switch strings.ToUpper(strings.TrimSpace(messageType)) {
	case "0X0":
		return "Single Frame"
	case "0X10":
		return "First Frame"
	case "0X20":
		if strings.TrimSpace(sequenceNumber) != "" {
			return "Consecutive Frame " + formatHex(sequenceNumber)
		}
		return "Consecutive Frame"
	case "0X30":
		return firstNonEmpty(flowControlLabel(flowStatus, "", ""), "Flow Control")
	default:
		if strings.TrimSpace(messageType) == "" {
			return ""
		}
		return "PCI " + strings.ToUpper(strings.TrimSpace(messageType))
	}
}

func flowControlLabel(flowStatus, blockSize, stmin string) string {
	switch strings.ToUpper(strings.TrimSpace(flowStatus)) {
	case "0X0":
		return compactJoin(" / ", "FC Continue To Send", nonEmptyPrefixed("BS", blockSize), nonEmptyPrefixed("STmin", stmin))
	case "0X1":
		return compactJoin(" / ", "FC Wait", nonEmptyPrefixed("BS", blockSize), nonEmptyPrefixed("STmin", stmin))
	case "0X2":
		return "FC Overflow"
	default:
		return ""
	}
}

func decodeOBDPayload(raw string) (string, string) {
	bytes := splitHexBytes(raw)
	if len(bytes) == 0 {
		return "OBD-II", ""
	}
	modeByte := parseHexByte(bytes[0])
	reply := false
	if modeByte >= 0x40 {
		reply = true
		modeByte -= 0x40
	}
	service := fmt.Sprintf("Mode %02X %s", modeByte, obdModeName(modeByte))
	if reply {
		service += " Response"
	}
	if len(bytes) < 2 {
		return service, previewHexBytes(raw, 12)
	}
	pid := bytes[1]
	detail := compactJoin(" / ",
		nonEmptyPrefixed("PID", strings.ToUpper(pid)),
		obdPIDName(modeByte, pid),
	)
	if len(bytes) > 2 {
		detail = compactJoin(" / ", detail, "Data "+strings.Join(bytes[2:], " "))
	}
	return service, detail
}

func parseHexByte(raw string) int {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(raw), "0X"))
	if raw == "" {
		return 0
	}
	if value, err := strconv.ParseInt(raw, 16, 64); err == nil {
		return int(value)
	}
	return parseFlexibleInt(raw)
}

func obdModeName(mode int) string {
	switch mode {
	case 0x01:
		return "Current Data"
	case 0x02:
		return "Freeze Frame"
	case 0x03:
		return "Stored DTC"
	case 0x04:
		return "Clear DTC"
	case 0x05:
		return "O2 Sensor Test"
	case 0x06:
		return "On-Board Monitoring"
	case 0x07:
		return "Pending DTC"
	case 0x08:
		return "Control Operation"
	case 0x09:
		return "Vehicle Information"
	case 0x0A:
		return "Permanent DTC"
	default:
		return "OBD Service"
	}
}

func obdPIDName(mode int, pid string) string {
	pid = strings.ToUpper(strings.TrimSpace(pid))
	if mode == 0x09 {
		switch pid {
		case "02":
			return "VIN"
		case "04":
			return "Calibration ID"
		case "0A":
			return "ECU Name"
		}
	}
	switch pid {
	case "00":
		return "Supported PIDs 00-20"
	case "05":
		return "Coolant Temperature"
	case "0C":
		return "Engine RPM"
	case "0D":
		return "Vehicle Speed"
	case "0F":
		return "Intake Air Temperature"
	case "10":
		return "MAF Air Flow Rate"
	case "11":
		return "Throttle Position"
	case "2F":
		return "Fuel Tank Level"
	case "42":
		return "Control Module Voltage"
	default:
		return ""
	}
}

func canopenFunctionName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 0x0:
		return "NMT"
	case 0x1:
		return "SYNC/EMCY"
	case 0x2:
		return "TIME"
	case 0x3:
		return "PDO1 Tx"
	case 0x4:
		return "PDO1 Rx"
	case 0x5:
		return "PDO2 Tx"
	case 0x6:
		return "PDO2 Rx"
	case 0x7:
		return "PDO3 Tx"
	case 0x8:
		return "PDO3 Rx"
	case 0x9:
		return "PDO4 Tx"
	case 0xA:
		return "PDO4 Rx"
	case 0xB:
		return "SDO Tx"
	case 0xC:
		return "SDO Rx"
	case 0xE:
		return "NMT Error Control"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Function " + formatHex(raw)
	}
}

func canopenServiceLabel(parts []string) string {
	service := firstNonEmpty(canopenFunctionName(safeTrim(parts, 30)), "CANopen")
	if safeTrim(parts, 33) != "" || safeTrim(parts, 34) != "" {
		return compactJoin(" / ", service, "SDO")
	}
	if safeTrim(parts, 36) != "" {
		return compactJoin(" / ", service, "Emergency")
	}
	if safeTrim(parts, 32) != "" {
		return compactJoin(" / ", service, "PDO")
	}
	return service
}

func canopenObjectIndex(mainIdx, subIdx string) string {
	mainIdx = formatHex(mainIdx)
	subIdx = formatHex(subIdx)
	if mainIdx == "" && subIdx == "" {
		return ""
	}
	if subIdx == "" {
		return "Index " + mainIdx
	}
	return fmt.Sprintf("Index %s:%s", mainIdx, strings.TrimPrefix(subIdx, "0X"))
}

func boolLabel(ok bool, label string) string {
	if !ok {
		return ""
	}
	return label
}
