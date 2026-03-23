package tshark

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func BuildIndustrialAnalysisFromFile(filePath string) (model.IndustrialAnalysis, error) {
	stats := model.IndustrialAnalysis{}
	protocolMap := make(map[string]int)
	conversationMap := make(map[string]conversationCount)

	modbus, modbusConversations, err := scanModbusAnalysis(filePath)
	if err != nil {
		return stats, err
	}
	stats.Modbus = modbus
	if modbus.TotalFrames > 0 {
		protocolMap["Modbus/TCP"] = modbus.TotalFrames
		stats.TotalIndustrialPackets += modbus.TotalFrames
		mergeConversationCounts(conversationMap, modbusConversations)
	}

	otherScanners := []func(string) (model.IndustrialProtocolDetail, map[string]conversationCount, error){
		scanS7CommDetail,
		scanDNP3Detail,
		scanCIPDetail,
		scanPROFINETDetail,
		scanBACnetDetail,
		scanIEC104Detail,
		scanOPCUADetail,
	}
	for _, scanner := range otherScanners {
		detail, detailConversations, scanErr := scanner(filePath)
		if scanErr != nil {
			return stats, scanErr
		}
		if detail.TotalFrames == 0 {
			continue
		}
		stats.Details = append(stats.Details, detail)
		protocolMap[detail.Name] = detail.TotalFrames
		stats.TotalIndustrialPackets += detail.TotalFrames
		mergeConversationCounts(conversationMap, detailConversations)
	}

	stats.Protocols = topBuckets(protocolMap, 0)
	stats.Conversations = sortConversationBuckets(conversationMap)
	stats.Notes = industrialNotes(stats)
	return stats, nil
}

func scanModbusAnalysis(filePath string) (model.ModbusAnalysis, map[string]conversationCount, error) {
	stats := model.ModbusAnalysis{}
	conversationMap := make(map[string]conversationCount)
	functionMap := make(map[string]int)
	unitMap := make(map[string]int)
	referenceMap := make(map[string]int)
	exceptionMap := make(map[string]int)

	fields := []string{
		"frame.number",
		"frame.time_epoch",
		"ip.src",
		"ipv6.src",
		"arp.src.proto_ipv4",
		"ip.dst",
		"ipv6.dst",
		"arp.dst.proto_ipv4",
		"frame.protocols",
		"_ws.col.Protocol",
		"_ws.col.Info",
		"tcp.srcport",
		"udp.srcport",
		"tcp.dstport",
		"udp.dstport",
		"mbtcp.trans_id",
		"mbtcp.unit_id",
		"modbus.func_code",
		"modbus.request_frame",
		"modbus.response_time",
		"modbus.exception",
		"modbus.exception_code",
		"modbus.reference_num",
		"modbus.reference_num_32",
		"modbus.read_reference_num",
		"modbus.write_reference_num",
		"modbus.word_cnt",
		"modbus.read_word_cnt",
		"modbus.write_word_cnt",
		"modbus.bit_cnt",
		"modbus.byte_cnt",
		"modbus.regnum16",
		"modbus.regnum32",
		"modbus.regval_uint16",
		"modbus.regval_int16",
		"modbus.regval_uint32",
		"modbus.regval_int32",
		"modbus.regval_float",
		"modbus.object_str_value",
	}

	err := scanFieldRows(filePath, fields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		protoPath := safeTrim(parts, 8)
		displayProto := safeTrim(parts, 9)
		info := safeTrim(parts, 10)
		srcPort := firstNonEmpty(safeTrim(parts, 11), safeTrim(parts, 12))
		dstPort := firstNonEmpty(safeTrim(parts, 13), safeTrim(parts, 14))

		if detectIndustrialProtocol(protoPath, displayProto, srcPort, dstPort) != "Modbus/TCP" {
			return
		}

		addConversationCount(conversationMap, "Modbus/TCP", buildConversationLabel(src, dst))
		stats.TotalFrames++

		transID := parseInt(safeTrim(parts, 15))
		unitID := parseInt(safeTrim(parts, 16))
		functionCode := parseInt(safeTrim(parts, 17))
		requestFrame := safeTrim(parts, 18)
		responseTime := safeTrim(parts, 19)
		exceptionFlag := parseTruthy(safeTrim(parts, 20))
		exceptionCode := parseInt(safeTrim(parts, 21))
		reference := formatModbusReference(
			firstNonEmpty(safeTrim(parts, 24), safeTrim(parts, 25), safeTrim(parts, 22), safeTrim(parts, 23), safeTrim(parts, 31), safeTrim(parts, 32)),
		)
		quantity := firstNonEmpty(safeTrim(parts, 27), safeTrim(parts, 28), safeTrim(parts, 26), safeTrim(parts, 29), safeTrim(parts, 30))
		registerValues := compactJoin(", ",
			safeTrim(parts, 33),
			safeTrim(parts, 34),
			safeTrim(parts, 35),
			safeTrim(parts, 36),
			safeTrim(parts, 37),
			safeTrim(parts, 38),
		)

		kind := "request"
		if requestFrame != "" || responseTime != "" {
			kind = "response"
		}
		if exceptionFlag || exceptionCode > 0 {
			kind = "exception"
		}

		switch kind {
		case "request":
			stats.Requests++
		case "response":
			stats.Responses++
		default:
			stats.Responses++
			stats.Exceptions++
		}

		functionLabel := fmt.Sprintf("%02d %s", functionCode, modbusFunctionName(functionCode))
		functionMap[functionLabel]++
		if unitID > 0 {
			unitMap[fmt.Sprintf("Unit %d", unitID)]++
		}
		if reference != "" {
			referenceMap[reference]++
		}
		if exceptionCode > 0 {
			exceptionMap[fmt.Sprintf("0x%02X %s", exceptionCode, modbusExceptionName(exceptionCode))]++
		}

		stats.Transactions = append(stats.Transactions, model.ModbusTransaction{
			PacketID:       parseInt64(safeTrim(parts, 0)),
			Time:           normalizeTimestamp(safeTrim(parts, 1)),
			Source:         src,
			Destination:    dst,
			TransactionID:  transID,
			UnitID:         unitID,
			FunctionCode:   functionCode,
			FunctionName:   modbusFunctionName(functionCode),
			Kind:           kind,
			Reference:      reference,
			Quantity:       quantity,
			ExceptionCode:  exceptionCode,
			ResponseTime:   responseTime,
			RegisterValues: registerValues,
			Summary:        info,
		})
	})
	if err != nil {
		return stats, nil, err
	}

	stats.FunctionCodes = topBuckets(functionMap, 0)
	stats.UnitIDs = topBuckets(unitMap, 0)
	stats.ReferenceHits = topBuckets(referenceMap, 0)
	stats.ExceptionCodes = topBuckets(exceptionMap, 0)
	return stats, conversationMap, nil
}

func detectIndustrialProtocol(protoPath, displayProto, srcPort, dstPort string) string {
	all := strings.ToLower(strings.Join([]string{protoPath, displayProto}, " "))
	switch {
	case strings.Contains(all, "mbtcp") || strings.Contains(all, "modbus") || srcPort == "502" || dstPort == "502":
		return "Modbus/TCP"
	case strings.Contains(all, "dnp3"):
		return "DNP3"
	case strings.Contains(all, "s7comm"):
		return "S7comm"
	case strings.Contains(all, "enip") || strings.Contains(all, "cip"):
		return "EtherNet/IP / CIP"
	case strings.Contains(all, "profinet") || strings.Contains(all, "pn_io") || strings.Contains(all, "pn-dcp") || strings.Contains(all, "pn_dcp"):
		return "PROFINET"
	case strings.Contains(all, "bacnet") || strings.Contains(all, "bacapp"):
		return "BACnet"
	case strings.Contains(all, "opcua"):
		return "OPC UA"
	case strings.Contains(all, "iec104") || strings.Contains(all, "iec60870"):
		return "IEC 104"
	default:
		return ""
	}
}

func buildConversationLabel(src, dst string) string {
	left := strings.TrimSpace(src)
	right := strings.TrimSpace(dst)
	if left == "" {
		left = "unknown"
	}
	if right == "" {
		right = "unknown"
	}
	return left + " -> " + right
}

func modbusFunctionName(code int) string {
	switch code {
	case 1:
		return "读线圈"
	case 2:
		return "读离散输入"
	case 3:
		return "读保持寄存器"
	case 4:
		return "读输入寄存器"
	case 5:
		return "写单线圈"
	case 6:
		return "写单寄存器"
	case 15:
		return "写多线圈"
	case 16:
		return "写多寄存器"
	case 22:
		return "掩码写寄存器"
	case 23:
		return "读写多寄存器"
	case 43:
		return "设备标识"
	default:
		if code <= 0 {
			return "未知功能码"
		}
		return "功能码"
	}
}

func modbusExceptionName(code int) string {
	switch code {
	case 1:
		return "非法功能"
	case 2:
		return "非法数据地址"
	case 3:
		return "非法数据值"
	case 4:
		return "从站设备故障"
	case 5:
		return "确认"
	case 6:
		return "从站忙"
	case 8:
		return "存储奇偶校验错误"
	case 10:
		return "网关路径不可用"
	case 11:
		return "网关目标设备未响应"
	default:
		return "未知异常"
	}
}

func formatModbusReference(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return "Ref " + raw
}

func compactJoin(sep string, values ...string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return strings.Join(filtered, sep)
}

func industrialNotes(stats model.IndustrialAnalysis) []string {
	notes := make([]string, 0, 6)
	if stats.Modbus.TotalFrames > 0 {
		notes = append(notes, "Modbus/TCP 已做字段级提取，可直接查看功能码、寄存器引用、异常码和请求/响应节奏。")
	}
	if len(stats.Details) > 0 {
		names := make([]string, 0, len(stats.Details))
		for _, detail := range stats.Details {
			names = append(names, detail.Name)
		}
		notes = append(notes, fmt.Sprintf("当前已补齐字段级解析的其他工控协议: %s。", strings.Join(names, "、")))
	}
	if stats.Modbus.Exceptions > 0 {
		notes = append(notes, "存在 Modbus 异常响应，建议优先核对异常码与对应寄存器地址。")
	}
	for _, detail := range stats.Details {
		if detail.Name == "IEC 104" || detail.Name == "DNP3" {
			notes = append(notes, "对遥测/遥控协议建议重点核对 CauseTx、对象地址、取值与否定位，识别误操作或伪造控制。")
			break
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "当前抓包未识别到常见工控协议。")
	}
	return notes
}

func addConversationCount(target map[string]conversationCount, protocol, label string) {
	key := protocol + "|" + label
	item := target[key]
	item.Label = label
	item.Protocol = protocol
	item.Count++
	target[key] = item
}

func mergeConversationCounts(target map[string]conversationCount, incoming map[string]conversationCount) {
	for key, item := range incoming {
		current := target[key]
		current.Label = item.Label
		current.Protocol = item.Protocol
		current.Count += item.Count
		target[key] = current
	}
}
