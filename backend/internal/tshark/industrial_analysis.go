package tshark

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var modbusAnalysisFields = []string{
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
	"modbus.data",
	"modbus.bitnum",
	"modbus.bitval",
}

const modbusBitPreviewLimit = 32

type modbusBitContext struct {
	BitType string
	Start   int
	Count   int
}

type modbusTransactionScratch struct {
	FunctionCode   int
	Kind           string
	RawReference   string
	RawQuantity    string
	RawData        string
	RawBitNumbers  string
	RawBitValues   string
	RequestFrameID int64
}

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
	stats.SuspiciousWrites = buildModbusSuspiciousWrites(stats.Modbus.Transactions)
	stats.ControlCommands = extractControlCommands(stats.Details)
	stats.RuleHits = buildIndustrialRuleHits(stats)
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
	requestBitContexts := make(map[int64]modbusBitContext)
	transactionScratch := make([]modbusTransactionScratch, 0, 256)

	err := scanFieldRows(filePath, modbusAnalysisFields, func(parts []string) {
		packetID := parseInt64(safeTrim(parts, 0))
		src := FirstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := FirstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		protoPath := safeTrim(parts, 8)
		displayProto := safeTrim(parts, 9)
		info := safeTrim(parts, 10)
		srcPort := FirstNonEmpty(safeTrim(parts, 11), safeTrim(parts, 12))
		dstPort := FirstNonEmpty(safeTrim(parts, 13), safeTrim(parts, 14))

		if detectIndustrialProtocol(protoPath, displayProto, srcPort, dstPort) != "Modbus/TCP" {
			return
		}

		addConversationCount(conversationMap, "Modbus/TCP", buildConversationLabel(src, dst))
		stats.TotalFrames++

		transID := parseInt(safeTrim(parts, 15))
		unitID := parseInt(safeTrim(parts, 16))
		functionCode := parseInt(safeTrim(parts, 17))
		requestFrame := safeTrim(parts, 18)
		requestFrameID := parseInt64(requestFrame)
		responseTime := safeTrim(parts, 19)
		exceptionFlag := parseTruthy(safeTrim(parts, 20))
		exceptionCode := parseInt(safeTrim(parts, 21))
		rawReference := FirstNonEmpty(safeTrim(parts, 24), safeTrim(parts, 25), safeTrim(parts, 22), safeTrim(parts, 23), safeTrim(parts, 31), safeTrim(parts, 32))
		reference := formatModbusReference(rawReference)
		rawQuantity := FirstNonEmpty(safeTrim(parts, 27), safeTrim(parts, 28), safeTrim(parts, 26), safeTrim(parts, 29), safeTrim(parts, 30))
		quantity := rawQuantity
		registerValues := compactJoin(", ",
			safeTrim(parts, 33),
			safeTrim(parts, 34),
			safeTrim(parts, 35),
			safeTrim(parts, 36),
			safeTrim(parts, 37),
			safeTrim(parts, 38),
		)
		rawBitData := safeTrim(parts, 39)
		rawBitNumbers := safeTrim(parts, 40)
		rawBitValues := safeTrim(parts, 41)

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

		requestCtx, hasRequestCtx := buildModbusBitContext(functionCode, rawReference, rawQuantity)
		responseCtx := modbusBitContext{}
		if requestFrameID > 0 {
			responseCtx = requestBitContexts[requestFrameID]
		}
		bitRange := buildModbusBitRange(functionCode, kind, rawReference, rawQuantity, rawBitData, rawBitNumbers, rawBitValues, responseCtx)

		stats.Transactions = append(stats.Transactions, model.ModbusTransaction{
			PacketID:       packetID,
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
			BitRange:       bitRange,
			Summary:        info,
		})
		transactionScratch = append(transactionScratch, modbusTransactionScratch{
			FunctionCode:   functionCode,
			Kind:           kind,
			RawReference:   rawReference,
			RawQuantity:    rawQuantity,
			RawData:        rawBitData,
			RawBitNumbers:  rawBitNumbers,
			RawBitValues:   rawBitValues,
			RequestFrameID: requestFrameID,
		})
		if kind == "request" && hasRequestCtx {
			requestBitContexts[packetID] = requestCtx
		}
	})
	if err != nil {
		return stats, nil, err
	}

	for idx := range stats.Transactions {
		if stats.Transactions[idx].BitRange != nil {
			continue
		}
		scratch := transactionScratch[idx]
		if scratch.RequestFrameID <= 0 {
			continue
		}
		requestCtx, ok := requestBitContexts[scratch.RequestFrameID]
		if !ok {
			continue
		}
		stats.Transactions[idx].BitRange = buildModbusBitRange(
			scratch.FunctionCode,
			scratch.Kind,
			scratch.RawReference,
			scratch.RawQuantity,
			scratch.RawData,
			scratch.RawBitNumbers,
			scratch.RawBitValues,
			requestCtx,
		)
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

func buildModbusBitContext(functionCode int, rawReference, rawQuantity string) (modbusBitContext, bool) {
	bitType := modbusBitType(functionCode)
	if bitType == "" {
		return modbusBitContext{}, false
	}
	start, ok := parseOptionalFlexibleInt(rawReference)
	if !ok {
		return modbusBitContext{}, false
	}

	count := 0
	switch functionCode {
	case 1, 2, 15:
		parsedCount, ok := parseOptionalFlexibleInt(rawQuantity)
		if !ok || parsedCount <= 0 {
			return modbusBitContext{}, false
		}
		count = parsedCount
	case 5:
		count = 1
	default:
		return modbusBitContext{}, false
	}

	return modbusBitContext{
		BitType: bitType,
		Start:   start,
		Count:   count,
	}, true
}

func buildModbusBitRange(functionCode int, kind, rawReference, rawQuantity, rawData, rawBitNumbers, rawBitValues string, requestCtx modbusBitContext) *model.ModbusBitRange {
	defaultBitType := modbusBitType(functionCode)
	if bitRange := buildModbusBitRangeFromFieldValues(defaultBitType, rawBitNumbers, rawBitValues, requestCtx); bitRange != nil {
		return bitRange
	}

	switch functionCode {
	case 1, 2:
		if kind != "response" || requestCtx.Count <= 0 || requestCtx.BitType == "" {
			return nil
		}
		return newModbusBitRange(requestCtx, decodeModbusPackedBits(rawData, requestCtx.Count))
	case 5:
		ctx, ok := buildModbusBitContext(functionCode, rawReference, rawQuantity)
		if !ok {
			return nil
		}
		value, ok := decodeModbusSingleBitValue(rawData)
		if !ok {
			return nil
		}
		return newModbusBitRange(ctx, []bool{value})
	case 15:
		if kind != "request" {
			return nil
		}
		ctx, ok := buildModbusBitContext(functionCode, rawReference, rawQuantity)
		if !ok {
			return nil
		}
		return newModbusBitRange(ctx, decodeModbusPackedBits(rawData, ctx.Count))
	default:
		return nil
	}
}

func buildModbusBitRangeFromFieldValues(defaultBitType, rawBitNumbers, rawBitValues string, fallbackCtx modbusBitContext) *model.ModbusBitRange {
	valuesRaw := splitCommaSeparatedField(rawBitValues)
	if len(valuesRaw) == 0 {
		return nil
	}

	bitType := FirstNonEmpty(fallbackCtx.BitType, defaultBitType)
	if bitType == "" {
		return nil
	}

	addressesRaw := splitCommaSeparatedField(rawBitNumbers)
	values := make([]bool, 0, len(valuesRaw))
	if len(addressesRaw) == len(valuesRaw) && len(addressesRaw) > 0 {
		start, ok := parseOptionalFlexibleInt(addressesRaw[0])
		if !ok {
			return nil
		}
		for _, rawValue := range valuesRaw {
			values = append(values, parseTruthy(rawValue))
		}
		return newModbusBitRange(modbusBitContext{
			BitType: bitType,
			Start:   start,
			Count:   len(values),
		}, values)
	}

	if fallbackCtx.Count <= 0 {
		return nil
	}
	limit := len(valuesRaw)
	if limit > fallbackCtx.Count {
		limit = fallbackCtx.Count
	}
	for idx := 0; idx < limit; idx++ {
		values = append(values, parseTruthy(valuesRaw[idx]))
	}
	return newModbusBitRange(modbusBitContext{
		BitType: bitType,
		Start:   fallbackCtx.Start,
		Count:   len(values),
	}, values)
}

func newModbusBitRange(ctx modbusBitContext, values []bool) *model.ModbusBitRange {
	if ctx.BitType == "" || ctx.Count <= 0 || len(values) == 0 {
		return nil
	}
	start := ctx.Start
	count := len(values)
	return &model.ModbusBitRange{
		Type:    ctx.BitType,
		Start:   intPtr(start),
		Count:   intPtr(count),
		Values:  append([]bool(nil), values...),
		Preview: formatModbusBitPreview(ctx.BitType, ctx.Start, values),
	}
}

func decodeModbusPackedBits(rawData string, count int) []bool {
	if count <= 0 {
		return nil
	}
	parts := splitHexBytes(rawData)
	if len(parts) == 0 {
		return nil
	}
	values := make([]bool, 0, count)
	for _, part := range parts {
		byteValue := parseFlexibleInt("0x" + part)
		for bit := 0; bit < 8 && len(values) < count; bit++ {
			values = append(values, byteValue&(1<<bit) != 0)
		}
		if len(values) >= count {
			break
		}
	}
	return values
}

func decodeModbusSingleBitValue(rawData string) (bool, bool) {
	parts := splitHexBytes(rawData)
	if len(parts) == 0 {
		return false, false
	}
	if len(parts) >= 2 {
		switch strings.ToUpper(parts[0] + parts[1]) {
		case "FF00":
			return true, true
		case "0000":
			return false, true
		}
	}
	for _, part := range parts {
		if parseFlexibleInt("0x"+part) != 0 {
			return true, true
		}
	}
	return false, true
}

func formatModbusBitPreview(bitType string, start int, values []bool) string {
	if len(values) == 0 {
		return ""
	}
	label := "线圈"
	if bitType == "discrete_input" {
		label = "离散输入"
	}
	if len(values) == 1 {
		if values[0] {
			return fmt.Sprintf("%s %d = ON", label, start)
		}
		return fmt.Sprintf("%s %d = OFF", label, start)
	}

	previewCount := len(values)
	if previewCount > modbusBitPreviewLimit {
		previewCount = modbusBitPreviewLimit
	}
	tokens := make([]string, 0, previewCount)
	for idx := 0; idx < previewCount; idx++ {
		if values[idx] {
			tokens = append(tokens, "1")
		} else {
			tokens = append(tokens, "0")
		}
	}
	result := fmt.Sprintf("%s %d-%d -> %s", label, start, start+len(values)-1, strings.Join(tokens, " "))
	if len(values) > previewCount {
		result += fmt.Sprintf(" ... (共 %d 位)", len(values))
	}
	return result
}

func modbusBitType(functionCode int) string {
	switch functionCode {
	case 1, 5, 15:
		return "coil"
	case 2:
		return "discrete_input"
	default:
		return ""
	}
}

func parseOptionalFlexibleInt(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	return parseFlexibleInt(raw), true
}

func splitCommaSeparatedField(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func intPtr(value int) *int {
	out := value
	return &out
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
	if hasBucketPrefix(stats.Modbus.FunctionCodes, "05 ") || hasBucketPrefix(stats.Modbus.FunctionCodes, "06 ") || hasBucketPrefix(stats.Modbus.FunctionCodes, "15 ") || hasBucketPrefix(stats.Modbus.FunctionCodes, "16 ") || hasBucketPrefix(stats.Modbus.FunctionCodes, "22 ") || hasBucketPrefix(stats.Modbus.FunctionCodes, "23 ") {
		notes = append(notes, "已出现 Modbus 写类功能码，CTF 里常对应灯控、阀门、寄存器改值和自动模式切换。")
	}
	if hasDetailOperation(stats.Details, "S7comm", "Write Var") || hasDetailOperation(stats.Details, "S7comm", "Download") || hasDetailOperation(stats.Details, "S7comm", "Upload") {
		notes = append(notes, "S7comm 已命中写块/下载/上传类操作，建议继续围绕 DB 块、偏移地址和十六进制负载找隐藏数据。")
	}
	if hasDetailOperation(stats.Details, "DNP3", "Operate") || hasDetailOperation(stats.Details, "DNP3", "Direct Operate") || hasDetailOperation(stats.Details, "DNP3", "Restart") {
		notes = append(notes, "DNP3 已出现控制或重启语义，优先核对对象索引、控制状态和值字段，判断是否在模拟遥控命令。")
	}
	if hasDetailOperation(stats.Details, "BACnet", "Write Property") || hasDetailOperation(stats.Details, "BACnet", "Reinitialize Device") {
		notes = append(notes, "BACnet 已出现写属性或设备重初始化，CTF 里常用来埋设备名、对象值或状态切换题。")
	}
	if hasDetailOperation(stats.Details, "IEC 104", "C_SC_NA_1") || hasDetailOperation(stats.Details, "IEC 104", "C_DC_NA_1") || hasDetailOperation(stats.Details, "IEC 104", "C_SE_NC_1") || hasDetailOperation(stats.Details, "IEC 104", "Clock Sync") {
		notes = append(notes, "IEC 104 已出现控制/设点/时钟同步类 ASDU，建议重点核对 CauseTx、IOA 和取值是否构成异常调度。")
	}
	if hasDetailOperation(stats.Details, "PROFINET", "DCP Set") {
		notes = append(notes, "PROFINET 已出现 DCP Set，建议重点看 station name、IP 配置或设备标识是否被重配。")
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

func hasBucketPrefix(items []model.TrafficBucket, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item.Label, prefix) {
			return true
		}
	}
	return false
}

func hasDetailOperation(details []model.IndustrialProtocolDetail, protocolName, keyword string) bool {
	for _, detail := range details {
		if detail.Name != protocolName {
			continue
		}
		for _, op := range detail.Operations {
			if strings.Contains(strings.ToLower(op.Label), strings.ToLower(keyword)) {
				return true
			}
		}
	}
	return false
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
