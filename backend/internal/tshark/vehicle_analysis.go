package tshark

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func BuildVehicleAnalysisFromFile(filePath string, databases ...*DBCDatabase) (model.VehicleAnalysis, error) {
	stats := model.VehicleAnalysis{}

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
		"can.id",
		"can.len",
		"can.bus_id",
		"can.flags.rtr",
		"can.flags.xtd",
		"can.flags.err",
		"can.err.ack",
		"can.err.busoff",
		"can.err.buserror",
		"can.err.restarted",
		"can.err.ctrl",
		"can.err.prot",
		"j1939.can_id",
		"j1939.pgn",
		"j1939.priority",
		"j1939.src_addr",
		"j1939.dst_addr",
		"j1939.data",
		"doip.type",
		"doip.vin",
		"doip.logical_address",
		"doip.logical_address_name",
		"doip.source_address",
		"doip.source_address_name",
		"doip.target_address",
		"doip.target_address_name",
		"doip.tester_logical_address",
		"doip.tester_logical_address_name",
		"doip.response_code",
		"doip.diag_ack_code",
		"doip.diag_nack_code",
		"uds.sid",
		"uds.reply",
		"uds.subfunction",
		"uds.diag_addr",
		"uds.diag_addr_name",
		"uds.diag_addr_source",
		"uds.diag_addr_source_name",
		"uds.diag_addr_target",
		"uds.diag_addr_target_name",
		"uds.err.sid",
		"uds.err.code",
		"uds.did_f190.vin",
		"uds.rdtci.dtc_id",
		"uds.rdtci.dtc_status",
		"uds.rdbi.data_identifier",
		"tcp.srcport",
		"udp.srcport",
		"tcp.dstport",
		"udp.dstport",
		"obdii.padding",
	}

	protocolMap := make(map[string]int)
	conversationMap := make(map[string]conversationCount)
	canBusMap := make(map[string]int)
	canIDMap := make(map[string]int)
	j1939PGNMap := make(map[string]int)
	j1939SrcMap := make(map[string]int)
	j1939DstMap := make(map[string]int)
	doipTypeMap := make(map[string]int)
	doipVINMap := make(map[string]int)
	doipEndpointMap := make(map[string]int)
	udsServiceMap := make(map[string]int)
	udsNegativeMap := make(map[string]int)
	udsDTCMap := make(map[string]int)
	udsVINMap := make(map[string]int)
	udsEvents := make([]udsEvent, 0, 128)

	err := scanFieldRows(filePath, fields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		protoPath := safeTrim(parts, 8)
		displayProto := safeTrim(parts, 9)
		info := safeTrim(parts, 10)
		tcpSrcPort := safeTrim(parts, 57)
		udpSrcPort := safeTrim(parts, 58)
		tcpDstPort := safeTrim(parts, 59)
		udpDstPort := safeTrim(parts, 60)
		obdPadding := safeTrim(parts, 61)

		protocols := detectVehicleProtocols(
			protoPath,
			displayProto,
			safeTrim(parts, 11),
			safeTrim(parts, 24),
			safeTrim(parts, 29),
			safeTrim(parts, 42),
			firstNonEmpty(tcpSrcPort, udpSrcPort),
			firstNonEmpty(tcpDstPort, udpDstPort),
			obdPadding,
		)
		if len(protocols) == 0 {
			return
		}

		stats.TotalVehiclePackets++
		for _, protocol := range protocols {
			protocolMap[protocol]++
			conversationLabel := buildVehicleConversation(protocol, src, dst, parts)
			conversationKey := protocol + "|" + conversationLabel
			item := conversationMap[conversationKey]
			item.Label = conversationLabel
			item.Protocol = protocol
			item.Count++
			conversationMap[conversationKey] = item
		}

		packetID := parseInt64(safeTrim(parts, 0))
		packetTime := normalizeTimestamp(safeTrim(parts, 1))

		if containsString(protocols, "CAN") {
			stats.CAN.TotalFrames++
			busID := formatHex(safeTrim(parts, 13))
			messageID := formatHex(safeTrim(parts, 11))
			if parseTruthy(safeTrim(parts, 15)) {
				stats.CAN.ExtendedFrames++
			}
			if parseTruthy(safeTrim(parts, 14)) {
				stats.CAN.RTRFrames++
			}
			if parseTruthy(safeTrim(parts, 16)) {
				stats.CAN.ErrorFrames++
			}
			if busID != "" {
				canBusMap[busID]++
			}
			if messageID != "" {
				canIDMap[messageID]++
			}
			stats.CAN.Frames = append(stats.CAN.Frames, model.CANFrameSummary{
				PacketID:   packetID,
				Time:       packetTime,
				Identifier: messageID,
				BusID:      busID,
				Length:     parseInt(safeTrim(parts, 12)),
				IsExtended: parseTruthy(safeTrim(parts, 15)),
				IsRTR:      parseTruthy(safeTrim(parts, 14)),
				IsError:    parseTruthy(safeTrim(parts, 16)),
				ErrorFlags: buildCANErrorFlags(parts),
				Summary:    info,
			})
		}

		if containsString(protocols, "J1939") {
			stats.J1939.TotalMessages++
			pgn := formatHex(safeTrim(parts, 24))
			srcAddr := formatHex(safeTrim(parts, 26))
			dstAddr := formatHex(safeTrim(parts, 27))
			if pgn != "" {
				j1939PGNMap[pgn]++
			}
			if srcAddr != "" {
				j1939SrcMap[srcAddr]++
			}
			if dstAddr != "" {
				j1939DstMap[dstAddr]++
			}
			stats.J1939.Messages = append(stats.J1939.Messages, model.J1939MessageSummary{
				PacketID:    packetID,
				Time:        packetTime,
				CANID:       formatHex(safeTrim(parts, 23)),
				PGN:         pgn,
				Priority:    parseInt(safeTrim(parts, 25)),
				SourceAddr:  srcAddr,
				TargetAddr:  dstAddr,
				DataPreview: safeTrim(parts, 28),
				Summary:     info,
			})
		}

		if containsString(protocols, "DoIP") {
			stats.DoIP.TotalMessages++
			messageType := formatHex(safeTrim(parts, 29))
			vin := strings.TrimSpace(safeTrim(parts, 30))
			logicalAddress := firstNonEmpty(strings.TrimSpace(safeTrim(parts, 32)), formatHex(safeTrim(parts, 31)))
			sourceAddress := firstNonEmpty(strings.TrimSpace(safeTrim(parts, 34)), formatHex(safeTrim(parts, 33)))
			targetAddress := firstNonEmpty(strings.TrimSpace(safeTrim(parts, 36)), formatHex(safeTrim(parts, 35)))
			testerAddress := firstNonEmpty(strings.TrimSpace(safeTrim(parts, 38)), formatHex(safeTrim(parts, 37)))
			responseCode := formatHex(safeTrim(parts, 39))
			diagState := firstNonEmpty(formatHex(safeTrim(parts, 40)), formatHex(safeTrim(parts, 41)))

			if messageType != "" {
				doipTypeMap[messageType]++
			}
			if vin != "" {
				doipVINMap[vin]++
			}
			for _, endpoint := range []string{sourceAddress, targetAddress, testerAddress, logicalAddress} {
				if endpoint != "" {
					doipEndpointMap[endpoint]++
				}
			}

			stats.DoIP.Messages = append(stats.DoIP.Messages, model.DoIPMessageSummary{
				PacketID:        packetID,
				Time:            packetTime,
				Source:          firstNonEmpty(src, sourceAddress),
				Destination:     firstNonEmpty(dst, targetAddress),
				Type:            messageType,
				VIN:             vin,
				LogicalAddress:  logicalAddress,
				SourceAddress:   sourceAddress,
				TargetAddress:   targetAddress,
				TesterAddress:   testerAddress,
				ResponseCode:    responseCode,
				DiagnosticState: diagState,
				Summary:         info,
			})
		}

		if containsString(protocols, "UDS") {
			stats.UDS.TotalMessages++
			serviceID := firstNonEmpty(formatHex(safeTrim(parts, 42)), formatHex(safeTrim(parts, 51)))
			serviceName := udsServiceName(serviceID)
			negativeCode := formatHex(safeTrim(parts, 52))
			vin := strings.TrimSpace(safeTrim(parts, 53))
			dtc := formatHex(safeTrim(parts, 54))
			dataIdentifier := formatHex(safeTrim(parts, 56))

			if serviceID != "" {
				udsServiceMap[fmt.Sprintf("%s %s", serviceID, serviceName)]++
			}
			if negativeCode != "" {
				udsNegativeMap[fmt.Sprintf("%s %s", negativeCode, udsNegativeResponseName(negativeCode))]++
			}
			if vin != "" {
				udsVINMap[vin]++
			}
			if dtc != "" {
				udsDTCMap[dtc]++
			}

			message := model.UDSMessageSummary{
				PacketID:       packetID,
				Time:           packetTime,
				ServiceID:      serviceID,
				ServiceName:    serviceName,
				IsReply:        parseTruthy(safeTrim(parts, 43)),
				SubFunction:    formatHex(safeTrim(parts, 44)),
				SourceAddress:  firstNonEmpty(strings.TrimSpace(safeTrim(parts, 48)), formatHex(safeTrim(parts, 47)), strings.TrimSpace(safeTrim(parts, 46)), formatHex(safeTrim(parts, 45))),
				TargetAddress:  firstNonEmpty(strings.TrimSpace(safeTrim(parts, 50)), formatHex(safeTrim(parts, 49))),
				DataIdentifier: dataIdentifier,
				DiagnosticVIN:  vin,
				DTC:            dtc,
				NegativeCode:   firstNonEmpty(negativeCode, udsNegativeResponseName(negativeCode)),
				Summary:        info,
			}
			stats.UDS.Messages = append(stats.UDS.Messages, message)
			udsEvents = append(udsEvents, udsEvent{
				UDSMessageSummary: message,
				epoch:             parseEpochSeconds(safeTrim(parts, 1)),
			})
		}
	})
	if err != nil {
		return stats, err
	}

	payloadProtocols, payloadRecords, err := scanCANPayloadAnalysis(filePath)
	if err != nil {
		return stats, err
	}
	decodedMessageDist, decodedSignals, decodedMessages, err := scanDBCDecodedMessages(filePath, databases)
	if err != nil {
		return stats, err
	}

	stats.Protocols = topBuckets(protocolMap, 0)
	stats.Conversations = sortConversationBuckets(conversationMap)
	stats.CAN.BusIDs = topBuckets(canBusMap, 0)
	stats.CAN.MessageIDs = topBuckets(canIDMap, 0)
	stats.CAN.PayloadProtocols = payloadProtocols
	stats.CAN.PayloadRecords = payloadRecords
	stats.CAN.DBCProfiles = buildDBCProfiles(databases)
	stats.CAN.DecodedMessageDist = decodedMessageDist
	stats.CAN.DecodedSignals = decodedSignals
	stats.CAN.DecodedMessages = decodedMessages
	stats.CAN.SignalTimelines = buildCANSignalTimelines(decodedMessages)
	stats.J1939.PGNs = topBuckets(j1939PGNMap, 0)
	stats.J1939.SourceAddrs = topBuckets(j1939SrcMap, 0)
	stats.J1939.TargetAddrs = topBuckets(j1939DstMap, 0)
	stats.DoIP.MessageTypes = topBuckets(doipTypeMap, 0)
	stats.DoIP.VINs = topBuckets(doipVINMap, 0)
	stats.DoIP.Endpoints = topBuckets(doipEndpointMap, 0)
	stats.UDS.ServiceIDs = topBuckets(udsServiceMap, 0)
	stats.UDS.NegativeCodes = topBuckets(udsNegativeMap, 0)
	stats.UDS.DTCs = topBuckets(udsDTCMap, 0)
	stats.UDS.VINs = topBuckets(udsVINMap, 0)
	stats.UDS.Transactions = buildUDSTransactions(udsEvents)
	stats.Recommendations = vehicleRecommendations(stats)
	trimVehicleAnalysisPreview(&stats)
	return stats, nil
}

func detectVehicleProtocols(protoPath, displayProto, canID, j1939PGN, doipType, udsSID, srcPort, dstPort, obdPadding string) []string {
	all := strings.ToLower(strings.Join([]string{protoPath, displayProto}, " "))
	protocols := make([]string, 0, 5)
	add := func(value string) {
		if value == "" || containsString(protocols, value) {
			return
		}
		protocols = append(protocols, value)
	}

	if canID != "" || strings.Contains(all, "can") {
		add("CAN")
	}
	if j1939PGN != "" || strings.Contains(all, "j1939") {
		add("J1939")
	}
	if doipType != "" || strings.Contains(all, "doip") || srcPort == "13400" || dstPort == "13400" {
		add("DoIP")
	}
	if udsSID != "" || strings.Contains(all, "uds") {
		add("UDS")
	}
	if obdPadding != "" || strings.Contains(all, "obdii") {
		add("OBD-II")
	}
	return protocols
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func buildVehicleConversation(protocol, src, dst string, parts []string) string {
	switch protocol {
	case "CAN":
		busID := formatHex(safeTrim(parts, 13))
		if busID != "" {
			return "Bus " + busID
		}
		return "CAN bus"
	case "J1939":
		sourceAddr := formatHex(safeTrim(parts, 26))
		targetAddr := formatHex(safeTrim(parts, 27))
		if sourceAddr != "" || targetAddr != "" {
			return firstNonEmpty(sourceAddr, "unknown") + " -> " + firstNonEmpty(targetAddr, "broadcast")
		}
		return "J1939 network"
	case "DoIP", "UDS":
		left := firstNonEmpty(src, strings.TrimSpace(safeTrim(parts, 34)), strings.TrimSpace(safeTrim(parts, 48)), formatHex(safeTrim(parts, 33)), formatHex(safeTrim(parts, 47)))
		right := firstNonEmpty(dst, strings.TrimSpace(safeTrim(parts, 36)), strings.TrimSpace(safeTrim(parts, 50)), formatHex(safeTrim(parts, 35)), formatHex(safeTrim(parts, 49)))
		return buildConversationLabel(left, right)
	default:
		return buildConversationLabel(src, dst)
	}
}

func buildCANErrorFlags(parts []string) string {
	flags := make([]string, 0, 6)
	if parseTruthy(safeTrim(parts, 17)) {
		flags = append(flags, "ACK")
	}
	if parseTruthy(safeTrim(parts, 18)) {
		flags = append(flags, "BUS-OFF")
	}
	if parseTruthy(safeTrim(parts, 19)) {
		flags = append(flags, "BUS-ERROR")
	}
	if parseTruthy(safeTrim(parts, 20)) {
		flags = append(flags, "RESTARTED")
	}
	if parseTruthy(safeTrim(parts, 21)) {
		flags = append(flags, "CTRL")
	}
	if parseTruthy(safeTrim(parts, 22)) {
		flags = append(flags, "PROTO")
	}
	return strings.Join(flags, ", ")
}

func udsServiceName(serviceID string) string {
	switch strings.ToUpper(strings.TrimSpace(serviceID)) {
	case "0X10":
		return "Diagnostic Session Control"
	case "0X11":
		return "ECU Reset"
	case "0X14":
		return "Clear Diagnostic Information"
	case "0X19":
		return "Read DTC Information"
	case "0X22":
		return "Read Data By Identifier"
	case "0X27":
		return "Security Access"
	case "0X2E":
		return "Write Data By Identifier"
	case "0X2F":
		return "Input Output Control"
	case "0X31":
		return "Routine Control"
	case "0X34":
		return "Request Download"
	case "0X36":
		return "Transfer Data"
	case "0X37":
		return "Request Transfer Exit"
	default:
		return "UDS Service"
	}
}

func udsNegativeResponseName(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "0X10":
		return "General Reject"
	case "0X11":
		return "Service Not Supported"
	case "0X12":
		return "SubFunction Not Supported"
	case "0X13":
		return "Incorrect Message Length"
	case "0X22":
		return "Conditions Not Correct"
	case "0X31":
		return "Request Out Of Range"
	case "0X33":
		return "Security Access Denied"
	case "0X35":
		return "Invalid Key"
	case "0X36":
		return "Exceeded Number Of Attempts"
	case "0X37":
		return "Required Time Delay Not Expired"
	case "0X7E":
		return "SubFunction Not Supported In Session"
	case "0X7F":
		return "Service Not Supported In Session"
	default:
		return ""
	}
}

func vehicleRecommendations(stats model.VehicleAnalysis) []string {
	recommendations := make([]string, 0, 5)
	if stats.CAN.TotalFrames > 0 {
		recommendations = append(recommendations, "先看 CAN ID 分布、总线错误帧和 RTR/扩展帧比例，快速判断是否存在异常节点或异常报文喷发。")
	}
	if stats.J1939.TotalMessages > 0 {
		recommendations = append(recommendations, "J1939 建议优先围绕 PGN、源地址和目标地址聚类，定位诊断类 PGN 与广播类 PGN 的异常占比。")
	}
	if stats.DoIP.TotalMessages > 0 {
		recommendations = append(recommendations, "DoIP 场景优先审计路由激活、逻辑地址和 VIN 暴露，确认是否存在未授权诊断入口。")
	}
	if stats.UDS.TotalMessages > 0 {
		recommendations = append(recommendations, "UDS 场景优先关注 SID 0x10/0x27/0x31/0x34/0x36/0x37 以及负响应码，识别会话切换、鉴权、刷写与例程调用。")
	}
	if containsBucket(stats.Protocols, "OBD-II") {
		recommendations = append(recommendations, "若存在 OBD-II，可继续补 PID 级解析，区分排放监测、实时参数读取与故障码读取。")
	}
	if containsBucket(stats.CAN.PayloadProtocols, "CANopen") {
		recommendations = append(recommendations, "CANopen 已命中，建议优先看 PDO/SDO/EMCY，核对对象字典索引与节点状态切换。")
	}
	if containsBucket(stats.CAN.PayloadProtocols, "ISO-TP") && stats.UDS.TotalMessages == 0 {
		recommendations = append(recommendations, "存在 ISO-TP 但未识别到 UDS，可继续核对私有上层协议或厂商自定义诊断载荷。")
	}
	if len(stats.CAN.DecodedMessages) > 0 {
		recommendations = append(recommendations, "已命中 DBC 信号映射，可结合报文名与信号值直接判断异常状态位、速度类和控制量变化。")
	}
	if len(stats.UDS.Transactions) > 0 {
		recommendations = append(recommendations, "UDS 请求-响应已完成配对，建议优先看高延迟、负响应和孤立响应，快速定位诊断失败链。")
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "当前抓包未识别到常见车载诊断或总线协议。")
	}
	return recommendations
}

func containsBucket(items []model.TrafficBucket, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}

func buildDBCProfiles(databases []*DBCDatabase) []model.DBCProfile {
	if len(databases) == 0 {
		return nil
	}
	out := make([]model.DBCProfile, 0, len(databases))
	for _, db := range databases {
		if db == nil {
			continue
		}
		out = append(out, db.Profile())
	}
	return out
}
