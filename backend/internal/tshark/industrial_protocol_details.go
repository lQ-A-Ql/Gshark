package tshark

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var s7CommDetailFields = []string{
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
	"s7comm.header.rosctr",
	"s7comm.header.errcls",
	"s7comm.header.errcod",
	"s7comm.param.func",
	"s7comm.param.item.db",
	"s7comm.param.item.area",
	"s7comm.param.item.address.byte",
}

var dnp3DetailFields = []string{
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
	"dnp3.src",
	"dnp3.dst",
	"dnp3.ctl.prifunc",
	"dnp3.ctl.secfunc",
	"dnp3.al.func",
	"dnp3.al.obj",
	"dnp3.al.point_index",
	"dnp3.al.count",
	"dnp3.al.ana.int",
	"dnp3.al.ana.float",
	"dnp3.al.cnt",
	"dnp3.al.bit",
	"dnp3.al.ctrlstatus",
	"dnp3.al.iin",
}

var cipDetailFields = []string{
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
	"enip.command",
	"cip.service",
	"cip.class",
	"cip.instance",
	"cip.attribute",
	"cip.genstat",
	"cip.symbol",
	"cip.id.vendor_id",
	"cip.id.product_name",
}

var bacnetDetailFields = []string{
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
	"bacnet.mesgtyp",
	"bacapp.confirmed_service",
	"bacapp.unconfirmed_service",
	"bacapp.object_name",
	"bacapp.objectIdentifier",
	"bacapp.property_identifier",
	"bacapp.error_code",
	"bacapp.present_value.char_string",
	"bacapp.present_value.real",
	"bacapp.present_value.uint",
	"bacapp.invoke_id",
}

var iec104DetailFields = []string{
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
	"iec60870_asdu.addr",
	"iec60870_asdu.typeid",
	"iec60870_asdu.causetx",
	"iec60870_asdu.ioa",
	"iec60870_asdu.float",
	"iec60870_asdu.normval",
	"iec60870_asdu.scalval",
	"iec60870_asdu.rawdata",
}

var opcuaDetailFields = []string{
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
	"opcua.servicenodeid.numeric",
	"opcua.ApplicationUri",
	"opcua.DiscoveryUrl",
	"opcua.EndpointUrl",
	"opcua.ServerUri",
	"opcua.SessionName",
	"opcua.ServiceResult",
	"opcua.StatusCode",
}

var profinetDetailFields = []string{
	"frame.number",
	"frame.time_epoch",
	"eth.src",
	"ip.src",
	"ipv6.src",
	"eth.dst",
	"ip.dst",
	"ipv6.dst",
	"frame.protocols",
	"_ws.col.Protocol",
	"_ws.col.Info",
	"pn_rt.frame_id",
	"pn_rt.cycle_counter",
	"pn_rt.ds_frame_info_type",
	"pn_dcp.service_id",
	"pn_dcp.service_type",
	"pn_dcp.suboption_device_devicevendorvalue",
	"pn_dcp.suboption_device_nameofstation",
	"pn_dcp.suboption_vendor_id",
	"pn_dcp.suboption_device_id",
	"pn_dcp.suboption_ip_ip",
	"pn_io.opnum",
	"pn_io.artype_req",
	"pn_io.cminitiator_station_name",
	"pn_io.cmresponder_station_name",
	"pn_io.parameter_server_station_name",
	"pn_io.iocr_type",
	"pn_io.iocr_reference",
	"pn_io.number_of_iocrs",
	"pn_io.error_code",
	"pn_io.error_decode",
	"pn_io.error_code1",
	"pn_io.error_code2",
}

type industrialDetailBuilder struct {
	name          string
	opMap         map[string]int
	targetMap     map[string]int
	resultMap     map[string]int
	conversations map[string]conversationCount
	records       []model.IndustrialProtocolRecord
	totalFrames   int
}

func newIndustrialDetailBuilder(name string) *industrialDetailBuilder {
	return &industrialDetailBuilder{
		name:          name,
		opMap:         make(map[string]int),
		targetMap:     make(map[string]int),
		resultMap:     make(map[string]int),
		conversations: make(map[string]conversationCount),
	}
}

func (b *industrialDetailBuilder) Add(packetID int64, packetTime, src, dst, operation, target, result, value, summary string) {
	b.totalFrames++
	addConversationCount(b.conversations, b.name, buildConversationLabel(src, dst))
	if operation != "" {
		b.opMap[operation]++
	}
	if target != "" {
		b.targetMap[target]++
	}
	if result != "" {
		b.resultMap[result]++
	}
	b.records = append(b.records, model.IndustrialProtocolRecord{
		PacketID:    packetID,
		Time:        packetTime,
		Source:      src,
		Destination: dst,
		Operation:   operation,
		Target:      target,
		Result:      result,
		Value:       value,
		Summary:     summary,
	})
}

func (b *industrialDetailBuilder) Build() (model.IndustrialProtocolDetail, map[string]conversationCount) {
	return model.IndustrialProtocolDetail{
		Name:        b.name,
		TotalFrames: b.totalFrames,
		Operations:  topBuckets(b.opMap, 0),
		Targets:     topBuckets(b.targetMap, 0),
		Results:     topBuckets(b.resultMap, 0),
		Records:     b.records,
	}, b.conversations
}

func scanS7CommDetail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("S7comm")
	err := scanFieldRows(filePath, s7CommDetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "S7comm" {
			return
		}

		rosctr := parseFlexibleInt(safeTrim(parts, 11))
		funcCode := parseFlexibleInt(safeTrim(parts, 14))
		operation := compactJoin(" / ", s7ROSCTRName(rosctr), s7FunctionName(funcCode))
		target := formatS7Target(safeTrim(parts, 15), safeTrim(parts, 16), safeTrim(parts, 17))
		result := formatProtocolError("err", safeTrim(parts, 12), safeTrim(parts, 13))

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			firstNonEmpty(operation, safeTrim(parts, 10)),
			target,
			result,
			"",
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanDNP3Detail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("DNP3")
	err := scanFieldRows(filePath, dnp3DetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "DNP3" {
			return
		}

		operation := firstNonEmpty(
			dnp3AppFunctionName(safeTrim(parts, 15)),
			dnp3LinkFunctionName(safeTrim(parts, 13)),
			dnp3LinkFunctionName(safeTrim(parts, 14)),
			safeTrim(parts, 10),
		)
		target := compactJoin(" / ",
			formatDNPAddress(safeTrim(parts, 11), safeTrim(parts, 12)),
			formatDNPObjectTarget(safeTrim(parts, 16), safeTrim(parts, 17), safeTrim(parts, 18)),
		)
		value := firstNonEmpty(safeTrim(parts, 20), safeTrim(parts, 19), safeTrim(parts, 21), safeTrim(parts, 22), safeTrim(parts, 23))
		result := safeTrim(parts, 24)

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanCIPDetail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("EtherNet/IP / CIP")
	err := scanFieldRows(filePath, cipDetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "EtherNet/IP / CIP" {
			return
		}

		operation := firstNonEmpty(
			cipServiceName(safeTrim(parts, 12)),
			enipCommandName(safeTrim(parts, 11)),
			safeTrim(parts, 10),
		)
		target := formatCIPTarget(safeTrim(parts, 13), safeTrim(parts, 14), safeTrim(parts, 15), safeTrim(parts, 17), safeTrim(parts, 18), safeTrim(parts, 19))
		result := cipGeneralStatusName(safeTrim(parts, 16))
		value := compactJoin(" / ", nonEmptyPrefixed("Vendor", safeTrim(parts, 18)), safeTrim(parts, 19))

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanBACnetDetail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("BACnet")
	err := scanFieldRows(filePath, bacnetDetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "BACnet" {
			return
		}

		operation := firstNonEmpty(
			bacnetServiceName(safeTrim(parts, 12), true),
			bacnetServiceName(safeTrim(parts, 13), false),
			bacnetMessageTypeName(safeTrim(parts, 11)),
			safeTrim(parts, 10),
		)
		target := compactJoin(" / ",
			firstNonEmpty(safeTrim(parts, 14), safeTrim(parts, 15)),
			nonEmptyPrefixed("Property", safeTrim(parts, 16)),
			nonEmptyPrefixed("Invoke", safeTrim(parts, 21)),
		)
		result := safeTrim(parts, 17)
		value := firstNonEmpty(safeTrim(parts, 18), safeTrim(parts, 19), safeTrim(parts, 20))

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanIEC104Detail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("IEC 104")
	err := scanFieldRows(filePath, iec104DetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "IEC 104" {
			return
		}

		typeID := safeTrim(parts, 12)
		cause := safeTrim(parts, 13)
		operation := firstNonEmpty(iec104TypeName(typeID), safeTrim(parts, 10))
		target := compactJoin(" / ",
			nonEmptyPrefixed("ASDU", safeTrim(parts, 11)),
			nonEmptyPrefixed("IOA", safeTrim(parts, 14)),
		)
		result := iec104CauseName(cause)
		value := firstNonEmpty(safeTrim(parts, 15), safeTrim(parts, 16), safeTrim(parts, 17), previewHexBytes(safeTrim(parts, 18), 8))

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanOPCUADetail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("OPC UA")
	err := scanFieldRows(filePath, opcuaDetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := firstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "OPC UA" {
			return
		}

		serviceNode := safeTrim(parts, 11)
		operation := firstNonEmpty(opcuaServiceName(serviceNode), safeTrim(parts, 10))
		target := compactJoin(" / ",
			firstNonEmpty(safeTrim(parts, 16), safeTrim(parts, 14), safeTrim(parts, 13), safeTrim(parts, 12), safeTrim(parts, 15)),
			nonEmptyPrefixed("Node", serviceNode),
		)
		result := firstNonEmpty(safeTrim(parts, 17), safeTrim(parts, 18))
		value := firstNonEmpty(safeTrim(parts, 16), safeTrim(parts, 14), safeTrim(parts, 13))

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func scanPROFINETDetail(filePath string) (model.IndustrialProtocolDetail, map[string]conversationCount, error) {
	builder := newIndustrialDetailBuilder("PROFINET")
	err := scanFieldRows(filePath, profinetDetailFields, func(parts []string) {
		src := firstNonEmpty(safeTrim(parts, 3), safeTrim(parts, 4), safeTrim(parts, 2))
		dst := firstNonEmpty(safeTrim(parts, 6), safeTrim(parts, 7), safeTrim(parts, 5))
		if detectIndustrialProtocol(safeTrim(parts, 8), safeTrim(parts, 9), "", "") != "PROFINET" {
			return
		}

		operation := firstNonEmpty(
			profinetDCPServiceName(safeTrim(parts, 14), safeTrim(parts, 15)),
			pnioOperationLabel(safeTrim(parts, 20), safeTrim(parts, 21), safeTrim(parts, 25), safeTrim(parts, 26), safeTrim(parts, 27)),
			safeTrim(parts, 13),
			safeTrim(parts, 10),
		)
		target := compactJoin(" / ",
			nonEmptyPrefixed("FrameID", formatHex(safeTrim(parts, 11))),
			nonEmptyPrefixed("Cycle", safeTrim(parts, 12)),
			firstNonEmpty(
				safeTrim(parts, 17),
				safeTrim(parts, 16),
				safeTrim(parts, 22),
				safeTrim(parts, 23),
				safeTrim(parts, 24),
				safeTrim(parts, 19),
			),
			compactJoin(" / ",
				nonEmptyPrefixed("VendorID", formatHex(safeTrim(parts, 18))),
				nonEmptyPrefixed("DeviceID", formatHex(safeTrim(parts, 19))),
			),
		)
		result := pnioResultLabel(safeTrim(parts, 28), safeTrim(parts, 29), safeTrim(parts, 30), safeTrim(parts, 31))
		value := compactJoin(" / ",
			nonEmptyPrefixed("Station", firstNonEmpty(safeTrim(parts, 17), safeTrim(parts, 22), safeTrim(parts, 23), safeTrim(parts, 24))),
			nonEmptyPrefixed("IOCRs", safeTrim(parts, 27)),
			nonEmptyPrefixed("ARType", safeTrim(parts, 21)),
		)

		builder.Add(
			parseInt64(safeTrim(parts, 0)),
			normalizeTimestamp(safeTrim(parts, 1)),
			src,
			dst,
			operation,
			target,
			result,
			value,
			safeTrim(parts, 10),
		)
	})
	if err != nil {
		return model.IndustrialProtocolDetail{}, nil, err
	}
	detail, conversations := builder.Build()
	return detail, conversations, nil
}

func s7ROSCTRName(raw int) string {
	switch raw {
	case 1:
		return "Job"
	case 2:
		return "Ack"
	case 3:
		return "Ack-Data"
	case 7:
		return "Userdata"
	default:
		if raw <= 0 {
			return ""
		}
		return fmt.Sprintf("ROSCTR %d", raw)
	}
}

func s7FunctionName(raw int) string {
	switch raw {
	case 4:
		return "Read Var"
	case 5:
		return "Write Var"
	case 26:
		return "Request Download"
	case 27:
		return "Download Block"
	case 28:
		return "Download Ended"
	case 29:
		return "Start Upload"
	case 30:
		return "Upload"
	case 31:
		return "End Upload"
	case 240:
		return "Setup Communication"
	default:
		if raw <= 0 {
			return ""
		}
		return fmt.Sprintf("Func %d", raw)
	}
}

func formatS7Target(dbRaw, areaRaw, addressRaw string) string {
	area := s7AreaName(areaRaw)
	target := make([]string, 0, 3)
	if dbRaw != "" {
		target = append(target, "DB "+strings.TrimSpace(dbRaw))
	}
	if area != "" {
		target = append(target, area)
	}
	if addressRaw != "" {
		target = append(target, "Byte "+strings.TrimSpace(addressRaw))
	}
	return strings.Join(target, " / ")
}

func s7AreaName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 0x81:
		return "Inputs"
	case 0x82:
		return "Outputs"
	case 0x83:
		return "Merkers"
	case 0x84:
		return "DB"
	case 0x1C:
		return "Counters"
	case 0x1D:
		return "Timers"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Area " + formatHex(raw)
	}
}

func dnp3AppFunctionName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 0:
		return "Confirm"
	case 1:
		return "Read"
	case 2:
		return "Write"
	case 3:
		return "Select"
	case 4:
		return "Operate"
	case 5:
		return "Direct Operate"
	case 13:
		return "Cold Restart"
	case 14:
		return "Warm Restart"
	case 20:
		return "Enable Unsolicited"
	case 21:
		return "Disable Unsolicited"
	case 129:
		return "Response"
	case 130:
		return "Unsolicited Response"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "App Func " + formatHex(raw)
	}
}

func dnp3LinkFunctionName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 0:
		return "Reset Link"
	case 3:
		return "Confirmed User Data"
	case 4:
		return "Unconfirmed User Data"
	case 9:
		return "Request Link Status"
	case 11:
		return "Link Status"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Link Func " + formatHex(raw)
	}
}

func formatDNPAddress(src, dst string) string {
	if src == "" && dst == "" {
		return ""
	}
	return firstNonEmpty(src, "unknown") + " -> " + firstNonEmpty(dst, "unknown")
}

func formatDNPObjectTarget(obj, pointIndex, count string) string {
	return compactJoin(" / ",
		nonEmptyPrefixed("Obj", obj),
		nonEmptyPrefixed("Point", pointIndex),
		nonEmptyPrefixed("Count", count),
	)
}

func cipServiceName(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "0X01":
		return "Get Attributes All"
	case "0X03":
		return "Get Attribute List"
	case "0X04":
		return "Set Attribute List"
	case "0X0E":
		return "Get Attribute Single"
	case "0X10":
		return "Set Attribute Single"
	case "0X4C":
		return "Read Tag"
	case "0X4D":
		return "Write Tag"
	case "0X52":
		return "Read Modify Write"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Service " + strings.ToUpper(strings.TrimSpace(raw))
	}
}

func enipCommandName(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "0X0004":
		return "List Services"
	case "0X0063":
		return "List Identity"
	case "0X0064":
		return "List Interfaces"
	case "0X0065":
		return "Register Session"
	case "0X0066":
		return "Unregister Session"
	case "0X006F":
		return "Send RR Data"
	case "0X0070":
		return "Send Unit Data"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Command " + strings.ToUpper(strings.TrimSpace(raw))
	}
}

func formatCIPTarget(classRaw, instanceRaw, attributeRaw, symbolRaw, vendorRaw, productRaw string) string {
	return compactJoin(" / ",
		nonEmptyPrefixed("Class", formatHex(classRaw)),
		nonEmptyPrefixed("Inst", formatHex(instanceRaw)),
		nonEmptyPrefixed("Attr", formatHex(attributeRaw)),
		nonEmptyPrefixed("Tag", symbolRaw),
		nonEmptyPrefixed("Vendor", vendorRaw),
		productRaw,
	)
}

func cipGeneralStatusName(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "0", "0X00":
		return "Success"
	case "0X01":
		return "Connection Failure"
	case "0X02":
		return "Resource Unavailable"
	case "0X04":
		return "Path Segment Error"
	case "0X05":
		return "Path Destination Unknown"
	case "0X0E":
		return "Attribute Not Settable"
	case "0X13":
		return "Not Enough Data"
	default:
		return "General Status " + strings.ToUpper(strings.TrimSpace(raw))
	}
}

func bacnetMessageTypeName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 0:
		return "Confirmed Request"
	case 1:
		return "Unconfirmed Request"
	case 2:
		return "Simple Ack"
	case 3:
		return "Complex Ack"
	case 5:
		return "Error"
	case 6:
		return "Reject"
	case 7:
		return "Abort"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Message Type " + raw
	}
}

func bacnetServiceName(raw string, confirmed bool) string {
	code := parseFlexibleInt(raw)
	if code == 0 && strings.TrimSpace(raw) == "" {
		return ""
	}
	if confirmed {
		switch code {
		case 5:
			return "Subscribe COV"
		case 8:
			return "Read Property"
		case 9:
			return "Read Property Conditional"
		case 12:
			return "Write Property"
		case 14:
			return "Device Communication Control"
		case 15:
			return "Confirmed Private Transfer"
		case 18:
			return "Reinitialize Device"
		case 26:
			return "Read Range"
		default:
			return fmt.Sprintf("Confirmed Service %d", code)
		}
	}
	switch code {
	case 2:
		return "I-Am"
	case 3:
		return "I-Have"
	case 7:
		return "Who-Is"
	case 8:
		return "Who-Has"
	case 9:
		return "UTCTimeSync"
	case 10:
		return "TimeSync"
	default:
		return fmt.Sprintf("Unconfirmed Service %d", code)
	}
}

func iec104TypeName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 1:
		return "M_SP_NA_1 Single Point"
	case 3:
		return "M_DP_NA_1 Double Point"
	case 9:
		return "M_ME_NA_1 Measured Value"
	case 13:
		return "M_ME_NC_1 Float"
	case 30:
		return "M_SP_TB_1 Single Point CP56"
	case 45:
		return "C_SC_NA_1 Single Command"
	case 46:
		return "C_DC_NA_1 Double Command"
	case 50:
		return "C_SE_NC_1 Setpoint Float"
	case 100:
		return "C_IC_NA_1 Interrogation"
	case 103:
		return "C_CS_NA_1 Clock Sync"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Type " + raw
	}
}

func iec104CauseName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 1:
		return "Periodic/Cyclic"
	case 3:
		return "Spontaneous"
	case 5:
		return "Requested"
	case 6:
		return "Activation"
	case 7:
		return "Activation Confirmation"
	case 8:
		return "Deactivation"
	case 10:
		return "Activation Termination"
	case 20:
		return "Interrogated by Station"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "Cause " + raw
	}
}

func opcuaServiceName(raw string) string {
	switch parseFlexibleInt(raw) {
	case 397:
		return "FindServers"
	case 428:
		return "GetEndpoints"
	case 461:
		return "CreateSession"
	case 467:
		return "ActivateSession"
	case 473:
		return "CloseSession"
	case 527:
		return "Read"
	case 530:
		return "Write"
	case 629:
		return "Browse"
	case 787:
		return "Call"
	default:
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "ServiceNode " + raw
	}
}

func profinetDCPServiceName(serviceID, serviceType string) string {
	if strings.TrimSpace(serviceID) == "" && strings.TrimSpace(serviceType) == "" {
		return ""
	}
	id := parseFlexibleInt(serviceID)
	typ := parseFlexibleInt(serviceType)
	switch id {
	case 3:
		if typ == 0 {
			return "DCP Get"
		}
		return "DCP Get Response"
	case 4:
		if typ == 0 {
			return "DCP Set"
		}
		return "DCP Set Response"
	case 5:
		return "DCP Identify"
	default:
		return compactJoin(" ", "DCP", strings.TrimSpace(serviceID), strings.TrimSpace(serviceType))
	}
}

func pnioOperationLabel(opnum, arType, iocrType, iocrReference, iocrCount string) string {
	return compactJoin(" / ",
		nonEmptyPrefixed("Op", opnum),
		firstNonEmpty(strings.TrimSpace(arType), ""),
		nonEmptyPrefixed("IOCRType", formatHex(iocrType)),
		nonEmptyPrefixed("IOCRRef", formatHex(iocrReference)),
		nonEmptyPrefixed("IOCRCount", iocrCount),
	)
}

func pnioResultLabel(errorCode, errorDecode, errorCode1, errorCode2 string) string {
	return compactJoin(" / ",
		nonEmptyPrefixed("ErrorCode", formatHex(errorCode)),
		nonEmptyPrefixed("Decode", formatHex(errorDecode)),
		nonEmptyPrefixed("Code1", formatHex(errorCode1)),
		nonEmptyPrefixed("Code2", formatHex(errorCode2)),
	)
}

func formatProtocolError(prefix, codeA, codeB string) string {
	codeA = strings.TrimSpace(codeA)
	codeB = strings.TrimSpace(codeB)
	if codeA == "" && codeB == "" {
		return ""
	}
	return compactJoin(" / ",
		nonEmptyPrefixed(prefix, formatHex(codeA)),
		nonEmptyPrefixed("detail", formatHex(codeB)),
	)
}

func nonEmptyPrefixed(prefix, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return prefix + " " + value
}
