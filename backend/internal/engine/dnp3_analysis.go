package engine

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// DNP3 link-layer constants.
const (
	dnp3StartBytes = 0x0564
	dnp3MinLength  = 5
	dnp3CRCSize    = 2
	dnp3ChunkSize  = 16 // CRC inserted every 16 bytes of user data
)

// DNP3 application function codes.
const (
	dnp3FCConfirm          = 0x00
	dnp3FCRead             = 0x01
	dnp3FCWrite            = 0x02
	dnp3FCSelect           = 0x03
	dnp3FCOperate          = 0x04
	dnp3FCDirectOperate    = 0x05
	dnp3FCDirectOperateNAK = 0x06
	dnp3FCFreeze           = 0x07
	dnp3FCFreezeNAK        = 0x08
	dnp3FCFreezeClear      = 0x09
	dnp3FCFreezeClearNAK   = 0x0A
	dnp3FCColdRestart      = 0x0D
	dnp3FCWarmRestart      = 0x0E
	dnp3FCInitData         = 0x0F
	dnp3FCInitApp          = 0x10
	dnp3FCStartApp         = 0x11
	dnp3FCStopApp          = 0x12
	dnp3FCSaveConfig       = 0x13
	dnp3FCEnableUnsol      = 0x14
	dnp3FCDisableUnsol     = 0x15
	dnp3FCAssignClass      = 0x16
	dnp3FCDelayMeasure     = 0x17
	dnp3FCRecordTime       = 0x18
	dnp3FCOpenFile         = 0x19
	dnp3FCCloseFile        = 0x1A
	dnp3FCDeleteFile       = 0x1B
	dnp3FCGetFileInfo      = 0x1C
	dnp3FCAuthFile         = 0x1D
	dnp3FCAbortFile        = 0x1E
	// Response function codes (0x81+).
	dnp3FCResponse        = 0x81
	dnp3FCUnsolicitedResp = 0x82
)

// DNP3 data object group definitions.
type dnp3ObjectDef struct {
	Name string
}

var dnp3ObjectDefs = map[int]dnp3ObjectDef{
	1:  {Name: "Binary Input"},
	2:  {Name: "Binary Input Event"},
	3:  {Name: "Double-bit Input"},
	4:  {Name: "Double-bit Input Event"},
	10: {Name: "Binary Output"},
	11: {Name: "Binary Output Event"},
	12: {Name: "Control Relay Output"},
	13: {Name: "Binary Output Cmd Event"},
	20: {Name: "Counter"},
	21: {Name: "Frozen Counter"},
	22: {Name: "Counter Event"},
	23: {Name: "Frozen Counter Event"},
	30: {Name: "Analog Input"},
	31: {Name: "Analog Input Event"},
	32: {Name: "Analog Input Deadband"},
	34: {Name: "Analog Output Status"},
	40: {Name: "Analog Output"},
	41: {Name: "Analog Output Event"},
	42: {Name: "Analog Output Cmd Event"},
	50: {Name: "Time and Date"},
	51: {Name: "Time and Date Event"},
	52: {Name: "Time Delay"},
	60: {Name: "Class Data"},
	70: {Name: "File"},
	80: {Name: "Internal Indications"},
}

// dnp3LinkHeader represents the parsed DNP3 link-layer header.
type dnp3LinkHeader struct {
	Length   int
	Control  byte
	DestAddr int
	SrcAddr  int
	UserData []byte // raw user data with embedded CRCs
}

// dnp3AppHeader represents the parsed DNP3 application-layer header.
type dnp3AppHeader struct {
	Control      byte
	FunctionCode int
	FIR          bool // First fragment
	FIN          bool // Last fragment
	CON          bool // Confirmation required
	Unsolicited  bool
	IIN          [2]byte // Internal Indications (response only)
	Objects      []byte  // object data after IIN
}

// ParseDNP3Packet parses a single raw DNP3 packet and returns a DNP3Frame.
// rawHex is the hex-encoded raw packet bytes (Ethernet/IP/TCP/DNP3).
func ParseDNP3Packet(packetID int64, packetTime, src, dst, rawHex string) *model.DNP3Frame {
	if rawHex == "" {
		return nil
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(rawHex, ":", ""))
	if err != nil {
		return nil
	}

	dnp3Offset := findDNP3Offset(raw)
	if dnp3Offset < 0 || dnp3Offset+10 > len(raw) {
		return nil
	}

	frame := raw[dnp3Offset:]
	link, ok := parseDNP3LinkHeader(frame)
	if !ok {
		return nil
	}

	app, ok := parseDNP3AppHeader(link.UserData)
	if !ok {
		return nil
	}

	direction := "request"
	if app.FunctionCode >= 0x81 {
		direction = "response"
	}

	fcName := dnp3FunctionCodeName(app.FunctionCode)
	dataObjects := parseDNP3Objects(app.Objects)
	isControl := dnp3IsControlFunction(app.FunctionCode)

	iinStr := ""
	if direction == "response" {
		iinStr = formatDNP3IIN(app.IIN)
	}

	summary := buildDNP3Summary(direction, fcName, dataObjects, link.DestAddr, link.SrcAddr)

	return &model.DNP3Frame{
		PacketID:      packetID,
		Time:          packetTime,
		Source:        src,
		Destination:   dst,
		SrcAddress:    link.SrcAddr,
		DstAddress:    link.DestAddr,
		Direction:     direction,
		FunctionCode:  app.FunctionCode,
		FunctionName:  fcName,
		DataObjects:   dataObjects,
		IIN:           iinStr,
		IsControl:     isControl,
		IsUnsolicited: app.Unsolicited,
		Summary:       summary,
	}
}

// AnalyzeDNP3Packets analyzes a slice of raw DNP3 packets and returns analysis results.
func AnalyzeDNP3Packets(packets []DNP3RawPacket) model.DNP3Analysis {
	analysis := model.DNP3Analysis{}
	fcMap := make(map[string]int)
	objMap := make(map[string]int)

	for _, pkt := range packets {
		frame := ParseDNP3Packet(pkt.PacketID, pkt.Time, pkt.Src, pkt.Dst, pkt.RawHex)
		if frame == nil {
			continue
		}

		analysis.TotalFrames++
		analysis.Frames = append(analysis.Frames, *frame)

		if frame.Direction == "request" {
			analysis.Requests++
		} else {
			analysis.Responses++
		}

		fcLabel := fmt.Sprintf("0x%02X %s", frame.FunctionCode, frame.FunctionName)
		fcMap[fcLabel]++

		for _, obj := range frame.DataObjects {
			objLabel := obj.ObjectName
			if objLabel == "" {
				objLabel = fmt.Sprintf("Group %d Var %d", obj.Group, obj.Variation)
			}
			objMap[objLabel]++
		}

		// Detect anomalies
		anomalies := detectDNP3Anomalies(frame)
		analysis.Anomalies = append(analysis.Anomalies, anomalies...)
	}

	analysis.FunctionCodes = topBucketsDNP3(fcMap)
	analysis.DataObjects = topBucketsDNP3(objMap)
	analysis.Notes = buildDNP3Notes(analysis)
	return analysis
}

// DNP3RawPacket is a minimal packet representation for DNP3 analysis.
type DNP3RawPacket struct {
	PacketID int64
	Time     string
	Src      string
	Dst      string
	RawHex   string
}

// findDNP3Offset locates the DNP3 start bytes (0x05 0x64) in raw packet data.
func findDNP3Offset(raw []byte) int {
	for i := 0; i < len(raw)-1; i++ {
		if raw[i] == 0x05 && raw[i+1] == 0x64 {
			return i
		}
	}
	return -1
}

// parseDNP3LinkHeader parses the DNP3 link-layer header.
func parseDNP3LinkHeader(frame []byte) (dnp3LinkHeader, bool) {
	var h dnp3LinkHeader
	if len(frame) < 10 {
		return h, false
	}
	// Start bytes
	if frame[0] != 0x05 || frame[1] != 0x64 {
		return h, false
	}
	h.Length = int(frame[2])
	h.Control = frame[3]
	h.DestAddr = int(frame[4]) | int(frame[5])<<8
	h.SrcAddr = int(frame[6]) | int(frame[7])<<8
	// CRC is at bytes 8-9 (not validated here)
	if h.Length < dnp3MinLength || len(frame) < 10+h.Length-dnp3MinLength {
		return h, false
	}
	// User data starts after link header (10 bytes: 2 start + 1 len + 1 ctrl + 2 dst + 2 src + 2 crc)
	userDataStart := 10
	userDataEnd := userDataStart + h.Length - dnp3MinLength
	if userDataEnd > len(frame) {
		userDataEnd = len(frame)
	}
	h.UserData = frame[userDataStart:userDataEnd]
	return h, true
}

// parseDNP3AppHeader parses the DNP3 application-layer header from user data.
// User data has embedded CRCs every 16 bytes that must be stripped.
func parseDNP3AppHeader(userData []byte) (dnp3AppHeader, bool) {
	var app dnp3AppHeader
	cleaned := stripDNP3CRCs(userData)
	if len(cleaned) < 2 {
		return app, false
	}

	app.Control = cleaned[0]
	app.FunctionCode = int(cleaned[1])
	app.FIR = (app.Control & 0x80) != 0
	app.FIN = (app.Control & 0x40) != 0
	app.CON = (app.Control & 0x20) != 0
	app.Unsolicited = (app.Control & 0x10) != 0

	if app.FunctionCode >= 0x81 && len(cleaned) >= 4 {
		// Response: IIN1 and IIN2 follow function code
		app.IIN[0] = cleaned[2]
		app.IIN[1] = cleaned[3]
		app.Objects = cleaned[4:]
	} else {
		app.Objects = cleaned[2:]
	}
	return app, true
}

// stripDNP3CRCs removes the 2-byte CRC inserted every 16 bytes of DNP3 user data.
func stripDNP3CRCs(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	var out []byte
	for i := 0; i < len(data); {
		end := i + dnp3ChunkSize
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[i:end]...)
		i = end + dnp3CRCSize // skip CRC
	}
	return out
}

// parseDNP3Objects parses DNP3 data objects from the application-layer payload.
func parseDNP3Objects(data []byte) []model.DNP3DataObject {
	var objects []model.DNP3DataObject
	offset := 0
	for offset < len(data)-2 {
		group := int(data[offset])
		variation := int(data[offset+1])
		offset += 2
		if offset >= len(data) {
			break
		}

		qp := data[offset]
		offset++
		qualifier := dnp3QualifierName(qp)

		var pointCount int
		var startIndex int
		switch qp & 0x70 {
		case 0x00: // 1-byte start, 1-byte count
			if offset+2 > len(data) {
				return objects
			}
			startIndex = int(data[offset])
			pointCount = int(data[offset+1])
			offset += 2
		case 0x10: // 2-byte start, 2-byte count
			if offset+4 > len(data) {
				return objects
			}
			startIndex = int(data[offset]) | int(data[offset+1])<<8
			pointCount = int(data[offset+2]) | int(data[offset+3])<<8
			offset += 4
		case 0x20: // 2-byte start, 2-byte count (for ranges)
			if offset+4 > len(data) {
				return objects
			}
			startIndex = int(data[offset]) | int(data[offset+1])<<8
			pointCount = int(data[offset+2]) | int(data[offset+3])<<8
			offset += 4
		default:
			// Unknown qualifier, skip remaining
			return objects
		}

		objName := dnp3ObjectName(group, variation)
		for i := 0; i < pointCount; i++ {
			value := extractDNP3Value(data, &offset, group, variation)
			objects = append(objects, model.DNP3DataObject{
				Group:      group,
				Variation:  variation,
				PointIndex: startIndex + i,
				ObjectName: objName,
				Value:      value,
				Qualifier:  qualifier,
			})
		}
	}
	return objects
}

// extractDNP3Value reads a single data value based on group/variation size.
func extractDNP3Value(data []byte, offset *int, group, variation int) string {
	size := dnp3ValueSize(group, variation)
	if *offset+size > len(data) {
		return ""
	}
	val := data[*offset : *offset+size]
	*offset += size
	return formatDNP3Value(val, group, variation)
}

// dnp3ValueSize returns the byte size of a data value for the given group/variation.
func dnp3ValueSize(group, variation int) int {
	switch group {
	case 1, 3, 10, 11, 12, 13: // Binary types
		switch variation {
		case 1:
			return 1
		case 2:
			return 1 + 7 // flag + timestamp
		default:
			return 1
		}
	case 20, 21, 22, 23: // Counter types
		switch variation {
		case 1:
			return 1 + 4 // flag + uint32
		case 2:
			return 1 + 2 // flag + uint16
		case 5:
			return 1 + 4 // flag + uint32
		case 6:
			return 1 + 2 // flag + uint16
		default:
			return 5
		}
	case 30, 31, 32, 34: // Analog types
		switch variation {
		case 1:
			return 1 + 4 // flag + int32
		case 2:
			return 1 + 2 // flag + int16
		case 3:
			return 1 + 4 // flag + float32
		case 4:
			return 1 + 2 // flag + int16 (deadband)
		case 5:
			return 1 + 4 // flag + int32
		default:
			return 5
		}
	case 40, 41, 42: // Analog output types
		switch variation {
		case 1:
			return 1 + 4 // flag + int32
		case 2:
			return 1 + 2 // flag + int16
		case 3:
			return 1 + 4 // flag + float32
		default:
			return 5
		}
	case 50: // Time and Date
		return 6
	default:
		return 1 // minimal
	}
}

// formatDNP3Value formats a raw value bytes into a human-readable string.
func formatDNP3Value(val []byte, group, variation int) string {
	if len(val) == 0 {
		return ""
	}
	switch group {
	case 1, 3, 10: // Binary
		if val[0]&0x80 != 0 {
			return "ON"
		}
		return "OFF"
	case 20, 21, 22, 23: // Counter
		if len(val) >= 5 {
			v := uint32(val[1]) | uint32(val[2])<<8 | uint32(val[3])<<16 | uint32(val[4])<<24
			return fmt.Sprintf("%d", v)
		}
		if len(val) >= 3 {
			v := uint16(val[1]) | uint16(val[2])<<8
			return fmt.Sprintf("%d", v)
		}
	case 30, 31, 34, 40, 41: // Analog
		if len(val) >= 5 {
			v := int32(val[1]) | int32(val[2])<<8 | int32(val[3])<<16 | int32(val[4])<<24
			return fmt.Sprintf("%d", v)
		}
		if len(val) >= 3 {
			v := int16(val[1]) | int16(val[2])<<8
			return fmt.Sprintf("%d", v)
		}
	}
	// Fallback: hex
	return fmt.Sprintf("0x%s", hex.EncodeToString(val))
}

// dnp3ObjectName returns the human-readable name for a DNP3 data object group/variation.
func dnp3ObjectName(group, variation int) string {
	def, ok := dnp3ObjectDefs[group]
	if !ok {
		return fmt.Sprintf("Group %d Var %d", group, variation)
	}
	return fmt.Sprintf("%s (G%dV%d)", def.Name, group, variation)
}

// dnp3FunctionCodeName returns the human-readable name for a DNP3 function code.
func dnp3FunctionCodeName(fc int) string {
	switch fc {
	case dnp3FCConfirm:
		return "Confirm"
	case dnp3FCRead:
		return "Read"
	case dnp3FCWrite:
		return "Write"
	case dnp3FCSelect:
		return "Select"
	case dnp3FCOperate:
		return "Operate"
	case dnp3FCDirectOperate:
		return "Direct Operate"
	case dnp3FCDirectOperateNAK:
		return "Direct Operate No ACK"
	case dnp3FCFreeze:
		return "Freeze"
	case dnp3FCFreezeNAK:
		return "Freeze No ACK"
	case dnp3FCFreezeClear:
		return "Freeze Clear"
	case dnp3FCFreezeClearNAK:
		return "Freeze Clear No ACK"
	case dnp3FCColdRestart:
		return "Cold Restart"
	case dnp3FCWarmRestart:
		return "Warm Restart"
	case dnp3FCInitData:
		return "Initialize Data"
	case dnp3FCInitApp:
		return "Initialize Application"
	case dnp3FCStartApp:
		return "Start Application"
	case dnp3FCStopApp:
		return "Stop Application"
	case dnp3FCSaveConfig:
		return "Save Configuration"
	case dnp3FCEnableUnsol:
		return "Enable Unsolicited"
	case dnp3FCDisableUnsol:
		return "Disable Unsolicited"
	case dnp3FCAssignClass:
		return "Assign Class"
	case dnp3FCDelayMeasure:
		return "Delay Measurement"
	case dnp3FCRecordTime:
		return "Record Current Time"
	case dnp3FCOpenFile:
		return "Open File"
	case dnp3FCCloseFile:
		return "Close File"
	case dnp3FCDeleteFile:
		return "Delete File"
	case dnp3FCGetFileInfo:
		return "Get File Info"
	case dnp3FCAuthFile:
		return "Authenticate File"
	case dnp3FCAbortFile:
		return "Abort File"
	case dnp3FCResponse:
		return "Response"
	case dnp3FCUnsolicitedResp:
		return "Unsolicited Response"
	default:
		if fc >= 0x81 {
			return fmt.Sprintf("Response 0x%02X", fc)
		}
		return fmt.Sprintf("Function 0x%02X", fc)
	}
}

// dnp3IsControlFunction returns true if the function code is a control/operate command.
func dnp3IsControlFunction(fc int) bool {
	switch fc {
	case dnp3FCSelect, dnp3FCOperate, dnp3FCDirectOperate, dnp3FCDirectOperateNAK,
		dnp3FCColdRestart, dnp3FCWarmRestart,
		dnp3FCWrite, dnp3FCInitData, dnp3FCInitApp, dnp3FCStartApp, dnp3FCStopApp,
		dnp3FCSaveConfig, dnp3FCEnableUnsol, dnp3FCDisableUnsol,
		dnp3FCFreeze, dnp3FCFreezeNAK, dnp3FCFreezeClear, dnp3FCFreezeClearNAK:
		return true
	default:
		return false
	}
}

// dnp3QualifierName returns a human-readable qualifier description.
func dnp3QualifierName(qp byte) string {
	switch qp {
	case 0x00:
		return "1-byte start/stop"
	case 0x01:
		return "1-byte start/count"
	case 0x06:
		return "no range, count"
	case 0x07:
		return "1-byte count"
	case 0x08:
		return "2-byte count"
	case 0x17:
		return "2-byte start/count"
	case 0x28:
		return "2-byte start/stop"
	case 0x3B:
		return "free-format"
	default:
		return fmt.Sprintf("qualifier 0x%02X", qp)
	}
}

// formatDNP3IIN formats the Internal Indications bytes into a descriptive string.
func formatDNP3IIN(iin [2]byte) string {
	var flags []string
	if iin[0]&0x01 != 0 {
		flags = append(flags, "All_Stations")
	}
	if iin[0]&0x02 != 0 {
		flags = append(flags, "Class1_Data")
	}
	if iin[0]&0x04 != 0 {
		flags = append(flags, "Class2_Data")
	}
	if iin[0]&0x08 != 0 {
		flags = append(flags, "Class3_Data")
	}
	if iin[0]&0x10 != 0 {
		flags = append(flags, "Need_Time")
	}
	if iin[0]&0x20 != 0 {
		flags = append(flags, "Local_Control")
	}
	if iin[0]&0x40 != 0 {
		flags = append(flags, "Device_Trouble")
	}
	if iin[0]&0x80 != 0 {
		flags = append(flags, "Device_Restart")
	}
	if iin[1]&0x01 != 0 {
		flags = append(flags, "Function_Not_Supported")
	}
	if iin[1]&0x02 != 0 {
		flags = append(flags, "Object_Not_Supported")
	}
	if iin[1]&0x04 != 0 {
		flags = append(flags, "Parameter_Error")
	}
	if iin[1]&0x08 != 0 {
		flags = append(flags, "Event_Buffer_Overflow")
	}
	if iin[1]&0x10 != 0 {
		flags = append(flags, "Already_Executing")
	}
	if iin[1]&0x20 != 0 {
		flags = append(flags, "Config_Corrupt")
	}
	if len(flags) == 0 {
		return ""
	}
	return strings.Join(flags, " | ")
}

// detectDNP3Anomalies checks a parsed DNP3 frame for security anomalies.
func detectDNP3Anomalies(frame *model.DNP3Frame) []model.DNP3Anomaly {
	var anomalies []model.DNP3Anomaly

	// 1. Unauthorized function code detection
	if dnp3IsUnauthorizedFC(frame.FunctionCode) {
		anomalies = append(anomalies, model.DNP3Anomaly{
			Type:        "unauthorized_fc",
			Severity:    "high",
			PacketID:    frame.PacketID,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: fmt.Sprintf("未授权功能码 %s (0x%02X)", frame.FunctionName, frame.FunctionCode),
			Detail:      fmt.Sprintf("源地址 %d -> 目标地址 %d", frame.SrcAddress, frame.DstAddress),
		})
	}

	// 2. Suspicious control commands
	if frame.IsControl && dnp3IsDangerousControl(frame.FunctionCode) {
		anomalies = append(anomalies, model.DNP3Anomaly{
			Type:        "suspicious_control",
			Severity:    "high",
			PacketID:    frame.PacketID,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: fmt.Sprintf("危险控制命令: %s", frame.FunctionName),
			Detail:      fmt.Sprintf("功能码 0x%02X / 源 %d -> 目标 %d", frame.FunctionCode, frame.SrcAddress, frame.DstAddress),
		})
	}

	// 3. Anomalous response detection (IIN flags)
	if frame.Direction == "response" && frame.IIN != "" {
		if strings.Contains(frame.IIN, "Device_Trouble") || strings.Contains(frame.IIN, "Device_Restart") {
			anomalies = append(anomalies, model.DNP3Anomaly{
				Type:        "anomalous_response",
				Severity:    "medium",
				PacketID:    frame.PacketID,
				Source:      frame.Source,
				Destination: frame.Destination,
				Description: "设备异常响应",
				Detail:      fmt.Sprintf("IIN: %s", frame.IIN),
			})
		}
		if strings.Contains(frame.IIN, "Function_Not_Supported") || strings.Contains(frame.IIN, "Parameter_Error") {
			anomalies = append(anomalies, model.DNP3Anomaly{
				Type:        "anomalous_response",
				Severity:    "low",
				PacketID:    frame.PacketID,
				Source:      frame.Source,
				Destination: frame.Destination,
				Description: "功能不支持或参数错误",
				Detail:      fmt.Sprintf("IIN: %s", frame.IIN),
			})
		}
	}

	// 4. Unsolicited response detection
	if frame.IsUnsolicited {
		anomalies = append(anomalies, model.DNP3Anomaly{
			Type:        "unsolicited_response",
			Severity:    "info",
			PacketID:    frame.PacketID,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: "非请求响应",
			Detail:      fmt.Sprintf("功能码 %s / 源 %d", frame.FunctionName, frame.SrcAddress),
		})
	}

	return anomalies
}

// dnp3IsUnauthorizedFC returns true if the function code is not a standard DNP3 function.
func dnp3IsUnauthorizedFC(fc int) bool {
	// Standard request function codes
	standardFCs := map[int]bool{
		dnp3FCConfirm: true, dnp3FCRead: true, dnp3FCWrite: true,
		dnp3FCSelect: true, dnp3FCOperate: true,
		dnp3FCDirectOperate: true, dnp3FCDirectOperateNAK: true,
		dnp3FCFreeze: true, dnp3FCFreezeNAK: true,
		dnp3FCFreezeClear: true, dnp3FCFreezeClearNAK: true,
		dnp3FCColdRestart: true, dnp3FCWarmRestart: true,
		dnp3FCInitData: true, dnp3FCInitApp: true,
		dnp3FCStartApp: true, dnp3FCStopApp: true,
		dnp3FCSaveConfig:  true,
		dnp3FCEnableUnsol: true, dnp3FCDisableUnsol: true,
		dnp3FCAssignClass: true, dnp3FCDelayMeasure: true,
		dnp3FCRecordTime: true,
		dnp3FCOpenFile:   true, dnp3FCCloseFile: true,
		dnp3FCDeleteFile: true, dnp3FCGetFileInfo: true,
		dnp3FCAuthFile: true, dnp3FCAbortFile: true,
		dnp3FCResponse: true, dnp3FCUnsolicitedResp: true,
	}
	if fc >= 0x81 {
		// Response codes are in 0x81-0xFF range
		return false
	}
	return !standardFCs[fc]
}

// dnp3IsDangerousControl returns true if the control function could cause harm.
func dnp3IsDangerousControl(fc int) bool {
	switch fc {
	case dnp3FCColdRestart, dnp3FCWarmRestart,
		dnp3FCStopApp, dnp3FCInitData, dnp3FCInitApp:
		return true
	default:
		return false
	}
}

// buildDNP3Summary builds a human-readable summary for a DNP3 frame.
func buildDNP3Summary(direction, fcName string, objects []model.DNP3DataObject, dstAddr, srcAddr int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%s %s", direction, fcName))
	parts = append(parts, fmt.Sprintf("addr %d->%d", srcAddr, dstAddr))
	if len(objects) > 0 {
		objName := objects[0].ObjectName
		if objName == "" {
			objName = fmt.Sprintf("G%dV%d", objects[0].Group, objects[0].Variation)
		}
		if len(objects) == 1 {
			parts = append(parts, objName)
		} else {
			parts = append(parts, fmt.Sprintf("%s +%d", objName, len(objects)-1))
		}
	}
	return strings.Join(parts, " / ")
}

// buildDNP3Notes generates analysis notes for DNP3 traffic.
func buildDNP3Notes(analysis model.DNP3Analysis) []string {
	var notes []string
	if analysis.TotalFrames > 0 {
		notes = append(notes, fmt.Sprintf("DNP3 流量共 %d 帧（请求 %d / 响应 %d），已做应用层功能码和数据对象解析。", analysis.TotalFrames, analysis.Requests, analysis.Responses))
	}
	if len(analysis.Anomalies) > 0 {
		highCount := 0
		for _, a := range analysis.Anomalies {
			if a.Severity == "high" {
				highCount++
			}
		}
		if highCount > 0 {
			notes = append(notes, fmt.Sprintf("检测到 %d 个高危异常（未授权功能码或危险控制命令），建议重点核对。", highCount))
		}
	}
	hasControl := false
	for _, fc := range analysis.FunctionCodes {
		if strings.Contains(fc.Label, "Operate") || strings.Contains(fc.Label, "Restart") || strings.Contains(fc.Label, "Write") {
			hasControl = true
			break
		}
	}
	if hasControl {
		notes = append(notes, "DNP3 已出现控制/写/重启语义，优先核对对象索引、控制状态和值字段。")
	}
	return notes
}

// topBucketsDNP3 creates sorted TrafficBucket list from a map.
func topBucketsDNP3(m map[string]int) []model.TrafficBucket {
	buckets := make([]model.TrafficBucket, 0, len(m))
	for label, count := range m {
		buckets = append(buckets, model.TrafficBucket{Label: label, Count: count})
	}
	sortTrafficBuckets(buckets)
	return buckets
}

// sortTrafficBuckets sorts buckets by count descending, then label ascending.
func sortTrafficBuckets(buckets []model.TrafficBucket) {
	for i := 1; i < len(buckets); i++ {
		for j := i; j > 0; j-- {
			if buckets[j].Count > buckets[j-1].Count {
				buckets[j], buckets[j-1] = buckets[j-1], buckets[j]
			} else if buckets[j].Count == buckets[j-1].Count && buckets[j].Label < buckets[j-1].Label {
				buckets[j], buckets[j-1] = buckets[j-1], buckets[j]
			} else {
				break
			}
		}
	}
}
