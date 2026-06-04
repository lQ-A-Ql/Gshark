package engine

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// IEC 60870-5-104 APCI frame format:
//   START (0x68) + LENGTH + Control Field (4 bytes)
//   Control field byte 1 & 2: Tx/Rx sequence or control function

const (
	iec104StartByte   = 0x68
	iec104MinFrameLen = 6 // START(1) + LENGTH(1) + APCI(4)
	iec104APCILen     = 4
	iec104DefaultPort = 2404
)

// APCI frame types determined by bit 1 of first control octet.
const (
	iec104TypeI = "I"
	iec104TypeS = "S"
	iec104TypeU = "U"
)

// U-format control functions (bits 2-7 of first control octet).
const (
	iec104UStartDTAct = "STARTDT act"
	iec104UStartDTCon = "STARTDT con"
	iec104UStopDTAct  = "STOPDT act"
	iec104UStopDTCon  = "STOPDT con"
	iec104UTestFRAct  = "TESTFR act"
	iec104UTestFRCon  = "TESTFR con"
)

// ASDU type IDs — monitoring direction (station → control center).
var iec104MonitoringTypes = map[int]string{
	1:  "M_SP_NA_1", // Single-point information
	2:  "M_SP_TA_1", // Single-point information with time tag
	3:  "M_DP_NA_1", // Double-point information
	4:  "M_DP_TA_1", // Double-point information with time tag
	5:  "M_ST_NA_1", // Step position information
	6:  "M_ST_TA_1", // Step position information with time tag
	7:  "M_BO_NA_1", // Bitstring of 32 bit
	8:  "M_BO_TA_1", // Bitstring of 32 bit with time tag
	9:  "M_ME_NA_1", // Measured value, normalized
	10: "M_ME_TA_1", // Measured value, normalized with time tag
	11: "M_ME_NB_1", // Measured value, scaled
	12: "M_ME_TB_1", // Measured value, scaled with time tag
	13: "M_ME_NC_1", // Measured value, short floating point
	14: "M_ME_TC_1", // Measured value, short floating point with time tag
	15: "M_IT_NA_1", // Integrated totals
	16: "M_IT_TA_1", // Integrated totals with time tag
	17: "M_EP_TA_1", // Event of protection equipment with time tag
	18: "M_EP_TB_1", // Packed start events of protection equipment with time tag
	19: "M_EP_TC_1", // Packed output circuit information of protection equipment with time tag
	20: "M_PS_NA_1", // Packed single-point information with status change detection
	21: "M_ME_ND_1", // Measured value, normalized without quality descriptor
	30: "M_SP_TB_1", // Single-point information with time tag CP56Time2a
	31: "M_DP_TB_1", // Double-point information with time tag CP56Time2a
	32: "M_ST_TB_1", // Step position information with time tag CP56Time2a
	33: "M_BO_TB_1", // Bitstring of 32 bit with time tag CP56Time2a
	34: "M_ME_TD_1", // Measured value, normalized with time tag CP56Time2a
	35: "M_ME_TE_1", // Measured value, scaled with time tag CP56Time2a
	36: "M_ME_TF_1", // Measured value, short floating point with time tag CP56Time2a
	37: "M_IT_TB_1", // Integrated totals with time tag CP56Time2a
	38: "M_EP_TD_1", // Event of protection equipment with time tag CP56Time2a
	39: "M_EP_TE_1", // Packed start events of protection equipment with time tag CP56Time2a
	40: "M_EP_TF_1", // Packed output circuit information of protection equipment with time tag CP56Time2a
	70: "M_EI_NA_1", // End of initialization
}

// ASDU type IDs — control direction (control center → station).
var iec104ControlTypes = map[int]string{
	45:  "C_SC_NA_1", // Single command
	46:  "C_DC_NA_1", // Double command
	47:  "C_RC_NA_1", // Regulating step command
	48:  "C_SE_NA_1", // Set-point command, normalized
	49:  "C_SE_NB_1", // Set-point command, scaled
	50:  "C_SE_NC_1", // Set-point command, short floating point
	51:  "C_BO_NA_1", // Bitstring of 32 bit command
	58:  "C_SC_TA_1", // Single command with time tag CP56Time2a
	59:  "C_DC_TA_1", // Double command with time tag CP56Time2a
	60:  "C_RC_TA_1", // Regulating step command with time tag CP56Time2a
	61:  "C_SE_TA_1", // Set-point command, normalized with time tag CP56Time2a
	62:  "C_SE_TB_1", // Set-point command, scaled with time tag CP56Time2a
	63:  "C_SE_TC_1", // Set-point command, short floating point with time tag CP56Time2a
	64:  "C_BO_TA_1", // Bitstring of 32 bit command with time tag CP56Time2a
	100: "C_IC_NA_1", // Interrogation command
	101: "C_CI_NA_1", // Counter interrogation command
	102: "C_RD_NA_1", // Read command
	103: "C_CS_NA_1", // Clock synchronization command
	104: "C_TS_NA_1", // Test command
	105: "C_RP_NA_1", // Reset process command
	106: "C_CD_NA_1", // Delay acquisition command
	107: "C_TS_TA_1", // Test command with time tag CP56Time2a
}

// Cause of Transmission (COT) values.
var iec104COTNames = map[int]string{
	0:  "not used",
	1:  "per/cyc",  // periodic, cyclic
	2:  "back",     // background scan
	3:  "spont",    // spontaneous
	4:  "init",     // initialized
	5:  "req",      // request or requested
	6:  "act",      // activation
	7:  "actcon",   // activation confirmation
	8:  "deact",    // deactivation
	9:  "deactcon", // deactivation confirmation
	10: "actterm",  // activation termination
	11: "retrem",   // return information caused by a remote command
	12: "retloc",   // return information caused by a local command
	13: "file",     // file transfer
	20: "inrogen",  // interrogated by station interrogation
	21: "inro1",    // interrogated by group 1 interrogation
	22: "inro2",    // interrogated by group 2 interrogation
	23: "inro3",    // interrogated by group 3 interrogation
	24: "inro4",    // interrogated by group 4 interrogation
	25: "inro5",    // interrogated by group 5 interrogation
	26: "inro6",    // interrogated by group 6 interrogation
	27: "inro7",    // interrogated by group 7 interrogation
	28: "inro8",    // interrogated by group 8 interrogation
	29: "inro9",    // interrogated by group 9 interrogation
	30: "inro10",   // interrogated by group 10 interrogation
	31: "inro11",   // interrogated by group 11 interrogation
	32: "inro12",   // interrogated by group 12 interrogation
	33: "inro13",   // interrogated by group 13 interrogation
	34: "inro14",   // interrogated by group 14 interrogation
	35: "inro15",   // interrogated by group 15 interrogation
	36: "inro16",   // interrogated by group 16 interrogation
	37: "reqco1",   // requested by general counter request
	38: "reqco2",   // requested by group 1 counter request
	39: "reqco3",   // requested by group 2 counter request
	40: "reqco4",   // requested by group 3 counter request
	41: "reqco5",   // requested by group 4 counter request
	42: "reqco6",   // requested by group 5 counter request
	43: "reqco7",   // requested by group 6 counter request
	44: "reqco8",   // requested by group 7 counter request
	45: "reqco9",   // requested by group 8 counter request
	46: "reqco10",  // requested by group 9 counter request
	47: "reqco11",  // requested by group 10 counter request
	48: "reqco12",  // requested by group 11 counter request
	49: "reqco13",  // requested by group 12 counter request
	50: "reqco14",  // requested by group 13 counter request
	51: "reqco15",  // requested by group 14 counter request
	52: "reqco16",  // requested by group 15 counter request
}

// ParseIEC104Packets parses IEC 104 frames from a list of packets.
func ParseIEC104Packets(packets []model.Packet) model.IEC104Analysis {
	analysis := model.IEC104Analysis{
		TypeIDs:   []model.TrafficBucket{},
		COTs:      []model.TrafficBucket{},
		Frames:    []model.IEC104Frame{},
		Anomalies: []model.IEC104Anomaly{},
	}

	// Track Tx/Rx sequence numbers per conversation for anomaly detection.
	type connState struct {
		lastSendSeq  int
		lastRecvSeq  int
		sendSeqValid bool
		recvSeqValid bool
		unconfirmedI int  // count of outstanding I-frames (sent but not confirmed by S-frame)
		started      bool // whether STARTDT has been activated
	}
	connStates := map[string]*connState{}

	typeIDCounts := map[int]int{}
	cotCounts := map[int]int{}

	for _, pkt := range packets {
		if !isIEC104Packet(pkt) {
			continue
		}

		raw, err := decodeHexPayload(pkt.Payload)
		if err != nil || len(raw) < iec104MinFrameLen {
			continue
		}

		// IEC 104 can have multiple frames in one TCP segment (concatenation).
		offset := 0
		for offset < len(raw) {
			if offset+iec104MinFrameLen > len(raw) {
				break
			}
			if raw[offset] != iec104StartByte {
				break
			}
			length := int(raw[offset+1])
			frameEnd := offset + 2 + length
			if frameEnd > len(raw) {
				break
			}
			if length < iec104APCILen {
				offset = frameEnd
				continue
			}

			frame := parseIEC104Frame(raw[offset:frameEnd], pkt)
			if frame != nil {
				frame.PacketID = pkt.ID
				frame.Time = pkt.Timestamp
				frame.Source = pkt.SourceIP
				frame.Destination = pkt.DestIP

				analysis.Frames = append(analysis.Frames, *frame)
				analysis.TotalFrames++

				switch frame.APCIClass {
				case iec104TypeI:
					analysis.IFrameCount++
					// Determine direction: control-type ASDU is request (client→server),
					// monitor-type ASDU is response (server→client).
					if frame.TypeDirection == "control" {
						analysis.RequestCount++
					} else if frame.TypeDirection == "monitor" {
						analysis.ResponseCount++
					}
					typeIDCounts[frame.TypeID]++
					cotCounts[frame.COT]++

					// Sequence number anomaly detection.
					connKey := frame.Source + "->" + frame.Destination
					st := connStates[connKey]
					if st == nil {
						st = &connState{}
						connStates[connKey] = st
					}
					st.started = true
					st.unconfirmedI++

					// Check Tx sequence continuity.
					if st.sendSeqValid && frame.SendSeq != (st.lastSendSeq+1)%32768 {
						analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
							Rule:        "iec104.seq.tx_gap",
							Level:       "medium",
							PacketID:    frame.PacketID,
							Time:        frame.Time,
							Source:      frame.Source,
							Destination: frame.Destination,
							Description: fmt.Sprintf("Tx sequence gap: expected %d, got %d", (st.lastSendSeq+1)%32768, frame.SendSeq),
							Summary:     "发送序列号不连续",
						})
					}
					st.lastSendSeq = frame.SendSeq
					st.sendSeqValid = true

					// Check Rx sequence continuity.
					if st.recvSeqValid && frame.RecvSeq != st.lastRecvSeq {
						analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
							Rule:        "iec104.seq.rx_mismatch",
							Level:       "low",
							PacketID:    frame.PacketID,
							Time:        frame.Time,
							Source:      frame.Source,
							Destination: frame.Destination,
							Description: fmt.Sprintf("Rx sequence %d does not match expected %d", frame.RecvSeq, st.lastRecvSeq),
							Summary:     "接收序列号与预期不一致",
						})
					}
					st.lastRecvSeq = frame.RecvSeq
					st.recvSeqValid = true

				case iec104TypeS:
					analysis.SFrameCount++
					// S-frame confirms I-frames up to confirmSeq.
					connKey := frame.Destination + "->" + frame.Source
					st := connStates[connKey]
					if st == nil {
						st = &connState{}
						connStates[connKey] = st
					}
					confirmed := frame.ConfirmSeq - st.lastSendSeq
					if confirmed < 0 {
						confirmed += 32768
					}
					st.unconfirmedI -= confirmed
					if st.unconfirmedI < 0 {
						st.unconfirmedI = 0
					}
					st.lastSendSeq = frame.ConfirmSeq

				case iec104TypeU:
					analysis.UFrameCount++
					connKey := frame.Source + "->" + frame.Destination
					st := connStates[connKey]
					if st == nil {
						st = &connState{}
						connStates[connKey] = st
					}
					switch frame.UFunction {
					case iec104UStartDTAct:
						st.started = true
					case iec104UStopDTAct:
						st.started = false
					}
				}

				// Anomaly detection for control commands.
				iec104DetectAnomalies(frame, &analysis)
			}

			offset = frameEnd
		}
	}

	// Build aggregated buckets.
	analysis.TypeIDs = typeIDsToBuckets(typeIDCounts)
	analysis.COTs = cotsToBuckets(cotCounts)

	// Convert control commands from frames.
	iec104BuildControlCommands(&analysis)

	// Notes.
	analysis.Notes = iec104BuildNotes(analysis)

	return analysis
}

// parseIEC104Frame parses a single IEC 104 frame from raw bytes.
// The input should start at the START byte and include the complete frame.
func parseIEC104Frame(data []byte, pkt model.Packet) *model.IEC104Frame {
	if len(data) < iec104MinFrameLen {
		return nil
	}
	if data[0] != iec104StartByte {
		return nil
	}

	ctrl := data[2:] // control field starts at offset 2
	frame := &model.IEC104Frame{}

	// Determine APCI type from bit 1 of first control octet.
	switch {
	case ctrl[0]&0x01 == 0:
		// I-format: bit 1 = 0
		frame.APCIClass = iec104TypeI
		frame.SendSeq = int(binary.LittleEndian.Uint16(ctrl[0:2])) >> 1
		frame.RecvSeq = int(binary.LittleEndian.Uint16(ctrl[2:4])) >> 1
		// Parse ASDU if present.
		if len(data) > iec104MinFrameLen {
			asdu := data[iec104MinFrameLen:]
			iec104ParseASDU(asdu, frame)
		}

	case ctrl[0]&0x03 == 1:
		// S-format: bit 1 = 1, bit 2 = 0
		frame.APCIClass = iec104TypeS
		frame.ConfirmSeq = int(binary.LittleEndian.Uint16(ctrl[2:4])) >> 1
		frame.IsUnconfirmed = true

	case ctrl[0]&0x03 == 3:
		// U-format: bit 1 = 1, bit 2 = 1
		frame.APCIClass = iec104TypeU
		frame.UFunction = iec104DecodeUFunction(ctrl[0])
	}

	return frame
}

// iec104DecodeUFunction decodes the U-format function from control byte 1.
func iec104DecodeUFunction(ctrl byte) string {
	switch {
	case ctrl&0x80 != 0:
		return iec104UTestFRCon
	case ctrl&0x40 != 0:
		return iec104UTestFRAct
	case ctrl&0x20 != 0:
		return iec104UStopDTCon
	case ctrl&0x10 != 0:
		return iec104UStopDTAct
	case ctrl&0x08 != 0:
		return iec104UStartDTCon
	default:
		return iec104UStartDTAct
	}
}

// iec104ParseASDU parses the ASDU portion of an I-format frame.
func iec104ParseASDU(asdu []byte, frame *model.IEC104Frame) {
	if len(asdu) < 2 {
		return
	}

	typeID := int(asdu[0])
	frame.TypeID = typeID

	// Determine direction and type name.
	if name, ok := iec104MonitoringTypes[typeID]; ok {
		frame.TypeName = name
		frame.TypeDirection = "monitor"
	} else if name, ok := iec104ControlTypes[typeID]; ok {
		frame.TypeName = name
		frame.TypeDirection = "control"
	} else {
		frame.TypeName = fmt.Sprintf("Unknown(%d)", typeID)
		frame.TypeDirection = "unknown"
	}

	// Byte 2: VSQ (Variable Structure Qualifier) — number of information objects.
	vsq := int(asdu[1])
	_ = vsq

	// Bytes 3-4: COT (Cause of Transmission) + originator address.
	if len(asdu) >= 4 {
		cot := int(asdu[2])
		frame.COT = cot
		if name, ok := iec104COTNames[cot]; ok {
			frame.COTName = name
		} else {
			frame.COTName = fmt.Sprintf("unknown(%d)", cot)
		}
		frame.OriginatorAddr = int(asdu[3])
	}

	// Bytes 5-6: Common Address of ASDU.
	if len(asdu) >= 6 {
		frame.CommonAddr = int(binary.LittleEndian.Uint16(asdu[4:6]))
	}

	// Bytes 7-9: Information Object Address (first 3 bytes).
	if len(asdu) >= 9 {
		frame.InfoObjectAddr = int(asdu[6]) | int(asdu[7])<<8 | int(asdu[8])<<16
	}

	// Build summary.
	frame.ASDUSummary = iec104BuildASDUSummary(frame)
}

// iec104BuildASDUSummary produces a human-readable summary of the ASDU.
func iec104BuildASDUSummary(frame *model.IEC104Frame) string {
	var parts []string
	parts = append(parts, frame.TypeName)
	if frame.COTName != "" {
		parts = append(parts, "COT="+frame.COTName)
	}
	if frame.CommonAddr > 0 {
		parts = append(parts, fmt.Sprintf("CA=%d", frame.CommonAddr))
	}
	if frame.InfoObjectAddr > 0 {
		parts = append(parts, fmt.Sprintf("IOA=%d", frame.InfoObjectAddr))
	}
	return strings.Join(parts, " / ")
}

// iec104DetectAnomalies checks a parsed frame for anomaly patterns.
func iec104DetectAnomalies(frame *model.IEC104Frame, analysis *model.IEC104Analysis) {
	if frame.APCIClass != iec104TypeI {
		return
	}

	// Rule 1: Unauthorized control command (COT=6 act with no prior actcon).
	// Flag control-type ASDU with COT=act (6) that are not common interrogation/read.
	if frame.TypeDirection == "control" && frame.COT == 6 {
		// Commands like C_IC_NA_1 (interrogation), C_RD_NA_1 (read) are benign.
		if frame.TypeID != 100 && frame.TypeID != 102 {
			analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
				Rule:        "iec104.cmd.unauthorized",
				Level:       "high",
				PacketID:    frame.PacketID,
				Time:        frame.Time,
				Source:      frame.Source,
				Destination: frame.Destination,
				Description: fmt.Sprintf("Control command %s (type %d) with COT=act", frame.TypeName, frame.TypeID),
				Summary:     "检测到控制方向激活命令",
			})
		}
	}

	// Rule 2: COT=init (4) outside initialization phase — may indicate reset.
	if frame.COT == 4 {
		analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
			Rule:        "iec104.cot.init",
			Level:       "medium",
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: fmt.Sprintf("Initialization indication (COT=init, type=%s)", frame.TypeName),
			Summary:     "收到初始化原因传输，可能指示设备重启",
		})
	}

	// Rule 3: Deactivation command (COT=8 deact).
	if frame.COT == 8 && frame.TypeDirection == "control" {
		analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
			Rule:        "iec104.cmd.deactivation",
			Level:       "medium",
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: fmt.Sprintf("Deactivation command %s (type %d)", frame.TypeName, frame.TypeID),
			Summary:     "检测到控制方向去激活命令",
		})
	}

	// Rule 4: Clock synchronization command (C_CS_NA_1, type 103).
	if frame.TypeID == 103 {
		analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
			Rule:        "iec104.cmd.clock_sync",
			Level:       "low",
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: "Clock synchronization command detected",
			Summary:     "检测到时钟同步命令",
		})
	}

	// Rule 5: Reset process command (C_RP_NA_1, type 105).
	if frame.TypeID == 105 {
		analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
			Rule:        "iec104.cmd.reset_process",
			Level:       "high",
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: "Reset process command detected",
			Summary:     "检测到进程复位命令",
		})
	}

	// Rule 6: Abnormal COT — unknown or reserved values.
	if frame.COT >= 44 && frame.COT <= 47 {
		level := "medium"
		if frame.COT == 44 || frame.COT == 45 {
			level = "low"
		}
		analysis.Anomalies = append(analysis.Anomalies, model.IEC104Anomaly{
			Rule:        "iec104.cot.abnormal",
			Level:       level,
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Source:      frame.Source,
			Destination: frame.Destination,
			Description: fmt.Sprintf("Abnormal COT=%d (%s) for type %s", frame.COT, frame.COTName, frame.TypeName),
			Summary:     "异常原因传输值",
		})
	}
}

// iec104BuildControlCommands extracts control command records from IEC 104 frames.
func iec104BuildControlCommands(analysis *model.IEC104Analysis) {
	for _, frame := range analysis.Frames {
		if frame.APCIClass != iec104TypeI || frame.TypeDirection != "control" {
			continue
		}
		// Only record actual commands (not interrogation/read).
		if frame.TypeID == 100 || frame.TypeID == 101 || frame.TypeID == 102 {
			continue
		}
		analysis.ControlCommands = append(analysis.ControlCommands, model.IndustrialControlCommand{
			PacketID:    frame.PacketID,
			Time:        frame.Time,
			Protocol:    "IEC104",
			Source:      frame.Source,
			Destination: frame.Destination,
			Operation:   frame.TypeName,
			Target:      fmt.Sprintf("IOA=%d CA=%d", frame.InfoObjectAddr, frame.CommonAddr),
			Result:      frame.COTName,
			Summary:     frame.ASDUSummary,
		})
	}
}

// iec104BuildNotes produces analysis notes.
func iec104BuildNotes(analysis model.IEC104Analysis) []string {
	var notes []string
	if analysis.TotalFrames == 0 {
		notes = append(notes, "未发现 IEC 104 协议流量。")
		return notes
	}
	notes = append(notes, fmt.Sprintf("IEC 104 帧 %d (I=%d / S=%d / U=%d)。",
		analysis.TotalFrames, analysis.IFrameCount, analysis.SFrameCount, analysis.UFrameCount))
	if len(analysis.Anomalies) > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条异常。", len(analysis.Anomalies)))
	}
	return notes
}

// --- helper functions ---

// isIEC104Packet checks if a packet likely carries IEC 104 traffic.
func isIEC104Packet(pkt model.Packet) bool {
	// Check by protocol field.
	if strings.EqualFold(pkt.Protocol, "IEC104") || strings.EqualFold(pkt.Protocol, "IEC 60870-5-104") || strings.EqualFold(pkt.Protocol, "iec104") {
		return true
	}
	// Check by port.
	if pkt.DestPort == iec104DefaultPort || pkt.SourcePort == iec104DefaultPort {
		// Verify start byte in payload.
		raw, err := decodeHexPayload(pkt.Payload)
		if err == nil && len(raw) > 0 && raw[0] == iec104StartByte {
			return true
		}
	}
	// Check payload for IEC 104 start byte pattern.
	if strings.HasPrefix(pkt.Payload, "68") {
		raw, err := decodeHexPayload(pkt.Payload)
		if err == nil && len(raw) >= iec104MinFrameLen && raw[0] == iec104StartByte {
			length := int(raw[1])
			if length >= iec104APCILen && length <= 253 {
				return true
			}
		}
	}
	return false
}

// decodeHexPayload decodes a hex-encoded payload string.
func decodeHexPayload(payload string) ([]byte, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, nil
	}
	// Try colon-separated hex first (tshark format).
	cleaned := strings.ReplaceAll(payload, ":", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	return hex.DecodeString(cleaned)
}

// typeIDsToBuckets converts a type ID count map to sorted TrafficBucket slice.
func typeIDsToBuckets(counts map[int]int) []model.TrafficBucket {
	buckets := make([]model.TrafficBucket, 0, len(counts))
	for typeID, count := range counts {
		name := fmt.Sprintf("Type %d", typeID)
		if n, ok := iec104MonitoringTypes[typeID]; ok {
			name = n
		} else if n, ok := iec104ControlTypes[typeID]; ok {
			name = n
		}
		buckets = append(buckets, model.TrafficBucket{Label: name, Count: count})
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Count > buckets[j].Count
	})
	return buckets
}

// cotsToBuckets converts a COT count map to sorted TrafficBucket slice.
func cotsToBuckets(counts map[int]int) []model.TrafficBucket {
	buckets := make([]model.TrafficBucket, 0, len(counts))
	for cot, count := range counts {
		name := fmt.Sprintf("COT %d", cot)
		if n, ok := iec104COTNames[cot]; ok {
			name = n
		}
		buckets = append(buckets, model.TrafficBucket{Label: name, Count: count})
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Count > buckets[j].Count
	})
	return buckets
}
