package engine

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// Helper to build a model.Packet with hex payload for IEC 104 testing.
func iec104TestPacket(id int64, src, dst string, srcPort, dstPort int, raw []byte) model.Packet {
	return model.Packet{
		ID:         id,
		Timestamp:  fmt.Sprintf("2024-01-01T00:00:%02dZ", id%60),
		SourceIP:   src,
		DestIP:     dst,
		SourcePort: srcPort,
		DestPort:   dstPort,
		Protocol:   "TCP",
		Payload:    hex.EncodeToString(raw),
	}
}

// buildIFormatFrame builds a raw IEC 104 I-format frame.
// sendSeq and recvSeq are 15-bit values (0-32767).
func buildIFormatFrame(sendSeq, recvSeq int, asdu []byte) []byte {
	length := byte(4 + len(asdu))
	if length > 253 {
		length = 253
	}
	ctrl0 := byte((sendSeq << 1) & 0xFE)
	ctrl1 := byte((sendSeq >> 7) & 0xFF)
	ctrl2 := byte((recvSeq << 1) & 0xFE)
	ctrl3 := byte((recvSeq >> 7) & 0xFF)
	frame := []byte{0x68, length, ctrl0, ctrl1, ctrl2, ctrl3}
	frame = append(frame, asdu...)
	return frame
}

// buildSFormatFrame builds a raw IEC 104 S-format frame.
func buildSFormatFrame(confirmSeq int) []byte {
	ctrl0 := byte(0x01)
	ctrl1 := byte(0x00)
	ctrl2 := byte((confirmSeq << 1) & 0xFE)
	ctrl3 := byte((confirmSeq >> 7) & 0xFF)
	return []byte{0x68, 0x04, ctrl0, ctrl1, ctrl2, ctrl3}
}

// buildUFormatFrame builds a raw IEC 104 U-format frame.
// act=true means activation, false means confirmation.
func buildUFormatFrame(function string, act bool) []byte {
	var ctrl0 byte
	switch function {
	case "STARTDT":
		if act {
			ctrl0 = 0x04 | 0x03 // STARTDT act: bit 3
		} else {
			ctrl0 = 0x08 | 0x03 // STARTDT con: bit 4
		}
	case "STOPDT":
		if act {
			ctrl0 = 0x10 | 0x03 // STOPDT act: bit 5
		} else {
			ctrl0 = 0x20 | 0x03 // STOPDT con: bit 6
		}
	case "TESTFR":
		if act {
			ctrl0 = 0x40 | 0x03 // TESTFR act: bit 7
		} else {
			ctrl0 = 0x80 | 0x03 // TESTFR con: bit 8
		}
	default:
		ctrl0 = 0x04 | 0x03 // STARTDT act
	}
	return []byte{0x68, 0x04, ctrl0, 0x00, 0x00, 0x00}
}

// buildASDU builds a minimal ASDU with given typeID, COT, originator, commonAddr, and infoObjectAddr.
func buildASDU(typeID, cot, originator byte, commonAddr uint16, infoObjectAddr uint32) []byte {
	asdu := []byte{
		typeID,                     // Type ID
		0x01,                       // VSQ = 1 information object
		cot,                        // Cause of Transmission
		originator,                 // Originator Address
		byte(commonAddr),           // Common Address low byte
		byte(commonAddr >> 8),      // Common Address high byte
		byte(infoObjectAddr),       // IOA low byte
		byte(infoObjectAddr >> 8),  // IOA mid byte
		byte(infoObjectAddr >> 16), // IOA high byte
	}
	return asdu
}

func TestParseIEC104PacketsIFrameMonitoring(t *testing.T) {
	// M_SP_NA_1 (type 1), COT=spont (3), CA=1, IOA=100
	asdu := buildASDU(1, 3, 0, 1, 100)
	frame := buildIFormatFrame(0, 0, asdu)
	pkt := iec104TestPacket(1, "10.0.0.1", "10.0.0.2", 2404, 50000, frame)

	analysis := ParseIEC104Packets([]model.Packet{pkt})

	if analysis.TotalFrames != 1 {
		t.Fatalf("expected 1 frame, got %d", analysis.TotalFrames)
	}
	if analysis.IFrameCount != 1 {
		t.Fatalf("expected 1 I-frame, got %d", analysis.IFrameCount)
	}
	if analysis.ResponseCount != 1 {
		t.Fatalf("expected 1 response (monitor direction), got %d", analysis.ResponseCount)
	}
	if len(analysis.Frames) != 1 {
		t.Fatalf("expected 1 frame in slice, got %d", len(analysis.Frames))
	}

	frame0 := analysis.Frames[0]
	if frame0.APCIClass != iec104TypeI {
		t.Fatalf("expected APCI class I, got %s", frame0.APCIClass)
	}
	if frame0.TypeID != 1 {
		t.Fatalf("expected type ID 1, got %d", frame0.TypeID)
	}
	if frame0.TypeName != "M_SP_NA_1" {
		t.Fatalf("expected type name M_SP_NA_1, got %s", frame0.TypeName)
	}
	if frame0.TypeDirection != "monitor" {
		t.Fatalf("expected direction monitor, got %s", frame0.TypeDirection)
	}
	if frame0.COT != 3 {
		t.Fatalf("expected COT 3 (spont), got %d", frame0.COT)
	}
	if frame0.COTName != "spont" {
		t.Fatalf("expected COT name spont, got %s", frame0.COTName)
	}
	if frame0.CommonAddr != 1 {
		t.Fatalf("expected CA 1, got %d", frame0.CommonAddr)
	}
	if frame0.InfoObjectAddr != 100 {
		t.Fatalf("expected IOA 100, got %d", frame0.InfoObjectAddr)
	}
	if frame0.SendSeq != 0 {
		t.Fatalf("expected send seq 0, got %d", frame0.SendSeq)
	}
	if frame0.RecvSeq != 0 {
		t.Fatalf("expected recv seq 0, got %d", frame0.RecvSeq)
	}
	if frame0.PacketID != 1 {
		t.Fatalf("expected packet ID 1, got %d", frame0.PacketID)
	}
}

func TestParseIEC104PacketsIFrameControl(t *testing.T) {
	// C_SC_NA_1 (type 45), COT=act (6), CA=1, IOA=200
	asdu := buildASDU(45, 6, 0, 1, 200)
	frame := buildIFormatFrame(5, 3, asdu)
	pkt := iec104TestPacket(10, "10.0.0.3", "10.0.0.4", 50000, 2404, frame)

	analysis := ParseIEC104Packets([]model.Packet{pkt})

	if analysis.TotalFrames != 1 {
		t.Fatalf("expected 1 frame, got %d", analysis.TotalFrames)
	}
	if analysis.RequestCount != 1 {
		t.Fatalf("expected 1 request (control direction), got %d", analysis.RequestCount)
	}

	frame0 := analysis.Frames[0]
	if frame0.TypeID != 45 {
		t.Fatalf("expected type ID 45, got %d", frame0.TypeID)
	}
	if frame0.TypeName != "C_SC_NA_1" {
		t.Fatalf("expected type name C_SC_NA_1, got %s", frame0.TypeName)
	}
	if frame0.TypeDirection != "control" {
		t.Fatalf("expected direction control, got %s", frame0.TypeDirection)
	}
	if frame0.COT != 6 {
		t.Fatalf("expected COT 6 (act), got %d", frame0.COT)
	}
	if frame0.SendSeq != 5 {
		t.Fatalf("expected send seq 5, got %d", frame0.SendSeq)
	}
	if frame0.RecvSeq != 3 {
		t.Fatalf("expected recv seq 3, got %d", frame0.RecvSeq)
	}

	// Should generate unauthorized command anomaly.
	if len(analysis.Anomalies) == 0 {
		t.Fatalf("expected anomaly for control act command, got 0")
	}
	found := false
	for _, a := range analysis.Anomalies {
		if a.Rule == "iec104.cmd.unauthorized" {
			found = true
			if a.Level != "high" {
				t.Fatalf("expected high severity for unauthorized command, got %s", a.Level)
			}
		}
	}
	if !found {
		t.Fatalf("expected iec104.cmd.unauthorized anomaly")
	}
}

func TestParseIEC104PacketsSFrame(t *testing.T) {
	frame := buildSFormatFrame(10)
	pkt := iec104TestPacket(20, "10.0.0.1", "10.0.0.2", 2404, 50000, frame)

	analysis := ParseIEC104Packets([]model.Packet{pkt})

	if analysis.TotalFrames != 1 {
		t.Fatalf("expected 1 frame, got %d", analysis.TotalFrames)
	}
	if analysis.SFrameCount != 1 {
		t.Fatalf("expected 1 S-frame, got %d", analysis.SFrameCount)
	}

	frame0 := analysis.Frames[0]
	if frame0.APCIClass != iec104TypeS {
		t.Fatalf("expected APCI class S, got %s", frame0.APCIClass)
	}
	if frame0.ConfirmSeq != 10 {
		t.Fatalf("expected confirm seq 10, got %d", frame0.ConfirmSeq)
	}
}

func TestParseIEC104PacketsUFrame(t *testing.T) {
	tests := []struct {
		function string
		act      bool
		want     string
	}{
		{"STARTDT", true, iec104UStartDTAct},
		{"STARTDT", false, iec104UStartDTCon},
		{"STOPDT", true, iec104UStopDTAct},
		{"STOPDT", false, iec104UStopDTCon},
		{"TESTFR", true, iec104UTestFRAct},
		{"TESTFR", false, iec104UTestFRCon},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			frame := buildUFormatFrame(tt.function, tt.act)
			pkt := iec104TestPacket(30, "10.0.0.1", "10.0.0.2", 2404, 50000, frame)
			analysis := ParseIEC104Packets([]model.Packet{pkt})

			if analysis.TotalFrames != 1 {
				t.Fatalf("expected 1 frame, got %d", analysis.TotalFrames)
			}
			if analysis.UFrameCount != 1 {
				t.Fatalf("expected 1 U-frame, got %d", analysis.UFrameCount)
			}
			if len(analysis.Frames) != 1 {
				t.Fatalf("expected 1 frame in slice")
			}
			if analysis.Frames[0].UFunction != tt.want {
				t.Fatalf("expected U-function %s, got %s", tt.want, analysis.Frames[0].UFunction)
			}
		})
	}
}

func TestParseIEC104PacketsAnomalyDetection(t *testing.T) {
	t.Run("reset_process_command", func(t *testing.T) {
		// C_RP_NA_1 (type 105), COT=act (6)
		asdu := buildASDU(105, 6, 0, 1, 0)
		frame := buildIFormatFrame(0, 0, asdu)
		pkt := iec104TestPacket(40, "10.0.0.3", "10.0.0.4", 50000, 2404, frame)
		analysis := ParseIEC104Packets([]model.Packet{pkt})

		found := false
		for _, a := range analysis.Anomalies {
			if a.Rule == "iec104.cmd.reset_process" {
				found = true
				if a.Level != "high" {
					t.Fatalf("expected high severity for reset process, got %s", a.Level)
				}
			}
		}
		if !found {
			t.Fatalf("expected iec104.cmd.reset_process anomaly")
		}
	})

	t.Run("clock_sync_command", func(t *testing.T) {
		// C_CS_NA_1 (type 103), COT=act (6)
		asdu := buildASDU(103, 6, 0, 1, 0)
		frame := buildIFormatFrame(0, 0, asdu)
		pkt := iec104TestPacket(41, "10.0.0.3", "10.0.0.4", 50000, 2404, frame)
		analysis := ParseIEC104Packets([]model.Packet{pkt})

		found := false
		for _, a := range analysis.Anomalies {
			if a.Rule == "iec104.cmd.clock_sync" {
				found = true
				if a.Level != "low" {
					t.Fatalf("expected low severity for clock sync, got %s", a.Level)
				}
			}
		}
		if !found {
			t.Fatalf("expected iec104.cmd.clock_sync anomaly")
		}
	})

	t.Run("cot_init", func(t *testing.T) {
		// M_EI_NA_1 (type 70), COT=init (4)
		asdu := buildASDU(70, 4, 0, 1, 0)
		frame := buildIFormatFrame(0, 0, asdu)
		pkt := iec104TestPacket(42, "10.0.0.1", "10.0.0.2", 2404, 50000, frame)
		analysis := ParseIEC104Packets([]model.Packet{pkt})

		found := false
		for _, a := range analysis.Anomalies {
			if a.Rule == "iec104.cot.init" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected iec104.cot.init anomaly")
		}
	})

	t.Run("deactivation_command", func(t *testing.T) {
		// C_IC_NA_1 (type 100), COT=deact (8) — interrogation deactivation
		asdu := buildASDU(100, 8, 0, 1, 0)
		frame := buildIFormatFrame(0, 0, asdu)
		pkt := iec104TestPacket(43, "10.0.0.3", "10.0.0.4", 50000, 2404, frame)
		analysis := ParseIEC104Packets([]model.Packet{pkt})

		found := false
		for _, a := range analysis.Anomalies {
			if a.Rule == "iec104.cmd.deactivation" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected iec104.cmd.deactivation anomaly")
		}
	})
}

func TestParseIEC104PacketsInterrogationNoAnomaly(t *testing.T) {
	// C_IC_NA_1 (type 100), COT=act (6) — normal interrogation, should NOT trigger unauthorized anomaly.
	asdu := buildASDU(100, 6, 0, 1, 0)
	frame := buildIFormatFrame(0, 0, asdu)
	pkt := iec104TestPacket(50, "10.0.0.3", "10.0.0.4", 50000, 2404, frame)
	analysis := ParseIEC104Packets([]model.Packet{pkt})

	for _, a := range analysis.Anomalies {
		if a.Rule == "iec104.cmd.unauthorized" {
			t.Fatalf("interrogation command should not trigger unauthorized anomaly")
		}
	}
}

func TestParseIEC104PacketsSequenceGapDetection(t *testing.T) {
	// Send two I-frames with a gap in send sequence.
	asdu1 := buildASDU(1, 3, 0, 1, 100) // M_SP_NA_1 spont
	frame1 := buildIFormatFrame(0, 0, asdu1)
	pkt1 := iec104TestPacket(60, "10.0.0.1", "10.0.0.2", 2404, 50000, frame1)

	// Gap: send seq jumps from 0 to 5 (should be 1).
	asdu2 := buildASDU(1, 3, 0, 1, 101)
	frame2 := buildIFormatFrame(5, 0, asdu2)
	pkt2 := iec104TestPacket(61, "10.0.0.1", "10.0.0.2", 2404, 50000, frame2)

	analysis := ParseIEC104Packets([]model.Packet{pkt1, pkt2})

	found := false
	for _, a := range analysis.Anomalies {
		if a.Rule == "iec104.seq.tx_gap" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tx sequence gap anomaly")
	}
}

func TestParseIEC104PacketsTypeAndCOTBuckets(t *testing.T) {
	// Send multiple frames with different type IDs and COTs.
	asdu1 := buildASDU(1, 3, 0, 1, 100) // M_SP_NA_1 spont
	asdu2 := buildASDU(9, 3, 0, 1, 200) // M_ME_NA_1 spont
	asdu3 := buildASDU(1, 5, 0, 1, 100) // M_SP_NA_1 req
	frame1 := buildIFormatFrame(0, 0, asdu1)
	frame2 := buildIFormatFrame(1, 0, asdu2)
	frame3 := buildIFormatFrame(2, 0, asdu3)

	packets := []model.Packet{
		iec104TestPacket(70, "10.0.0.1", "10.0.0.2", 2404, 50000, frame1),
		iec104TestPacket(71, "10.0.0.1", "10.0.0.2", 2404, 50000, frame2),
		iec104TestPacket(72, "10.0.0.1", "10.0.0.2", 2404, 50000, frame3),
	}

	analysis := ParseIEC104Packets(packets)

	if analysis.TotalFrames != 3 {
		t.Fatalf("expected 3 frames, got %d", analysis.TotalFrames)
	}
	if len(analysis.TypeIDs) < 2 {
		t.Fatalf("expected at least 2 type ID buckets, got %d", len(analysis.TypeIDs))
	}
	if len(analysis.COTs) < 2 {
		t.Fatalf("expected at least 2 COT buckets, got %d", len(analysis.COTs))
	}
}

func TestParseIEC104PacketsConcatenation(t *testing.T) {
	// Multiple IEC 104 frames concatenated in one TCP segment.
	asdu1 := buildASDU(1, 3, 0, 1, 100)
	asdu2 := buildASDU(1, 3, 0, 1, 101)
	frame1 := buildIFormatFrame(0, 0, asdu1)
	frame2 := buildIFormatFrame(1, 0, asdu2)
	combined := append(frame1, frame2...)

	pkt := iec104TestPacket(80, "10.0.0.1", "10.0.0.2", 2404, 50000, combined)
	analysis := ParseIEC104Packets([]model.Packet{pkt})

	if analysis.TotalFrames != 2 {
		t.Fatalf("expected 2 frames from concatenation, got %d", analysis.TotalFrames)
	}
}

func TestParseIEC104PacketsPortDetection(t *testing.T) {
	// Packet on port 2404 without protocol field set to IEC104.
	asdu := buildASDU(1, 3, 0, 1, 100)
	frame := buildIFormatFrame(0, 0, asdu)
	pkt := iec104TestPacket(90, "10.0.0.1", "10.0.0.2", 2404, 50000, frame)
	// Override protocol to plain TCP.
	pkt.Protocol = "TCP"

	analysis := ParseIEC104Packets([]model.Packet{pkt})

	if analysis.TotalFrames != 1 {
		t.Fatalf("expected port-based detection to find 1 frame, got %d", analysis.TotalFrames)
	}
}

func TestParseIEC104PacketsEmptyInput(t *testing.T) {
	analysis := ParseIEC104Packets(nil)
	if analysis.TotalFrames != 0 {
		t.Fatalf("expected 0 frames for nil input, got %d", analysis.TotalFrames)
	}
	if len(analysis.Notes) == 0 {
		t.Fatalf("expected notes for empty analysis")
	}
}

func TestParseIEC104PacketsNonIEC104Packet(t *testing.T) {
	pkt := model.Packet{
		ID:       100,
		Protocol: "HTTP",
		SourceIP: "10.0.0.1",
		DestIP:   "10.0.0.2",
		DestPort: 80,
		Payload:  "47:45:54:20:2f:20:48:54:54:50:2f:31:2e:31",
	}
	analysis := ParseIEC104Packets([]model.Packet{pkt})
	if analysis.TotalFrames != 0 {
		t.Fatalf("expected 0 frames for non-IEC104 packet, got %d", analysis.TotalFrames)
	}
}

func TestBuildIEC104InvestigationReport(t *testing.T) {
	analysis := model.IEC104Analysis{
		TotalFrames:   10,
		IFrameCount:   6,
		SFrameCount:   2,
		UFrameCount:   2,
		RequestCount:  3,
		ResponseCount: 3,
		Anomalies: []model.IEC104Anomaly{
			{
				Rule:        "iec104.cmd.unauthorized",
				Level:       "high",
				PacketID:    10,
				Source:      "10.0.0.3",
				Destination: "10.0.0.4",
				Description: "Control command C_SC_NA_1 (type 45) with COT=act",
				Summary:     "检测到控制方向激活命令",
			},
			{
				Rule:        "iec104.cot.init",
				Level:       "medium",
				PacketID:    20,
				Source:      "10.0.0.1",
				Destination: "10.0.0.2",
				Description: "Initialization indication (COT=init, type=M_EI_NA_1)",
				Summary:     "收到初始化原因传输，可能指示设备重启",
			},
		},
		ControlCommands: []model.IndustrialControlCommand{
			{
				PacketID:    10,
				Protocol:    "IEC104",
				Source:      "10.0.0.3",
				Destination: "10.0.0.4",
				Operation:   "C_SC_NA_1",
				Target:      "IOA=200 CA=1",
				Result:      "act",
				Summary:     "C_SC_NA_1 / COT=act / CA=1 / IOA=200",
			},
		},
		TypeIDs: []model.TrafficBucket{
			{Label: "M_SP_NA_1", Count: 4},
			{Label: "C_SC_NA_1", Count: 2},
		},
		COTs: []model.TrafficBucket{
			{Label: "spont", Count: 4},
			{Label: "act", Count: 2},
		},
		Notes: []string{"IEC 104 帧 10。"},
	}

	report := buildIEC104InvestigationReport(analysis)

	if len(report.Summary) == 0 {
		t.Fatalf("expected report summary, got empty")
	}
	if len(report.Evidence) < 2 {
		t.Fatalf("expected at least 2 evidence items, got %d", len(report.Evidence))
	}
	if len(report.Details) == 0 {
		t.Fatalf("expected report details, got empty")
	}

	// Verify evidence has rule metadata.
	assertReportEvidenceHasRuleMetadata(t, report.Evidence[0], "iec104.cmd.unauthorized")
}

func TestIEC104ReportRulesInRegistry(t *testing.T) {
	for _, ruleID := range []string{
		"iec104.cmd.unauthorized",
		"iec104.cmd.deactivation",
		"iec104.cmd.reset_process",
		"iec104.cmd.clock_sync",
		"iec104.cot.init",
		"iec104.cot.abnormal",
		"iec104.seq.tx_gap",
		"iec104.seq.rx_mismatch",
		"iec104.anomaly",
	} {
		item := withReportRuleID(reportItem("title", "summary", "medium", 1, 0), ruleID, 0)
		if item.RuleID != ruleID {
			t.Fatalf("expected rule_id=%q, got %+v", ruleID, item)
		}
		if item.Reason == "" || item.Confidence <= 0 || len(item.Caveats) == 0 {
			t.Fatalf("expected complete rule metadata for %q, got %+v", ruleID, item)
		}
	}
}
