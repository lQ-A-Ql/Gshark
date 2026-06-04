package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildIndustrialInvestigationReport(analysis model.IndustrialAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("工控协议概览", fmt.Sprintf("工控包 %d / 协议 %d / 会话 %d", analysis.TotalIndustrialPackets, len(analysis.Protocols), len(analysis.Conversations)), "", 0, 0),
		reportItem("Modbus 视角", fmt.Sprintf("帧 %d / 请求 %d / 异常 %d", analysis.Modbus.TotalFrames, analysis.Modbus.Requests, analysis.Modbus.Exceptions), "", 0, 0),
	)

	if analysis.IEC104.TotalFrames > 0 {
		report.Summary = append(report.Summary,
			reportItem("IEC 104 视角", fmt.Sprintf("帧 %d / I=%d / S=%d / U=%d / 异常 %d",
				analysis.IEC104.TotalFrames, analysis.IEC104.IFrameCount, analysis.IEC104.SFrameCount,
				analysis.IEC104.UFrameCount, len(analysis.IEC104.Anomalies)), "", 0, 0),
		)
	}

	for _, hit := range analysis.RuleHits {
		report.Evidence = append(report.Evidence, withReportRuleID(reportItem(
			firstNonEmptyText(hit.Rule, "工控规则命中"),
			firstNonEmptyText(hit.Summary, hit.Evidence),
			mapIndustrialSeverity(hit.Level),
			hit.PacketID,
			0,
			"industrial", strings.ToLower(strings.TrimSpace(hit.Rule)),
		), "industrial.rule.hit", confidenceFromSeverity(mapIndustrialSeverity(hit.Level))))
	}
	for _, write := range analysis.SuspiciousWrites {
		report.Evidence = append(report.Evidence, withReportRuleID(reportItem(
			fmt.Sprintf("%s 写操作集中出现", firstNonEmptyText(write.FunctionName, "Modbus 写操作")),
			fmt.Sprintf("目标 %s / 次数 %d / 来源 %s", write.Target, write.WriteCount, joinOrFallback(write.Sources, "无")),
			"medium",
			write.SamplePacketID,
			0,
			"industrial", "write",
		), "industrial.modbus.write", 58))
	}

	// IEC 104 anomaly evidence.
	for _, anomaly := range limitIEC104Anomalies(analysis.IEC104.Anomalies, 4) {
		report.Evidence = append(report.Evidence, withReportRuleID(reportItem(
			anomaly.Summary,
			anomaly.Description,
			mapIndustrialSeverity(anomaly.Level),
			anomaly.PacketID,
			0,
			"industrial", "iec104",
		), iec104RuleIDFromAnomaly(anomaly.Rule), confidenceFromSeverity(mapIndustrialSeverity(anomaly.Level))))
	}

	for _, command := range limitIndustrialCommands(analysis.ControlCommands, 4) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("%s %s", command.Protocol, command.Operation),
			fmt.Sprintf("%s -> %s / 目标 %s / 值 %s", command.Source, command.Destination, orDash(command.Target), orDash(command.Value)),
			"",
			command.PacketID,
			0,
			"industrial",
		))
	}
	if len(report.Details) == 0 {
		for _, detail := range limitIndustrialDetails(analysis.Details, 4) {
			report.Details = append(report.Details, reportItem(
				detail.Name,
				fmt.Sprintf("总帧 %d / 操作 %s / 目标 %s", detail.TotalFrames, renderBucketLabels(detail.Operations), renderBucketLabels(detail.Targets)),
				"",
				firstIndustrialDetailPacketID(detail),
				0,
				"industrial",
			))
		}
	}

	report.Recommendations = appendRecommendations(nil, analysis.Notes, 4)
	return trimReport(report, 4, 6, 4)
}

func buildVehicleInvestigationReport(analysis model.VehicleAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("车机协议概览", fmt.Sprintf("车机包 %d / 协议 %d / 会话 %d", analysis.TotalVehiclePackets, len(analysis.Protocols), len(analysis.Conversations)), "", 0, 0),
		reportItem("诊断视角", fmt.Sprintf("CAN %d / J1939 %d / DoIP %d / UDS %d", analysis.CAN.TotalFrames, analysis.J1939.TotalMessages, analysis.DoIP.TotalMessages, analysis.UDS.TotalMessages), "", 0, 0),
	)

	for _, tx := range analysis.UDS.Transactions {
		confidence, emit := vehicleEvidenceConfidence(tx)
		if !emit {
			continue
		}
		packetID := tx.ResponsePacketID
		if packetID == 0 {
			packetID = tx.RequestPacketID
		}
		report.Evidence = append(report.Evidence, withReportRuleID(reportItem(
			buildUDSEvidenceSummary(tx),
			fmt.Sprintf("%s -> %s / 状态 %s / 请求 %s / 响应 %s", orDash(tx.SourceAddress), orDash(tx.TargetAddress), tx.Status, orDash(tx.RequestSummary), orDash(tx.ResponseSummary)),
			severityFromConfidence(confidence),
			packetID,
			0,
			"vehicle", "uds",
		), "vehicle.uds.security_access", confidence))
	}
	if len(report.Evidence) == 0 && analysis.CAN.ErrorFrames > 0 {
		report.Evidence = append(report.Evidence, reportItem(
			"CAN 总线存在错误帧",
			fmt.Sprintf("错误帧 %d / 扩展帧 %d / RTR %d", analysis.CAN.ErrorFrames, analysis.CAN.ExtendedFrames, analysis.CAN.RTRFrames),
			"low",
			firstCANPacketID(analysis.CAN.Frames),
			0,
			"vehicle", "can",
		))
	}

	for _, tx := range limitUDSTransactions(analysis.UDS.Transactions, 4) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("%s %s", tx.ServiceID, tx.ServiceName),
			fmt.Sprintf("状态 %s / %s -> %s / 请求 %s / 响应 %s", tx.Status, orDash(tx.SourceAddress), orDash(tx.TargetAddress), orDash(tx.RequestSummary), orDash(tx.ResponseSummary)),
			"",
			firstNonZero(tx.ResponsePacketID, tx.RequestPacketID),
			0,
			"vehicle", "uds",
		))
	}
	if len(report.Details) == 0 {
		for _, frame := range limitCANFrames(analysis.CAN.Frames, 4) {
			report.Details = append(report.Details, reportItem(
				fmt.Sprintf("CAN %s", frame.Identifier),
				fmt.Sprintf("bus=%s / len=%d / %s", frame.BusID, frame.Length, frame.Summary),
				"",
				frame.PacketID,
				0,
				"vehicle", "can",
			))
		}
	}

	report.Recommendations = appendRecommendations(analysis.Recommendations, nil, 4)
	return trimReport(report, 4, 6, 4)
}

func confidenceFromSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 92
	case "high":
		return 78
	case "medium":
		return 58
	case "low":
		return 28
	default:
		return 0
	}
}

func limitIndustrialCommands(items []model.IndustrialControlCommand, limit int) []model.IndustrialControlCommand {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.IndustrialControlCommand(nil), items[:limit]...)
}

func limitIndustrialDetails(items []model.IndustrialProtocolDetail, limit int) []model.IndustrialProtocolDetail {
	cloned := append([]model.IndustrialProtocolDetail(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].TotalFrames != cloned[j].TotalFrames {
			return cloned[i].TotalFrames > cloned[j].TotalFrames
		}
		return cloned[i].Name < cloned[j].Name
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitUDSTransactions(items []model.UDSTransaction, limit int) []model.UDSTransaction {
	cloned := append([]model.UDSTransaction(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		ci, _ := vehicleEvidenceConfidence(cloned[i])
		cj, _ := vehicleEvidenceConfidence(cloned[j])
		if ci != cj {
			return ci > cj
		}
		return firstNonZero(cloned[i].ResponsePacketID, cloned[i].RequestPacketID) < firstNonZero(cloned[j].ResponsePacketID, cloned[j].RequestPacketID)
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitCANFrames(items []model.CANFrameSummary, limit int) []model.CANFrameSummary {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.CANFrameSummary(nil), items[:limit]...)
}

func mapIndustrialSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func firstIndustrialDetailPacketID(detail model.IndustrialProtocolDetail) int64 {
	if len(detail.Records) == 0 {
		return 0
	}
	return detail.Records[0].PacketID
}

func firstCANPacketID(items []model.CANFrameSummary) int64 {
	if len(items) == 0 {
		return 0
	}
	return items[0].PacketID
}

// IEC 104 report helpers.

func buildIEC104InvestigationReport(analysis model.IEC104Analysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("IEC 104 概览", fmt.Sprintf("帧 %d / I=%d / S=%d / U=%d", analysis.TotalFrames, analysis.IFrameCount, analysis.SFrameCount, analysis.UFrameCount), "", 0, 0),
		reportItem("IEC 104 通信", fmt.Sprintf("请求 %d / 响应 %d / 异常 %d", analysis.RequestCount, analysis.ResponseCount, len(analysis.Anomalies)), "", 0, 0),
	)

	for _, anomaly := range limitIEC104Anomalies(analysis.Anomalies, 6) {
		report.Evidence = append(report.Evidence, withReportRuleID(reportItem(
			anomaly.Summary,
			anomaly.Description,
			mapIndustrialSeverity(anomaly.Level),
			anomaly.PacketID,
			0,
			"industrial", "iec104",
		), iec104RuleIDFromAnomaly(anomaly.Rule), confidenceFromSeverity(mapIndustrialSeverity(anomaly.Level))))
	}

	for _, cmd := range limitIndustrialCommands(analysis.ControlCommands, 4) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("IEC104 %s", cmd.Operation),
			fmt.Sprintf("%s -> %s / 目标 %s / 状态 %s", cmd.Source, cmd.Destination, orDash(cmd.Target), orDash(cmd.Result)),
			"",
			cmd.PacketID,
			0,
			"industrial", "iec104",
		))
	}

	if len(report.Details) == 0 {
		for _, bucket := range limitTrafficBuckets(analysis.TypeIDs, 4) {
			report.Details = append(report.Details, reportItem(
				bucket.Label,
				fmt.Sprintf("出现 %d 次", bucket.Count),
				"",
				0,
				0,
				"industrial", "iec104",
			))
		}
	}

	report.Recommendations = appendRecommendations(analysis.Notes, nil, 4)
	return trimReport(report, 4, 6, 4)
}

func limitIEC104Anomalies(items []model.IEC104Anomaly, limit int) []model.IEC104Anomaly {
	cloned := append([]model.IEC104Anomaly(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		pi := severityPriority(cloned[i].Level)
		pj := severityPriority(cloned[j].Level)
		if pi != pj {
			return pi > pj
		}
		return cloned[i].PacketID < cloned[j].PacketID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func iec104RuleIDFromAnomaly(rule string) string {
	switch rule {
	case "iec104.cmd.unauthorized":
		return "iec104.cmd.unauthorized"
	case "iec104.cmd.deactivation":
		return "iec104.cmd.deactivation"
	case "iec104.cmd.reset_process":
		return "iec104.cmd.reset_process"
	case "iec104.cmd.clock_sync":
		return "iec104.cmd.clock_sync"
	case "iec104.cot.init":
		return "iec104.cot.init"
	case "iec104.cot.abnormal":
		return "iec104.cot.abnormal"
	case "iec104.seq.tx_gap":
		return "iec104.seq.tx_gap"
	case "iec104.seq.rx_mismatch":
		return "iec104.seq.rx_mismatch"
	default:
		return "iec104.anomaly"
	}
}

func severityPriority(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func limitTrafficBuckets(items []model.TrafficBucket, limit int) []model.TrafficBucket {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.TrafficBucket(nil), items[:limit]...)
}
