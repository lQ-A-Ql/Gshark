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

	for _, hit := range analysis.RuleHits {
		report.Evidence = append(report.Evidence, withReportRule(reportItem(
			firstNonEmptyText(hit.Rule, "工控规则命中"),
			firstNonEmptyText(hit.Summary, hit.Evidence),
			mapIndustrialSeverity(hit.Level),
			hit.PacketID,
			0,
			"industrial", strings.ToLower(strings.TrimSpace(hit.Rule)),
		), "industrial.rule.hit", "工控规则命中来自协议字段、操作类型或异常响应组合，需结合原始协议帧复核。", confidenceFromSeverity(mapIndustrialSeverity(hit.Level)), "教学或基线流量可能存在协议操作，不应仅凭单条规则命中判定入侵。"))
	}
	for _, write := range analysis.SuspiciousWrites {
		report.Evidence = append(report.Evidence, withReportRule(reportItem(
			fmt.Sprintf("%s 写操作集中出现", firstNonEmptyText(write.FunctionName, "Modbus 写操作")),
			fmt.Sprintf("目标 %s / 次数 %d / 来源 %s", write.Target, write.WriteCount, joinOrFallback(write.Sources, "无")),
			"high",
			write.SamplePacketID,
			0,
			"industrial", "write",
		), "industrial.modbus.write", "Modbus 写类功能码集中出现，优先复核目标寄存器、来源主机和时间窗口。", 78, "普通控制任务也可能包含写操作，需结合业务时段和资产角色判断。"))
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
		report.Evidence = append(report.Evidence, withReportRule(reportItem(
			buildUDSEvidenceSummary(tx),
			fmt.Sprintf("%s -> %s / 状态 %s / 请求 %s / 响应 %s", orDash(tx.SourceAddress), orDash(tx.TargetAddress), tx.Status, orDash(tx.RequestSummary), orDash(tx.ResponseSummary)),
			severityFromConfidence(confidence),
			packetID,
			0,
			"vehicle", "uds",
		), "vehicle.uds.security_access", "UDS 诊断事务触发安全访问、负响应或高风险服务，需结合请求/响应 packet 复核。", confidence, "车机诊断流量在维修或测试场景中可能正常出现，不能脱离场景直接定性。"))
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
