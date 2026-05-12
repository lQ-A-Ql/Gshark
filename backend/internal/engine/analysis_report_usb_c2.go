package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildUSBInvestigationReport(analysis model.USBAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("USB 概览", fmt.Sprintf("USB 包 %d / 设备 %d / Endpoint %d", analysis.TotalUSBPackets, len(analysis.Devices), len(analysis.Endpoints)), "", 0, 0, "usb", "summary"),
		reportItem("域分布", fmt.Sprintf("HID %d / Mass Storage %d / Other %d", analysis.HIDPackets, analysis.MassStoragePackets, analysis.OtherUSBPackets), "", 0, 0, "usb", "domains"),
	)

	for _, op := range analysis.MassStorage.WriteOperations {
		severity := "medium"
		if op.Status != "" && !strings.EqualFold(op.Status, "ok") {
			severity = "high"
		}
		if op.DataResidue > 0 {
			severity = "high"
		}
		confidence := 60
		if severity == "high" {
			confidence = 78
		}
		report.Evidence = append(report.Evidence, withReportRule(reportItem(
			buildUSBEvidenceSummary(op),
			fmt.Sprintf("设备 %s / %s / 长度 %d / status=%s", orDash(op.Device), orDash(op.LUN), op.TransferLength, orDash(op.Status)),
			severity,
			op.PacketID,
			0,
			"usb", "mass-storage", "write",
		), "usb.mass_storage.write.failed", "USB Mass Storage 写操作存在失败状态或非零 Data Residue，需要回到 packet 复核写入是否成功。", confidence, "普通挂载流量也可能出现写类操作，需结合状态码、残留长度和上下文判断。"))
	}
	for _, event := range limitUSBKeyboardEvents(analysis.HID.KeyboardEvents, 3) {
		report.Details = append(report.Details, reportItem(
			"USB 键盘事件",
			fmt.Sprintf("%s / 文本 %s / 按键 %s", orDash(event.Device), orDash(event.Text), joinOrFallback(event.Keys, "无")),
			"",
			event.PacketID,
			0,
			"usb", "hid", "keyboard",
		))
	}
	for _, record := range limitUSBControlRecords(analysis.Other.ControlRecords, 3) {
		report.Details = append(report.Details, reportItem(
			"USB 控制请求",
			fmt.Sprintf("%s / %s / %s", orDash(record.SetupRequest), orDash(record.Endpoint), orDash(record.Summary)),
			"",
			record.PacketID,
			0,
			"usb", "control",
		))
	}

	recommendations := []string{}
	if len(analysis.MassStorage.WriteOperations) > 0 {
		recommendations = append(recommendations, "优先定位 USB Mass Storage 写操作对应的数据包，结合状态码、残留长度和设备/LUN 判断是否为可疑落盘。")
	}
	if len(analysis.HID.KeyboardEvents) > 0 {
		recommendations = append(recommendations, "如需复核输入行为，可继续围绕键盘事件文本、修饰键变化和时间顺序回放 HID 轨迹。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 6, 6)
}

func buildC2FamilyInvestigationReport(family string, analysis model.C2FamilyAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	label := strings.ToUpper(strings.TrimSpace(family))
	report.Summary = append(report.Summary,
		reportItem(fmt.Sprintf("%s 候选概览", label), fmt.Sprintf("候选 %d / 规则位 %d / 通道 %d", analysis.CandidateCount, analysis.MatchedRuleCount, len(analysis.Channels)), "", 0, 0, "c2", family),
		reportItem(fmt.Sprintf("%s 画像概览", label), fmt.Sprintf("Beacon %d / HTTP 聚合 %d / DNS 聚合 %d / Stream 聚合 %d", len(analysis.BeaconPatterns), len(analysis.HostURIAggregates), len(analysis.DNSAggregates), len(analysis.StreamAggregates)), "", 0, 0, "c2", family),
	)

	for _, candidate := range limitC2Candidates(analysis.Candidates, 4) {
		report.Evidence = append(report.Evidence, withReportRule(reportItem(
			firstNonEmptyText(candidate.Summary, fmt.Sprintf("%s candidate", label)),
			fmt.Sprintf("%s -> %s / %s / %s", orDash(candidate.Source), orDash(candidate.Destination), orDash(candidate.IndicatorType), firstNonEmptyText(candidate.Evidence, candidate.IndicatorValue)),
			severityFromConfidence(candidate.Confidence),
			candidate.PacketID,
			candidate.StreamID,
			append([]string{"c2", family}, candidate.Tags...)...,
		), c2ReportRuleID(family), "C2 候选由 family-specific 规则、通信形态或解密结果聚合产生，需回到 packet/stream 复核。", candidate.Confidence, c2ReportCaveat(family)))
	}
	for _, aggregate := range limitC2HTTPEndpoints(analysis.HostURIAggregates, 2) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("%s %s", aggregate.Host, aggregate.URI),
			fmt.Sprintf("total=%d / methods=%s / confidence=%d", aggregate.Total, renderBucketLabels(aggregate.Methods), aggregate.Confidence),
			"",
			firstInt64(aggregate.Packets),
			firstInt64ToStream(aggregate.Streams),
			"c2", family, "http-aggregate",
		))
	}
	for _, aggregate := range limitC2DNSAggregates(analysis.DNSAggregates, 2) {
		report.Details = append(report.Details, reportItem(
			aggregate.QName,
			fmt.Sprintf("total=%d / query=%d / response=%d / TXT=%d", aggregate.Total, aggregate.RequestCount, aggregate.ResponseCount, aggregate.TxtCount),
			"",
			firstInt64(aggregate.Packets),
			0,
			"c2", family, "dns-aggregate",
		))
	}
	for _, aggregate := range limitC2StreamAggregates(analysis.StreamAggregates, 2) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("stream #%d", aggregate.StreamID),
			fmt.Sprintf("packets=%d / websocket=%t / heartbeat=%s / confidence=%d", aggregate.TotalPackets, aggregate.HasWebSocket, firstNonEmptyText(aggregate.HeartbeatAvg, "--"), aggregate.Confidence),
			"",
			firstInt64(aggregate.Packets),
			aggregate.StreamID,
			"c2", family, "stream-aggregate",
		))
	}

	recommendations := []string{}
	if len(analysis.Candidates) > 0 {
		recommendations = append(recommendations, "优先从最高置信候选回到原始数据包，再打开关联流确认同一 channel/host/stream 上下文。")
	}
	if len(analysis.DeliveryChains) > 0 || len(analysis.RelatedActors) > 0 {
		recommendations = append(recommendations, "相关 actor 与 delivery chain 只作为扩展线索，仍需以候选证据和聚合画像为主进行复核。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 6, 6)
}

func c2ReportRuleID(family string) string {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "vshell":
		return "c2.vshell.decrypt.hit"
	case "cs":
		return "c2.cs.high_confidence"
	default:
		return "c2.family.candidate"
	}
}

func c2ReportCaveat(family string) string {
	if strings.EqualFold(strings.TrimSpace(family), "vshell") {
		return "VShell 弱信号和解密命中仍需结合密钥来源、stream 方向和明文语义复核。"
	}
	return "CS raw key 通常不能仅从 PCAP 推出；解密结论需结合 TeamServer key 或 RSA 私钥来源。"
}

func limitUSBKeyboardEvents(items []model.USBKeyboardEvent, limit int) []model.USBKeyboardEvent {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.USBKeyboardEvent(nil), items[:limit]...)
}

func limitUSBControlRecords(items []model.USBPacketRecord, limit int) []model.USBPacketRecord {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.USBPacketRecord(nil), items[:limit]...)
}

func limitC2Candidates(items []model.C2IndicatorRecord, limit int) []model.C2IndicatorRecord {
	cloned := append([]model.C2IndicatorRecord(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].Confidence != cloned[j].Confidence {
			return cloned[i].Confidence > cloned[j].Confidence
		}
		return cloned[i].PacketID < cloned[j].PacketID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitC2HTTPEndpoints(items []model.C2HTTPEndpointAggregate, limit int) []model.C2HTTPEndpointAggregate {
	cloned := append([]model.C2HTTPEndpointAggregate(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].Confidence != cloned[j].Confidence {
			return cloned[i].Confidence > cloned[j].Confidence
		}
		if cloned[i].Total != cloned[j].Total {
			return cloned[i].Total > cloned[j].Total
		}
		return cloned[i].Host+cloned[i].URI < cloned[j].Host+cloned[j].URI
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitC2DNSAggregates(items []model.C2DNSAggregate, limit int) []model.C2DNSAggregate {
	cloned := append([]model.C2DNSAggregate(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].Confidence != cloned[j].Confidence {
			return cloned[i].Confidence > cloned[j].Confidence
		}
		if cloned[i].Total != cloned[j].Total {
			return cloned[i].Total > cloned[j].Total
		}
		return cloned[i].QName < cloned[j].QName
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitC2StreamAggregates(items []model.C2StreamAggregate, limit int) []model.C2StreamAggregate {
	cloned := append([]model.C2StreamAggregate(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].Confidence != cloned[j].Confidence {
			return cloned[i].Confidence > cloned[j].Confidence
		}
		if cloned[i].TotalPackets != cloned[j].TotalPackets {
			return cloned[i].TotalPackets > cloned[j].TotalPackets
		}
		return cloned[i].StreamID < cloned[j].StreamID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}
