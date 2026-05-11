package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildHTTPLoginInvestigationReport(analysis model.HTTPLoginAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("候选端点", fmt.Sprintf("%d 个端点 / %d 次尝试", analysis.CandidateEndpoints, analysis.TotalAttempts), "", 0, 0),
		reportItem("结果分布", fmt.Sprintf("成功 %d · 失败 %d · 待确认 %d", analysis.SuccessCount, analysis.FailureCount, analysis.UncertainCount), "", 0, 0),
	)
	if analysis.BruteforceCount > 0 {
		report.Summary = append(report.Summary, reportItem("高风险信号", fmt.Sprintf("疑似爆破 %d 个端点", analysis.BruteforceCount), "high", 0, 0))
	}

	for _, endpoint := range analysis.Endpoints {
		packetID := firstInt64(endpoint.SamplePacketIDs)
		switch {
		case endpoint.PossibleBruteforce:
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 疑似爆破", renderHTTPLoginEndpointReportTitle(endpoint)),
				fmt.Sprintf("尝试 %d / 成功 %d / 失败 %d / 用户名变体 %d", endpoint.AttemptCount, endpoint.SuccessCount, endpoint.FailureCount, endpoint.UsernameVariants),
				"high",
				packetID,
				0,
				"login", "bruteforce",
			))
		case endpoint.UncertainCount > 0 && endpoint.SuccessCount == 0:
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 存在未决认证结果", renderHTTPLoginEndpointReportTitle(endpoint)),
				fmt.Sprintf("失败 %d / 待确认 %d / 响应信号 %s", endpoint.FailureCount, endpoint.UncertainCount, joinOrFallback(endpoint.ResponseIndicators, "无")),
				"medium",
				packetID,
				0,
				"login", "uncertain",
			))
		case endpoint.FailureCount > 0 && endpoint.SuccessCount == 0:
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 连续失败", renderHTTPLoginEndpointReportTitle(endpoint)),
				fmt.Sprintf("失败 %d 次 / 请求键 %s", endpoint.FailureCount, joinOrFallback(endpoint.RequestKeys, "无")),
				"low",
				packetID,
				0,
				"login", "failure",
			))
		}
	}

	for _, endpoint := range limitHTTPLoginEndpoints(analysis.Endpoints, 4) {
		report.Details = append(report.Details, reportItem(
			renderHTTPLoginEndpointReportTitle(endpoint),
			fmt.Sprintf("样本包 %d / 尝试 %d / 状态码 %s / 请求键 %s", firstInt64(endpoint.SamplePacketIDs), endpoint.AttemptCount, renderBucketLabels(endpoint.StatusCodes), joinOrFallback(endpoint.RequestKeys, "无")),
			"",
			firstInt64(endpoint.SamplePacketIDs),
			0,
			"endpoint",
		))
	}

	recommendations := []string{}
	if analysis.BruteforceCount > 0 {
		recommendations = append(recommendations, "优先定位疑似爆破端点的首个样本包，回到主工作区确认用户名变体、验证码字段和返回码节奏。")
	}
	if analysis.SuccessCount > 0 {
		recommendations = append(recommendations, "对成功登录请求继续打开关联 HTTP 流，追踪 Set-Cookie、Location 跳转和 token 下发。")
	}
	if analysis.UncertainCount > 0 {
		recommendations = append(recommendations, "待确认结果建议结合同一 stream 的前后响应包，核对是否存在 302 跳转、二次验证或 JavaScript 异步登录。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 5, 4)
}

func buildSMTPInvestigationReport(analysis model.SMTPAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("SMTP 会话", fmt.Sprintf("%d 条会话 / %d 封邮件", analysis.SessionCount, analysis.MessageCount), "", 0, 0),
		reportItem("认证与附件", fmt.Sprintf("认证 %d / 附件线索 %d", analysis.AuthCount, analysis.AttachmentHintCount), "", 0, 0),
	)

	for _, session := range analysis.Sessions {
		packetID := firstSMTPPacketID(session)
		if session.AuthPasswordSeen && session.PossibleCleartext {
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("SMTP stream #%d 发现明文认证", session.StreamID),
				fmt.Sprintf("AUTH %s / 用户 %s / 状态 %s", joinOrFallback(session.AuthMechanisms, "未知"), orDash(session.AuthUsername), joinOrFallback(session.StatusHints, "无")),
				"high",
				packetID,
				session.StreamID,
				"smtp", "auth",
			))
		}
		if session.AttachmentHints > 0 {
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("SMTP stream #%d 存在附件线索", session.StreamID),
				fmt.Sprintf("附件提示 %d / 收件人 %s", session.AttachmentHints, joinOrFallback(session.RcptTo, "无")),
				"medium",
				packetID,
				session.StreamID,
				"smtp", "attachment",
			))
		}
	}

	for _, session := range limitSMTPSessions(analysis.Sessions, 4) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("SMTP stream #%d", session.StreamID),
			fmt.Sprintf("%s / HELO=%s / 邮件 %d / 命令 %d", renderSMTPEndpointPair(session), orDash(session.Helo), session.MessageCount, session.CommandCount),
			"",
			firstSMTPPacketID(session),
			session.StreamID,
			"smtp",
		))
	}

	recommendations := []string{}
	if analysis.AuthCount > 0 {
		recommendations = append(recommendations, "优先检查 AUTH 会话是否仍处于明文阶段，并结合用户名、RCPT TO 和响应码确认是否存在账号投递链。")
	}
	if analysis.AttachmentHintCount > 0 {
		recommendations = append(recommendations, "对带附件线索的会话打开关联流，继续核对 DATA 正文、边界字段和附件文件名。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 5, 4)
}

func buildMySQLInvestigationReport(analysis model.MySQLAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("MySQL 会话", fmt.Sprintf("%d 条会话 / 登录 %d", analysis.SessionCount, analysis.LoginCount), "", 0, 0),
		reportItem("查询与异常", fmt.Sprintf("查询 %d / 错误 %d / 结果集 %d", analysis.QueryCount, analysis.ErrorCount, analysis.ResultsetCount), "", 0, 0),
	)

	for _, session := range analysis.Sessions {
		for _, query := range session.Queries {
			severity, label := classifyMySQLQueryRisk(query.SQL)
			if severity == "" {
				continue
			}
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("MySQL stream #%d %s", session.StreamID, label),
				fmt.Sprintf("用户 %s / DB %s / SQL %s", orDash(session.Username), orDash(firstNonEmptyText(query.Database, session.Database)), truncatePreview(strings.TrimSpace(query.SQL), 180)),
				severity,
				query.PacketID,
				session.StreamID,
				"mysql", "query",
			))
		}
		if session.ErrCount > 0 {
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("MySQL stream #%d 返回错误响应", session.StreamID),
				fmt.Sprintf("错误 %d / 命令 %s", session.ErrCount, joinOrFallback(session.CommandTypes, "未知")),
				"medium",
				firstMySQLPacketID(session),
				session.StreamID,
				"mysql", "error",
			))
		}
	}

	for _, session := range limitMySQLSessions(analysis.Sessions, 4) {
		report.Details = append(report.Details, reportItem(
			fmt.Sprintf("MySQL stream #%d", session.StreamID),
			fmt.Sprintf("%s / 用户=%s / DB=%s / 版本=%s / 查询=%d", renderMySQLEndpointPair(session), orDash(session.Username), orDash(session.Database), orDash(session.ServerVersion), session.QueryCount),
			"",
			firstMySQLPacketID(session),
			session.StreamID,
			"mysql",
		))
	}

	recommendations := []string{}
	if analysis.ErrorCount > 0 {
		recommendations = append(recommendations, "优先查看 ERR 响应对应的查询包，确认是普通语法错误、权限拒绝还是高风险管理指令失败。")
	}
	if hasHighRiskMySQLQuery(analysis.Sessions) {
		recommendations = append(recommendations, "已出现管理/文件型 SQL，建议继续定位关联响应包，核对是否存在 OUTFILE、LOAD_FILE、用户管理或全局配置修改。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 6, 4)
}

func buildShiroInvestigationReport(analysis model.ShiroRememberMeAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("rememberMe 候选", fmt.Sprintf("%d 个 Cookie 样本 / 密钥命中 %d", analysis.CandidateCount, analysis.HitCount), "", 0, 0),
	)

	for _, candidate := range analysis.Candidates {
		switch {
		case candidate.HitCount > 0:
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 命中候选密钥", renderShiroCandidateReportTitle(candidate)),
				fmt.Sprintf("stream=%d / 命中 %d 个密钥 / 预览 %s", candidate.StreamID, candidate.HitCount, orDash(candidate.CookiePreview)),
				"high",
				candidate.PacketID,
				candidate.StreamID,
				"shiro", "rememberme",
			))
		case shiroCandidateDeleteMe(candidate):
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 出现 deleteMe 回收痕迹", renderShiroCandidateReportTitle(candidate)),
				fmt.Sprintf("源头 %s / 说明 %s", orDash(candidate.SourceHeader), joinOrFallback(candidate.Notes, "无")),
				"medium",
				candidate.PacketID,
				candidate.StreamID,
				"shiro", "deleteme",
			))
		case candidate.DecodeOK:
			report.Evidence = append(report.Evidence, reportItem(
				fmt.Sprintf("%s 已解码但未命中密钥", renderShiroCandidateReportTitle(candidate)),
				fmt.Sprintf("长度 %d / CBC=%t / GCM=%t", candidate.EncryptedLength, candidate.PossibleCBC, candidate.PossibleGCM),
				"low",
				candidate.PacketID,
				candidate.StreamID,
				"shiro", "cookie",
			))
		}
	}

	for _, candidate := range limitShiroCandidates(analysis.Candidates, 4) {
		report.Details = append(report.Details, reportItem(
			renderShiroCandidateReportTitle(candidate),
			fmt.Sprintf("stream=%d / 命中=%d / 说明=%s", candidate.StreamID, candidate.HitCount, joinOrFallback(candidate.Notes, "无")),
			"",
			candidate.PacketID,
			candidate.StreamID,
			"shiro",
		))
	}

	recommendations := []string{}
	if analysis.HitCount > 0 {
		recommendations = append(recommendations, "已命中 rememberMe 密钥，优先回到对应 HTTP 包和关联流确认 Cookie 下发、回收及后续会话行为。")
	}
	if analysis.CandidateCount > 0 && analysis.HitCount == 0 {
		recommendations = append(recommendations, "候选样本已定位但未命中密钥，建议补充自定义密钥或继续核对应用是否使用了非默认 rememberMe 名称。")
	}
	report.Recommendations = appendRecommendations(recommendations, analysis.Notes, 4)
	return trimReport(report, 4, 5, 4)
}

func buildIndustrialInvestigationReport(analysis model.IndustrialAnalysis) model.InvestigationReport {
	report := emptyInvestigationReport()
	report.Summary = append(report.Summary,
		reportItem("工控协议概览", fmt.Sprintf("工控包 %d / 协议 %d / 会话 %d", analysis.TotalIndustrialPackets, len(analysis.Protocols), len(analysis.Conversations)), "", 0, 0),
		reportItem("Modbus 视角", fmt.Sprintf("帧 %d / 请求 %d / 异常 %d", analysis.Modbus.TotalFrames, analysis.Modbus.Requests, analysis.Modbus.Exceptions), "", 0, 0),
	)

	for _, hit := range analysis.RuleHits {
		report.Evidence = append(report.Evidence, reportItem(
			firstNonEmptyText(hit.Rule, "工控规则命中"),
			firstNonEmptyText(hit.Summary, hit.Evidence),
			mapIndustrialSeverity(hit.Level),
			hit.PacketID,
			0,
			"industrial", strings.ToLower(strings.TrimSpace(hit.Rule)),
		))
	}
	for _, write := range analysis.SuspiciousWrites {
		report.Evidence = append(report.Evidence, reportItem(
			fmt.Sprintf("%s 写操作集中出现", firstNonEmptyText(write.FunctionName, "Modbus 写操作")),
			fmt.Sprintf("目标 %s / 次数 %d / 来源 %s", write.Target, write.WriteCount, joinOrFallback(write.Sources, "无")),
			"high",
			write.SamplePacketID,
			0,
			"industrial", "write",
		))
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
		report.Evidence = append(report.Evidence, reportItem(
			buildUDSEvidenceSummary(tx),
			fmt.Sprintf("%s -> %s / 状态 %s / 请求 %s / 响应 %s", orDash(tx.SourceAddress), orDash(tx.TargetAddress), tx.Status, orDash(tx.RequestSummary), orDash(tx.ResponseSummary)),
			severityFromConfidence(confidence),
			packetID,
			0,
			"vehicle", "uds",
		))
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
		report.Evidence = append(report.Evidence, reportItem(
			buildUSBEvidenceSummary(op),
			fmt.Sprintf("设备 %s / %s / 长度 %d / status=%s", orDash(op.Device), orDash(op.LUN), op.TransferLength, orDash(op.Status)),
			severity,
			op.PacketID,
			0,
			"usb", "mass-storage", "write",
		))
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
		report.Evidence = append(report.Evidence, reportItem(
			firstNonEmptyText(candidate.Summary, fmt.Sprintf("%s candidate", label)),
			fmt.Sprintf("%s -> %s / %s / %s", orDash(candidate.Source), orDash(candidate.Destination), orDash(candidate.IndicatorType), firstNonEmptyText(candidate.Evidence, candidate.IndicatorValue)),
			severityFromConfidence(candidate.Confidence),
			candidate.PacketID,
			candidate.StreamID,
			append([]string{"c2", family}, candidate.Tags...)...,
		))
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

func emptyInvestigationReport() model.InvestigationReport {
	return model.InvestigationReport{
		Summary:         []model.InvestigationReportItem{},
		Evidence:        []model.InvestigationReportItem{},
		Details:         []model.InvestigationReportItem{},
		Recommendations: []string{},
	}
}

func reportItem(title, summary, severity string, packetID, streamID int64, tags ...string) model.InvestigationReportItem {
	return model.InvestigationReportItem{
		Title:    strings.TrimSpace(title),
		Summary:  strings.TrimSpace(summary),
		Severity: strings.TrimSpace(severity),
		PacketID: packetID,
		StreamID: streamID,
		Tags:     dedupeNonEmpty(tags),
	}
}

func trimReport(report model.InvestigationReport, summaryLimit, evidenceLimit, detailLimit int) model.InvestigationReport {
	report.Summary = trimReportItems(report.Summary, summaryLimit)
	report.Evidence = trimReportItems(report.Evidence, evidenceLimit)
	report.Details = trimReportItems(report.Details, detailLimit)
	report.Recommendations = trimStringList(report.Recommendations, 6)
	return report
}

func trimReportItems(items []model.InvestigationReportItem, limit int) []model.InvestigationReportItem {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.InvestigationReportItem(nil), items[:limit]...)
}

func appendRecommendations(primary, fallback []string, limit int) []string {
	out := []string{}
	for _, item := range append(append([]string{}, primary...), fallback...) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = appendUniqueString(out, item)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func dedupeNonEmpty(items []string) []string {
	out := []string{}
	for _, item := range items {
		out = appendUniqueString(out, item)
	}
	return out
}

func renderHTTPLoginEndpointReportTitle(endpoint model.HTTPLoginEndpoint) string {
	base := strings.TrimSpace(endpoint.Path)
	if host := strings.TrimSpace(endpoint.Host); host != "" {
		base = host + firstNonEmptyText(base, "/")
	}
	return fmt.Sprintf("%s %s", firstNonEmptyText(endpoint.Method, "HTTP"), firstNonEmptyText(base, "/"))
}

func limitHTTPLoginEndpoints(items []model.HTTPLoginEndpoint, limit int) []model.HTTPLoginEndpoint {
	cloned := append([]model.HTTPLoginEndpoint(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].AttemptCount != cloned[j].AttemptCount {
			return cloned[i].AttemptCount > cloned[j].AttemptCount
		}
		return cloned[i].Key < cloned[j].Key
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitSMTPSessions(items []model.SMTPSession, limit int) []model.SMTPSession {
	cloned := append([]model.SMTPSession(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].MessageCount != cloned[j].MessageCount {
			return cloned[i].MessageCount > cloned[j].MessageCount
		}
		if cloned[i].AttachmentHints != cloned[j].AttachmentHints {
			return cloned[i].AttachmentHints > cloned[j].AttachmentHints
		}
		return cloned[i].StreamID < cloned[j].StreamID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitMySQLSessions(items []model.MySQLSession, limit int) []model.MySQLSession {
	cloned := append([]model.MySQLSession(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].QueryCount != cloned[j].QueryCount {
			return cloned[i].QueryCount > cloned[j].QueryCount
		}
		if cloned[i].ErrCount != cloned[j].ErrCount {
			return cloned[i].ErrCount > cloned[j].ErrCount
		}
		return cloned[i].StreamID < cloned[j].StreamID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
}

func limitShiroCandidates(items []model.ShiroRememberMeCandidate, limit int) []model.ShiroRememberMeCandidate {
	cloned := append([]model.ShiroRememberMeCandidate(nil), items...)
	sort.SliceStable(cloned, func(i, j int) bool {
		if cloned[i].HitCount != cloned[j].HitCount {
			return cloned[i].HitCount > cloned[j].HitCount
		}
		return cloned[i].PacketID < cloned[j].PacketID
	})
	if limit > 0 && len(cloned) > limit {
		return cloned[:limit]
	}
	return cloned
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

func classifyMySQLQueryRisk(sql string) (string, string) {
	text := strings.ToLower(strings.TrimSpace(sql))
	switch {
	case text == "":
		return "", ""
	case strings.Contains(text, "into outfile") || strings.Contains(text, "into dumpfile"):
		return "high", "出现文件写出类 SQL"
	case strings.Contains(text, "load_file("):
		return "high", "出现文件读取类 SQL"
	case strings.Contains(text, "grant ") || strings.Contains(text, "create user") || strings.Contains(text, "alter user") || strings.Contains(text, "set password"):
		return "medium", "出现账号/权限管理 SQL"
	case strings.Contains(text, "set global") || strings.Contains(text, "shutdown"):
		return "medium", "出现实例级管理 SQL"
	default:
		return "", ""
	}
}

func hasHighRiskMySQLQuery(sessions []model.MySQLSession) bool {
	for _, session := range sessions {
		for _, query := range session.Queries {
			if severity, _ := classifyMySQLQueryRisk(query.SQL); severity != "" {
				return true
			}
		}
	}
	return false
}

func shiroCandidateDeleteMe(candidate model.ShiroRememberMeCandidate) bool {
	for _, note := range candidate.Notes {
		if strings.Contains(strings.ToLower(note), "deleteme") {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(candidate.CookieValue), "deleteme")
}

func severityFromConfidence(confidence int) string {
	switch {
	case confidence >= 90:
		return "critical"
	case confidence >= 75:
		return "high"
	case confidence >= 55:
		return "medium"
	case confidence > 0:
		return "low"
	default:
		return "info"
	}
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

func renderBucketLabels(items []model.TrafficBucket) string {
	if len(items) == 0 {
		return "无"
	}
	labels := make([]string, 0, minReportInt(len(items), 3))
	for _, item := range items {
		if label := strings.TrimSpace(item.Label); label != "" {
			labels = append(labels, label)
		}
		if len(labels) >= 3 {
			break
		}
	}
	if len(labels) == 0 {
		return "无"
	}
	return strings.Join(labels, " / ")
}

func firstInt64(items []int64) int64 {
	if len(items) == 0 {
		return 0
	}
	return items[0]
}

func firstInt64ToStream(items []int64) int64 {
	return firstInt64(items)
}

func firstNonZero(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstSMTPPacketID(session model.SMTPSession) int64 {
	for _, command := range session.Commands {
		if command.PacketID > 0 {
			return command.PacketID
		}
	}
	for _, message := range session.Messages {
		if packetID := firstInt64(message.PacketIDs); packetID > 0 {
			return packetID
		}
	}
	return 0
}

func firstMySQLPacketID(session model.MySQLSession) int64 {
	if session.LoginPacketID > 0 {
		return session.LoginPacketID
	}
	for _, query := range session.Queries {
		if query.PacketID > 0 {
			return query.PacketID
		}
	}
	for _, event := range session.ServerEvents {
		if event.PacketID > 0 {
			return event.PacketID
		}
	}
	return 0
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

func renderSMTPEndpointPair(session model.SMTPSession) string {
	left := orDash(session.Client)
	if session.ClientPort > 0 {
		left = fmt.Sprintf("%s:%d", left, session.ClientPort)
	}
	right := orDash(session.Server)
	if session.ServerPort > 0 {
		right = fmt.Sprintf("%s:%d", right, session.ServerPort)
	}
	return left + " -> " + right
}

func renderMySQLEndpointPair(session model.MySQLSession) string {
	left := orDash(session.Client)
	if session.ClientPort > 0 {
		left = fmt.Sprintf("%s:%d", left, session.ClientPort)
	}
	right := orDash(session.Server)
	if session.ServerPort > 0 {
		right = fmt.Sprintf("%s:%d", right, session.ServerPort)
	}
	return left + " -> " + right
}

func renderShiroCandidateReportTitle(candidate model.ShiroRememberMeCandidate) string {
	location := strings.TrimSpace(candidate.Path)
	if host := strings.TrimSpace(candidate.Host); host != "" {
		location = host + firstNonEmptyText(location, "/")
	}
	return fmt.Sprintf("%s @ %s", firstNonEmptyText(candidate.CookieName, "rememberMe"), firstNonEmptyText(location, "/"))
}

func joinOrFallback(items []string, fallback string) string {
	values := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
		if len(values) >= 4 {
			break
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return strings.Join(values, " / ")
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "--"
	}
	return strings.TrimSpace(value)
}

func minReportInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
