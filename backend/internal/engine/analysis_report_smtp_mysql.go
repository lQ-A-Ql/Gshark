package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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
