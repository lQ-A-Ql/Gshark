package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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

func shiroCandidateDeleteMe(candidate model.ShiroRememberMeCandidate) bool {
	for _, note := range candidate.Notes {
		if strings.Contains(strings.ToLower(note), "deleteme") {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(candidate.CookieValue), "deleteme")
}

func renderShiroCandidateReportTitle(candidate model.ShiroRememberMeCandidate) string {
	location := strings.TrimSpace(candidate.Path)
	if host := strings.TrimSpace(candidate.Host); host != "" {
		location = host + firstNonEmptyText(location, "/")
	}
	return fmt.Sprintf("%s @ %s", firstNonEmptyText(candidate.CookieName, "rememberMe"), firstNonEmptyText(location, "/"))
}
