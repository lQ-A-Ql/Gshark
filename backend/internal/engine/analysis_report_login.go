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
