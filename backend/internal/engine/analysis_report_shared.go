package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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

func withReportRule(item model.InvestigationReportItem, ruleID, reason string, confidence int, caveats ...string) model.InvestigationReportItem {
	item.RuleID = strings.TrimSpace(ruleID)
	item.Reason = strings.TrimSpace(reason)
	if confidence > 0 {
		item.Confidence = clampReportConfidence(confidence)
	}
	item.Caveats = dedupeNonEmpty(caveats)
	return item
}

func clampReportConfidence(value int) int {
	switch {
	case value < 0:
		return 0
	case value > 100:
		return 100
	default:
		return value
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

func severityFromConfidence(confidence int) string {
	switch {
	case confidence >= 85:
		return "critical"
	case confidence >= 70:
		return "high"
	case confidence >= 45:
		return "medium"
	case confidence > 0:
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
