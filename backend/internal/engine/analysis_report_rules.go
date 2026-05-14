package engine

import (
	"github.com/gshark/sentinel/backend/internal/model"
	reportrules "github.com/gshark/sentinel/backend/internal/report"
)

func withReportRuleID(item model.InvestigationReportItem, ruleID string, confidence int) model.InvestigationReportItem {
	return reportrules.ApplyRule(item, ruleID, confidence)
}
