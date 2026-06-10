package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestApplyRuleUsesRegisteredMetadataDefaults(t *testing.T) {
	meta := RuleRegistry["http.login.bruteforce"]
	item := ApplyRule(model.InvestigationReportItem{Title: "login"}, meta.RuleID, 0)

	if item.RuleID != meta.RuleID {
		t.Fatalf("RuleID = %q, want %q", item.RuleID, meta.RuleID)
	}
	if item.Reason != strings.TrimSpace(meta.Reason) {
		t.Fatalf("Reason = %q, want registry reason", item.Reason)
	}
	if item.Confidence != meta.DefaultConfidence {
		t.Fatalf("Confidence = %d, want %d", item.Confidence, meta.DefaultConfidence)
	}
	if !reflect.DeepEqual(item.Caveats, dedupeNonEmpty(meta.Caveats)) {
		t.Fatalf("Caveats = %#v, want registry caveats", item.Caveats)
	}
}

func TestApplyRuleUnknownRuleReturnsLowConfidenceFallback(t *testing.T) {
	item := ApplyRule(model.InvestigationReportItem{}, " missing.rule ", 0)

	if item.RuleID != "missing.rule" {
		t.Fatalf("RuleID = %q, want trimmed unknown rule id", item.RuleID)
	}
	if item.Confidence != 1 {
		t.Fatalf("Confidence = %d, want low confidence fallback 1", item.Confidence)
	}
	if !strings.Contains(item.Caveats[0], "unknown report rule metadata") {
		t.Fatalf("Caveats = %#v, want unknown metadata caveat", item.Caveats)
	}
	if strings.TrimSpace(item.Reason) == "" {
		t.Fatal("Reason is empty for unknown rule fallback")
	}
}

func TestApplyRuleClampsPositiveConfidence(t *testing.T) {
	item := ApplyRule(model.InvestigationReportItem{}, "http.login.bruteforce", 250)
	if item.Confidence != 100 {
		t.Fatalf("Confidence = %d, want clamp to 100", item.Confidence)
	}

	if got := clampConfidence(-8); got != 0 {
		t.Fatalf("clampConfidence(-8) = %d, want 0", got)
	}
	if got := clampConfidence(42); got != 42 {
		t.Fatalf("clampConfidence(42) = %d, want 42", got)
	}
}

func TestApplyRuleFieldsDedupeAndTrimCaveats(t *testing.T) {
	item := applyRuleFields(
		model.InvestigationReportItem{},
		" rule ",
		" reason ",
		50,
		" duplicate ",
		"",
		"duplicate",
		" second ",
	)

	if item.RuleID != "rule" || item.Reason != "reason" {
		t.Fatalf("trimmed fields = rule %q reason %q", item.RuleID, item.Reason)
	}
	want := []string{"duplicate", "second"}
	if !reflect.DeepEqual(item.Caveats, want) {
		t.Fatalf("Caveats = %#v, want %#v", item.Caveats, want)
	}
}
