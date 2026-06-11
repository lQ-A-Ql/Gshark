package engine

import (
	"reflect"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestWithReportRuleTrimsClampsAndDeduplicatesMetadata(t *testing.T) {
	item := reportItem(" title ", " summary ", " medium ", 7, 3, "alpha", " alpha ", "", "beta")
	got := withReportRule(item, " rule.id ", " reason text ", 130, " caveat ", "", "caveat", "second")

	if got.RuleID != "rule.id" || got.Reason != "reason text" {
		t.Fatalf("rule metadata was not trimmed: %+v", got)
	}
	if got.Confidence != 100 {
		t.Fatalf("confidence = %d, want clamp to 100", got.Confidence)
	}
	if !reflect.DeepEqual(got.Caveats, []string{"caveat", "second"}) {
		t.Fatalf("caveats = %+v", got.Caveats)
	}
	if !reflect.DeepEqual(got.Tags, []string{"alpha", "beta"}) {
		t.Fatalf("tags = %+v", got.Tags)
	}

	zero := withReportRule(model.InvestigationReportItem{}, "id", "reason", 0)
	if zero.Confidence != 0 {
		t.Fatalf("zero confidence should remain unset, got %+v", zero)
	}
}

func TestReportClampAndSelectionHelpersCoverEdges(t *testing.T) {
	for _, tt := range []struct {
		value int
		want  int
	}{
		{value: -1, want: 0},
		{value: 0, want: 0},
		{value: 58, want: 58},
		{value: 101, want: 100},
	} {
		if got := clampReportConfidence(tt.value); got != tt.want {
			t.Fatalf("clampReportConfidence(%d) = %d, want %d", tt.value, got, tt.want)
		}
	}

	if got := firstCANPacketID(nil); got != 0 {
		t.Fatalf("firstCANPacketID(nil) = %d", got)
	}
	if got := firstCANPacketID([]model.CANFrameSummary{{PacketID: 42}}); got != 42 {
		t.Fatalf("firstCANPacketID = %d, want 42", got)
	}
	if got := limitTrafficBuckets([]model.TrafficBucket{{Label: "a"}, {Label: "b"}, {Label: "c"}}, 2); len(got) != 2 || got[1].Label != "b" {
		t.Fatalf("limitTrafficBuckets = %+v", got)
	}
	if got := limitTrafficBuckets([]model.TrafficBucket{{Label: "a"}}, 0); len(got) != 1 {
		t.Fatalf("limitTrafficBuckets limit 0 = %+v", got)
	}
}

func TestIEC104RuleIDFallbackAndKnownRules(t *testing.T) {
	for _, rule := range []string{
		"iec104.cmd.unauthorized",
		"iec104.cmd.deactivation",
		"iec104.cmd.reset_process",
		"iec104.cmd.clock_sync",
		"iec104.cot.init",
		"iec104.cot.abnormal",
		"iec104.seq.tx_gap",
		"iec104.seq.rx_mismatch",
	} {
		if got := iec104RuleIDFromAnomaly(rule); got != rule {
			t.Fatalf("iec104RuleIDFromAnomaly(%q) = %q", rule, got)
		}
	}
	if got := iec104RuleIDFromAnomaly("vendor.rule"); got != "iec104.anomaly" {
		t.Fatalf("unknown IEC104 rule = %q", got)
	}
}

func TestReportLimitSortersPreferMostActionableItems(t *testing.T) {
	uds := []model.UDSTransaction{
		{RequestPacketID: 30, ServiceID: "0x22", Status: "request-only"},
		{RequestPacketID: 10, ServiceID: "0x27", Status: "negative-response", NegativeCode: "0x35"},
		{RequestPacketID: 20, ServiceID: "0x34", Status: "positive"},
	}
	limitedUDS := limitUDSTransactions(uds, 2)
	if len(limitedUDS) != 2 || limitedUDS[0].ServiceID != "0x27" || limitedUDS[1].ServiceID != "0x34" {
		t.Fatalf("limitUDSTransactions = %+v", limitedUDS)
	}
	if uds[0].RequestPacketID != 30 {
		t.Fatalf("limitUDSTransactions mutated input: %+v", uds)
	}

	smtp := []model.SMTPSession{
		{StreamID: 1, MessageCount: 5, AttachmentHints: 0},
		{StreamID: 2, MessageCount: 1, AttachmentHints: 9},
		{StreamID: 3, MessageCount: 5, AttachmentHints: 1},
	}
	limitedSMTP := limitSMTPSessions(smtp, 2)
	if len(limitedSMTP) != 2 || limitedSMTP[0].StreamID != 3 || limitedSMTP[1].StreamID != 1 {
		t.Fatalf("limitSMTPSessions = %+v", limitedSMTP)
	}

	mysql := []model.MySQLSession{
		{StreamID: 2, QueryCount: 3, ErrCount: 1},
		{StreamID: 1, QueryCount: 5, ErrCount: 0},
		{StreamID: 3, QueryCount: 5, ErrCount: 2},
	}
	limitedMySQL := limitMySQLSessions(mysql, 2)
	if len(limitedMySQL) != 2 || limitedMySQL[0].StreamID != 3 || limitedMySQL[1].StreamID != 1 {
		t.Fatalf("limitMySQLSessions = %+v", limitedMySQL)
	}

	streams := []model.C2StreamAggregate{
		{StreamID: 3, Confidence: 70, TotalPackets: 5},
		{StreamID: 2, Confidence: 90, TotalPackets: 2},
		{StreamID: 1, Confidence: 90, TotalPackets: 9},
	}
	limitedStreams := limitC2StreamAggregates(streams, 2)
	if len(limitedStreams) != 2 || limitedStreams[0].StreamID != 1 || limitedStreams[1].StreamID != 2 {
		t.Fatalf("limitC2StreamAggregates = %+v", limitedStreams)
	}
}
