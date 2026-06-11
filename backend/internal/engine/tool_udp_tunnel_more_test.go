package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildUDPTunnelAnalysisDetectsDNSAndUniformUDPSessions(t *testing.T) {
	packets := make([]model.Packet, 0, 380)
	for idx := 0; idx < 60; idx++ {
		subdomain := fmt.Sprintf("x%02dq9vaz%02dby7mpr4t6n0kc5e8s2h1", idx, 59-idx)
		packets = append(packets, model.Packet{
			ID:        int64(idx + 1),
			Protocol:  "DNS",
			Length:    240 + idx%5,
			Info:      "Standard query 0x1234 TXT " + subdomain + ".evil.test",
			SourceIP:  "10.10.0.10",
			DestIP:    "10.10.0.53",
			DestPort:  53,
			Timestamp: fmt.Sprintf("%.3f", float64(idx)/10),
		})
	}
	for idx := 0; idx < 250; idx++ {
		packets = append(packets, model.Packet{
			ID:            int64(1000 + idx),
			Timestamp:     fmt.Sprintf("%.3f", float64(idx)/20),
			SourceIP:      "10.20.0.10",
			DestIP:        "198.51.100.50",
			SourcePort:    53000,
			DestPort:      4444,
			Protocol:      "UDP",
			Length:        120,
			UDPPayloadHex: "aa",
		})
	}
	for idx := 0; idx < 110; idx++ {
		packets = append(packets, model.Packet{
			ID:            int64(2000 + idx),
			Timestamp:     fmt.Sprintf("%.3f", float64(idx)/20),
			SourceIP:      "10.20.0.20",
			DestIP:        "198.51.100.60",
			SourcePort:    54000,
			DestPort:      5555,
			Protocol:      "UDP",
			Length:        30 + idx%120,
			UDPPayloadHex: "bb",
		})
	}

	analysis, err := buildUDPTunnelAnalysis(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildUDPTunnelAnalysis() error = %v", err)
	}
	if analysis.TotalSuspicious != 2 {
		t.Fatalf("expected DNS and UDP tunnel findings, got %+v", analysis)
	}
	if len(analysis.DNSTunnelHits) != 1 {
		t.Fatalf("expected one DNS tunnel hit, got %+v", analysis.DNSTunnelHits)
	}
	dns := analysis.DNSTunnelHits[0]
	if dns.BaseDomain != "evil.test" || dns.QueryCount != 60 || dns.UniqueSubdomains != 60 {
		t.Fatalf("unexpected DNS tunnel identity: %+v", dns)
	}
	if dns.Confidence < 60 || !strings.Contains(dns.Evidence, "evil.test") {
		t.Fatalf("expected DNS tunnel confidence/evidence, got %+v", dns)
	}

	if len(analysis.UDPTunnelHits) != 1 {
		t.Fatalf("expected one uniform UDP tunnel hit, got %+v", analysis.UDPTunnelHits)
	}
	udp := analysis.UDPTunnelHits[0]
	if udp.Source != "10.20.0.10" || udp.Destination != "198.51.100.50" || udp.Port != 4444 {
		t.Fatalf("unexpected UDP tunnel identity: %+v", udp)
	}
	if udp.PacketCount != 250 || udp.AvgPayloadLen != 120 || udp.StdDevLen != 0 || udp.Confidence != 70 {
		t.Fatalf("unexpected UDP tunnel metrics: %+v", udp)
	}
	if udp.DurationSec <= 0 {
		t.Fatalf("expected duration from numeric timestamps, got %+v", udp)
	}
	if len(analysis.Notes) != 2 {
		t.Fatalf("expected notes for DNS and UDP findings, got %+v", analysis.Notes)
	}
}

func TestBuildUDPTunnelAnalysisNoFindingsHelpersAndCancellation(t *testing.T) {
	analysis, err := buildUDPTunnelAnalysis(context.Background(), []model.Packet{
		{ID: 1, Protocol: "DNS", Info: "Standard query A example.com", Length: 60},
		{ID: 2, Protocol: "UDP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 1234, Length: 40},
	})
	if err != nil {
		t.Fatalf("buildUDPTunnelAnalysis() error = %v", err)
	}
	if analysis.TotalSuspicious != 0 || len(analysis.DNSTunnelHits) != 0 || len(analysis.UDPTunnelHits) != 0 {
		t.Fatalf("expected no findings, got %+v", analysis)
	}
	if len(analysis.Notes) != 1 || analysis.Notes[0] == "" {
		t.Fatalf("expected empty-analysis note, got %+v", analysis.Notes)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = buildUDPTunnelAnalysis(ctx, []model.Packet{{ID: 1, Protocol: "DNS", Info: "Standard query A one.example.com"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation to propagate, got %v", err)
	}

	if got := extractSubdomain("host.branch.example.com", "example.com"); got != "host.branch" {
		t.Fatalf("extractSubdomain() = %q", got)
	}
	if got := extractSubdomain("example.org", "example.com"); got != "" {
		t.Fatalf("extractSubdomain mismatch = %q", got)
	}
	if got := calcStdDev([]int{100, 100, 100}, 100); got != 0 {
		t.Fatalf("calcStdDev uniform = %f", got)
	}
	if got := calcStdDev(nil, 100); got != 0 {
		t.Fatalf("calcStdDev empty = %f", got)
	}
	if got := estimateDurationSec("10.5", "7.5"); got != 3 {
		t.Fatalf("estimateDurationSec reverse = %f", got)
	}
	if got := estimateDurationSec("bad", "7.5"); got != 0 {
		t.Fatalf("estimateDurationSec invalid = %f", got)
	}
	if len(buildUDPTunnelNotes(model.UDPTunnelAnalysis{})) != 1 {
		t.Fatalf("expected no-finding UDP tunnel note")
	}
}
