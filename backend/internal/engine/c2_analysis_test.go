package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestServiceC2SampleAnalysisReturnsSkeleton(t *testing.T) {
	svc := NewService(nil, nil)
	svc.pcap = "fixture.pcapng"

	analysis, err := svc.C2SampleAnalysis(context.Background())
	if err != nil {
		t.Fatalf("C2SampleAnalysis() error = %v", err)
	}
	if analysis.TotalMatchedPackets != 0 {
		t.Fatalf("expected zero matched packets, got %d", analysis.TotalMatchedPackets)
	}
	if analysis.CS.Candidates == nil || analysis.VShell.Candidates == nil {
		t.Fatalf("expected initialized family slices, got %+v", analysis)
	}
	if len(analysis.Notes) == 0 {
		t.Fatalf("expected explanatory notes for skeleton analysis")
	}
}

func TestServiceC2SampleAnalysisHonorsContextCancel(t *testing.T) {
	svc := NewService(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := svc.C2SampleAnalysis(ctx); err == nil {
		t.Fatalf("expected canceled context error")
	}
}

func TestBuildC2SampleAnalysisDetectsVShellWebSocketHandshake(t *testing.T) {
	packets := []model.Packet{
		{
			ID:         10,
			Timestamp:  "12:00:00.000000",
			SourceIP:   "10.0.0.5",
			SourcePort: 51111,
			DestIP:     "10.0.0.9",
			DestPort:   8088,
			Protocol:   "HTTP",
			Info:       "GET /?a=l64&h=10.0.0.9&t=ws_&p=8088 HTTP/1.1",
			Payload:    "GET /?a=l64&h=10.0.0.9&t=ws_&p=8088 HTTP/1.1\r\nHost: 10.0.0.9\r\n\r\n",
			StreamID:   1,
		},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if analysis.VShell.CandidateCount == 0 {
		t.Fatalf("expected VShell candidate, got %+v", analysis.VShell)
	}
	got := analysis.VShell.Candidates[0]
	if got.IndicatorType != "websocket-handshake" || got.Channel != "websocket" {
		t.Fatalf("unexpected VShell candidate: %+v", got)
	}
}

func TestBuildC2SampleAnalysisDetectsVShellTCPShapes(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50000, DestIP: "10.0.0.9", DestPort: 8084, Protocol: "TCP", Payload: "6c:36:34:00:00:00", StreamID: 7},
		{ID: 2, Timestamp: "12:00:10.000000", SourceIP: "10.0.0.5", SourcePort: 50000, DestIP: "10.0.0.9", DestPort: 8084, Protocol: "TCP", Payload: "00:00:00:04:de:ad:be:ef", StreamID: 7},
		{ID: 3, Timestamp: "12:00:20.000000", SourceIP: "10.0.0.5", SourcePort: 50000, DestIP: "10.0.0.9", DestPort: 8084, Protocol: "TCP", Payload: "00:00:00:04:aa:bb:cc:dd", StreamID: 7},
		{ID: 4, Timestamp: "12:00:30.000000", SourceIP: "10.0.0.5", SourcePort: 50000, DestIP: "10.0.0.9", DestPort: 8084, Protocol: "TCP", Payload: "00:00:00:04:01:02:03:04", StreamID: 7},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if analysis.VShell.CandidateCount < 3 {
		t.Fatalf("expected multiple VShell candidates, got %+v", analysis.VShell.Candidates)
	}
	if !hasC2Indicator(analysis.VShell.Candidates, "arch-marker") {
		t.Fatalf("expected arch-marker candidate: %+v", analysis.VShell.Candidates)
	}
	if !hasC2Indicator(analysis.VShell.Candidates, "length-prefixed-encrypted-payload") {
		t.Fatalf("expected length-prefix candidate: %+v", analysis.VShell.Candidates)
	}
	if !hasC2Indicator(analysis.VShell.Candidates, "heartbeat-interval") {
		t.Fatalf("expected heartbeat interval candidate: %+v", analysis.VShell.Candidates)
	}
}

func TestBuildC2SampleAnalysisDetectsCSHTTPAndDNS(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "GET /jquery.min.js HTTP/1.1", Payload: "GET /jquery.min.js HTTP/1.1\r\nHost: cdn.demo\r\nUser-Agent: Mozilla/5.0\r\n\r\n", StreamID: 3},
		{ID: 2, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "POST /submit.php?id=1 HTTP/1.1", Payload: "POST /submit.php?id=1 HTTP/1.1\r\nHost: cdn.demo\r\n\r\nabc", StreamID: 3},
		{ID: 3, Timestamp: "12:01:01.000000", SourceIP: "10.0.0.5", SourcePort: 53000, DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", Info: "Standard query TXT abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.example.com"},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if analysis.CS.CandidateCount < 2 {
		t.Fatalf("expected CS HTTP and DNS candidates, got %+v", analysis.CS.Candidates)
	}
	if !hasC2Indicator(analysis.CS.Candidates, "http-beacon-shape") {
		t.Fatalf("expected HTTP beacon shape candidate")
	}
	if !hasC2Indicator(analysis.CS.Candidates, "dns-beacon-shape") {
		t.Fatalf("expected DNS beacon shape candidate")
	}
}

func TestBuildC2SampleAnalysisSuppressesBenignSingleHTTPRequests(t *testing.T) {
	packets := []model.Packet{
		{ID: 21, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "93.184.216.34", DestPort: 80, Protocol: "HTTP", Info: "GET /index.html HTTP/1.1", Payload: "GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n", StreamID: 11},
		{ID: 22, Timestamp: "12:00:02.000000", SourceIP: "10.0.0.5", SourcePort: 50101, DestIP: "93.184.216.34", DestPort: 80, Protocol: "HTTP", Info: "POST /login HTTP/1.1", Payload: "POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=demo", StreamID: 12},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if hasC2Indicator(analysis.CS.Candidates, "http-beacon-shape") {
		t.Fatalf("benign one-off HTTP requests should not be promoted to CS candidates: %+v", analysis.CS.Candidates)
	}
	if len(analysis.CS.HostURIAggregates) != 0 {
		t.Fatalf("benign one-off HTTP requests should not form aggregates: %+v", analysis.CS.HostURIAggregates)
	}
}

func TestBuildC2SampleAnalysisBuildsCSHostURIAggregates(t *testing.T) {
	packets := []model.Packet{
		{ID: 41, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "GET /api/checkin HTTP/1.1", Payload: "GET /api/checkin HTTP/1.1\r\nHost: c2.demo\r\n\r\n", StreamID: 8},
		{ID: 42, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "POST /api/checkin HTTP/1.1", Payload: "POST /api/checkin HTTP/1.1\r\nHost: c2.demo\r\n\r\nabc", StreamID: 8},
		{ID: 43, Timestamp: "12:02:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "GET /api/checkin HTTP/1.1", Payload: "GET /api/checkin HTTP/1.1\r\nHost: c2.demo\r\n\r\n", StreamID: 8},
		{ID: 44, Timestamp: "12:03:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "POST /api/checkin HTTP/1.1", Payload: "POST /api/checkin HTTP/1.1\r\nHost: c2.demo\r\n\r\nabc", StreamID: 8},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if len(analysis.CS.HostURIAggregates) == 0 {
		t.Fatalf("expected CS Host/URI aggregate, got %+v", analysis.CS)
	}
	got := analysis.CS.HostURIAggregates[0]
	if got.Host != "c2.demo" || got.URI != "/api/checkin" {
		t.Fatalf("unexpected aggregate key: %+v", got)
	}
	if got.GetCount != 2 || got.PostCount != 2 || got.Total != 4 {
		t.Fatalf("unexpected method counts: %+v", got)
	}
	if got.AvgInterval != "60.0s" || got.Jitter != "0%" {
		t.Fatalf("unexpected timing profile: %+v", got)
	}
	if len(got.Streams) != 1 || got.Streams[0] != 8 || len(got.Packets) != 4 {
		t.Fatalf("unexpected stream/packet refs: %+v", got)
	}
	if got.RepresentativePacket != 42 && got.RepresentativePacket != 44 {
		t.Fatalf("expected POST packet as representative, got %d", got.RepresentativePacket)
	}
}

func TestBuildC2SampleAnalysisBuildsCSDNSAggregates(t *testing.T) {
	packets := []model.Packet{
		{ID: 51, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 53000, DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", Info: "Standard query TXT abcdef.example.com"},
		{ID: 52, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 53000, DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", Info: "Standard query TXT abcdef.example.com"},
		{ID: 53, Timestamp: "12:02:00.000000", SourceIP: "10.0.0.5", SourcePort: 53000, DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", Info: "Standard query A abcdef.example.com"},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if len(analysis.CS.DNSAggregates) == 0 {
		t.Fatalf("expected CS DNS aggregate, got %+v", analysis.CS)
	}
	got := analysis.CS.DNSAggregates[0]
	if got.QName != "abcdef.example.com" {
		t.Fatalf("unexpected qname: %s", got.QName)
	}
	if got.Total != 3 {
		t.Fatalf("unexpected total: %d", got.Total)
	}
	if got.TxtCount != 2 {
		t.Fatalf("unexpected TXT count: %d", got.TxtCount)
	}
	if got.RequestCount != 3 {
		t.Fatalf("unexpected request count: %d", got.RequestCount)
	}
}

func hasC2Indicator(items []model.C2IndicatorRecord, indicator string) bool {
	for _, item := range items {
		if item.IndicatorType == indicator {
			return true
		}
	}
	return false
}
