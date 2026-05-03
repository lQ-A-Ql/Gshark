package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestServiceC2SampleAnalysisReturnsInitializedEmptyState(t *testing.T) {
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
		t.Fatalf("expected explanatory notes for initialized empty-state analysis")
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

func TestServiceAPTAnalysisReturnsInitializedBaseline(t *testing.T) {
	svc := NewService(nil, nil)

	analysis, err := svc.APTAnalysis(context.Background())
	if err != nil {
		t.Fatalf("APTAnalysis() error = %v", err)
	}
	if analysis.TotalEvidence != 0 {
		t.Fatalf("expected zero evidence, got %d", analysis.TotalEvidence)
	}
	if analysis.Evidence == nil || len(analysis.Profiles) == 0 {
		t.Fatalf("expected initialized apt baseline, got %+v", analysis)
	}
	if analysis.Profiles[0].ID != "silver-fox" {
		t.Fatalf("expected silver fox baseline profile, got %+v", analysis.Profiles)
	}
	if len(analysis.Notes) == 0 {
		t.Fatalf("expected explanatory notes for apt baseline")
	}
}

func TestServiceAPTAnalysisHonorsContextCancel(t *testing.T) {
	svc := NewService(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := svc.APTAnalysis(ctx); err == nil {
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

func TestBuildVShellStreamAggregatesReturnsIntervals(t *testing.T) {
	streamData := map[int64]*c2VShellStreamWork{
		7: {
			streamID:      7,
			protocol:      "TCP",
			archMarkers:   map[string]int{"l64": 1},
			lengthPrefix:  3,
			shortPackets:  3,
			longPackets:   1,
			transitions:   2,
			heartbeatAvg:  "10.0s",
			listenerHints: map[string]int{"vshell-listener-port": 1},
			confidence:    60,
			packets: []model.Packet{
				{ID: 1, Timestamp: "12:00:00.000000"},
				{ID: 2, Timestamp: "12:00:10.000000"},
				{ID: 3, Timestamp: "12:00:20.000000"},
				{ID: 4, Timestamp: "12:00:30.000000"},
			},
		},
	}
	aggregates := buildVShellStreamAggregates(streamData, 16)
	if len(aggregates) != 1 {
		t.Fatalf("expected one aggregate, got %+v", aggregates)
	}
	if !floatSliceEqual(aggregates[0].Intervals, []float64{10, 10, 10}) {
		t.Fatalf("expected stream intervals, got %+v", aggregates[0].Intervals)
	}
}

func TestBuildC2SampleAnalysisDetectsCSHTTPAndDNS(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "GET /submit.php?id=1 HTTP/1.1", Payload: "GET /submit.php?id=1 HTTP/1.1\r\nHost: cdn.demo\r\n\r\n", StreamID: 3},
		{ID: 2, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "POST /submit.php?id=1 HTTP/1.1", Payload: "POST /submit.php?id=1 HTTP/1.1\r\nHost: cdn.demo\r\n\r\nabc", StreamID: 3},
		{ID: 3, Timestamp: "12:02:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "GET /submit.php?id=1 HTTP/1.1", Payload: "GET /submit.php?id=1 HTTP/1.1\r\nHost: cdn.demo\r\n\r\n", StreamID: 3},
		{ID: 4, Timestamp: "12:03:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 80, Protocol: "HTTP", Info: "POST /submit.php?id=1 HTTP/1.1", Payload: "POST /submit.php?id=1 HTTP/1.1\r\nHost: cdn.demo\r\n\r\nabc", StreamID: 3},
		{ID: 5, Timestamp: "12:03:01.000000", SourceIP: "10.0.0.5", SourcePort: 53000, DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS", Info: "Standard query TXT abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.example.com"},
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

func TestBuildC2SampleAnalysisSuppressesBrowserPollingAsCSHTTP(t *testing.T) {
	packets := []model.Packet{}
	for i := 0; i < 8; i++ {
		packets = append(packets, model.Packet{
			ID:         int64(70 + i),
			Timestamp:  "12:0" + string(rune('0'+i)) + ":00.000000",
			SourceIP:   "10.0.0.5",
			SourcePort: 50100,
			DestIP:     "93.184.216.34",
			DestPort:   80,
			Protocol:   "HTTP",
			Info:       "GET /api/poll HTTP/1.1",
			Payload:    "GET /api/poll HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120.0 Safari/537.36\r\n\r\n",
			StreamID:   13,
		})
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if hasC2Indicator(analysis.CS.Candidates, "http-beacon-shape") || hasC2Indicator(analysis.CS.Candidates, "beacon-interval") {
		t.Fatalf("browser polling should not be promoted to CS candidates: %+v", analysis.CS.Candidates)
	}
	if len(analysis.CS.HostURIAggregates) != 0 {
		t.Fatalf("browser polling should not form CS Host/URI aggregates: %+v", analysis.CS.HostURIAggregates)
	}
}

func TestBuildC2SampleAnalysisSuppressesRawTCPPeriodicAsCS(t *testing.T) {
	packets := []model.Packet{
		{ID: 91, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 9001, Protocol: "TCP", Payload: "aa", StreamID: 21},
		{ID: 92, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 9001, Protocol: "TCP", Payload: "bb", StreamID: 21},
		{ID: 93, Timestamp: "12:02:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 9001, Protocol: "TCP", Payload: "cc", StreamID: 21},
		{ID: 94, Timestamp: "12:03:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 9001, Protocol: "TCP", Payload: "dd", StreamID: 21},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if hasC2Indicator(analysis.CS.Candidates, "beacon-interval") {
		t.Fatalf("raw TCP periodic stream should not be promoted as CS beacon: %+v", analysis.CS.Candidates)
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
	if !floatSliceEqual(got.Intervals, []float64{60, 60, 60}) {
		t.Fatalf("unexpected raw intervals: %+v", got.Intervals)
	}
	if !stringSliceContains(got.SignalTags, "stable-interval") || !stringSliceContains(got.SignalTags, "get-post-tasking-shape") {
		t.Fatalf("expected scoring signal tags, got %+v", got.SignalTags)
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
	if !floatSliceEqual(got.Intervals, []float64{60, 60}) {
		t.Fatalf("unexpected DNS intervals: %+v", got.Intervals)
	}
}

func TestBuildC2SampleAnalysisAnnotatesSilverFoxCompatibleHTTP(t *testing.T) {
	packets := []model.Packet{
		{ID: 61, Timestamp: "12:00:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "GET /api/checkin HTTP/1.1", Payload: "GET /api/checkin HTTP/1.1\r\nHost: hfs.demo\r\nUser-Agent: Winos updater\r\nX-Server: HFS/2.3\r\n\r\n", StreamID: 16},
		{ID: 62, Timestamp: "12:01:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "POST /api/checkin HTTP/1.1", Payload: "POST /api/checkin HTTP/1.1\r\nHost: hfs.demo\r\nUser-Agent: Winos updater\r\nX-Server: HFS/2.3\r\n\r\nabc", StreamID: 16},
		{ID: 63, Timestamp: "12:02:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "GET /api/checkin HTTP/1.1", Payload: "GET /api/checkin HTTP/1.1\r\nHost: hfs.demo\r\nUser-Agent: Winos updater\r\nX-Server: HFS/2.3\r\n\r\n", StreamID: 16},
		{ID: 64, Timestamp: "12:03:00.000000", SourceIP: "10.0.0.5", SourcePort: 50100, DestIP: "10.0.0.9", DestPort: 443, Protocol: "HTTP", Info: "POST /api/checkin HTTP/1.1", Payload: "POST /api/checkin HTTP/1.1\r\nHost: hfs.demo\r\nUser-Agent: Winos updater\r\nX-Server: HFS/2.3\r\n\r\nabc", StreamID: 16},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}
	if !hasC2Indicator(analysis.CS.Candidates, "http-beacon-shape") {
		t.Fatalf("expected HTTP beacon shape candidate")
	}
	found := false
	for _, item := range analysis.CS.Candidates {
		if item.SampleFamily == "Winos 4.0" &&
			stringSliceContains(item.ActorHints, "Silver Fox / 银狐") &&
			stringSliceContains(item.InfrastructureHints, "hfs-download-chain") &&
			stringSliceContains(item.TransportTraits, "https-c2") &&
			stringSliceContains(item.TTPTags, "multi-stage-delivery") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Silver Fox compatible metadata, got %+v", analysis.CS.Candidates)
	}
	apt := buildAPTAnalysisFromC2(analysis)
	if apt.TotalEvidence == 0 || len(apt.Actors) == 0 {
		t.Fatalf("expected APT evidence from C2 metadata, got %+v", apt)
	}
	if apt.Evidence[0].SourceModule != "c2-analysis" {
		t.Fatalf("expected c2-analysis source module, got %+v", apt.Evidence[0])
	}
	if !hasAPTScoreFactor(apt.Evidence[0].ScoreFactors, "hfs-download-chain") || !hasAPTScoreFactor(apt.Evidence[0].ScoreFactors, "winos-family-hint") {
		t.Fatalf("expected structured APT score factors, got %+v", apt.Evidence[0].ScoreFactors)
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

func stringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func floatSliceEqual(got, want []float64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func hasAPTScoreFactor(items []model.APTScoreFactor, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}
