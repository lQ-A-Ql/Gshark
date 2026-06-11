package engine

import (
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestC2APTEnrichmentCoversTransportDeliveryAndFamilyBranches(t *testing.T) {
	packet := model.Packet{
		SourcePort: 18856,
		DestPort:   443,
		Protocol:   "TCP",
		Info:       "periodic heartbeat to Rejetto HFS delivery",
		Payload:    "GET /hfs/download.exe HTTP/1.1\r\nHost: hfs.example\r\n\r\nValleyRAT Winos gh0st",
	}

	enrichment := c2APTEnrichmentForCandidate(packet, "https", "beacon-heartbeat", "http file server 60s valleyrat winos ghost rat", []string{"periodic"})

	if enrichment.sampleFamily != "Gh0st variant" {
		t.Fatalf("expected final family hint from gh0st branch, got %+v", enrichment)
	}
	if enrichment.campaignStage != "delivery" {
		t.Fatalf("expected HFS delivery campaign stage, got %+v", enrichment)
	}
	for _, want := range []string{"https-c2", "tcp", "periodic-callback", "tcp-long-connection"} {
		if !stringSliceContains(enrichment.transportTraits, want) {
			t.Fatalf("expected transport trait %q in %+v", want, enrichment.transportTraits)
		}
	}
	for _, want := range []string{"custom-high-port", "silverfox-case-port-weak", "fallback-c2", "hfs-download-chain", "hfs-delivery"} {
		if !stringSliceContains(enrichment.infrastructureHints, want) {
			t.Fatalf("expected infrastructure hint %q in %+v", want, enrichment.infrastructureHints)
		}
	}
	for _, want := range []string{"encrypted-c2", "command-and-control", "rat-family", "multi-stage-delivery"} {
		if !stringSliceContains(enrichment.ttpTags, want) {
			t.Fatalf("expected ttp tag %q in %+v", want, enrichment.ttpTags)
		}
	}
	if enrichment.confidence < 48 {
		t.Fatalf("expected strongest family confidence, got %+v", enrichment)
	}
}

func TestBuildCSHostURIAggregatesCoversScoreAndFallbackBranches(t *testing.T) {
	candidates := []model.C2IndicatorRecord{
		{Family: "vshell", IndicatorType: "http-beacon-shape", Channel: "http", Host: "skip.example", URI: "/skip"},
		{Family: "cs", IndicatorType: "dns-beacon-shape", Channel: "dns", Host: "skip.example", URI: "/skip"},
		{Family: "cs", IndicatorType: "http-beacon-shape", Channel: "tcp", Host: "skip.example", URI: "/skip"},
		{Family: "cs", IndicatorType: "http-beacon-shape", Channel: "http"},
	}
	for i, item := range []struct {
		id     int64
		method string
		ts     string
	}{
		{1, "GET", "12:00:00.000000"},
		{2, "POST", "12:01:00.000000"},
		{3, "GET", "12:02:00.000000"},
		{4, "POST", "12:03:00.000000"},
	} {
		candidates = append(candidates, model.C2IndicatorRecord{
			PacketID:      item.id,
			StreamID:      int64(30 + i%2),
			Time:          item.ts,
			Family:        "cs",
			Channel:       "http",
			Host:          "Cdn.Demo",
			URI:           "/submit.php?id=1",
			Method:        item.method,
			IndicatorType: "http-beacon-shape",
			Confidence:    96,
			Tags: []string{
				"stable-interval",
				"get-post-tasking-shape",
				"endpoint-repeat",
				"stable-content-type",
				"non-browser-context",
				"browser-context",
				"needs-correlation",
				"weak-signal",
				"malleable-profile-weak",
				"tls-fingerprint",
				"ja3-match",
				"unknown-score-tag",
			},
		})
	}
	candidates = append(candidates, model.C2IndicatorRecord{
		PacketID:      99,
		Time:          "42.5",
		Family:        "cs",
		Channel:       "https",
		URI:           "/fallback",
		IndicatorType: "http-beacon-shape",
		Confidence:    40,
	})

	aggregates := buildCSHostURIAggregates(candidates, 0)
	if len(aggregates) != 2 {
		t.Fatalf("expected two aggregates after skip filters, got %+v", aggregates)
	}

	primary := aggregates[0]
	if primary.Host != "Cdn.Demo" || primary.URI != "/submit.php?id=1" {
		t.Fatalf("unexpected primary aggregate: %+v", primary)
	}
	if primary.Total != 4 || primary.GetCount != 2 || primary.PostCount != 2 {
		t.Fatalf("expected balanced GET/POST counts, got %+v", primary)
	}
	if primary.AvgInterval != "60.0s" || primary.Jitter != "0%" {
		t.Fatalf("expected stable interval summary, got avg=%q jitter=%q intervals=%+v", primary.AvgInterval, primary.Jitter, primary.Intervals)
	}
	if primary.RepresentativePacket != 2 {
		t.Fatalf("expected first POST packet as representative, got %d", primary.RepresentativePacket)
	}
	if primary.Confidence != 100 {
		t.Fatalf("expected clamped aggregate confidence, got %d", primary.Confidence)
	}
	for _, want := range []string{"stable-interval", "browser-context", "tls-fingerprint", "ja3-match"} {
		if !c2More85HasScoreFactor(primary.ScoreFactors, want) {
			t.Fatalf("expected score factor %q in %+v", want, primary.ScoreFactors)
		}
	}

	fallback := aggregates[1]
	if fallback.Host != "(no-host)" || fallback.URI != "/fallback" {
		t.Fatalf("expected fallback host/uri aggregate, got %+v", fallback)
	}
	if fallback.Methods[0].Label != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN method bucket, got %+v", fallback.Methods)
	}

	limited := buildCSHostURIAggregates(candidates, 1)
	if len(limited) != 1 || limited[0].Total != 4 {
		t.Fatalf("expected limit to keep highest-volume aggregate, got %+v", limited)
	}
}

func TestBuildCSDNSAggregatesCoversTypeRatioAndClampBranches(t *testing.T) {
	longLabel := strings.Repeat("a", 46) + ".example.com"
	observations := []c2DNSObservation{
		{},
		{qname: "Other.Example", queryType: "A", packet: model.Packet{ID: 9, Timestamp: "12:00:00.000000"}, confidence: 20},
		{qname: longLabel, maxLabel: 46, queryType: "TXT", isTXT: true, packet: model.Packet{ID: 1, Timestamp: "12:00:00.000000"}, confidence: 95},
		{qname: strings.ToUpper(longLabel), maxLabel: 46, queryType: "NULL", isNull: true, isResponse: true, packet: model.Packet{ID: 2, Timestamp: "12:01:00.000000"}, confidence: 80},
		{qname: longLabel, maxLabel: 46, queryType: "CNAME", isCNAME: true, packet: model.Packet{ID: 3, Timestamp: "12:02:00.000000"}, confidence: 70},
	}

	aggregates := buildCSDNSAggregates(observations, 0)
	if len(aggregates) != 2 {
		t.Fatalf("expected two DNS aggregates, got %+v", aggregates)
	}

	primary := aggregates[0]
	if primary.QName != longLabel || primary.Total != 3 {
		t.Fatalf("unexpected primary DNS aggregate: %+v", primary)
	}
	if primary.TxtCount != 1 || primary.NullCount != 1 || primary.CnameCount != 1 {
		t.Fatalf("expected TXT/NULL/CNAME counters, got %+v", primary)
	}
	if primary.RequestCount != 2 || primary.ResponseCount != 1 {
		t.Fatalf("expected request/response ratio counters, got %+v", primary)
	}
	if primary.AvgInterval != "60.0s" || primary.Jitter != "0%" {
		t.Fatalf("expected DNS intervals, got avg=%q jitter=%q intervals=%+v", primary.AvgInterval, primary.Jitter, primary.Intervals)
	}
	if primary.Confidence != 100 {
		t.Fatalf("expected clamped DNS confidence, got %d", primary.Confidence)
	}
	if !strings.Contains(primary.Summary, "req=2 resp=1") {
		t.Fatalf("expected request/response summary, got %q", primary.Summary)
	}

	limited := buildCSDNSAggregates(observations, 1)
	if len(limited) != 1 || limited[0].QName != longLabel {
		t.Fatalf("expected limit to keep highest-volume DNS aggregate, got %+v", limited)
	}
}

func TestBuildVShellStreamAggregatesCoversSkipSortAndSummaryBranches(t *testing.T) {
	streamData := map[int64]*c2VShellStreamWork{
		-1: {streamID: -1, packets: []model.Packet{{ID: 1}, {ID: 2}, {ID: 3}}},
		2:  {streamID: 2, packets: []model.Packet{{ID: 1}, {ID: 2}}},
		7: {
			streamID:      7,
			protocol:      "tcp",
			archMarkers:   map[string]int{"l64": 2},
			lengthPrefix:  3,
			shortPackets:  3,
			longPackets:   1,
			transitions:   2,
			heartbeatAvg:  "10.0s",
			heartbeatJit:  "0%",
			hasWebSocket:  true,
			wsParams:      "a=l64&t=ws_",
			listenerHints: map[string]int{"listener-port": 2},
			confidence:    95,
			packets: []model.Packet{
				{ID: 4, Timestamp: "12:00:00.000000"},
				{ID: 5, Timestamp: "12:00:10.000000"},
				{ID: 6, Timestamp: "12:00:20.000000"},
				{ID: 7, Timestamp: "12:00:30.000000"},
			},
		},
		8: {
			streamID:      8,
			protocol:      "tcp",
			archMarkers:   map[string]int{},
			listenerHints: map[string]int{},
			confidence:    50,
			packets: []model.Packet{
				{ID: 8, Timestamp: "1"},
				{ID: 9, Timestamp: "2"},
				{ID: 10, Timestamp: "4"},
			},
		},
	}

	aggregates := buildVShellStreamAggregates(streamData, 0)
	if len(aggregates) != 2 {
		t.Fatalf("expected invalid and short stream entries to be skipped, got %+v", aggregates)
	}
	if aggregates[0].StreamID != 7 || aggregates[0].Confidence != 100 {
		t.Fatalf("expected highest confidence stream first and clamped, got %+v", aggregates)
	}
	primary := aggregates[0]
	if !primary.HasWebSocket || primary.WSParams == "" || primary.HeartbeatAvg != "10.0s" || primary.HeartbeatJitter != "0%" {
		t.Fatalf("expected websocket and heartbeat fields, got %+v", primary)
	}
	if !floatSliceEqual(primary.Intervals, []float64{10, 10, 10}) {
		t.Fatalf("expected stream intervals, got %+v", primary.Intervals)
	}
	if !strings.Contains(primary.Summary, "websocket") || !strings.Contains(primary.Summary, "length-prefix=3") {
		t.Fatalf("expected summary to include websocket and length prefix, got %q", primary.Summary)
	}

	limited := buildVShellStreamAggregates(streamData, 1)
	if len(limited) != 1 || limited[0].StreamID != 7 {
		t.Fatalf("expected limit to keep best stream, got %+v", limited)
	}
}

func TestPromoteCSHTTPObservationsCoversStableHighVolumeBranches(t *testing.T) {
	builder := newC2More85Builder()
	builder.promoteCSHTTPObservations()
	if len(builder.result.CS.Candidates) != 0 {
		t.Fatalf("empty observations should not emit candidates")
	}

	builder.httpObservations = append(builder.httpObservations,
		c2HTTPObservation{method: "DELETE", host: "skip.example", path: "/skip"},
		c2HTTPObservation{method: "GET", host: "short.example", path: "/short"},
		c2HTTPObservation{method: "GET", host: "short.example", path: "/short"},
		c2HTTPObservation{method: "GET", host: "short.example", path: "/short"},
	)
	for i := 0; i < 8; i++ {
		method := "GET"
		path := "/__utm.gif"
		if i%2 == 1 {
			method = "POST"
			path = "/submit.php?id=1"
		}
		packet := model.Packet{
			ID:         int64(100 + i),
			Timestamp:  "12:0" + string(rune('0'+i)) + ":00.000000",
			SourceIP:   "10.0.0.5",
			SourcePort: 50000 + i,
			DestIP:     "10.0.0.9",
			DestPort:   80,
			Protocol:   "HTTP",
			Payload:    method + " /beacon HTTP/1.1\r\nHost: beacon.example\r\n\r\n",
			StreamID:   77,
		}
		builder.httpObservations = append(builder.httpObservations, c2HTTPObservation{
			packet:       packet,
			method:       method,
			path:         "/beacon",
			host:         "beacon.example",
			channel:      "http",
			statusCode:   200,
			contentType:  "application/octet-stream; charset=binary",
			responseSize: 128,
			evidence:     "synthetic stable callback",
			confidence:   30,
			tags:         []string{"http"},
		})
		_ = path
	}

	builder.promoteCSHTTPObservations()
	if len(builder.result.CS.Candidates) != 8 {
		t.Fatalf("expected one emitted candidate per stable observation, got %+v", builder.result.CS.Candidates)
	}
	first := builder.result.CS.Candidates[0]
	for _, want := range []string{"endpoint-repeat", "get-post-tasking-shape", "stable-interval", "high-volume-repeat", "non-browser-context", "stable-status-code", "stable-content-type"} {
		if !stringSliceContains(first.Tags, want) {
			t.Fatalf("expected promoted tag %q in %+v", want, first.Tags)
		}
	}
	if first.Confidence < 80 {
		t.Fatalf("expected high confidence promotion, got %+v", first)
	}
}

func TestClassifyScoreFactorCoversPositiveNegativeAndUnknownTags(t *testing.T) {
	tests := []struct {
		tag       string
		direction string
		weight    int
	}{
		{"stable-interval", "positive", 10},
		{"get-post-tasking-shape", "positive", 8},
		{"endpoint-repeat", "positive", 6},
		{"correlated-signal", "positive", 5},
		{"default-profile-like", "positive", 4},
		{"stable-status-code", "positive", 3},
		{"stable-content-type", "positive", 2},
		{"non-browser-context", "positive", 3},
		{"periodic-callback", "positive", 7},
		{"beacon-like", "positive", 6},
		{"browser-context", "negative", -4},
		{"needs-correlation", "negative", -2},
		{"weak-signal", "negative", -1},
		{"malleable-profile-weak", "negative", -1},
		{"tls-fingerprint", "positive", 12},
		{"ja3s-match", "positive", 12},
		{"not-a-factor", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			direction, weight, summary := classifyScoreFactor(tt.tag)
			if direction != tt.direction || weight != tt.weight {
				t.Fatalf("classifyScoreFactor(%q) = (%q, %d, %q), want (%q, %d)", tt.tag, direction, weight, summary, tt.direction, tt.weight)
			}
			if tt.direction != "" && summary == "" {
				t.Fatalf("expected summary for known tag %q", tt.tag)
			}
		})
	}
}

func newC2More85Builder() *c2AnalysisBuilder {
	return &c2AnalysisBuilder{
		csIndicators:         map[string]int{},
		csChannels:           map[string]int{},
		vshellIndicators:     map[string]int{},
		vshellChannels:       map[string]int{},
		families:             map[string]int{},
		conversations:        map[string]int{},
		csConversations:      map[string]int{},
		vshellConversations:  map[string]int{},
		csRelatedActors:      map[string]int{},
		vshellRelatedActors:  map[string]int{},
		csDeliveryChains:     map[string]int{},
		vshellDeliveryChains: map[string]int{},
		streams:              map[string][]model.Packet{},
		httpObservations:     []c2HTTPObservation{},
		dnsObservations:      []c2DNSObservation{},
		vshellStreamData:     map[int64]*c2VShellStreamWork{},
		emittedCSHTTPPackets: map[int64]struct{}{},
	}
}

func c2More85HasScoreFactor(items []model.C2ScoreFactor, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}
