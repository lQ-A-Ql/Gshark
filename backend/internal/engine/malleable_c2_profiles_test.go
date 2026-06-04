package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestMatchMalleableProfileNilOnEmpty(t *testing.T) {
	if got := MatchMalleableProfile(nil); got != nil {
		t.Fatalf("expected nil on empty observations, got %+v", got)
	}
	if got := MatchMalleableProfile([]c2HTTPObservation{}); got != nil {
		t.Fatalf("expected nil on empty slice, got %+v", got)
	}
}

func TestMatchMalleableProfileNilWhenNoURI(t *testing.T) {
	obs := []c2HTTPObservation{
		{
			method:    "GET",
			path:      "", // no URI
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		},
	}
	if got := MatchMalleableProfile(obs); got != nil {
		t.Fatalf("expected nil when no URI, got %+v", got)
	}
}

func TestMatchMalleableProfileNilWhenOnlyURI(t *testing.T) {
	// URI match alone is not enough — needs corroborating signal.
	obs := []c2HTTPObservation{
		{
			method: "GET",
			path:   "/submit.php",
		},
	}
	if got := MatchMalleableProfile(obs); got != nil {
		t.Fatalf("expected nil with only URI match (no corroboration), got %+v", got)
	}
}

func TestMatchMalleableProfileCSDefault(t *testing.T) {
	obs := []c2HTTPObservation{
		{
			method:    "GET",
			path:      "/jquery-3.3.1.min.js",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			packet: model.Packet{
				Payload: "GET /jquery-3.3.1.min.js HTTP/1.1\r\nHost: example.com\r\nX-Requested-With: XMLHttpRequest\r\nAccept: */*\r\n\r\n",
			},
		},
	}
	got := MatchMalleableProfile(obs)
	if got == nil {
		t.Fatal("expected match for CS default profile, got nil")
	}
	if got.Family != "cs" {
		t.Errorf("expected family=cs, got %s", got.Family)
	}
	if got.ProfileName != "cs-default" {
		t.Errorf("expected profile_name=cs-default, got %s", got.ProfileName)
	}
	if got.Confidence < 85 {
		t.Errorf("expected confidence >= 85, got %d", got.Confidence)
	}
	if len(got.MatchedOn) == 0 {
		t.Error("expected non-empty matched_on")
	}
}

func TestMatchMalleableProfileCSDefaultSubmitPHP(t *testing.T) {
	obs := []c2HTTPObservation{
		{
			method:      "POST",
			path:        "/submit.php",
			userAgent:   "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
			contentType: "application/octet-stream",
			packet: model.Packet{
				Payload: "POST /submit.php HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nX-Requested-With: XMLHttpRequest\r\n\r\n",
			},
		},
	}
	got := MatchMalleableProfile(obs)
	if got == nil {
		t.Fatal("expected match for CS default submit.php, got nil")
	}
	if got.Family != "cs" {
		t.Errorf("expected family=cs, got %s", got.Family)
	}
	if got.Confidence < 80 {
		t.Errorf("expected confidence >= 80, got %d", got.Confidence)
	}
}

func TestMatchMalleableProfileCSZeus(t *testing.T) {
	obs := []c2HTTPObservation{
		{
			method:      "GET",
			path:        "/wp-content/themes/flavor/style.css",
			userAgent:   "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
			contentType: "application/x-www-form-urlencoded",
			packet: model.Packet{
				Payload: "GET /wp-content/themes/flavor/style.css HTTP/1.1\r\nHost: blog.example.com\r\nAccept: text/html\r\nReferer: https://blog.example.com/\r\n\r\n",
			},
		},
	}
	got := MatchMalleableProfile(obs)
	if got == nil {
		t.Fatal("expected match for CS Zeus profile, got nil")
	}
	if got.ProfileName != "cs-zeus" {
		t.Errorf("expected profile_name=cs-zeus, got %s", got.ProfileName)
	}
}

func TestMatchMalleableProfileVShellWS(t *testing.T) {
	obs := []c2HTTPObservation{
		{
			method: "GET",
			path:   "/?a=l64&h=10.0.0.5&t=ws_&p=8088",
			packet: model.Packet{
				Payload: "GET /?a=l64&h=10.0.0.5&t=ws_&p=8088 HTTP/1.1\r\nHost: 10.0.0.5\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
			},
		},
	}
	got := MatchMalleableProfile(obs)
	if got == nil {
		t.Fatal("expected match for VShell WS profile, got nil")
	}
	if got.Family != "vshell" {
		t.Errorf("expected family=vshell, got %s", got.Family)
	}
	if got.ProfileName != "vshell-default-ws" {
		t.Errorf("expected profile_name=vshell-default-ws, got %s", got.ProfileName)
	}
	if got.Confidence < 88 {
		t.Errorf("expected confidence >= 88, got %d", got.Confidence)
	}
}

func TestMatchMalleableProfileMultiSignalBoost(t *testing.T) {
	// Multiple observations that collectively match many signals.
	obs := []c2HTTPObservation{
		{
			method:    "GET",
			path:      "/jquery-3.3.1.min.js",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			packet: model.Packet{
				Payload: "GET /jquery-3.3.1.min.js HTTP/1.1\r\nHost: c2.example.com\r\nAccept: */*\r\nAccept-Language: en-US\r\nAccept-Encoding: gzip\r\nReferer: https://c2.example.com/\r\nX-Requested-With: XMLHttpRequest\r\n\r\n",
			},
		},
		{
			method:      "POST",
			path:        "/submit.php",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			contentType: "application/octet-stream",
			packet: model.Packet{
				Payload: "POST /submit.php HTTP/1.1\r\nHost: c2.example.com\r\nContent-Type: application/octet-stream\r\nX-Requested-With: XMLHttpRequest\r\n\r\n",
			},
		},
	}
	got := MatchMalleableProfile(obs)
	if got == nil {
		t.Fatal("expected match with multi-signal boost, got nil")
	}
	if got.Confidence < 89 {
		t.Errorf("expected boosted confidence >= 89, got %d", got.Confidence)
	}
	if got.Family != "cs" {
		t.Errorf("expected family=cs, got %s", got.Family)
	}
}

func TestMatchMalleableProfileFromIndicatorsNilOnEmpty(t *testing.T) {
	if got := MatchMalleableProfileFromIndicators(nil); got != nil {
		t.Fatalf("expected nil on empty candidates, got %+v", got)
	}
}

func TestMatchMalleableProfileFromIndicatorsCSDefault(t *testing.T) {
	candidates := []model.C2IndicatorRecord{
		{
			Family:         "cs",
			URI:            "/jquery-3.3.1.min.js",
			IndicatorType:  "http-beacon-shape",
			IndicatorValue: "X-Requested-With: XMLHttpRequest",
			Tags:           []string{"http", "default-profile-like"},
		},
		{
			Family:         "cs",
			URI:            "/submit.php",
			IndicatorType:  "http-beacon-shape",
			IndicatorValue: "Content-Type: application/octet-stream",
			Tags:           []string{"http", "post-result-shape"},
		},
	}
	got := MatchMalleableProfileFromIndicators(candidates)
	if got == nil {
		t.Fatal("expected match from indicators, got nil")
	}
	if got.Family != "cs" {
		t.Errorf("expected family=cs, got %s", got.Family)
	}
	if got.Confidence < 80 {
		t.Errorf("expected confidence >= 80, got %d", got.Confidence)
	}
}

func TestMatchMalleableProfileFromIndicatorsEncodingHint(t *testing.T) {
	candidates := []model.C2IndicatorRecord{
		{
			Family: "cs",
			URI:    "/__utm.gif",
			Tags:   []string{"http", "default-profile-like", "mask"},
		},
		{
			Family:         "cs",
			URI:            "/submit.php",
			IndicatorValue: "X-Requested-With: XMLHttpRequest",
			Tags:           []string{"http", "malleable-profile-weak"},
		},
	}
	got := MatchMalleableProfileFromIndicators(candidates)
	if got == nil {
		t.Fatal("expected match from indicators with encoding hint, got nil")
	}
	hasEncoding := false
	for _, m := range got.MatchedOn {
		if m == "encoding:mask" {
			hasEncoding = true
			break
		}
	}
	if !hasEncoding {
		t.Errorf("expected encoding:mask in matched_on, got %v", got.MatchedOn)
	}
}

func TestBuildC2SampleAnalysisMalleableProfileMatch(t *testing.T) {
	// Packets that should trigger CS default profile matching via the full pipeline.
	packets := []model.Packet{
		{
			ID:        100,
			Timestamp: "12:00:01.000000",
			SourceIP:  "10.0.0.5",
			DestIP:    "192.168.1.1",
			DestPort:  443,
			Protocol:  "HTTP",
			Info:      "GET /jquery-3.3.1.min.js HTTP/1.1",
			Payload:   "GET /jquery-3.3.1.min.js HTTP/1.1\r\nHost: c2.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nX-Requested-With: XMLHttpRequest\r\nAccept: */*\r\nAccept-Language: en-US\r\nAccept-Encoding: gzip\r\nReferer: https://c2.example.com/\r\n\r\n",
		},
		{
			ID:        101,
			Timestamp: "12:00:10.000000",
			SourceIP:  "10.0.0.5",
			DestIP:    "192.168.1.1",
			DestPort:  443,
			Protocol:  "HTTP",
			Info:      "POST /submit.php HTTP/1.1",
			Payload:   "POST /submit.php HTTP/1.1\r\nHost: c2.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nContent-Type: application/octet-stream\r\nX-Requested-With: XMLHttpRequest\r\n\r\n",
		},
		{
			ID:        102,
			Timestamp: "12:00:20.000000",
			SourceIP:  "10.0.0.5",
			DestIP:    "192.168.1.1",
			DestPort:  443,
			Protocol:  "HTTP",
			Info:      "GET /__utm.gif HTTP/1.1",
			Payload:   "GET /__utm.gif HTTP/1.1\r\nHost: c2.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n",
		},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}

	// The malleable profile match should be populated on CS.
	if analysis.CS.MalleableProfileMatch == nil {
		t.Fatal("expected CS MalleableProfileMatch to be non-nil")
	}
	if analysis.CS.MalleableProfileMatch.Family != "cs" {
		t.Errorf("expected CS malleable match family=cs, got %s", analysis.CS.MalleableProfileMatch.Family)
	}
	if analysis.CS.MalleableProfileMatch.Confidence < 80 {
		t.Errorf("expected CS malleable match confidence >= 80, got %d", analysis.CS.MalleableProfileMatch.Confidence)
	}
}

func TestBuildC2SampleAnalysisNoMalleableMatchOnPlainHTTP(t *testing.T) {
	// Plain HTTP traffic that does not match any known profile.
	packets := []model.Packet{
		{
			ID:        200,
			Timestamp: "13:00:00.000000",
			SourceIP:  "10.0.0.10",
			DestIP:    "93.184.216.34",
			DestPort:  80,
			Protocol:  "HTTP",
			Info:      "GET /index.html HTTP/1.1",
			Payload:   "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
		},
	}

	analysis, err := buildC2SampleAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildC2SampleAnalysisFromPackets() error = %v", err)
	}

	// Should not match any malleable profile.
	if analysis.CS.MalleableProfileMatch != nil {
		t.Errorf("expected no CS malleable match on plain HTTP, got %+v", analysis.CS.MalleableProfileMatch)
	}
}
