package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildHTTPLoginAnalysisFromPacketsDetectsSuccessAndFailure(t *testing.T) {
	packets := []model.Packet{
		{
			ID:         1,
			Timestamp:  "2026-04-26T10:00:00Z",
			SourceIP:   "10.0.0.10",
			DestIP:     "10.0.0.20",
			SourcePort: 51000,
			DestPort:   80,
			Protocol:   "HTTP",
			Info:       "POST /login HTTP/1.1",
			Payload:    "POST /login HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=secret",
			StreamID:   7,
		},
		{
			ID:         2,
			Timestamp:  "2026-04-26T10:00:01Z",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.10",
			SourcePort: 80,
			DestPort:   51000,
			Protocol:   "HTTP",
			Info:       "HTTP/1.1 302 Found",
			Payload:    "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nSet-Cookie: sid=abc\r\n\r\n",
			StreamID:   7,
		},
		{
			ID:         3,
			Timestamp:  "2026-04-26T10:00:02Z",
			SourceIP:   "10.0.0.11",
			DestIP:     "10.0.0.20",
			SourcePort: 51001,
			DestPort:   80,
			Protocol:   "HTTP",
			Info:       "POST /signin HTTP/1.1",
			Payload:    "POST /signin HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"bob\",\"password\":\"badpass\"}",
			StreamID:   8,
		},
		{
			ID:         4,
			Timestamp:  "2026-04-26T10:00:03Z",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.11",
			SourcePort: 80,
			DestPort:   51001,
			Protocol:   "HTTP",
			Info:       "HTTP/1.1 401 Unauthorized",
			Payload:    "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\ninvalid username or password",
			StreamID:   8,
		},
	}

	analysis, err := buildHTTPLoginAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildHTTPLoginAnalysisFromPackets returned error: %v", err)
	}
	if analysis.TotalAttempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", analysis.TotalAttempts)
	}
	if analysis.SuccessCount != 1 || analysis.FailureCount != 1 {
		t.Fatalf("unexpected success/failure counts: %+v", analysis)
	}
	if len(analysis.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(analysis.Endpoints))
	}
	if analysis.Attempts[0].Result != "success" {
		t.Fatalf("expected first attempt success, got %+v", analysis.Attempts[0])
	}
	if !analysis.Attempts[0].ResponseSetCookie {
		t.Fatalf("expected Set-Cookie to be detected in success attempt")
	}
	if analysis.Attempts[1].Result != "failure" {
		t.Fatalf("expected second attempt failure, got %+v", analysis.Attempts[1])
	}
	if analysis.Attempts[1].Username != "bob" {
		t.Fatalf("expected username bob, got %+v", analysis.Attempts[1])
	}
}

func TestBuildHTTPLoginAnalysisFromPacketsFlagsBruteforce(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Protocol: "HTTP", Info: "POST /login HTTP/1.1", Payload: "POST /login HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=bad1", StreamID: 11},
		{ID: 2, Protocol: "HTTP", Info: "HTTP/1.1 401 Unauthorized", Payload: "HTTP/1.1 401 Unauthorized\r\n\r\ninvalid credentials", StreamID: 11},
		{ID: 3, Protocol: "HTTP", Info: "POST /login HTTP/1.1", Payload: "POST /login HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=bob&password=bad2", StreamID: 12},
		{ID: 4, Protocol: "HTTP", Info: "HTTP/1.1 401 Unauthorized", Payload: "HTTP/1.1 401 Unauthorized\r\n\r\ninvalid credentials", StreamID: 12},
		{ID: 5, Protocol: "HTTP", Info: "POST /login HTTP/1.1", Payload: "POST /login HTTP/1.1\r\nHost: demo.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=carol&password=bad3", StreamID: 13},
		{ID: 6, Protocol: "HTTP", Info: "HTTP/1.1 429 Too Many Requests", Payload: "HTTP/1.1 429 Too Many Requests\r\n\r\nrate limit", StreamID: 13},
	}

	analysis, err := buildHTTPLoginAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildHTTPLoginAnalysisFromPackets returned error: %v", err)
	}
	if analysis.BruteforceCount != 1 {
		t.Fatalf("expected 1 bruteforce endpoint, got %d", analysis.BruteforceCount)
	}
	if len(analysis.Endpoints) != 1 || !analysis.Endpoints[0].PossibleBruteforce {
		t.Fatalf("expected bruteforce endpoint flag, got %+v", analysis.Endpoints)
	}
	for _, attempt := range analysis.Attempts {
		if !attempt.PossibleBruteforce {
			t.Fatalf("expected attempt %+v to inherit bruteforce flag", attempt)
		}
	}
}
