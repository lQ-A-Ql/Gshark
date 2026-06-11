package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildBruteforceAnalysisDetectsPortScanAndDirectoryBrute(t *testing.T) {
	packets := make([]model.Packet, 0, 180)
	for port := 1; port <= 60; port++ {
		packets = append(packets, model.Packet{
			ID:         int64(port),
			Timestamp:  fmt.Sprintf("%.3f", float64(port)/10),
			SourceIP:   "10.0.0.10",
			DestIP:     "10.0.0.20",
			SourcePort: 51000 + port,
			DestPort:   port,
			Protocol:   "TCP",
			Info:       "[SYN]",
			Color:      model.PacketColorFeatures{TCPSYN: true},
		})
		if port <= 35 {
			packets = append(packets, model.Packet{
				ID:         int64(1000 + port),
				Timestamp:  fmt.Sprintf("%.3f", float64(port)/10+0.001),
				SourceIP:   "10.0.0.20",
				DestIP:     "10.0.0.10",
				SourcePort: port,
				DestPort:   51000 + port,
				Protocol:   "TCP",
				Info:       "[RST]",
				Color:      model.PacketColorFeatures{TCPRST: true},
			})
		}
	}
	for _, port := range []int{22, 80} {
		packets = append(packets, model.Packet{
			ID:         int64(2000 + port),
			Timestamp:  "6.500",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.10",
			SourcePort: port,
			DestPort:   51000 + port,
			Protocol:   "TCP",
			Info:       "[SYN, ACK]",
		})
	}

	streamID := int64(3000)
	for idx := 0; idx < 40; idx++ {
		streamID++
		path := fmt.Sprintf("/admin-%02d", idx)
		packets = append(packets,
			model.Packet{
				ID:         int64(3000 + idx*2),
				Timestamp:  fmt.Sprintf("%.3f", float64(idx)/20),
				SourceIP:   "10.0.0.30",
				DestIP:     "10.0.0.40",
				SourcePort: 52000 + idx,
				DestPort:   8080,
				Protocol:   "HTTP",
				Info:       "GET " + path + " HTTP/1.1",
				StreamID:   streamID,
			},
			model.Packet{
				ID:         int64(3001 + idx*2),
				Timestamp:  fmt.Sprintf("%.3f", float64(idx)/20+0.001),
				SourceIP:   "10.0.0.40",
				DestIP:     "10.0.0.30",
				SourcePort: 8080,
				DestPort:   52000 + idx,
				Protocol:   "HTTP",
				Info:       "HTTP/1.1 404 Not Found",
				StreamID:   streamID,
			},
		)
	}

	analysis, err := buildBruteforceAnalysis(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildBruteforceAnalysis() error = %v", err)
	}
	if analysis.TotalSuspicious != 2 {
		t.Fatalf("expected one port scan and one directory brute, got %+v", analysis)
	}
	if len(analysis.PortScanHits) != 1 {
		t.Fatalf("expected one port scan hit, got %+v", analysis.PortScanHits)
	}
	scan := analysis.PortScanHits[0]
	if scan.SourceIP != "10.0.0.10" || scan.TargetIP != "10.0.0.20" || scan.UniquePortsHit != 60 {
		t.Fatalf("unexpected port scan identity: %+v", scan)
	}
	if scan.ScanType != "syn-scan" || scan.Confidence != 80 {
		t.Fatalf("expected RST-boosted SYN scan confidence, got %+v", scan)
	}
	if len(scan.OpenPorts) != 2 || scan.OpenPorts[0] != 22 || scan.OpenPorts[1] != 80 {
		t.Fatalf("expected sorted open ports [22 80], got %+v", scan.OpenPorts)
	}

	if len(analysis.DirBruteforceHits) != 1 {
		t.Fatalf("expected one directory brute hit, got %+v", analysis.DirBruteforceHits)
	}
	dir := analysis.DirBruteforceHits[0]
	if dir.SourceIP != "10.0.0.30" || dir.TargetHost != "10.0.0.40:8080" {
		t.Fatalf("unexpected directory brute identity: %+v", dir)
	}
	if dir.TotalRequests != 40 || dir.Status404Count != 40 || dir.UniquePaths != 40 {
		t.Fatalf("unexpected directory brute counters: %+v", dir)
	}
	if len(dir.SamplePaths) != 10 || dir.SamplePaths[0] != "/admin-00" {
		t.Fatalf("expected capped sample paths, got %+v", dir.SamplePaths)
	}
	if len(analysis.Notes) != 2 {
		t.Fatalf("expected notes for both findings, got %+v", analysis.Notes)
	}
}

func TestBuildBruteforceAnalysisSuppressesFalsePositiveAndHonorsCancellation(t *testing.T) {
	packets := make([]model.Packet, 0, 130)
	for port := 1; port <= 25; port++ {
		packets = append(packets, model.Packet{
			ID:         int64(port),
			Timestamp:  fmt.Sprintf("%.3f", float64(port)),
			SourceIP:   "10.1.0.10",
			DestIP:     "10.1.0.20",
			SourcePort: 53000 + port,
			DestPort:   port,
			Protocol:   "TCP",
			Info:       "[SYN]",
			Color:      model.PacketColorFeatures{TCPSYN: true},
		})
	}
	for idx := 0; idx < 90; idx++ {
		packets = append(packets, model.Packet{
			ID:         int64(100 + idx),
			Timestamp:  fmt.Sprintf("%.3f", float64(idx)),
			SourceIP:   "10.1.0.10",
			DestIP:     "10.1.0.20",
			SourcePort: 54000,
			DestPort:   443,
			Protocol:   "TCP",
			Info:       "Application data",
		})
	}

	analysis, err := buildBruteforceAnalysis(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildBruteforceAnalysis() error = %v", err)
	}
	if analysis.TotalSuspicious != 0 || len(analysis.PortScanHits) != 0 || len(analysis.DirBruteforceHits) != 0 {
		t.Fatalf("expected high-data TCP flow to suppress scan finding, got %+v", analysis)
	}
	if len(analysis.Notes) != 1 || analysis.Notes[0] == "" {
		t.Fatalf("expected empty-analysis note, got %+v", analysis.Notes)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = buildBruteforceAnalysis(ctx, []model.Packet{{ID: 1, Protocol: "TCP"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation to propagate, got %v", err)
	}

	if path := extractBruteforceHTTPRequestPath("POST /login?q=1 HTTP/1.1"); path != "/login?q=1" {
		t.Fatalf("request path parser = %q", path)
	}
	if path := extractBruteforceHTTPRequestPath("not a request"); path != "" {
		t.Fatalf("expected non-request to return empty path, got %q", path)
	}
	if status := extractBruteforceHTTPResponseStatus("HTTP/1.1 403 Forbidden"); status != 403 {
		t.Fatalf("response parser = %d", status)
	}
	if status := extractBruteforceHTTPResponseStatus("HTTP/1.1 nope"); status != 0 {
		t.Fatalf("bad response parser = %d", status)
	}
	if len(buildBruteforceNotes(model.BruteforceAnalysis{})) != 1 {
		t.Fatalf("expected no-finding note to be populated")
	}
}
