package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildHTTPLoginAnalysisFromPacketsAddsStructuredReport(t *testing.T) {
	packets := []model.Packet{
		{
			ID:         10,
			StreamID:   3,
			Protocol:   "HTTP",
			Info:       "POST /login",
			SourceIP:   "10.0.0.10",
			DestIP:     "10.0.0.20",
			SourcePort: 51111,
			DestPort:   80,
			Payload:    "POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=bad",
		},
		{
			ID:         11,
			StreamID:   3,
			Protocol:   "HTTP",
			Info:       "HTTP/1.1 401 Unauthorized",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.10",
			SourcePort: 80,
			DestPort:   51111,
			Payload:    "HTTP/1.1 401 Unauthorized\r\nSet-Cookie: sid=1\r\n\r\ninvalid password",
		},
		{
			ID:         12,
			StreamID:   3,
			Protocol:   "HTTP",
			Info:       "POST /login",
			SourceIP:   "10.0.0.10",
			DestIP:     "10.0.0.20",
			SourcePort: 51111,
			DestPort:   80,
			Payload:    "POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=guest&password=guess",
		},
		{
			ID:         13,
			StreamID:   3,
			Protocol:   "HTTP",
			Info:       "HTTP/1.1 401 Unauthorized",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.10",
			SourcePort: 80,
			DestPort:   51111,
			Payload:    "HTTP/1.1 401 Unauthorized\r\n\r\ninvalid password",
		},
	}

	analysis, err := buildHTTPLoginAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildHTTPLoginAnalysisFromPackets() error = %v", err)
	}
	if len(analysis.Report.Summary) == 0 || len(analysis.Report.Evidence) == 0 || len(analysis.Report.Details) == 0 {
		t.Fatalf("expected structured HTTP report sections, got %+v", analysis.Report)
	}
	if analysis.Report.Evidence[0].PacketID == 0 || analysis.Report.Evidence[0].Severity == "" {
		t.Fatalf("expected actionable HTTP evidence item, got %+v", analysis.Report.Evidence[0])
	}
}

func TestBuildShiroRememberMeAnalysisAddsStructuredReport(t *testing.T) {
	plaintext := append([]byte{0xac, 0xed, 0x00, 0x05}, []byte("org.apache.shiro.subject.SimplePrincipalCollection")...)
	cookieValue := mustMakeRememberMeCBC(t, "kPH+bIxk5D2deZiIxcaaaA==", plaintext)
	packets := []model.Packet{
		{
			ID:         40,
			StreamID:   8,
			Protocol:   "HTTP",
			Info:       "GET / HTTP/1.1",
			SourceIP:   "10.0.0.1",
			DestIP:     "10.0.0.2",
			SourcePort: 51000,
			DestPort:   8080,
			Payload:    "GET / HTTP/1.1\r\nHost: shiro.example\r\nCookie: rememberMe=" + cookieValue + "\r\n\r\n",
		},
	}

	analysis, err := buildShiroRememberMeAnalysisFromPackets(context.Background(), packets, model.ShiroRememberMeRequest{})
	if err != nil {
		t.Fatalf("buildShiroRememberMeAnalysisFromPackets() error = %v", err)
	}
	if len(analysis.Report.Evidence) == 0 || analysis.Report.Evidence[0].Severity != "high" {
		t.Fatalf("expected high-severity Shiro report evidence, got %+v", analysis.Report)
	}
	if len(analysis.Report.Recommendations) == 0 {
		t.Fatalf("expected structured Shiro recommendations, got %+v", analysis.Report)
	}
}

func TestBuildUSBInvestigationReportCapturesWriteEvidence(t *testing.T) {
	report := buildUSBInvestigationReport(model.USBAnalysis{
		TotalUSBPackets:    4,
		HIDPackets:         1,
		MassStoragePackets: 3,
		Devices:            []model.TrafficBucket{{Label: "Disk A", Count: 3}},
		Endpoints:          []model.TrafficBucket{{Label: "0x02", Count: 2}},
		HID: model.USBHIDAnalysis{
			KeyboardEvents: []model.USBKeyboardEvent{{PacketID: 7, Device: "Keyboard A", Text: "A", Keys: []string{"A"}}},
		},
		MassStorage: model.USBMassStorageAnalysis{
			WriteOperations: []model.USBMassStorageOperation{{
				PacketID:       21,
				Device:         "Disk A",
				LUN:            "LUN 0",
				Command:        "WRITE(10)",
				TransferLength: 4096,
				Status:         "failed",
				DataResidue:    512,
			}},
		},
		Other: model.USBOtherAnalysis{
			ControlRecords: []model.USBPacketRecord{{PacketID: 31, SetupRequest: "GET_DESCRIPTOR", Endpoint: "0x00", Summary: "descriptor"}},
		},
	})

	if len(report.Evidence) == 0 || report.Evidence[0].Severity != "high" {
		t.Fatalf("expected USB write evidence with escalated severity, got %+v", report)
	}
	if len(report.Details) == 0 {
		t.Fatalf("expected USB report details, got %+v", report)
	}
}

func TestBuildC2FamilyInvestigationReportCapturesCandidateAndAggregateDetails(t *testing.T) {
	report := buildC2FamilyInvestigationReport("cs", model.C2FamilyAnalysis{
		CandidateCount:   1,
		MatchedRuleCount: 1,
		Channels:         []model.TrafficBucket{{Label: "http", Count: 1}},
		Candidates: []model.C2IndicatorRecord{{
			PacketID:       9,
			StreamID:       4,
			Family:         "cs",
			Source:         "10.0.0.1",
			Destination:    "10.0.0.2",
			IndicatorType:  "uri",
			IndicatorValue: "/submit.php",
			Confidence:     88,
			Summary:        "uri candidate",
			Tags:           []string{"http"},
		}},
		HostURIAggregates: []model.C2HTTPEndpointAggregate{{
			Host:       "c2.example",
			URI:        "/submit.php",
			Total:      5,
			Methods:    []model.TrafficBucket{{Label: "POST", Count: 5}},
			Packets:    []int64{9},
			Streams:    []int64{4},
			Confidence: 90,
		}},
	})

	if len(report.Summary) == 0 || len(report.Evidence) == 0 || len(report.Details) == 0 {
		t.Fatalf("expected structured C2 family report, got %+v", report)
	}
	if report.Evidence[0].PacketID != 9 || report.Evidence[0].StreamID != 4 {
		t.Fatalf("expected packet-linked C2 report evidence, got %+v", report.Evidence[0])
	}
}
