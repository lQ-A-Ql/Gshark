package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBundledPublicSMTPReportBuildsFromBaselineSample(t *testing.T) {
	svc := loadBundledPublicSample(t, "benign", "smtp.pcap")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	analysis, err := svc.SMTPAnalysis(ctx)
	if err != nil {
		t.Fatalf("SMTPAnalysis() error = %v", err)
	}
	if analysis.SessionCount == 0 || len(analysis.Report.Summary) == 0 || len(analysis.Report.Details) == 0 {
		t.Fatalf("expected SMTP baseline report, got %+v", analysis.Report)
	}
}

func TestBundledPublicMySQLReportBuildsFromBaselineSample(t *testing.T) {
	svc := loadBundledPublicSample(t, "benign", "mysql_complete.pcap")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	analysis, err := svc.MySQLAnalysis(ctx)
	if err != nil {
		t.Fatalf("MySQLAnalysis() error = %v", err)
	}
	if analysis.SessionCount == 0 || len(analysis.Report.Summary) == 0 || len(analysis.Report.Details) == 0 {
		t.Fatalf("expected MySQL baseline report, got %+v", analysis.Report)
	}
}

func TestBundledPublicIndustrialReportStaysActionableOnS7Sample(t *testing.T) {
	svc := loadBundledPublicSample(t, "industrial", "s7comm_downloading_block_db1.pcap")

	analysis, err := svc.IndustrialAnalysis()
	if err != nil {
		t.Fatalf("IndustrialAnalysis() error = %v", err)
	}
	if analysis.TotalIndustrialPackets == 0 || len(analysis.Report.Summary) == 0 {
		t.Fatalf("expected industrial report summary, got %+v", analysis.Report)
	}
	if len(analysis.Report.Evidence) == 0 && len(analysis.Report.Details) == 0 {
		t.Fatalf("expected industrial report to include evidence or details, got %+v", analysis.Report)
	}
}

func TestBundledPublicVehicleBaselineReportAvoidsHighRiskUDSWithoutUDS(t *testing.T) {
	svc := loadBundledPublicSample(t, "vehicle", "caneth.pcapng")

	analysis, err := svc.VehicleAnalysis()
	if err != nil {
		t.Fatalf("VehicleAnalysis() error = %v", err)
	}
	if analysis.TotalVehiclePackets == 0 || len(analysis.Report.Summary) == 0 {
		t.Fatalf("expected vehicle report summary, got %+v", analysis.Report)
	}
	if analysis.UDS.TotalMessages != 0 {
		t.Fatalf("expected CAN baseline without UDS messages, got %+v", analysis.UDS)
	}
	for _, item := range analysis.Report.Evidence {
		if (item.Severity == "high" || item.Severity == "critical") && hasAnyTag(item.Tags, "uds") {
			t.Fatalf("expected no high-risk UDS evidence on CAN baseline, got %+v", item)
		}
	}
}

func TestBundledPublicUSBWriteSampleBuildsReportEvidence(t *testing.T) {
	svc := loadBundledPublicSample(t, "usb", "usb_memory_stick_create_file.pcap")

	analysis, err := svc.USBAnalysis()
	if err != nil {
		t.Fatalf("USBAnalysis() error = %v", err)
	}
	if analysis.MassStoragePackets == 0 || len(analysis.Report.Summary) == 0 {
		t.Fatalf("expected USB report summary, got %+v", analysis.Report)
	}
	if len(analysis.Report.Evidence) == 0 {
		t.Fatalf("expected USB write evidence on create-file sample, got %+v", analysis.Report)
	}
}

func TestBundledPublicUSBDeleteBaselineDoesNotInventHighRiskWriteReport(t *testing.T) {
	svc := loadBundledPublicSample(t, "usb", "usb_memory_stick_delete_file.pcap")

	analysis, err := svc.USBAnalysis()
	if err != nil {
		t.Fatalf("USBAnalysis() error = %v", err)
	}
	for _, item := range analysis.Report.Evidence {
		if (item.Severity == "high" || item.Severity == "critical") && hasAnyTag(item.Tags, "write") {
			t.Fatalf("expected delete baseline not to emit high-risk write evidence, got %+v", item)
		}
	}
}

func TestBundledPublicBenignHTTPThreatHuntStaysQuiet(t *testing.T) {
	svc := loadBundledPublicSample(t, "benign", "http.cap")
	packets, err := svc.packetStore.All(nil)
	if err != nil {
		t.Fatalf("packetStore.All() error = %v", err)
	}
	hits := HuntThreats(packets, []string{"flag{", "ctf{"})
	if len(hits) != 0 {
		t.Fatalf("expected benign HTTP baseline to stay quiet, got %+v", hits)
	}
}

func TestBundledPublicObjectHTTPBaselineExtractsNonExecutableObjects(t *testing.T) {
	svc := loadBundledPublicSample(t, "object", "http_with_jpegs.cap.gz")
	objects := svc.ObjectsWithContext(context.Background())
	if len(objects) == 0 {
		t.Fatalf("expected object extraction on public JPEG baseline")
	}
	for _, object := range objects {
		if object.MIME == "application/x-dosexec" {
			t.Fatalf("expected non-executable object baseline, got %+v", object)
		}
	}
}

func loadBundledPublicSample(t *testing.T, parts ...string) *Service {
	t.Helper()
	path := filepath.Join(append([]string{repoRootForTest(t), "samples", "public-pcaps"}, parts...)...)
	return loadThreatSampleService(t, path)
}

func hasAnyTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
