package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
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

func TestBundledPublicUSBMountBaselineKeepsWriteEvidenceBelowHighSeverity(t *testing.T) {
	svc := loadBundledPublicSample(t, "usb", "usb_memory_stick.pcap")

	analysis, err := svc.USBAnalysis()
	if err != nil {
		t.Fatalf("USBAnalysis() error = %v", err)
	}
	if len(analysis.MassStorage.WriteOperations) == 0 {
		t.Fatalf("expected mount baseline to parse mass-storage operations")
	}

	evidence, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"usb"}})
	if err != nil {
		t.Fatalf("GatherEvidence(usb) error = %v", err)
	}
	for _, item := range evidence.Records {
		if item.Severity == "high" || item.Severity == "critical" {
			t.Fatalf("expected mount baseline writes to stay below high severity, got %+v", item)
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

func TestBundledPublicBenignSMTPThreatHuntStaysQuiet(t *testing.T) {
	svc := loadBundledPublicSample(t, "benign", "smtp.pcap")
	packets, err := svc.packetStore.All(nil)
	if err != nil {
		t.Fatalf("packetStore.All() error = %v", err)
	}
	hits := HuntThreats(packets, []string{"flag{", "ctf{"})
	if len(hits) != 0 {
		t.Fatalf("expected benign SMTP baseline to stay quiet, got %+v", hits)
	}
}

func TestBundledPublicBenignMySQLThreatHuntStaysQuiet(t *testing.T) {
	svc := loadBundledPublicSample(t, "benign", "mysql_complete.pcap")
	packets, err := svc.packetStore.All(nil)
	if err != nil {
		t.Fatalf("packetStore.All() error = %v", err)
	}
	hits := HuntThreats(packets, []string{"flag{", "ctf{"})
	if len(hits) != 0 {
		t.Fatalf("expected benign MySQL baseline to stay quiet, got %+v", hits)
	}
}

func TestBundledPublicObjectGzipBaselineAvoidsExecutableClassification(t *testing.T) {
	svc := loadBundledPublicSample(t, "object", "http_gzip.cap")
	objects := svc.ObjectsWithContext(context.Background())
	if len(objects) == 0 {
		t.Fatalf("expected object extraction on public gzip baseline")
	}
	for _, object := range objects {
		if object.MIME == "application/x-dosexec" || object.Magic == "PE/DOS MZ" {
			t.Fatalf("expected gzip baseline to avoid executable classification, got %+v", object)
		}
	}
}

func TestBundledPublicObjectJPEGBaselineKeepsEvidenceAtInfoSeverity(t *testing.T) {
	svc := loadBundledPublicSample(t, "object", "http_with_jpegs.cap.gz")
	evidence, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"object"}})
	if err != nil {
		t.Fatalf("GatherEvidence(object) error = %v", err)
	}
	if len(evidence.Records) == 0 {
		t.Fatalf("expected object evidence on JPEG baseline")
	}
	for _, item := range evidence.Records {
		if item.Severity != "info" {
			t.Fatalf("expected JPEG object evidence to stay informational, got %+v", item)
		}
	}
}

func TestBundledPublicTFTPObjectBaselineDoesNotFabricateExecutableObjects(t *testing.T) {
	svc := loadBundledPublicSample(t, "object", "tftp_wrq.pcap")
	objects := svc.ObjectsWithContext(context.Background())
	for _, object := range objects {
		if object.MIME == "application/x-dosexec" || object.Magic == "PE/DOS MZ" {
			t.Fatalf("expected TFTP baseline to avoid executable classification, got %+v", object)
		}
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
