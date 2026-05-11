package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestGatherEvidenceFiltersVehicleAndUSBAndExcludesMisc(t *testing.T) {
	svc := NewService(nil, nil)
	t.Cleanup(func() {
		_ = svc.packetStore.Close()
	})

	svc.vehicleAnalysis = &model.VehicleAnalysis{
		UDS: model.UDSAnalysis{
			Transactions: []model.UDSTransaction{
				{
					RequestPacketID:  101,
					ResponsePacketID: 102,
					SourceAddress:    "0x0e80",
					TargetAddress:    "0x07e0",
					ServiceID:        "0x27",
					ServiceName:      "Security Access",
					Status:           "negative",
					NegativeCode:     "0x33",
					RequestSummary:   "security access request",
					ResponseSummary:  "security access denied",
				},
			},
		},
	}

	svc.usbAnalysis = &model.USBAnalysis{
		MassStorage: model.USBMassStorageAnalysis{
			WriteOperations: []model.USBMassStorageOperation{
				{
					PacketID:       201,
					Device:         "Bus 1 Device 2",
					Endpoint:       "EP 0x02 (OUT)",
					LUN:            "LUN 0",
					Command:        "WRITE(10)",
					Operation:      "write",
					TransferLength: 4096,
					Status:         "failed",
					DataResidue:    512,
					RequestFrame:   201,
					ResponseFrame:  202,
					LatencyMs:      1.8,
				},
			},
		},
	}

	result, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{
		Modules: []string{"vehicle", "usb"},
	})
	if err != nil {
		t.Fatalf("GatherEvidence() error = %v", err)
	}

	if result.Total != 2 {
		t.Fatalf("expected 2 evidence records, got %d", result.Total)
	}

	modules := map[string]bool{}
	for _, record := range result.Records {
		modules[record.Module] = true
		if record.Module == "misc" {
			t.Fatalf("expected MISC to stay out of evidence, got %+v", record)
		}
	}
	if !modules["vehicle"] || !modules["usb"] {
		t.Fatalf("expected vehicle and usb evidence, got %+v", result.Records)
	}
}

func TestGatherEvidenceBuildsConsistentRecordsAcrossCoreModules(t *testing.T) {
	svc := NewService(nil, nil)
	t.Cleanup(func() {
		_ = svc.packetStore.Close()
	})

	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:       1,
			Protocol: "TCP",
			Info:     "flag{demo_flag}",
			Payload:  "flag{demo_flag}",
			SourceIP: "192.168.1.10",
			DestIP:   "10.0.0.5",
			DestPort: 8080,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	svc.c2Analysis = &model.C2SampleAnalysis{
		CS: model.C2FamilyAnalysis{
			Candidates: []model.C2IndicatorRecord{
				{
					PacketID:       11,
					StreamID:       4,
					Family:         "cs",
					IndicatorType:  "http-host",
					IndicatorValue: "c2.example.test",
					Confidence:     78,
					Summary:        "C2 host candidate",
					Source:         "10.0.0.1:50100",
					Destination:    "10.0.0.9:443",
					Host:           "c2.example.test",
					URI:            "/submit",
					Tags:           []string{"https-c2"},
				},
			},
		},
	}

	svc.industrialAnalysis = &model.IndustrialAnalysis{
		RuleHits: []model.IndustrialRuleHit{
			{
				Rule:         "Modbus 可疑写突发",
				Level:        "high",
				PacketID:     21,
				Source:       "10.0.0.20:502",
				Destination:  "10.0.0.30:502",
				FunctionName: "Write Multiple Registers",
				Target:       "Holding Register 40001",
				Evidence:     "write burst",
				Summary:      "High-frequency writes",
			},
		},
	}

	svc.objectsLoaded = true
	svc.objects = []model.ObjectFile{
		{
			ID:        1,
			PacketID:  31,
			Name:      "payload.exe",
			SizeBytes: 2048,
			MIME:      "application/x-dosexec",
			Magic:     "PE/DOS MZ",
			Source:    "HTTP",
		},
	}

	result, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{
		Modules: []string{"hunting", "c2", "industrial", "object"},
	})
	if err != nil {
		t.Fatalf("GatherEvidence() error = %v", err)
	}

	if result.Total != 4 {
		t.Fatalf("expected 4 evidence records, got %d", result.Total)
	}

	var objectRecord *model.EvidenceRecord
	for _, record := range result.Records {
		if record.Module == "" || record.SourceType == "" || record.Summary == "" || record.Severity == "" {
			t.Fatalf("expected populated core evidence fields, got %+v", record)
		}
		if record.Module == "object" {
			copy := record
			objectRecord = &copy
		}
	}
	if objectRecord == nil {
		t.Fatalf("expected object evidence record, got %+v", result.Records)
	}
	if objectRecord.SourceType != "object-file" || objectRecord.Severity != "medium" || objectRecord.Confidence == 0 {
		t.Fatalf("expected calibrated executable object evidence, got %+v", *objectRecord)
	}
	if !containsEvidenceString(objectRecord.Tags, "executable") {
		t.Fatalf("expected executable object tag, got %+v", objectRecord.Tags)
	}
}

func TestGatherEvidenceKeepsBenignImageObjectsInformational(t *testing.T) {
	svc := NewService(nil, nil)
	t.Cleanup(func() {
		_ = svc.packetStore.Close()
	})

	svc.objectsLoaded = true
	svc.objects = []model.ObjectFile{
		{
			ID:        2,
			PacketID:  41,
			Name:      "image.jpg",
			SizeBytes: 1024,
			MIME:      "image/jpeg",
			Magic:     "JPEG image",
			Source:    "HTTP",
		},
	}

	result, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"object"}})
	if err != nil {
		t.Fatalf("GatherEvidence(object) error = %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 object evidence record, got %d", result.Total)
	}
	record := result.Records[0]
	if record.Severity != "info" || record.Confidence != 0 {
		t.Fatalf("expected benign image object to stay informational, got %+v", record)
	}
	if !containsEvidenceString(record.Tags, "image") {
		t.Fatalf("expected image tag, got %+v", record.Tags)
	}
}

func TestEvidenceAndInvestigationReportsKeepSeverityAndPacketLinksAligned(t *testing.T) {
	svc := NewService(nil, nil)
	t.Cleanup(func() {
		_ = svc.packetStore.Close()
	})

	svc.usbAnalysis = &model.USBAnalysis{
		TotalUSBPackets:    4,
		MassStoragePackets: 4,
		MassStorage: model.USBMassStorageAnalysis{
			WriteOperations: []model.USBMassStorageOperation{{
				PacketID:       21,
				Device:         "Disk A",
				Endpoint:       "EP 0x02 (OUT)",
				Command:        "WRITE(10)",
				TransferLength: 4096,
				Status:         "failed",
				DataResidue:    512,
			}},
		},
	}
	svc.c2Analysis = &model.C2SampleAnalysis{
		CS: model.C2FamilyAnalysis{
			CandidateCount: 1,
			Candidates: []model.C2IndicatorRecord{{
				PacketID:       31,
				StreamID:       7,
				Family:         "cs",
				IndicatorType:  "uri",
				IndicatorValue: "/submit.php",
				Confidence:     88,
				Summary:        "C2 URI candidate",
				Tags:           []string{"http"},
			}},
		},
	}

	evidence, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"usb", "c2"}})
	if err != nil {
		t.Fatalf("GatherEvidence() error = %v", err)
	}
	usbReport := buildUSBInvestigationReport(*svc.usbAnalysis)
	c2Report := buildC2FamilyInvestigationReport("cs", svc.c2Analysis.CS)

	usbEvidence := firstEvidenceByModule(evidence.Records, "usb")
	if usbEvidence == nil || len(usbReport.Evidence) == 0 {
		t.Fatalf("expected USB evidence and report items, got evidence=%+v report=%+v", evidence.Records, usbReport)
	}
	if usbEvidence.PacketID != usbReport.Evidence[0].PacketID || usbEvidence.Severity != usbReport.Evidence[0].Severity {
		t.Fatalf("USB evidence/report mismatch: evidence=%+v report=%+v", *usbEvidence, usbReport.Evidence[0])
	}

	c2Evidence := firstEvidenceByModule(evidence.Records, "c2")
	if c2Evidence == nil || len(c2Report.Evidence) == 0 {
		t.Fatalf("expected C2 evidence and report items, got evidence=%+v report=%+v", evidence.Records, c2Report)
	}
	if c2Evidence.PacketID != c2Report.Evidence[0].PacketID ||
		c2Evidence.StreamID != c2Report.Evidence[0].StreamID ||
		c2Evidence.Severity != c2Report.Evidence[0].Severity {
		t.Fatalf("C2 evidence/report mismatch: evidence=%+v report=%+v", *c2Evidence, c2Report.Evidence[0])
	}
}

func firstEvidenceByModule(records []model.EvidenceRecord, module string) *model.EvidenceRecord {
	for _, record := range records {
		if record.Module == module {
			copy := record
			return &copy
		}
	}
	return nil
}

func containsEvidenceString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestExtractObjectsDetectsMagicAndRefinesMIME(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Protocol: "HTTP",
			Info:     "POST /upload",
			RawHex:   "4d5a900003000000",
			Payload:  "content-type: application/octet-stream\nfilename=\"payload.bin\"\n4d5a900003000000",
			Length:   8,
		},
	}

	objects := ExtractObjects(packets)
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objects))
	}
	if objects[0].Magic != "PE/DOS MZ" {
		t.Fatalf("expected PE/DOS MZ magic, got %+v", objects[0])
	}
	if objects[0].MIME != "application/x-dosexec" {
		t.Fatalf("expected refined MIME application/x-dosexec, got %+v", objects[0])
	}
}
