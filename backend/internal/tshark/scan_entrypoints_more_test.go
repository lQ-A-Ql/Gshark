package tshark

import (
	"strings"
	"testing"
)

func TestScanUSBAnalysisFromFileUsesFakeTSharkRows(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	ClearFieldScanCache("")
	ClearUSBAnalysisRawScanCache()
	t.Cleanup(func() {
		ClearCapabilityCache()
		ClearFieldScanCache("")
		ClearUSBAnalysisRawScanCache()
	})

	raw, err := scanUSBAnalysisFromFile("usb-entry.pcapng")
	if err != nil {
		t.Fatalf("scanUSBAnalysisFromFile() error = %v", err)
	}
	if len(raw.Rows) != 3 {
		t.Fatalf("scanUSBAnalysisFromFile rows = %d, want 3", len(raw.Rows))
	}
	if raw.Rows[0][usbFieldFrameNumber] != "21" || raw.Rows[0][usbFieldCapData] == "" {
		t.Fatalf("unexpected first USB raw row: %+v", raw.Rows[0])
	}

	analysis, err := BuildUSBAnalysisFromFile("usb-entry.pcapng")
	if err != nil {
		t.Fatalf("BuildUSBAnalysisFromFile() error = %v", err)
	}
	if analysis.TotalUSBPackets != 3 || analysis.HIDPackets != 1 || analysis.MassStoragePackets != 2 {
		t.Fatalf("unexpected USB analysis counts: %+v", analysis)
	}
	if len(analysis.MassStorage.WriteOperations) != 1 {
		t.Fatalf("expected merged write operation from fake CBW/CSW rows, got %+v", analysis.MassStorage)
	}
	if write := analysis.MassStorage.WriteOperations[0]; write.Status != "check_condition" || write.DataResidue != 8 {
		t.Fatalf("unexpected fake write operation: %+v", write)
	}

	if USBAnalysisScanRunnerForTesting() == nil {
		t.Fatal("USBAnalysisScanRunnerForTesting returned nil")
	}
	SetUSBAnalysisScanRunnerForTesting(nil)
	ClearUSBAnalysisRawScanCache()
}

func TestScanDBCDecodedMessagesWithFakeTSharkRows(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearCapabilityCache()
		ClearFieldScanCache("")
	})

	db := &DBCDatabase{
		Name: "fleet",
		Messages: map[uint32][]DBCMessageDef{
			0x123: {
				{
					ID:     0x123,
					Name:   "VehicleSpeed",
					Length: 8,
					Sender: "ECU",
					Signals: []DBCSignalDef{
						{Name: "Speed", StartBit: 0, Length: 8, LittleEndian: true, Factor: 1, Unit: "km/h"},
					},
				},
			},
		},
		MessageCount: 1,
		SignalCount:  1,
	}

	messages, signals, records, err := scanDBCDecodedMessages("vehicle.pcapng", []*DBCDatabase{db})
	if err != nil {
		t.Fatalf("scanDBCDecodedMessages() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want one decoded DBC record", records)
	}
	if records[0].PacketID != 501 || records[0].Database != "fleet" || records[0].Signals[0].Value != "42" {
		t.Fatalf("unexpected decoded DBC record: %+v", records[0])
	}
	if len(messages) != 1 || !strings.Contains(messages[0].Label, "VehicleSpeed") {
		t.Fatalf("unexpected message buckets: %+v", messages)
	}
	if len(signals) != 1 || signals[0].Label != "Speed" {
		t.Fatalf("unexpected signal buckets: %+v", signals)
	}

	emptyMessages, emptySignals, emptyRecords, err := scanDBCDecodedMessages("vehicle.pcapng", nil)
	if err != nil || len(emptyMessages) != 0 || len(emptySignals) != 0 || len(emptyRecords) != 0 {
		t.Fatalf("empty DBC scan = messages=%+v signals=%+v records=%+v err=%v", emptyMessages, emptySignals, emptyRecords, err)
	}
}

func TestPacketLayersAndMediaProgressEntrypointsUseFakeTShark(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearCapabilityCache()
		ClearFieldScanCache("")
	})

	layers, err := ReadPacketLayersFromFile("sample.pcapng", 1)
	if err != nil {
		t.Fatalf("ReadPacketLayersFromFile() error = %v", err)
	}
	if _, ok := layers["frame"]; !ok {
		t.Fatalf("expected frame layer from fake EK output, got %+v", layers)
	}
	if _, err := ReadPacketLayersFromFile("", 1); err == nil {
		t.Fatal("empty pcap path should fail")
	}
	if _, err := ReadPacketLayersFromFile("sample.pcapng", 0); err == nil {
		t.Fatal("invalid packet id should fail")
	}

	var progress []string
	analysis, artifacts, err := BuildMediaAnalysisFromFileWithProgress("media.pcapng", t.TempDir(), func(current, total int, label string) {
		progress = append(progress, label)
	})
	if err != nil {
		t.Fatalf("BuildMediaAnalysisFromFileWithProgress() error = %v", err)
	}
	if analysis.TotalMediaPackets == 0 || len(analysis.Sessions) == 0 {
		t.Fatalf("expected fake media sessions, got %+v", analysis)
	}
	if len(progress) < 3 {
		t.Fatalf("expected progress callbacks, got %+v", progress)
	}
	if artifacts == nil {
		t.Fatalf("artifacts map should be non-nil")
	}
}
