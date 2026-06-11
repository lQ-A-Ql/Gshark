package tshark

import (
	"reflect"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildVehicleAnalysisFromCachedFieldRowsCoversProtocolAndPayloadBranches(t *testing.T) {
	const filePath = "vehicle-cache.pcapng"
	ClearFieldScanCache("")
	t.Cleanup(func() { ClearFieldScanCache("") })

	storeCachedRowsForFields(filePath, vehicleAnalysisFields, [][]string{
		vehicleAnalysisRow(map[int]string{
			0:  "10",
			1:  "1.000",
			2:  "192.0.2.10",
			5:  "192.0.2.20",
			8:  "eth:can:uds",
			9:  "UDS",
			10: "ReadDataByIdentifier request",
			11: "0x123",
			12: "8",
			13: "1",
			42: "0x22",
			47: "0x0e00",
			49: "0x0e01",
			56: "0xf190",
			62: "22 f1 90",
		}),
		vehicleAnalysisRow(map[int]string{
			0:  "11",
			1:  "1.050",
			2:  "192.0.2.20",
			5:  "192.0.2.10",
			8:  "eth:can:uds",
			9:  "UDS",
			10: "ReadDataByIdentifier positive response",
			11: "0x123",
			12: "8",
			13: "1",
			42: "0x62",
			43: "1",
			47: "0x0e01",
			49: "0x0e00",
			53: "TESTVIN123456789",
			56: "0xf190",
			62: "62 f1 90 54 45 53 54",
		}),
		vehicleAnalysisRow(map[int]string{
			0:  "12",
			1:  "2.000",
			2:  "198.51.100.10",
			5:  "198.51.100.20",
			8:  "eth:can:j1939:doip:obdii:xcp:kwp2000",
			9:  "DoIP",
			10: "mixed vehicle bus frame",
			11: "0x18feeca1",
			12: "8",
			13: "2",
			15: "1",
			16: "1",
			17: "1",
			18: "1",
			19: "1",
			20: "1",
			21: "1",
			22: "1",
			23: "0x18feeca1",
			24: "65260",
			25: "6",
			26: "0xa1",
			27: "0xff",
			28: "aa bb cc",
			29: "0x0005",
			30: "VINTEST123456789",
			31: "0x0e00",
			33: "0x0e01",
			35: "0x0e02",
			37: "0x0e03",
			39: "0x10",
			40: "0x00",
			57: "13400",
			60: "13400",
			61: "00",
			62: "41 0c 1a f8",
		}),
	})

	storeCachedRowsForFields(filePath, canPayloadAnalysisFields, [][]string{
		canPayloadRow(map[int]string{
			0:  "20",
			1:  "3.000",
			2:  "can:canopen",
			3:  "CANopen",
			4:  "CANopen SDO write",
			5:  "1",
			6:  "0x601",
			7:  "8",
			29: "0x601",
			30: "0xB",
			31: "0x05",
			33: "0x2000",
			34: "0x01",
			35: "11:22:33:44",
		}),
		canPayloadRow(map[int]string{
			0:  "21",
			1:  "3.100",
			2:  "can:iso15765:uds",
			3:  "UDS",
			4:  "UDS read DID",
			5:  "1",
			6:  "0x7e0",
			7:  "8",
			10: "0x0e01",
			11: "0x0e00",
			12: "0x0",
			21: "22 f1 90",
			22: "0x22",
			23: "0x01",
			26: "0xf190",
		}),
		canPayloadRow(map[int]string{
			0:  "22",
			1:  "3.200",
			2:  "can:iso15765:obd-ii",
			3:  "OBD-II",
			4:  "OBD engine RPM",
			5:  "1",
			6:  "0x7df",
			7:  "8",
			8:  "41 0C 1A F8",
			12: "0x0",
			28: "00",
		}),
		canPayloadRow(map[int]string{
			0:  "23",
			1:  "3.300",
			2:  "can:iso15765",
			3:  "ISO-TP",
			4:  "ISO-TP first frame",
			5:  "1",
			6:  "0x700",
			7:  "8",
			12: "0x10",
			15: "32",
			17: "1",
			18: "0x0",
			19: "8",
			20: "10",
			21: "10 20 30 40",
		}),
	})

	storeCachedRowsForFields(filePath, dbcDecodedMessageFields, [][]string{
		dbcDecodedRow(map[int]string{
			0: "30",
			1: "4.000",
			2: "DBC decoded engine data",
			3: "1",
			4: "0x123",
			5: "8",
			6: "2a:00:00:00:00:00:00:00",
		}),
	})
	db := &DBCDatabase{
		Path:         "fleet.dbc",
		Name:         "fleet",
		MessageCount: 1,
		SignalCount:  1,
		Messages: map[uint32][]DBCMessageDef{
			0x123: {{
				ID:     0x123,
				Name:   "EngineData",
				Length: 8,
				Sender: "ECU",
				Signals: []DBCSignalDef{{
					Name:         "Speed",
					StartBit:     0,
					Length:       8,
					LittleEndian: true,
					Factor:       1,
					Offset:       0,
					Unit:         "km/h",
				}},
			}},
		},
	}

	stats, err := BuildVehicleAnalysisFromFile(filePath, db)
	if err != nil {
		t.Fatalf("BuildVehicleAnalysisFromFile() error = %v", err)
	}
	if stats.TotalVehiclePackets != 3 {
		t.Fatalf("TotalVehiclePackets = %d, want 3", stats.TotalVehiclePackets)
	}
	for _, label := range []string{"CAN", "UDS", "J1939", "DoIP", "OBD-II", "XCP", "KWP2000"} {
		if !containsBucket(stats.Protocols, label) {
			t.Fatalf("protocol %q missing from %+v", label, stats.Protocols)
		}
	}
	if stats.CAN.TotalFrames != 3 || stats.CAN.ExtendedFrames != 1 || stats.CAN.ErrorFrames != 1 {
		t.Fatalf("unexpected CAN summary: %+v", stats.CAN)
	}
	if stats.J1939.TotalMessages != 1 || stats.DoIP.TotalMessages != 1 || stats.UDS.TotalMessages != 2 {
		t.Fatalf("unexpected protocol totals: j1939=%+v doip=%+v uds=%+v", stats.J1939, stats.DoIP, stats.UDS)
	}
	if len(stats.UDS.Transactions) != 1 || stats.UDS.Transactions[0].Status != "positive" || stats.UDS.Transactions[0].LatencyMS != 50 {
		t.Fatalf("unexpected UDS transactions: %+v", stats.UDS.Transactions)
	}
	if len(stats.CAN.PayloadRecords) != 4 {
		t.Fatalf("expected 4 CAN payload records, got %+v", stats.CAN.PayloadRecords)
	}
	for _, label := range []string{"CANopen", "UDS", "OBD-II", "ISO-TP"} {
		if !containsBucket(stats.CAN.PayloadProtocols, label) {
			t.Fatalf("payload protocol %q missing from %+v", label, stats.CAN.PayloadProtocols)
		}
	}
	if len(stats.CAN.DBCProfiles) != 1 || stats.CAN.DBCProfiles[0].Name != "fleet" {
		t.Fatalf("unexpected DBC profiles: %+v", stats.CAN.DBCProfiles)
	}
	if len(stats.CAN.DecodedMessages) != 1 || stats.CAN.DecodedMessages[0].Signals[0].Value != "42" {
		t.Fatalf("unexpected decoded DBC messages: %+v", stats.CAN.DecodedMessages)
	}
	if len(stats.CAN.SignalTimelines) != 1 || stats.CAN.SignalTimelines[0].Name != "Speed" {
		t.Fatalf("unexpected signal timelines: %+v", stats.CAN.SignalTimelines)
	}
	if len(stats.Recommendations) < 8 {
		t.Fatalf("expected rich recommendations, got %+v", stats.Recommendations)
	}
	if !reflect.DeepEqual(stats.CAN.DecodedSignals, []model.TrafficBucket{{Label: "Speed", Count: 1}}) {
		t.Fatalf("unexpected decoded signals: %+v", stats.CAN.DecodedSignals)
	}
}

func storeCachedRowsForFields(filePath string, fields []string, rows [][]string) {
	normalizedFields := normalizeFieldScanFields(fields)
	key := cacheKey(buildFieldScanCacheParams(filePath, normalizeFieldScanOptions(fieldScanOptions{})))
	storeFieldScanCacheEntry(key, filePath, normalizedFields, rows)
}

func vehicleAnalysisRow(values map[int]string) []string {
	return indexedFieldRow(len(vehicleAnalysisFields), values)
}

func canPayloadRow(values map[int]string) []string {
	return indexedFieldRow(len(canPayloadAnalysisFields), values)
}

func dbcDecodedRow(values map[int]string) []string {
	return indexedFieldRow(len(dbcDecodedMessageFields), values)
}

func indexedFieldRow(width int, values map[int]string) []string {
	row := make([]string, width)
	for idx, value := range values {
		if idx >= 0 && idx < width {
			row[idx] = value
		}
	}
	return row
}
