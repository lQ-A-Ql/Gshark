package tshark

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDBCDatabaseAndDecodeSignals(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sample.dbc")
	content := `VERSION ""

BO_ 291 VehicleStatus: 8 ECU
 SG_ Speed : 0|16@1+ (0.1,0) [0|250] "km/h" Vector__XXX
 SG_ Temp : 23|8@0+ (1,0) [0|255] "C" Vector__XXX
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write dbc: %v", err)
	}

	db, err := LoadDBCDatabase(path)
	if err != nil {
		t.Fatalf("load dbc: %v", err)
	}
	if db.MessageCount != 1 || db.SignalCount != 2 {
		t.Fatalf("unexpected dbc counts: %#v", db.Profile())
	}

	foundDB, msg := findDBCMessage([]*DBCDatabase{db}, 291, 8)
	if foundDB == nil || msg == nil || msg.Name != "VehicleStatus" {
		t.Fatalf("failed to match dbc message: %#v %#v", foundDB, msg)
	}

	signals := decodeDBCSignals(msg, []byte{0xD2, 0x04, 0x64, 0, 0, 0, 0, 0})
	if len(signals) != 2 {
		t.Fatalf("expected 2 decoded signals, got %#v", signals)
	}
	if signals[0].Name != "Speed" || signals[0].Value != "123.400" {
		t.Fatalf("unexpected speed decode: %#v", signals[0])
	}
	if signals[1].Name != "Temp" || signals[1].Value != "100" {
		t.Fatalf("unexpected temp decode: %#v", signals[1])
	}
}
