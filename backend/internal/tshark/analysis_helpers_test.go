package tshark

import "testing"

func TestScanFieldRowsWithOptionsReusesSupersetCache(t *testing.T) {
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearFieldScanCache("")
	})

	key := buildFieldScanCacheKey("demo.pcap", normalizeFieldScanOptions(fieldScanOptions{}))
	storeFieldScanCacheEntry(key, []string{"frame.number", "ip.src", "_ws.col.Info"}, [][]string{
		{"7", "192.0.2.10", "GET /index"},
	})

	var rows [][]string
	err := scanFieldRowsWithOptions("demo.pcap", []string{"_ws.col.Info", "frame.number"}, fieldScanOptions{}, func(parts []string) {
		rows = append(rows, parts)
	})
	if err != nil {
		t.Fatalf("scanFieldRowsWithOptions() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 projected row, got %d", len(rows))
	}
	if rows[0][0] != "GET /index" || rows[0][1] != "7" {
		t.Fatalf("unexpected projected row: %#v", rows[0])
	}
}
