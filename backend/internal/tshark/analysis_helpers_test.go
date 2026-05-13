package tshark

import (
	"strings"
	"testing"
)

func TestPlanFieldScanByCapabilitiesSkipsMissingOptionalFields(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	// Include display-layer fields so _ws.col.Info is present and resolvable,
	// matching the test's original semantics of measuring optional-field skip
	// behavior (modbus.func_code is the field that should be skipped).
	fields := append([]string{}, requiredCapabilityFields...)
	fields = append(fields, displayLayerCapabilityFields...)
	fields = append(fields, "ip.src")
	binary := writeFakeTShark(t, "TShark 4.2.0", fields)
	SetBinaryPath(binary)

	plan, err := planFieldScanByCapabilities([]string{"frame.number", "ip.src", "modbus.func_code", "_ws.col.Info"})
	if err != nil {
		t.Fatalf("planFieldScanByCapabilities() error = %v", err)
	}
	if len(plan.tsharkFields) != 3 {
		t.Fatalf("expected optional field to be skipped, got %#v", plan.tsharkFields)
	}
	row := projectCapabilityFieldScanRow([]string{"7", "192.0.2.10", "GET /index"}, plan)
	if len(row) != 4 || row[0] != "7" || row[1] != "192.0.2.10" || row[2] != "" || row[3] != "GET /index" {
		t.Fatalf("unexpected projected row: %#v", row)
	}
}

func TestPlanFieldScanByCapabilitiesRejectsMissingRequiredFields(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	// Fake tshark publishes only frame.number, so requesting frame.protocols
	// (a genuinely required protocol-layer field) must trigger the missing-
	// required-field error. _ws.col.Info is no longer required after the
	// P0-3 display-layer downgrade, so it cannot be used to drive this path.
	binary := writeFakeTShark(t, "TShark 3.2.0", []string{"frame.number"})
	SetBinaryPath(binary)

	_, err := planFieldScanByCapabilities([]string{"frame.number", "frame.protocols"})
	if err == nil {
		t.Fatal("expected missing required field error")
	}
	if got := err.Error(); got == "" || !stringContainsAll(got, "frame.protocols", "TShark 3.2.0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlanFieldScanByCapabilitiesUsesRegisteredAliases(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	fields := []string{"frame.number", "frame.time_epoch", "frame.protocols", "_ws.col.protocol", "_ws.col.info"}
	binary := writeFakeTShark(t, "TShark 4.6.5", fields)
	SetBinaryPath(binary)

	plan, err := planFieldScanByCapabilities([]string{"_ws.col.Info", "_ws.col.Protocol"})
	if err != nil {
		t.Fatalf("planFieldScanByCapabilities() error = %v", err)
	}
	if len(plan.tsharkFields) != 2 || plan.tsharkFields[0] != "_ws.col.info" || plan.tsharkFields[1] != "_ws.col.protocol" {
		t.Fatalf("unexpected tshark fields: %#v", plan.tsharkFields)
	}
}

func TestAppendPlannedFieldArgsUsesAliasesAndSkipsOptional(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	fields := []string{"frame.number", "frame.time_epoch", "frame.protocols", "_ws.col.protocol", "_ws.col.info"}
	binary := writeFakeTShark(t, "TShark 4.6.5", fields)
	SetBinaryPath(binary)

	args, plan, err := appendPlannedFieldArgs([]string{"-T", "fields"}, []string{"_ws.col.Info", "udp.payload", "frame.number"})
	if err != nil {
		t.Fatalf("appendPlannedFieldArgs() error = %v", err)
	}
	if len(plan.tsharkFields) != 2 || plan.tsharkFields[0] != "_ws.col.info" || plan.tsharkFields[1] != "frame.number" {
		t.Fatalf("unexpected planned fields: %#v", plan.tsharkFields)
	}
	if !stringSliceHas(args, "_ws.col.info") || !stringSliceHas(args, "frame.number") || stringSliceHas(args, "udp.payload") {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestPlannedFieldScanZeroValuePreservesRows(t *testing.T) {
	row := (PlannedFieldScan{}).ProjectRow([]string{"a", "b"})
	if len(row) != 2 || row[0] != "a" || row[1] != "b" {
		t.Fatalf("unexpected zero-value projection: %#v", row)
	}
}

func TestBuildPlannedFieldArgsPreservesBaseArgsBeforeFields(t *testing.T) {
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		SetBinaryPath(oldBinary)
		ClearCapabilityCache()
	})
	ClearCapabilityCache()

	binary := writeFakeTShark(t, "TShark 4.6.5", requiredCapabilityFields)
	SetBinaryPath(binary)

	planned, err := BuildPlannedFieldArgs([]string{"-n", "-r", "demo.pcap", "-T", "fields"}, []string{"frame.number"})
	if err != nil {
		t.Fatalf("BuildPlannedFieldArgs() error = %v", err)
	}
	if len(planned.Args) < 7 || planned.Args[0] != "-n" || planned.Args[3] != "-T" || planned.Args[len(planned.Args)-2] != "-e" || planned.Args[len(planned.Args)-1] != "frame.number" {
		t.Fatalf("unexpected planned args ordering: %#v", planned.Args)
	}
}

func TestBuildTSharkFieldDegradationNoteSummarizesMissingOptionalFields(t *testing.T) {
	note := buildTSharkFieldDegradationNote("USB 分析字段扫描", []string{
		"usb.capdata",
		"usbhid.data",
		"usb.capdata",
		"scsi.status",
	})
	if !strings.Contains(note, "USB 分析字段扫描") {
		t.Fatalf("expected scope in note, got %q", note)
	}
	if !strings.Contains(note, "缺少 3 个可选字段") {
		t.Fatalf("expected deduplicated field count, got %q", note)
	}
	if !strings.Contains(note, "相关列已按空值降级") {
		t.Fatalf("expected degradation guidance, got %q", note)
	}
}

func TestScanFieldRowsWithOptionsReusesSupersetCache(t *testing.T) {
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearFieldScanCache("")
	})

	key := cacheKey(buildFieldScanCacheParams("demo.pcap", normalizeFieldScanOptions(fieldScanOptions{})))
	storeFieldScanCacheEntry(key, "demo.pcap", []string{"frame.number", "ip.src", "_ws.col.Info"}, [][]string{
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

func stringContainsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
