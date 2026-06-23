package miscpkg

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNormalizeRunResultCoversTableOutputAndFallbacks(t *testing.T) {
	if got := normalizeRunResult(nil); got.Message == "" || got.Text != "" || got.Output != nil {
		t.Fatalf("nil normalizeRunResult = %+v", got)
	}
	if got := normalizeRunResult("hello"); got.Text != "hello" || got.Message == "" {
		t.Fatalf("string normalizeRunResult = %+v", got)
	}

	result := normalizeRunResult(map[string]any{
		"message": " done ",
		"text":    "",
		"table": map[string]any{
			"columns": []any{
				map[string]any{"key": "host", "label": "Host"},
				map[string]any{"key": "port"},
				map[string]any{"key": ""},
				"bad",
			},
			"rows": []any{
				map[string]any{"host": "example.test", "port": 443},
				"bad",
			},
		},
	})
	if result.Message != "done" || result.Table == nil || len(result.Table.Columns) != 2 || len(result.Table.Rows) != 1 {
		t.Fatalf("table normalizeRunResult = %+v", result)
	}
	if result.Table.Columns[1].Label != "port" || result.Table.Rows[0]["port"] != "443" {
		t.Fatalf("table normalization lost fallback label/string row conversion: %+v", result.Table)
	}

	withOutput := normalizeRunResult(map[string]any{"output": []any{"x"}})
	if withOutput.Output == nil {
		t.Fatalf("explicit output should be preserved: %+v", withOutput)
	}
	fallback := normalizeRunResult(42)
	if fallback.Output != 42 || fallback.Message == "" {
		t.Fatalf("fallback normalizeRunResult = %+v", fallback)
	}
}

func TestMiscUtilityAndScanFieldHelpersCoverBoundaries(t *testing.T) {
	if runtimeFromPath("demo.PY") != "python" || runtimeFromPath("demo.mjs") != "javascript" || runtimeFromPath("demo.bin") != "unknown" {
		t.Fatal("runtimeFromPath did not classify expected extensions")
	}
	if got := joinPythonPath(" a ", "", "b"); !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Fatalf("joinPythonPath = %q", got)
	}
	if _, err := resolveManagedPath(t.TempDir(), "../escape.txt"); err == nil {
		t.Fatal("resolveManagedPath should reject traversal")
	}
	if err := validateModuleID("valid-module_1"); err != nil {
		t.Fatalf("validateModuleID valid error = %v", err)
	}
	if err := validateModuleID("../bad"); err == nil {
		t.Fatal("validateModuleID should reject traversal-ish ID")
	}
	values := normalizeValues(map[string]string{" key ": "value"})
	if values["key"] != "value" {
		t.Fatalf("normalizeValues = %+v", values)
	}
	if asString(7) != "" || defaultIfEmpty("  ", "fallback") != "fallback" {
		t.Fatal("string fallback helpers failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runScanFields(ctx, InvokeContext{CapturePath: "demo.pcap"}, []string{"frame.number"}, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("runScanFields canceled fallback error = %v", err)
	}
	rows, err := runScanFields(context.Background(), InvokeContext{
		CapturePath: "demo.pcap",
		ScanFields: func(filePath string, fields []string, displayFilter string) ([]map[string]string, error) {
			return []map[string]string{{fields[0]: filePath + "|" + displayFilter}}, nil
		},
	}, []string{"frame.number"}, "tcp")
	if err != nil || rows[0]["frame.number"] != "demo.pcap|tcp" {
		t.Fatalf("runScanFields legacy callback rows=%+v err=%v", rows, err)
	}
}

func TestPythonHostCallValidationErrors(t *testing.T) {
	resp := handlePythonHostCall(context.Background(), map[string]any{
		"id":     "1",
		"method": "scan_fields",
		"params": map[string]any{"fields": []any{"frame.number"}},
	}, InvokeContext{Permissions: []string{"host.scan"}})
	if !hostResponseContainsError(t, resp, "抓") && !hostResponseContainsError(t, resp, "capture") {
		t.Fatalf("expected missing capture error response, got %s", resp)
	}

	resp = handlePythonHostCall(context.Background(), map[string]any{
		"id":     "2",
		"method": "scan_fields",
		"params": map[string]any{"fields": []any{}},
	}, InvokeContext{CapturePath: "demo.pcap", Permissions: []string{"host.scan"}})
	if !hostResponseContainsError(t, resp, "non-empty fields") {
		t.Fatalf("expected empty fields error response, got %s", resp)
	}

	resp = handlePythonHostCall(context.Background(), map[string]any{
		"id":     "3",
		"method": "scan_fields",
		"params": map[string]any{"fields": []any{"frame.number"}},
	}, InvokeContext{
		CapturePath: "demo.pcap",
		Permissions: []string{"host.scan"},
		ScanFieldsWithContext: func(context.Context, string, []string, string) ([]map[string]string, error) {
			return nil, errors.New("scan failed")
		},
	})
	if !hostResponseContainsError(t, resp, "scan failed") {
		t.Fatalf("expected scan error response, got %s", resp)
	}
}

func hostResponseContainsError(t *testing.T, raw string, needle string) bool {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("decode host response: %v raw=%s", err, raw)
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(asString(payload["error"]))), strings.ToLower(needle))
}
