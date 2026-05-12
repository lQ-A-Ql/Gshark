package tshark

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCurrentCapabilitiesBuildsFullProfileFromFieldRegistry(t *testing.T) {
	ClearCapabilityCache()
	t.Cleanup(ClearCapabilityCache)

	binary := writeFakeTShark(t, "TShark 4.2.0", append(requiredCapabilityFields, optionalCapabilityFields...))
	capabilities := CurrentCapabilities(context.Background(), binary)

	if capabilities.Version != "TShark 4.2.0" {
		t.Fatalf("expected version from fake tshark, got %+v", capabilities)
	}
	if capabilities.FieldProfile != "full" || capabilities.CapabilityCheckDegraded {
		t.Fatalf("expected full profile, got %+v", capabilities)
	}
	if capabilities.FieldCount != len(append(requiredCapabilityFields, optionalCapabilityFields...)) {
		t.Fatalf("expected field count, got %+v", capabilities)
	}
}

func TestCurrentCapabilitiesReportsMissingRequiredAndOptionalFields(t *testing.T) {
	ClearCapabilityCache()
	t.Cleanup(ClearCapabilityCache)

	binary := writeFakeTShark(t, "TShark 3.6.0", []string{"frame.number", "frame.time_epoch"})
	capabilities := CurrentCapabilities(context.Background(), binary)

	if capabilities.FieldProfile != "incompatible" || !capabilities.CapabilityCheckDegraded {
		t.Fatalf("expected incompatible degraded profile, got %+v", capabilities)
	}
	if !stringSliceHas(capabilities.MissingRequiredFields, "_ws.col.Info") {
		t.Fatalf("expected missing required fields, got %+v", capabilities.MissingRequiredFields)
	}
	if !stringSliceHas(capabilities.MissingOptionalFields, "modbus.func_code") {
		t.Fatalf("expected missing optional fields, got %+v", capabilities.MissingOptionalFields)
	}
}

func TestParseFieldRegistryName(t *testing.T) {
	tests := map[string]string{
		"F\tFrame number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\tFrame number": "frame.number",
		"P\tProtocol\tframe": "",
		"":                   "",
	}
	for input, want := range tests {
		if got := parseFieldRegistryName(input); got != want {
			t.Fatalf("parseFieldRegistryName(%q) = %q, want %q", input, got, want)
		}
	}
}

func writeFakeTShark(t *testing.T, version string, fields []string) string {
	t.Helper()
	dir := t.TempDir()
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.bat"
	}
	path := filepath.Join(dir, name)
	fieldLines := make([]string, 0, len(fields))
	for _, field := range fields {
		fieldLines = append(fieldLines, "F\t"+field+"\t"+field+"\tFT_STRING\tfake\tBASE_NONE\t0x0\t"+field)
	}
	if runtime.GOOS == "windows" {
		body := "@echo off\r\n" +
			"if \"%1\"==\"-v\" (\r\n" +
			"echo " + version + "\r\n" +
			"exit /b 0\r\n" +
			")\r\n" +
			"if \"%1\"==\"-G\" (\r\n" +
			strings.Join(prefixLines(fieldLines, "echo "), "\r\n") +
			"\r\nexit /b 0\r\n" +
			")\r\n" +
			"exit /b 1\r\n"
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatalf("write fake tshark: %v", err)
		}
		return path
	}
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-v\" ]; then echo '" + version + "'; exit 0; fi\n" +
		"if [ \"$1\" = \"-G\" ]; then\n" +
		"cat <<'EOF'\n" +
		strings.Join(fieldLines, "\n") +
		"\nEOF\n" +
		"exit 0\n" +
		"fi\n" +
		"exit 1\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake tshark: %v", err)
	}
	return path
}

func prefixLines(lines []string, prefix string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, prefix+line)
	}
	return out
}

func stringSliceHas(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
