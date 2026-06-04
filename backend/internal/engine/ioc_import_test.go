package engine

import (
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ─── ImportSTIX Edge Cases ───────────────────────────────────────────────────

func TestImportSTIX_EmptyBundle(t *testing.T) {
	input := `{"type": "bundle", "objects": []}`
	entries, err := ImportSTIX(strings.NewReader(input), "stix-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from empty bundle, got %d", len(entries))
	}
}

func TestImportSTIX_NoPattern(t *testing.T) {
	input := `{
		"type": "bundle",
		"objects": [
			{
				"type": "indicator",
				"id": "indicator--1",
				"name": "No Pattern Indicator",
				"labels": ["malicious"]
			},
			{
				"type": "indicator",
				"id": "indicator--2",
				"name": "Empty Pattern",
				"pattern": "",
				"labels": ["suspicious"]
			},
			{
				"type": "indicator",
				"id": "indicator--3",
				"name": "Valid",
				"pattern": "[ipv4-addr:value = '1.2.3.4']"
			}
		]
	}`
	entries, err := ImportSTIX(strings.NewReader(input), "stix-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (only indicator--3), got %d", len(entries))
	}
	if entries[0].Value != "1.2.3.4" {
		t.Errorf("expected value 1.2.3.4, got %s", entries[0].Value)
	}
}

// ─── ImportCSV Edge Cases ────────────────────────────────────────────────────

func TestImportCSV_HeaderOnly(t *testing.T) {
	input := "type,value,severity,confidence,tags,description,source\n"
	entries, err := ImportCSV(strings.NewReader(input), "csv-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from header-only CSV, got %d", len(entries))
	}
}

func TestImportCSV_EmptyLines(t *testing.T) {
	input := `type,value,severity
ip,1.2.3.4,high

domain,evil.com,medium

ip,10.0.0.1,low
`
	entries, err := ImportCSV(strings.NewReader(input), "csv-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (empty lines skipped), got %d", len(entries))
	}
	if entries[0].Value != "1.2.3.4" {
		t.Errorf("entry 0: expected 1.2.3.4, got %s", entries[0].Value)
	}
	if entries[1].Value != "evil.com" {
		t.Errorf("entry 1: expected evil.com, got %s", entries[1].Value)
	}
	if entries[2].Value != "10.0.0.1" {
		t.Errorf("entry 2: expected 10.0.0.1, got %s", entries[2].Value)
	}
}

// ─── ImportJSON Edge Cases ───────────────────────────────────────────────────

func TestImportJSON_NestedObjects(t *testing.T) {
	// JSON objects with extra nested fields should still parse core fields.
	input := `[
		{
			"type": "ip",
			"value": "1.2.3.4",
			"metadata": {"source": "threat-intel", "tags": ["c2"]},
			"nested": {"deep": {"key": "val"}}
		},
		{
			"type": "domain",
			"value": "evil.com",
			"extra": [1, 2, 3]
		}
	]`
	entries, err := ImportJSON(strings.NewReader(input), "test-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Type != model.IOCTypeIP || entries[0].Value != "1.2.3.4" {
		t.Errorf("entry 0: expected ip/1.2.3.4, got %s/%s", entries[0].Type, entries[0].Value)
	}
	if entries[1].Type != model.IOCTypeDomain || entries[1].Value != "evil.com" {
		t.Errorf("entry 1: expected domain/evil.com, got %s/%s", entries[1].Type, entries[1].Value)
	}
}

// ─── parseSTIXPattern Tests ──────────────────────────────────────────────────

func TestParseSTIXPattern_IPv4(t *testing.T) {
	tests := []struct {
		pattern string
		wantVal string
	}{
		{"[ipv4-addr:value = '1.2.3.4']", "1.2.3.4"},
		{"[ipv4-addr:value = '192.168.1.1']", "192.168.1.1"},
		{"[ipv6-addr:value = '::1']", "::1"},
	}
	for _, tt := range tests {
		iocType, iocValue := parseSTIXPattern(tt.pattern)
		if iocType != model.IOCTypeIP {
			t.Errorf("parseSTIXPattern(%q): type = %q, want %q", tt.pattern, iocType, model.IOCTypeIP)
		}
		if iocValue != tt.wantVal {
			t.Errorf("parseSTIXPattern(%q): value = %q, want %q", tt.pattern, iocValue, tt.wantVal)
		}
	}
}

func TestParseSTIXPattern_Domain(t *testing.T) {
	tests := []struct {
		pattern string
		wantVal string
	}{
		{"[domain-name:value = 'evil.com']", "evil.com"},
		{"[domain-name:value = 'malware.net']", "malware.net"},
	}
	for _, tt := range tests {
		iocType, iocValue := parseSTIXPattern(tt.pattern)
		if iocType != model.IOCTypeDomain {
			t.Errorf("parseSTIXPattern(%q): type = %q, want %q", tt.pattern, iocType, model.IOCTypeDomain)
		}
		if iocValue != tt.wantVal {
			t.Errorf("parseSTIXPattern(%q): value = %q, want %q", tt.pattern, iocValue, tt.wantVal)
		}
	}
}

func TestParseSTIXPattern_Hash(t *testing.T) {
	tests := []struct {
		pattern  string
		wantType string
		wantVal  string
	}{
		{
			"[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
			model.IOCTypeHashMD5,
			"d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			"[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
			model.IOCTypeHashSHA1,
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			"[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
			model.IOCTypeHashSHA256,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			// Fallback: hash type detected by length (MD5 = 32 hex chars)
			"[file:hashes = 'd41d8cd98f00b204e9800998ecf8427e']",
			model.IOCTypeHashMD5,
			"d41d8cd98f00b204e9800998ecf8427e",
		},
	}
	for _, tt := range tests {
		iocType, iocValue := parseSTIXPattern(tt.pattern)
		if iocType != tt.wantType {
			t.Errorf("parseSTIXPattern(%q): type = %q, want %q", tt.pattern, iocType, tt.wantType)
		}
		if iocValue != tt.wantVal {
			t.Errorf("parseSTIXPattern(%q): value = %q, want %q", tt.pattern, iocValue, tt.wantVal)
		}
	}
}

func TestParseSTIXPattern_URL(t *testing.T) {
	iocType, iocValue := parseSTIXPattern("[url:value = 'http://evil.com/payload']")
	if iocType != model.IOCTypeURL {
		t.Errorf("type = %q, want %q", iocType, model.IOCTypeURL)
	}
	if iocValue != "http://evil.com/payload" {
		t.Errorf("value = %q, want %q", iocValue, "http://evil.com/payload")
	}
}

func TestParseSTIXPattern_EmptyAndInvalid(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"[unknown:value = 'test']",
		"no brackets here",
	}
	for _, pattern := range tests {
		iocType, iocValue := parseSTIXPattern(pattern)
		if iocType != "" || iocValue != "" {
			t.Errorf("parseSTIXPattern(%q): expected empty, got type=%q value=%q", pattern, iocType, iocValue)
		}
	}
}

// ─── classifyHashByLength Tests ──────────────────────────────────────────────

func TestClassifyHashByLength(t *testing.T) {
	tests := []struct {
		input    string
		wantType string
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", model.IOCTypeHashMD5},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", model.IOCTypeHashSHA1},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", model.IOCTypeHashSHA256},
		{"tooshort", ""},
		{"", ""},
	}
	for _, tt := range tests {
		iocType, _ := classifyHashByLength(tt.input)
		if iocType != tt.wantType {
			t.Errorf("classifyHashByLength(%q): type = %q, want %q", tt.input, iocType, tt.wantType)
		}
	}
}

// ─── normalizeIOCType Extended Coverage ──────────────────────────────────────

func TestNormalizeIOCType_ExtendedAliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"IP-ADDRESS", model.IOCTypeIP},
		{"IPv4-addr", model.IOCTypeIP},
		{"IPv6-addr", model.IOCTypeIP},
		{"hostname", model.IOCTypeDomain},
		{"SHA-1", model.IOCTypeHashSHA1},
		{"SHA-256", model.IOCTypeHashSHA256},
		{"hash_sha1", model.IOCTypeHashSHA1},
		{"hash_sha256", model.IOCTypeHashSHA256},
		{"URI", model.IOCTypeURL},
		{"  ip  ", model.IOCTypeIP},
		{"Bogus", ""},
	}
	for _, tt := range tests {
		got := normalizeIOCType(tt.input)
		if got != tt.want {
			t.Errorf("normalizeIOCType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── severityFromLabels Extended Coverage ────────────────────────────────────

func TestSeverityFromLabels_Extended(t *testing.T) {
	tests := []struct {
		labels []string
		want   string
	}{
		{[]string{"critical", "malicious"}, "critical"},    // critical takes priority
		{[]string{"unknown", "high"}, "high"},              // second label matches
		{[]string{"benign"}, "low"},                        // benign → low
		{[]string{"UNKNOWN_LABEL"}, "medium"},              // default
		{[]string{"CRITICAL"}, "critical"},                 // case-insensitive
		{[]string{"Malicious"}, "high"},                    // mixed case
	}
	for _, tt := range tests {
		got := severityFromLabels(tt.labels)
		if got != tt.want {
			t.Errorf("severityFromLabels(%v) = %q, want %q", tt.labels, got, tt.want)
		}
	}
}
