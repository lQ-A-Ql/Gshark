package yararules

import (
	"os"
	"strings"
	"testing"
)

func TestDefaultRuleSourceMatchesRuleFile(t *testing.T) {
	onDisk, err := os.ReadFile("default.yar")
	if err != nil {
		t.Fatalf("ReadFile(default.yar) error = %v", err)
	}

	if DefaultRuleSource != string(onDisk) {
		t.Fatal("embedded YARA rule source is out of sync with default.yar")
	}
}

func TestTrafficCVERuleSourceMatchesRuleFile(t *testing.T) {
	onDisk, err := os.ReadFile("traffic_cve_webshell.yar")
	if err != nil {
		t.Fatalf("ReadFile(traffic_cve_webshell.yar) error = %v", err)
	}

	if TrafficCVERuleSource != string(onDisk) {
		t.Fatal("embedded CVE YARA rule source is out of sync with traffic_cve_webshell.yar")
	}
}

func TestAllRuleSourcesContainsBothFiles(t *testing.T) {
	all := AllRuleSources()
	if !strings.Contains(all, "OWASP_SQL_INJECTION") {
		t.Fatal("AllRuleSources() missing default.yar rules")
	}
	if !strings.Contains(all, "TRAFFIC_CVE_2024_1709") {
		t.Fatal("AllRuleSources() missing traffic_cve_webshell.yar rules")
	}
	if !strings.Contains(all, "TRAFFIC_WEBSHELL_CHINA_CHOPPER") {
		t.Fatal("AllRuleSources() missing webshell rules")
	}
}

func TestCommunityRulesEmbedded(t *testing.T) {
	sources := readCommunityRules()
	if sources == "" {
		t.Fatal("readCommunityRules() returned empty; community rules should be embedded")
	}
	if !strings.Contains(sources, "COMMUNITY_MALWARE_CobaltStrike_Beacon") {
		t.Fatal("community rules missing CobaltStrike beacon rule")
	}
	if !strings.Contains(sources, "COMMUNITY_EXPLOIT_Log4Shell_CVE202144228") {
		t.Fatal("community rules missing Log4Shell exploit rule")
	}
	if !strings.Contains(sources, "COMMUNITY_WEBSHELL_ChinaChopper_Generic") {
		t.Fatal("community rules missing China Chopper webshell rule")
	}
}

func TestCommunityEnabledDefault(t *testing.T) {
	// Ensure env is unset for default test
	os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY")
	if CommunityEnabled() {
		t.Fatal("CommunityEnabled() should return false by default (env unset)")
	}
}

func TestCommunityEnabledExplicitValues(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"0", false},
		{"false", false},
		{"FALSE", false},
		{"", false},
		{"no", false},
		{"yes", false},
	}

	for _, tt := range tests {
		t.Run("env="+tt.value, func(t *testing.T) {
			if tt.value == "" {
				os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY")
			} else {
				os.Setenv("MEOW_TRAFFIC_YARA_COMMUNITY", tt.value)
			}
			t.Cleanup(func() { os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY") })

			if got := CommunityEnabled(); got != tt.expected {
				t.Fatalf("CommunityEnabled() with env=%q = %v, want %v", tt.value, got, tt.expected)
			}
		})
	}
}

func TestAllRuleSourcesIncludesCommunityWhenEnabled(t *testing.T) {
	os.Setenv("MEOW_TRAFFIC_YARA_COMMUNITY", "1")
	t.Cleanup(func() { os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY") })

	all := AllRuleSources()
	if !strings.Contains(all, "COMMUNITY_MALWARE_CobaltStrike_Beacon") {
		t.Fatal("AllRuleSources() should include community rules when enabled")
	}
	if !strings.Contains(all, "COMMUNITY_EXPLOIT_Log4Shell_CVE202144228") {
		t.Fatal("AllRuleSources() should include exploit rules when community enabled")
	}
	if !strings.Contains(all, "COMMUNITY_WEBSHELL_ChinaChopper_Generic") {
		t.Fatal("AllRuleSources() should include webshell rules when community enabled")
	}
}

func TestAllRuleSourcesExcludesCommunityWhenDisabled(t *testing.T) {
	os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY")

	all := AllRuleSources()
	if strings.Contains(all, "COMMUNITY_MALWARE_CobaltStrike_Beacon") {
		t.Fatal("AllRuleSources() should not include community rules when disabled")
	}
	// Built-in rules should still be present
	if !strings.Contains(all, "OWASP_SQL_INJECTION") {
		t.Fatal("AllRuleSources() should still include built-in rules")
	}
}

func TestCommunityRuleSourcesRespectsEnvToggle(t *testing.T) {
	os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY")
	if s := CommunityRuleSources(); s != "" {
		t.Fatalf("CommunityRuleSources() should be empty when disabled, got %d chars", len(s))
	}

	os.Setenv("MEOW_TRAFFIC_YARA_COMMUNITY", "1")
	t.Cleanup(func() { os.Unsetenv("MEOW_TRAFFIC_YARA_COMMUNITY") })
	if s := CommunityRuleSources(); s == "" {
		t.Fatal("CommunityRuleSources() should be non-empty when enabled")
	}
}
