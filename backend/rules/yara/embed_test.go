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
