package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestResolveYaraRuleBundleFromDirectory(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yar")
	second := filepath.Join(dir, "nested", "second.yar")
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(first, []byte(`
rule FIRST_RULE {
  meta:
    family = "CVE"
    severity = "high"
    description = "第一条规则"
  strings:
    $a = "/first"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	if err := os.WriteFile(second, []byte(`
rule SECOND_RULE {
  meta:
    project = "JeecgBoot"
    severity = "critical"
    description = "第二条规则"
  strings:
    $a = "/second"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(second) error = %v", err)
	}

	bundle, err := resolveYaraRuleBundle(dir)
	if err != nil {
		t.Fatalf("resolveYaraRuleBundle() error = %v", err)
	}
	if bundle.path == "" {
		t.Fatalf("expected bundle path")
	}
	if _, err := os.Stat(bundle.path); err != nil {
		t.Fatalf("expected bundle file to exist, stat err=%v", err)
	}
	if got := bundle.meta["FIRST_RULE"]; got.category != "CVE" || got.ruleName != "第一条规则" || got.level != "high" {
		t.Fatalf("unexpected FIRST_RULE meta: %+v", got)
	}
	if got := bundle.meta["SECOND_RULE"]; got.category != "JeecgBoot" || got.ruleName != "第二条规则" || got.level != "critical" {
		t.Fatalf("unexpected SECOND_RULE meta: %+v", got)
	}
}

func TestCachedYaraHitsIncludesWarningWhenYaraFails(t *testing.T) {
	oldRun := runYaraCommand
	t.Cleanup(func() {
		runYaraCommand = oldRun
	})
	runYaraCommand = func(_ context.Context, _, _, _ string) ([]byte, error) {
		return []byte("boom"), errors.New("runner failed")
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	tempDir := t.TempDir()
	fakeExe := filepath.Join(tempDir, "fake-yara.exe")
	ruleFile := filepath.Join(tempDir, "rule.yar")
	objectFile := filepath.Join(tempDir, "payload.txt")
	for _, item := range []string{fakeExe, objectFile} {
		if err := os.WriteFile(item, []byte("ok"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", item, err)
		}
	}
	if err := os.WriteFile(ruleFile, []byte(`
rule DUMMY_RULE {
  strings:
    $a = "ok"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(rule) error = %v", err)
	}

	svc.huntMu.Lock()
	svc.yaraConf = model.YaraConfig{
		Enabled:   true,
		Bin:       fakeExe,
		Rules:     ruleFile,
		TimeoutMS: 25000,
	}
	svc.huntMu.Unlock()

	hits := svc.cachedYaraHits([]model.ObjectFile{{
		ID:       1,
		PacketID: 88,
		Name:     "payload.txt",
		Path:     objectFile,
		Source:   "Extracted",
	}})
	if len(hits) == 0 {
		t.Fatalf("expected warning hit, got none")
	}
	last := hits[len(hits)-1]
	if last.Rule != "YARA 扫描异常" {
		t.Fatalf("expected warning hit, got %+v", last)
	}
	if !strings.Contains(last.Preview, "runner failed") {
		t.Fatalf("expected warning preview to mention runner failure, got %+v", last)
	}
}

func TestThreatHuntYaraScansHTTPReassembledStream(t *testing.T) {
	oldRun := runYaraCommand
	t.Cleanup(func() {
		runYaraCommand = oldRun
	})
	runYaraCommand = func(_ context.Context, _, _, scanPath string) ([]byte, error) {
		target := filepath.Join(scanPath, "http-stream-7.txt")
		content, err := os.ReadFile(target)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(string(content), "/SetupWizard.aspx") {
			return nil, errors.New("stream content was not materialized")
		}
		return []byte("TRAFFIC_HTTP_STREAM_SETUP " + target + "\n"), nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	tempDir := t.TempDir()
	fakeExe := filepath.Join(tempDir, "fake-yara.exe")
	ruleFile := filepath.Join(tempDir, "stream-rule.yar")
	if err := os.WriteFile(fakeExe, []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile(fake exe) error = %v", err)
	}
	if err := os.WriteFile(ruleFile, []byte(`
rule TRAFFIC_HTTP_STREAM_SETUP {
  meta:
    family = "CVE"
    severity = "critical"
    description = "HTTP 重组流命中"
  strings:
    $a = "/SetupWizard.aspx"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(rule) error = %v", err)
	}

	svc.huntMu.Lock()
	svc.yaraConf = model.YaraConfig{
		Enabled:   true,
		Bin:       fakeExe,
		Rules:     ruleFile,
		TimeoutMS: 25000,
	}
	svc.huntMu.Unlock()

	if err := svc.packetStore.Append([]model.Packet{
		{ID: 11, Protocol: "HTTP", StreamID: 7, SourceIP: "10.0.0.1", SourcePort: 50123, DestIP: "10.0.0.2", DestPort: 80, Info: "GET /SetupWizard.aspx HTTP/1.1", Payload: "GET /SetupWizard.aspx HTTP/1.1\r\nHost: demo\r\n\r\n"},
		{ID: 12, Protocol: "HTTP", StreamID: 7, SourceIP: "10.0.0.2", SourcePort: 80, DestIP: "10.0.0.1", DestPort: 50123, Info: "HTTP/1.1 200 OK", Payload: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	hits := svc.ThreatHunt(nil)
	found := false
	for _, hit := range hits {
		if hit.Rule == "HTTP 重组流命中" {
			found = true
			if hit.PacketID != 11 {
				t.Fatalf("expected stream hit to point at first stream packet, got %+v", hit)
			}
			if hit.Category != "CVE" || hit.Level != "critical" {
				t.Fatalf("unexpected stream hit meta: %+v", hit)
			}
		}
	}
	if !found {
		t.Fatalf("expected HTTP stream YARA hit, got %+v", hits)
	}
}
