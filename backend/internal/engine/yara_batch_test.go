package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestParseYaraRuleMetaKeepsCommunityOrigin(t *testing.T) {
	meta := parseYaraRuleMetaFromSource(`
rule COMMUNITY_RULE {
  meta:
    family = "Malware"
    severity = "high"
    description = "社区规则命中"
    rule_pack = "signature-base"
    rule_source = "Neo23x0/signature-base"
    community_rule = "true"
  strings:
    $a = "evil"
  condition:
    $a
}
`)

	got := meta["COMMUNITY_RULE"]
	if got.rulePack != "signature-base" || got.ruleOrigin != "community" || got.ruleSource != "Neo23x0/signature-base" || !got.communityRule {
		t.Fatalf("expected community yara metadata, got %+v", got)
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

	svc := NewService(NopEmitter{})
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

func TestCachedYaraHitsPreflightsYaraBeforeBuildingStreamTargets(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	tempDir := t.TempDir()
	svc.huntMu.Lock()
	svc.yaraConf = model.YaraConfig{
		Enabled:   true,
		Bin:       filepath.Join(tempDir, "missing-yara.exe"),
		Rules:     filepath.Join(tempDir, "missing-rules.yar"),
		TimeoutMS: 25000,
	}
	svc.huntMu.Unlock()

	if err := svc.packetStore.Append([]model.Packet{
		{ID: 41, Protocol: "HTTP", StreamID: 3, SourceIP: "10.0.0.1", SourcePort: 50123, DestIP: "10.0.0.2", DestPort: 80, Info: "GET /payload HTTP/1.1", Payload: "GET /payload HTTP/1.1\r\nHost: demo\r\n\r\n"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	hits := svc.cachedYaraHitsWithContext(context.Background(), nil)
	if len(hits) != 1 {
		t.Fatalf("expected one warning hit without stream target build, got %+v", hits)
	}
	if hits[0].Rule != "YARA 扫描异常" || !strings.Contains(hits[0].Preview, "yara 自定义路径") {
		t.Fatalf("unexpected preflight warning hit: %+v", hits[0])
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

	svc := NewService(NopEmitter{})
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
			if hit.Metadata["rule_origin"] != "custom" || hit.Metadata["community_rule"] != "false" {
				t.Fatalf("expected custom yara metadata, got %+v", hit.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("expected HTTP stream YARA hit, got %+v", hits)
	}
}

func TestBuildYaraScanTargetsRespectsCanceledContext(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	if err := svc.packetStore.Append([]model.Packet{
		{ID: 41, Protocol: "HTTP", StreamID: 3, SourceIP: "10.0.0.1", SourcePort: 50123, DestIP: "10.0.0.2", DestPort: 80, Info: "GET /payload HTTP/1.1", Payload: "GET /payload HTTP/1.1\r\nHost: demo\r\n\r\n"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	targets, cleanup, err := svc.buildYaraScanTargetsWithContext(ctx, nil)
	if cleanup != nil {
		cleanup()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context, got targets=%+v err=%v", targets, err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected no stream targets after cancel, got %+v", targets)
	}
}

func TestYarcCachePath(t *testing.T) {
	tests := []struct {
		name      string
		rulePath  string
		cacheDir  string
		wantName  string
		wantDirFn func() string
	}{
		{
			name:     "default same directory",
			rulePath: filepath.Join(string(os.PathSeparator), "rules", "default.yar"),
			wantName: "default.yarc",
			wantDirFn: func() string {
				return filepath.Join(string(os.PathSeparator), "rules")
			},
		},
		{
			name:     "custom cache dir",
			rulePath: filepath.Join(string(os.PathSeparator), "rules", "default.yar"),
			cacheDir: filepath.Join(string(os.PathSeparator), "tmp", "cache"),
			wantName: "default.yarc",
			wantDirFn: func() string {
				return filepath.Join(string(os.PathSeparator), "tmp", "cache")
			},
		},
		{
			name:     "traffic rules",
			rulePath: filepath.Join(string(os.PathSeparator), "some", "path", "traffic_cve_webshell.yar"),
			wantName: "traffic_cve_webshell.yarc",
			wantDirFn: func() string {
				return filepath.Join(string(os.PathSeparator), "some", "path")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldDir := yarcCacheDir
			yarcCacheDir = tt.cacheDir
			t.Cleanup(func() { yarcCacheDir = oldDir })

			got := yarcCachePath(tt.rulePath)
			gotBase := filepath.Base(got)
			gotDir := filepath.Dir(got)

			if gotBase != tt.wantName {
				t.Errorf("yarcCachePath() base = %q, want %q", gotBase, tt.wantName)
			}
			wantDir := tt.wantDirFn()
			if gotDir != wantDir {
				t.Errorf("yarcCachePath() dir = %q, want %q", gotDir, wantDir)
			}
		})
	}
}

func TestCompileYaraRulesToCacheReturnsYarcUnchanged(t *testing.T) {
	// If the rule path is already a .yarc file, return it unchanged.
	rulePath := "/some/rules/compiled.yarc"
	got := compileYaraRulesToCache("yara", rulePath)
	if got != rulePath {
		t.Errorf("compileYaraRulesToCache(.yarc) = %q, want %q", got, rulePath)
	}
}

func TestCompileYaraRulesToCacheReturnsOriginalWhenNoYarac(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	// When yarac is not available, the original .yar path should be returned.
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.yar")
	if err := os.WriteFile(rulePath, []byte(`
rule TEST {
  strings:
    $a = "test"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Use a non-existent yara exe directory so yarac won't be found
	got := compileYaraRulesToCache(filepath.Join(dir, "nonexistent-yara.exe"), rulePath)
	if got != rulePath {
		t.Errorf("compileYaraRulesToCache(no yarac) = %q, want %q", got, rulePath)
	}
}

func TestCompileYaraRulesToCacheUsesCacheWhenNewer(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.yar")
	cachePath := filepath.Join(dir, "test.yarc")

	if err := os.WriteFile(rulePath, []byte(`
rule TEST {
  strings:
    $a = "test"
  condition:
    $a
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(yar) error = %v", err)
	}

	// Create a fake .yarc cache file (newer than source)
	if err := os.WriteFile(cachePath, []byte("cached"), 0o644); err != nil {
		t.Fatalf("WriteFile(yarc) error = %v", err)
	}

	// Touch the source file to be older
	oldTime := time.Now().Add(-1 * time.Hour)
	os.Chtimes(rulePath, oldTime, oldTime)

	got := compileYaraRulesToCache("yara", rulePath)
	if got != cachePath {
		t.Errorf("compileYaraRulesToCache(cached) = %q, want %q", got, cachePath)
	}
}

func TestYarcCacheDirSetting(t *testing.T) {
	oldDir := yarcCacheDir
	t.Cleanup(func() { yarcCacheDir = oldDir })

	customDir := filepath.Join(string(os.PathSeparator), "custom", "cache")
	yarcCacheDir = customDir
	rulePath := filepath.Join(string(os.PathSeparator), "rules", "test.yar")
	got := yarcCachePath(rulePath)
	want := filepath.Join(customDir, "test.yarc")
	if got != want {
		t.Errorf("yarcCachePath() with custom dir = %q, want %q", got, want)
	}
}
