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

func TestBatchScanObjectsWithYaraConfigCoversWrappersAndFallbackMeta(t *testing.T) {
	oldRun := runYaraCommand
	t.Cleanup(func() { runYaraCommand = oldRun })

	dir := t.TempDir()
	fakeExe := filepath.Join(dir, "fake-yara.exe")
	ruleFile := filepath.Join(dir, "rules.yarc")
	objectPath := filepath.Join(dir, "payload.bin")
	for _, item := range []string{fakeExe, ruleFile, objectPath} {
		if err := os.WriteFile(item, []byte("ok"), 0o755); err != nil {
			t.Fatalf("write %s: %v", item, err)
		}
	}

	runYaraCommand = func(ctx context.Context, yaraExe, rulePath, scanPath string) ([]byte, error) {
		if ctx == nil || ctx.Err() != nil {
			t.Fatalf("unexpected scan context err: %v", ctx.Err())
		}
		if yaraExe != fakeExe || rulePath != ruleFile || scanPath != dir {
			t.Fatalf("unexpected run args exe=%q rule=%q scan=%q", yaraExe, rulePath, scanPath)
		}
		return []byte("WEBSHELL_CUSTOM " + filepath.Base(objectPath) + "\n"), nil
	}

	hits, err := BatchScanObjectsWithYaraConfig([]model.ObjectFile{
		{ID: 1, PacketID: 99, Name: "payload.bin", Path: objectPath, Source: "tcp-stream"},
		{ID: 2, PacketID: 100, Name: "empty-path"},
	}, model.YaraConfig{Enabled: true, Bin: fakeExe, Rules: ruleFile, TimeoutMS: 250})
	if err != nil {
		t.Fatalf("BatchScanObjectsWithYaraConfig() error = %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected one hit, got %+v", hits)
	}
	hit := hits[0]
	if hit.PacketID != 99 || hit.Category != "WebShell" || hit.Rule != "WEBSHELL_CUSTOM" || hit.Level != "medium" {
		t.Fatalf("unexpected fallback-meta hit: %+v", hit)
	}
	if hit.Metadata["rule_pack"] != "custom" || hit.Metadata["community_rule"] != "false" {
		t.Fatalf("unexpected fallback metadata: %+v", hit.Metadata)
	}
	if !strings.Contains(hit.Preview, readableYaraTargetSource("tcp-stream")) {
		t.Fatalf("preview should include readable source, got %q", hit.Preview)
	}
}

func TestBatchScanTargetsWithYaraConfigBoundaryBranches(t *testing.T) {
	if hits, err := BatchScanTargetsWithYaraConfig(nil, model.YaraConfig{Enabled: true}); err != nil || hits != nil {
		t.Fatalf("empty targets = hits=%+v err=%v, want nil nil", hits, err)
	}
	if hits, err := BatchScanTargetsWithYaraConfig([]yaraScanTarget{{path: "x"}}, model.YaraConfig{}); err != nil || hits != nil {
		t.Fatalf("disabled yara = hits=%+v err=%v, want nil nil", hits, err)
	}

	dir := t.TempDir()
	targetPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(targetPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	fakeExe := filepath.Join(dir, "fake-yara.exe")
	ruleFile := filepath.Join(dir, "rule.yarc")
	for _, item := range []string{fakeExe, ruleFile} {
		if err := os.WriteFile(item, []byte("ok"), 0o755); err != nil {
			t.Fatalf("write %s: %v", item, err)
		}
	}

	oldRun := runYaraCommand
	t.Cleanup(func() { runYaraCommand = oldRun })
	runnerErr := errors.New("runner exploded")
	runYaraCommand = func(context.Context, string, string, string) ([]byte, error) {
		return []byte("boom from yara"), runnerErr
	}

	hits, err := BatchScanTargetsWithYaraConfigContext(nil, []yaraScanTarget{{name: "payload.bin", path: targetPath}}, model.YaraConfig{Enabled: true, Bin: fakeExe, Rules: ruleFile})
	if err == nil || !errors.Is(err, runnerErr) || !strings.Contains(err.Error(), "boom from yara") || len(hits) != 0 {
		t.Fatalf("runner error = hits=%+v err=%v", hits, err)
	}
}

func TestYaraBatchLookupAndMetadataHelpers(t *testing.T) {
	dir := t.TempDir()
	alpha := filepath.Join(dir, "alpha.bin")
	beta := filepath.Join(dir, "nested", "beta.bin")
	if err := os.MkdirAll(filepath.Dir(beta), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, item := range []string{alpha, beta} {
		if err := os.WriteFile(item, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", item, err)
		}
	}

	byPath, byBase := buildYaraTargetLookup([]yaraScanTarget{
		{name: "alpha", path: alpha, source: "http-stream"},
		{name: "beta", path: beta, source: "udp-stream"},
		{name: "dupe-a", path: filepath.Join(dir, "dupe.bin")},
		{name: "dupe-b", path: filepath.Join(dir, "other", "dupe.bin")},
	})
	if target, ok := resolveMatchedYaraTarget(dir, filepath.Base(alpha), byPath, byBase); !ok || target.name != "alpha" {
		t.Fatalf("resolve by basename = %+v ok=%v", target, ok)
	}
	relBeta := filepath.Join("nested", "beta.bin")
	if target, ok := resolveMatchedYaraTarget(dir, relBeta, byPath, byBase); !ok || target.name != "beta" {
		t.Fatalf("resolve by relative path = %+v ok=%v", target, ok)
	}
	if _, ok := resolveMatchedYaraTarget("", "dupe.bin", byPath, byBase); ok {
		t.Fatal("duplicate basename should not resolve through basename lookup")
	}

	sourceCases := map[string]string{
		"http-stream": "HTTP",
		"tcp-stream":  "TCP",
		"udp-stream":  "UDP",
		"extracted":   "",
		"":            "",
		"custom-src":  "custom-src",
	}
	for source, contains := range sourceCases {
		got := readableYaraTargetSource(source)
		if contains != "" && !strings.Contains(got, contains) {
			t.Fatalf("readableYaraTargetSource(%q) = %q, want contains %q", source, got, contains)
		}
		if source == "" && strings.TrimSpace(got) == "" {
			t.Fatal("empty source should still have a readable fallback")
		}
	}

	meta := fallbackYaraRuleMeta("TRAFFIC_CVE_2026_DEMO")
	if meta.category != "CVE" || meta.ruleName == "" || meta.ruleOrigin != "custom" {
		t.Fatalf("unexpected CVE fallback meta: %+v", meta)
	}
	if ruleID, matched, ok := parseYaraOutputLine("RULE_ID\t/path/to/file"); !ok || ruleID != "RULE_ID" || matched != "/path/to/file" {
		t.Fatalf("parseYaraOutputLine tab = %q %q ok=%v", ruleID, matched, ok)
	}
	for _, line := range []string{"", "NO_SPACE", "   RULE_ONLY   "} {
		if _, _, ok := parseYaraOutputLine(line); ok {
			t.Fatalf("expected parseYaraOutputLine(%q) to fail", line)
		}
	}

	if got := summarizeYaraOutput([]byte(strings.Repeat("x", 600))); !strings.HasSuffix(got, "...") || len(got) > 520 {
		t.Fatalf("summarizeYaraOutput long = len %d value %q", len(got), got)
	}
	if got := resolveYaraTimeout(42); got.String() != "42ms" {
		t.Fatalf("resolveYaraTimeout(42) = %s", got)
	}
}
