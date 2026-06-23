package engine

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func newLocalRuleTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local test server: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestNewRuleManager(t *testing.T) {
	dir := t.TempDir()
	rm := NewRuleManager(dir)
	if rm == nil {
		t.Fatal("expected non-nil RuleManager")
	}
	if rm.dataDir != dir {
		t.Errorf("dataDir = %q, want %q", rm.dataDir, dir)
	}
}

func TestNewRuleManagerDefaultDir(t *testing.T) {
	rm := NewRuleManager("")
	if rm == nil {
		t.Fatal("expected non-nil RuleManager")
	}
	if rm.dataDir == "" {
		t.Error("expected non-empty default dataDir")
	}
}

func TestLoadBuiltinPacks(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	rm.LoadBuiltinPacks()

	status := rm.Status()
	if len(status.Packs) != 3 {
		t.Fatalf("expected 3 builtin packs, got %d", len(status.Packs))
	}

	ids := map[string]bool{}
	for _, p := range status.Packs {
		ids[p.ID] = true
	}
	for _, want := range []string{"builtin-default", "builtin-cve-webshell", "builtin-community"} {
		if !ids[want] {
			t.Errorf("missing builtin pack: %s", want)
		}
	}
}

func TestSetPackEnabled(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	rm.LoadBuiltinPacks()

	if err := rm.SetPackEnabled("builtin-default", false); err != nil {
		t.Fatalf("SetPackEnabled(false) error = %v", err)
	}

	pack, ok := rm.GetPack("builtin-default")
	if !ok {
		t.Fatal("expected pack to exist")
	}
	if pack.Enabled {
		t.Error("expected pack to be disabled")
	}

	if err := rm.SetPackEnabled("builtin-default", true); err != nil {
		t.Fatalf("SetPackEnabled(true) error = %v", err)
	}

	pack, ok = rm.GetPack("builtin-default")
	if !ok {
		t.Fatal("expected pack to exist")
	}
	if !pack.Enabled {
		t.Error("expected pack to be enabled")
	}
}

func TestSetPackEnabledNotFound(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	err := rm.SetPackEnabled("nonexistent", true)
	if err == nil {
		t.Error("expected error for nonexistent pack")
	}
}

func TestRegisterAndGetPack(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	pack := &model.RulePack{
		ID:        "test-pack",
		Name:      "Test Pack",
		Source:    "test",
		Enabled:   true,
		RuleCount: 3,
	}
	if err := rm.RegisterPack(pack); err != nil {
		t.Fatalf("RegisterPack() error = %v", err)
	}

	got, ok := rm.GetPack("test-pack")
	if !ok {
		t.Fatal("expected pack to exist")
	}
	if got.Name != "Test Pack" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Pack")
	}
	if got.RuleCount != 3 {
		t.Errorf("RuleCount = %d, want 3", got.RuleCount)
	}
}

func TestRegisterPackInvalid(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	if err := rm.RegisterPack(nil); err == nil {
		t.Error("expected error for nil pack")
	}
	if err := rm.RegisterPack(&model.RulePack{}); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestRemovePack(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	pack := &model.RulePack{
		ID:      "custom-pack",
		Name:    "Custom",
		Source:  "test",
		Enabled: true,
	}
	rm.RegisterPack(pack)

	if err := rm.RemovePack("custom-pack"); err != nil {
		t.Fatalf("RemovePack() error = %v", err)
	}

	if _, ok := rm.GetPack("custom-pack"); ok {
		t.Error("expected pack to be removed")
	}
}

func TestRemoveBuiltinPackForbidden(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	rm.LoadBuiltinPacks()

	err := rm.RemovePack("builtin-default")
	if err == nil {
		t.Error("expected error removing builtin pack")
	}
}

func TestRemovePackNotFound(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	err := rm.RemovePack("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent pack")
	}
}

func TestStatusCounts(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	rm.RegisterPack(&model.RulePack{
		ID: "p1", Source: "test", Enabled: true, RuleCount: 10,
	})
	rm.RegisterPack(&model.RulePack{
		ID: "p2", Source: "test", Enabled: false, RuleCount: 5,
	})

	status := rm.Status()
	if status.TotalRules != 15 {
		t.Errorf("TotalRules = %d, want 15", status.TotalRules)
	}
	if status.EnabledRules != 10 {
		t.Errorf("EnabledRules = %d, want 10", status.EnabledRules)
	}
	if status.DisabledRules != 5 {
		t.Errorf("DisabledRules = %d, want 5", status.DisabledRules)
	}
}

func TestUpdateConfig(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	cfg := model.RuleUpdateConfig{
		RemoteURL:      "https://example.com/rules",
		AutoUpdate:     true,
		UpdateInterval: 24,
	}
	rm.SetUpdateConfig(cfg)

	got := rm.GetUpdateConfig()
	if got.RemoteURL != cfg.RemoteURL {
		t.Errorf("RemoteURL = %q, want %q", got.RemoteURL, cfg.RemoteURL)
	}
	if got.AutoUpdate != cfg.AutoUpdate {
		t.Errorf("AutoUpdate = %v, want %v", got.AutoUpdate, cfg.AutoUpdate)
	}
}

func TestDetectConflictsNoDuplicates(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	rm.RegisterPack(&model.RulePack{
		ID:      "pack1",
		Source:  "test",
		Enabled: true,
		Rules: []model.RuleEntry{
			{ID: "RULE_A", Name: "Rule A", Enabled: true},
			{ID: "RULE_B", Name: "Rule B", Enabled: true},
		},
	})

	conflicts := rm.DetectConflicts()
	if len(conflicts) != 0 {
		t.Errorf("expected no conflicts, got %d", len(conflicts))
	}
}

func TestDetectConflictsDuplicateIDs(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	rm.RegisterPack(&model.RulePack{
		ID:      "pack1",
		Source:  "test",
		Enabled: true,
		Rules: []model.RuleEntry{
			{ID: "RULE_A", Name: "Rule A from Pack 1", Enabled: true, Severity: "high"},
		},
	})
	rm.RegisterPack(&model.RulePack{
		ID:      "pack2",
		Source:  "test",
		Enabled: true,
		Rules: []model.RuleEntry{
			{ID: "RULE_A", Name: "Rule A from Pack 2", Enabled: true, Severity: "low"},
		},
	})

	conflicts := rm.DetectConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Conflict != "duplicate rule ID" {
		t.Errorf("conflict = %q, want %q", conflicts[0].Conflict, "duplicate rule ID")
	}
	if conflicts[0].Severity != "error" {
		t.Errorf("severity = %q, want %q (mismatched severity)", conflicts[0].Severity, "error")
	}
}

func TestDetectConflictsDisabledPackIgnored(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	rm.RegisterPack(&model.RulePack{
		ID:      "pack1",
		Source:  "test",
		Enabled: true,
		Rules: []model.RuleEntry{
			{ID: "RULE_A", Name: "Rule A", Enabled: true},
		},
	})
	rm.RegisterPack(&model.RulePack{
		ID:      "pack2",
		Source:  "test",
		Enabled: false, // disabled
		Rules: []model.RuleEntry{
			{ID: "RULE_A", Name: "Rule A", Enabled: true},
		},
	})

	conflicts := rm.DetectConflicts()
	if len(conflicts) != 0 {
		t.Errorf("expected no conflicts (disabled pack), got %d", len(conflicts))
	}
}

func TestValidateRulesValidContent(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	content := `
rule VALID_RULE {
  meta:
    description = "A valid rule"
    severity = "high"
  strings:
    $a = "test"
  condition:
    $a
}
`
	errors := rm.ValidateRules(content)
	if len(errors) != 0 {
		t.Errorf("expected no errors for valid content, got %d", len(errors))
	}
}

func TestValidateRulesMissingCondition(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	content := `
rule BAD_RULE {
  meta:
    description = "Missing condition"
  strings:
    $a = "test"
}
`
	errors := rm.ValidateRules(content)
	if len(errors) == 0 {
		t.Error("expected validation error for missing condition")
	}
}

func TestValidateRulesUnmatchedBrace(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	content := `
rule BRACE_RULE {
  strings:
    $a = "test"
  condition:
    $a
  }
  }
`
	errors := rm.ValidateRules(content)
	if len(errors) == 0 {
		t.Error("expected validation error for unmatched brace")
	}
}

func TestCountYARARules(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name:    "empty",
			content: "",
			want:    0,
		},
		{
			name: "single rule",
			content: `rule TEST {
  condition: true
}`,
			want: 1,
		},
		{
			name: "multiple rules",
			content: `rule A { condition: true }
rule B { condition: true }
rule C { condition: true }`,
			want: 3,
		},
		{
			name:    "comment only",
			content: "// no rules here",
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countYARARules(tt.content)
			if got != tt.want {
				t.Errorf("countYARARules() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExtractRuleEntries(t *testing.T) {
	content := `
rule FIRST {
  meta:
    family = "CVE"
    severity = "high"
    description = "CVE Rule"
  strings:
    $a = "/vuln"
  condition:
    $a
}

rule SECOND {
  meta:
    project = "TestProject"
    severity = "critical"
    description = "Test Rule"
  strings:
    $b = "/test"
  condition:
    $b
}
`
	entries := extractRuleEntries(content)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].ID != "FIRST" {
		t.Errorf("entries[0].ID = %q, want %q", entries[0].ID, "FIRST")
	}
	if entries[0].Category != "CVE" {
		t.Errorf("entries[0].Category = %q, want %q", entries[0].Category, "CVE")
	}
	if entries[0].Severity != "high" {
		t.Errorf("entries[0].Severity = %q, want %q", entries[0].Severity, "high")
	}
	if entries[1].Category != "TestProject" {
		t.Errorf("entries[1].Category = %q, want %q", entries[1].Category, "TestProject")
	}
}

func TestIsNewerVersion(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		a, b model.RuleVersion
		want bool
	}{
		{"same", model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: now}, model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: now}, false},
		{"major newer", model.RuleVersion{Major: 2, Minor: 0, Patch: 0, ReleasedAt: now}, model.RuleVersion{Major: 1, Minor: 9, Patch: 9, ReleasedAt: now}, true},
		{"major older", model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: now}, model.RuleVersion{Major: 2, Minor: 0, Patch: 0, ReleasedAt: now}, false},
		{"minor newer", model.RuleVersion{Major: 1, Minor: 1, Patch: 0, ReleasedAt: now}, model.RuleVersion{Major: 1, Minor: 0, Patch: 9, ReleasedAt: now}, true},
		{"patch newer", model.RuleVersion{Major: 1, Minor: 0, Patch: 1, ReleasedAt: now}, model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: now}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNewerVersion(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("isNewerVersion(%+v, %+v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDownloadPackFromMockServer(t *testing.T) {
	ruleContent := `
rule MOCK_RULE {
  meta:
    description = "Mock rule"
    severity = "medium"
  strings:
    $a = "mock"
  condition:
    $a
}
`
	srv := newLocalRuleTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(ruleContent))
	}))

	rm := NewRuleManager(t.TempDir())
	checksum := sha256Hex([]byte(ruleContent))
	pack, err := rm.DownloadPack("test-download", srv.URL, checksum)
	if err != nil {
		t.Fatalf("DownloadPack() error = %v", err)
	}

	if pack.ID != "test-download" {
		t.Errorf("ID = %q, want %q", pack.ID, "test-download")
	}
	if pack.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1", pack.RuleCount)
	}
	if pack.Checksum == "" {
		t.Error("expected non-empty checksum")
	}
	if !pack.Enabled {
		t.Error("expected pack to be enabled")
	}

	// Verify cache file exists
	cachePath := filepath.Join(rm.getCacheDir(), "test-download.yar")
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("expected cache file to exist: %v", err)
	}
}

func TestDownloadPackEmptyURL(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test", "", "")
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestDownloadPackRequiresChecksum(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test", "http://127.0.0.1:1/rules.yar", "")
	if err == nil || !strings.Contains(err.Error(), "checksum is required") {
		t.Fatalf("expected checksum required error, got %v", err)
	}
}

func TestDownloadPackRejectsDisallowedHost(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test", "https://evil.example.com/rules.yar", strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestRuleDownloadHostNormalizationHandlesPortsAndIPv6(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		allowed []string
		want    bool
	}{
		{name: "host with port", host: "example.com:443", allowed: []string{"example.com"}, want: true},
		{name: "allowed host with port", host: "example.com", allowed: []string{"example.com:443"}, want: true},
		{name: "bracketed ipv6 with port", host: "[::1]:17891", allowed: []string{"::1"}, want: true},
		{name: "bracketed ipv6 allowed", host: "::1", allowed: []string{"[::1]:17891"}, want: true},
		{name: "different ipv6", host: "[::2]:17891", allowed: []string{"::1"}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowedRuleHost(tc.host, tc.allowed); got != tc.want {
				t.Fatalf("isAllowedRuleHost(%q, %v) = %v, want %v", tc.host, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestDownloadPackServerDown(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test", "http://127.0.0.1:1/nonexistent", "")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestReadLimitedRulePackRejectsOversize(t *testing.T) {
	body := strings.NewReader(strings.Repeat("a", 11))
	got, err := readLimitedRulePack(body, 10)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error, got body=%q err=%v", string(got), err)
	}
}

func TestDownloadPackRejectsPathTraversal(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("../../../tmp/evil", "http://127.0.0.1:1/rules.yar", "")
	if err == nil || !strings.Contains(err.Error(), "invalid pack_id") {
		t.Fatalf("expected invalid pack_id error, got %v", err)
	}
}

func TestDownloadPackRejectsNonHTTPScheme(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test", "file:///etc/passwd", "")
	if err == nil || !strings.Contains(err.Error(), "invalid download URL scheme") {
		t.Fatalf("expected invalid URL scheme error, got %v", err)
	}
}

func TestDownloadPackRejectsChecksumMismatch(t *testing.T) {
	ruleContent := `
rule MOCK_RULE {
  meta:
    description = "Mock rule"
    severity = "medium"
  strings:
    $a = "mock"
  condition:
    $a
}
`
	srv := newLocalRuleTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(ruleContent))
	}))

	rm := NewRuleManager(t.TempDir())
	_, err := rm.DownloadPack("test-checksum", srv.URL, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got %v", err)
	}
}

func TestCheckForUpdatesWithMockServer(t *testing.T) {
	ruleContent := `
rule UPDATED_RULE {
  meta:
    description = "Updated rule"
    severity = "high"
  strings:
    $a = "updated"
  condition:
    $a
}
`
	checksum := sha256Hex([]byte(ruleContent))
	var serverURL string
	srv := newLocalRuleTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			manifest := []remoteRulePack{
				{
					ID:          "remote-pack-1",
					Name:        "Remote Pack",
					Description: "From server",
					URL:         serverURL + "/rules/remote-pack-1.yar",
					RuleCount:   1,
					Checksum:    checksum,
				},
			}
			manifest[0].Version.Major = 2
			manifest[0].Version.Minor = 0
			manifest[0].Version.Patch = 0
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(manifest)
		case "/rules/remote-pack-1.yar":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(ruleContent))
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = srv.URL

	rm := NewRuleManager(t.TempDir())
	rm.SetUpdateConfig(model.RuleUpdateConfig{
		RemoteURL: srv.URL,
	})

	results, err := rm.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Updated {
		t.Error("expected pack to be updated")
	}
	if results[0].Downloaded != 1 {
		t.Errorf("Downloaded = %d, want 1", results[0].Downloaded)
	}
}

func TestCheckForUpdatesNoURL(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	_, err := rm.CheckForUpdates()
	if err == nil {
		t.Error("expected error when remote URL not configured")
	}
}

func TestCheckForUpdatesNoNewerVersion(t *testing.T) {
	manifest := []remoteRulePack{
		{
			ID:   "builtin-default",
			Name: "Default",
		},
	}
	manifest[0].Version.Major = 1
	manifest[0].Version.Minor = 0
	manifest[0].Version.Patch = 0

	srv := newLocalRuleTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			json.NewEncoder(w).Encode(manifest)
			return
		}
		http.NotFound(w, r)
	}))

	rm := NewRuleManager(t.TempDir())
	rm.LoadBuiltinPacks()
	rm.SetUpdateConfig(model.RuleUpdateConfig{RemoteURL: srv.URL})

	results, err := rm.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Updated {
		t.Error("expected no update for same version")
	}
}

func TestRefreshPackFromDisk(t *testing.T) {
	rm := NewRuleManager(t.TempDir())

	// Write a rule file to cache
	cacheDir := rm.getCacheDir()
	os.MkdirAll(cacheDir, 0o755)
	rulePath := filepath.Join(cacheDir, "refresh-test.yar")
	os.WriteFile(rulePath, []byte(`
rule DISK_RULE_1 {
  condition: true
}
rule DISK_RULE_2 {
  condition: true
}
`), 0o644)

	rm.RegisterPack(&model.RulePack{
		ID:      "refresh-test",
		Source:  "test",
		Enabled: true,
		Version: model.RuleVersion{Major: 1, Minor: 0, Patch: 0},
	})

	if err := rm.RefreshPackFromDisk("refresh-test"); err != nil {
		t.Fatalf("RefreshPackFromDisk() error = %v", err)
	}

	pack, ok := rm.GetPack("refresh-test")
	if !ok {
		t.Fatal("expected pack to exist")
	}
	if pack.RuleCount != 2 {
		t.Errorf("RuleCount = %d, want 2", pack.RuleCount)
	}
	if pack.Version.Patch != 1 {
		t.Errorf("Patch = %d, want 1 (bumped)", pack.Version.Patch)
	}
	if pack.Checksum == "" {
		t.Error("expected non-empty checksum")
	}
}

func TestRefreshPackFromDiskNotFound(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	err := rm.RefreshPackFromDisk("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent pack")
	}
}

func TestSHA256Hex(t *testing.T) {
	got := sha256Hex([]byte("hello"))
	// SHA-256 of "hello" is well-known
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256Hex() = %q, want %q", got, want)
	}
}

func TestRuleVersionString(t *testing.T) {
	tests := []struct {
		v    model.RuleVersion
		want string
	}{
		{model.RuleVersion{Major: 1, Minor: 2, Patch: 3}, "v1.2.3"},
		{model.RuleVersion{Major: 0, Minor: 0, Patch: 1}, "v0.0.1"},
		{model.RuleVersion{Major: 2, Minor: 0, Patch: 0, Tag: "beta"}, "v2.0.0-beta"},
	}

	for _, tt := range tests {
		got := tt.v.String()
		if got != tt.want {
			t.Errorf("RuleVersion{%d,%d,%d}.String() = %q, want %q",
				tt.v.Major, tt.v.Minor, tt.v.Patch, got, tt.want)
		}
	}
}

func TestStatusSortedByID(t *testing.T) {
	rm := NewRuleManager(t.TempDir())
	rm.RegisterPack(&model.RulePack{ID: "z-pack", Source: "test"})
	rm.RegisterPack(&model.RulePack{ID: "a-pack", Source: "test"})
	rm.RegisterPack(&model.RulePack{ID: "m-pack", Source: "test"})

	status := rm.Status()
	if len(status.Packs) != 3 {
		t.Fatalf("expected 3 packs, got %d", len(status.Packs))
	}
	if status.Packs[0].ID != "a-pack" {
		t.Errorf("Packs[0].ID = %q, want %q", status.Packs[0].ID, "a-pack")
	}
	if status.Packs[2].ID != "z-pack" {
		t.Errorf("Packs[2].ID = %q, want %q", status.Packs[2].ID, "z-pack")
	}
}
