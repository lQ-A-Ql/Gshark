package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// RuleManager manages YARA rule packs: versioning, download, cache,
// enable/disable, and conflict detection.
type RuleManager struct {
	mu           sync.RWMutex
	packs        map[string]*model.RulePack
	config       model.RuleUpdateConfig
	dataDir      string
	client       *http.Client
	allowedHosts []string
}

// DefaultAllowedRuleHosts lists trusted hosts for remote rule downloads.
var DefaultAllowedRuleHosts = []string{
	"127.0.0.1",
	"localhost",
	"::1",
	"github.com",
	"raw.githubusercontent.com",
}

// NewRuleManager creates a RuleManager that stores rule data under dataDir.
func NewRuleManager(dataDir string) *RuleManager {
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "meow-traffic", "rules")
	}
	return &RuleManager{
		packs:        make(map[string]*model.RulePack),
		dataDir:      dataDir,
		allowedHosts: append([]string(nil), DefaultAllowedRuleHosts...),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetAllowedHosts overrides the list of hosts allowed for remote rule downloads.
// Use this in tests or when a deployment needs additional trusted sources.
func (rm *RuleManager) SetAllowedHosts(hosts []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.allowedHosts = append([]string(nil), hosts...)
}

// LoadBuiltinPacks registers the embedded rule packs shipped with the backend.
func (rm *RuleManager) LoadBuiltinPacks() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	defaultPack := &model.RulePack{
		ID:          "builtin-default",
		Name:        "内置规则集",
		Description: "meow~traffic 默认 YARA 规则",
		Source:      "embedded",
		Version:     model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: time.Now()},
		Enabled:     true,
		RuleCount:   5,
		UpdatedAt:   time.Now(),
	}
	rm.packs[defaultPack.ID] = defaultPack

	cvePack := &model.RulePack{
		ID:          "builtin-cve-webshell",
		Name:        "CVE 与 WebShell 规则",
		Description: "CVE 漏洞利用与 WebShell 特征检测",
		Source:      "embedded",
		Version:     model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: time.Now()},
		Enabled:     true,
		RuleCount:   0,
		UpdatedAt:   time.Now(),
	}
	rm.packs[cvePack.ID] = cvePack

	communityPack := &model.RulePack{
		ID:          "builtin-community",
		Name:        "Neo23x0 社区规则",
		Description: "Neo23x0/signature-base 社区 YARA 规则",
		Source:      "embedded",
		Version:     model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: time.Now()},
		Enabled:     false,
		RuleCount:   0,
		UpdatedAt:   time.Now(),
	}
	rm.packs[communityPack.ID] = communityPack
}

// Status returns the current rule status snapshot.
func (rm *RuleManager) Status() model.RuleStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	packs := make([]model.RulePack, 0, len(rm.packs))
	totalRules := 0
	enabledRules := 0
	disabledRules := 0
	var lastUpdate time.Time

	for _, p := range rm.packs {
		packs = append(packs, *p)
		totalRules += p.RuleCount
		if p.Enabled {
			enabledRules += p.RuleCount
		} else {
			disabledRules += p.RuleCount
		}
		if p.UpdatedAt.After(lastUpdate) {
			lastUpdate = p.UpdatedAt
		}
	}

	sort.Slice(packs, func(i, j int) bool {
		return packs[i].ID < packs[j].ID
	})

	conflicts := rm.detectConflictsLocked()

	return model.RuleStatus{
		Packs:         packs,
		TotalRules:    totalRules,
		EnabledRules:  enabledRules,
		DisabledRules: disabledRules,
		LastUpdate:    lastUpdate,
		UpdateConfig:  rm.config,
		Conflicts:     conflicts,
	}
}

// SetUpdateConfig updates the remote rule fetch configuration.
func (rm *RuleManager) SetUpdateConfig(cfg model.RuleUpdateConfig) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.config = cfg
}

// GetUpdateConfig returns the current update configuration.
func (rm *RuleManager) GetUpdateConfig() model.RuleUpdateConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.config
}

// SetPackEnabled enables or disables a rule pack by ID.
func (rm *RuleManager) SetPackEnabled(packID string, enabled bool) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	pack, ok := rm.packs[packID]
	if !ok {
		return fmt.Errorf("rule pack not found: %s", packID)
	}
	pack.Enabled = enabled
	pack.UpdatedAt = time.Now()
	return nil
}

// RegisterPack adds or updates a rule pack.
func (rm *RuleManager) RegisterPack(pack *model.RulePack) error {
	if pack == nil || pack.ID == "" {
		return fmt.Errorf("invalid rule pack: missing ID")
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if pack.UpdatedAt.IsZero() {
		pack.UpdatedAt = time.Now()
	}
	rm.packs[pack.ID] = pack
	return nil
}

// GetPack returns a rule pack by ID.
func (rm *RuleManager) GetPack(packID string) (*model.RulePack, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	p, ok := rm.packs[packID]
	if !ok {
		return nil, false
	}
	copy := *p
	return &copy, true
}

// RemovePack removes a rule pack by ID. Built-in packs cannot be removed.
func (rm *RuleManager) RemovePack(packID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if strings.HasPrefix(packID, "builtin-") {
		return fmt.Errorf("cannot remove built-in pack: %s", packID)
	}
	if _, ok := rm.packs[packID]; !ok {
		return fmt.Errorf("rule pack not found: %s", packID)
	}
	delete(rm.packs, packID)
	return nil
}

// CheckForUpdates fetches remote manifest and registers new packs.
// Returns update results for each pack checked.
func (rm *RuleManager) CheckForUpdates() ([]model.RuleUpdateResult, error) {
	rm.mu.RLock()
	remoteURL := strings.TrimSpace(rm.config.RemoteURL)
	rm.mu.RUnlock()

	if remoteURL == "" {
		return nil, fmt.Errorf("remote URL not configured")
	}

	manifest, err := rm.fetchManifest(remoteURL)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	var results []model.RuleUpdateResult
	for _, remotePack := range manifest {
		result := rm.processRemotePack(remotePack)
		results = append(results, result)
	}
	return results, nil
}

// DownloadPack downloads a rule pack from the given URL and caches it locally.
// expectedChecksum is required (SHA-256 hex) and must match the downloaded content.
func (rm *RuleManager) DownloadPack(packID, downloadURL string, expectedChecksum string) (*model.RulePack, error) {
	if err := validateRulePackID(packID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(downloadURL) == "" {
		return nil, fmt.Errorf("download URL is empty")
	}

	rm.mu.RLock()
	allowedHosts := rm.allowedHosts
	rm.mu.RUnlock()
	parsed, err := validateRuleDownloadURL(downloadURL, allowedHosts)
	if err != nil {
		return nil, err
	}
	if err := validateRuleChecksum(expectedChecksum); err != nil {
		return nil, err
	}

	resp, err := rm.client.Get(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", downloadURL, resp.StatusCode)
	}

	body, err := readLimitedRulePack(resp.Body, 10<<20)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	checksum := sha256Hex(body)
	if !strings.EqualFold(expectedChecksum, checksum) {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, checksum)
	}

	cacheDir := rm.getCacheDir()
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	cachePath, err := safeCachePath(cacheDir, packID)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cachePath, body, 0o644); err != nil {
		return nil, fmt.Errorf("write cache: %w", err)
	}

	ruleCount := countYARARules(string(body))

	pack := &model.RulePack{
		ID:        packID,
		Name:      packID,
		Source:    downloadURL,
		Version:   model.RuleVersion{Major: 1, Minor: 0, Patch: 0, ReleasedAt: time.Now()},
		Enabled:   true,
		RuleCount: ruleCount,
		Checksum:  checksum,
		UpdatedAt: time.Now(),
		Rules:     extractRuleEntries(string(body)),
	}

	if err := rm.RegisterPack(pack); err != nil {
		return nil, err
	}

	return pack, nil
}

// RefreshPackFromDisk re-reads a cached rule file and updates the pack metadata.
func (rm *RuleManager) RefreshPackFromDisk(packID string) error {
	cacheDir := rm.getCacheDir()
	cachePath := filepath.Join(cacheDir, packID+".yar")

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return fmt.Errorf("read cached rules: %w", err)
	}

	content := string(data)
	checksum := sha256Hex(data)
	ruleCount := countYARARules(content)

	rm.mu.Lock()
	defer rm.mu.Unlock()

	pack, ok := rm.packs[packID]
	if !ok {
		return fmt.Errorf("rule pack not found: %s", packID)
	}

	pack.Checksum = checksum
	pack.RuleCount = ruleCount
	pack.UpdatedAt = time.Now()
	pack.Rules = extractRuleEntries(content)

	// Bump patch version
	pack.Version.Patch++

	return nil
}

// detectConflictsLocked finds duplicate rule IDs across enabled packs.
// Must be called with rm.mu held (at least RLock).
func (rm *RuleManager) detectConflictsLocked() []model.RuleConflict {
	type ruleLocation struct {
		packID   string
		ruleName string
		severity string
	}

	seen := map[string]ruleLocation{}
	var conflicts []model.RuleConflict

	for _, pack := range rm.packs {
		if !pack.Enabled {
			continue
		}
		for _, rule := range pack.Rules {
			if !rule.Enabled {
				continue
			}
			key := strings.ToUpper(strings.TrimSpace(rule.ID))
			if key == "" {
				continue
			}
			if existing, ok := seen[key]; ok {
				conflict := model.RuleConflict{
					RuleID1:  existing.ruleName,
					RuleID2:  rule.Name,
					PackID1:  existing.packID,
					PackID2:  pack.ID,
					Conflict: "duplicate rule ID",
					Severity: "warning",
				}
				if existing.severity != rule.Severity {
					conflict.Severity = "error"
				}
				conflicts = append(conflicts, conflict)
			} else {
				seen[key] = ruleLocation{
					packID:   pack.ID,
					ruleName: rule.Name,
					severity: rule.Severity,
				}
			}
		}
	}

	return conflicts
}

// DetectConflicts returns conflict analysis for all enabled packs.
func (rm *RuleManager) DetectConflicts() []model.RuleConflict {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.detectConflictsLocked()
}

// ValidateRules checks for syntax issues in rule content.
func (rm *RuleManager) ValidateRules(content string) []RuleValidationError {
	var errors []RuleValidationError
	lines := strings.Split(content, "\n")

	ruleDepth := 0
	inRule := false
	hasCondition := false
	currentRule := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if strings.HasPrefix(trimmed, "rule ") {
			if inRule && ruleDepth == 0 {
				if !hasCondition {
					errors = append(errors, RuleValidationError{
						Line:    i,
						Rule:    currentRule,
						Message: "rule missing condition block",
					})
				}
			}
			inRule = true
			hasCondition = false
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentRule = strings.TrimRight(parts[1], " {")
			}
			ruleDepth = 0
		}

		if strings.Contains(trimmed, "{") {
			ruleDepth += strings.Count(trimmed, "{")
		}
		if strings.Contains(trimmed, "}") {
			ruleDepth -= strings.Count(trimmed, "}")
		}

		if trimmed == "condition:" || strings.HasPrefix(trimmed, "condition:") {
			hasCondition = true
		}

		if ruleDepth < 0 {
			errors = append(errors, RuleValidationError{
				Line:    i + 1,
				Rule:    currentRule,
				Message: "unexpected closing brace",
			})
			ruleDepth = 0
		}
	}

	if inRule && !hasCondition {
		errors = append(errors, RuleValidationError{
			Line:    len(lines),
			Rule:    currentRule,
			Message: "rule missing condition block",
		})
	}

	return errors
}

// RuleValidationError describes a syntax issue found during validation.
type RuleValidationError struct {
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// getCacheDir returns the rule cache directory.
func (rm *RuleManager) getCacheDir() string {
	if rm.dataDir != "" {
		return filepath.Join(rm.dataDir, "cache")
	}
	return filepath.Join(os.TempDir(), "meow-traffic", "rules", "cache")
}

// fetchManifest downloads a rule manifest JSON from a remote URL.
type remoteRulePack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Version     struct {
		Major int    `json:"major"`
		Minor int    `json:"minor"`
		Patch int    `json:"patch"`
		Tag   string `json:"tag"`
	} `json:"version"`
	RuleCount int    `json:"rule_count"`
	Checksum  string `json:"checksum"`
}

func (rm *RuleManager) fetchManifest(baseURL string) ([]remoteRulePack, error) {
	manifestURL := strings.TrimRight(baseURL, "/") + "/manifest.json"

	rm.mu.RLock()
	allowedHosts := rm.allowedHosts
	rm.mu.RUnlock()
	if _, err := validateRuleDownloadURL(manifestURL, allowedHosts); err != nil {
		return nil, err
	}

	resp, err := rm.client.Get(manifestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}

	var packs []remoteRulePack
	if err := json.NewDecoder(resp.Body).Decode(&packs); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	return packs, nil
}

func (rm *RuleManager) processRemotePack(remote remoteRulePack) model.RuleUpdateResult {
	result := model.RuleUpdateResult{
		PackID: remote.ID,
		NewVersion: model.RuleVersion{
			Major: remote.Version.Major,
			Minor: remote.Version.Minor,
			Patch: remote.Version.Patch,
			Tag:   remote.Version.Tag,
		},
	}

	rm.mu.RLock()
	existing, exists := rm.packs[remote.ID]
	rm.mu.RUnlock()

	if exists {
		result.OldVersion = existing.Version
		if !isNewerVersion(result.NewVersion, result.OldVersion) {
			return result
		}
	}

	if remote.URL == "" {
		result.Error = "no download URL"
		return result
	}
	if strings.TrimSpace(remote.Checksum) == "" {
		result.Error = "missing checksum"
		return result
	}

	pack, err := rm.DownloadPack(remote.ID, remote.URL, remote.Checksum)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Updated = true
	result.Downloaded = pack.RuleCount
	return result
}

// isNewerVersion returns true if a is strictly newer than b.
func isNewerVersion(a, b model.RuleVersion) bool {
	if a.Major != b.Major {
		return a.Major > b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor > b.Minor
	}
	return a.Patch > b.Patch
}

// sha256Hex computes SHA-256 hex digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// init ensures cache directory exists.
func (rm *RuleManager) init() error {
	cacheDir := rm.getCacheDir()
	return os.MkdirAll(cacheDir, 0o755)
}

// init is called on first use; no-op if already initialized.
func (rm *RuleManager) ensureInit() {
	// Lazy init: just ensure cache dir exists
	if err := rm.init(); err != nil {
		log.Printf("rule manager: init cache dir: %v", err)
	}
}
