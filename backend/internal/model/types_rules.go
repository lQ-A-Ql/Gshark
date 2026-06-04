package model

import "time"

// RulePack represents a downloadable rule pack with version metadata.
type RulePack struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Source      string      `json:"source"`
	Version     RuleVersion `json:"version"`
	Enabled     bool        `json:"enabled"`
	RuleCount   int         `json:"rule_count"`
	Checksum    string      `json:"checksum"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Rules       []RuleEntry `json:"rules,omitempty"`
}

// RuleVersion tracks semantic version info for a rule pack.
type RuleVersion struct {
	Major      int       `json:"major"`
	Minor      int       `json:"minor"`
	Patch      int       `json:"patch"`
	Tag        string    `json:"tag,omitempty"`
	ReleasedAt time.Time `json:"released_at"`
}

// String returns the version in "vMajor.Minor.Patch" format.
func (v RuleVersion) String() string {
	s := "v" + itoa(v.Major) + "." + itoa(v.Minor) + "." + itoa(v.Patch)
	if v.Tag != "" {
		s += "-" + v.Tag
	}
	return s
}

func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// RuleEntry represents a single YARA rule within a pack.
type RuleEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// RuleUpdateConfig controls remote rule fetching behavior.
type RuleUpdateConfig struct {
	RemoteURL      string `json:"remote_url"`
	AutoUpdate     bool   `json:"auto_update"`
	UpdateInterval int    `json:"update_interval_hours"`
	CacheDir       string `json:"cache_dir"`
}

// RuleStatus reports the current state of all loaded rule packs.
type RuleStatus struct {
	Packs         []RulePack       `json:"packs"`
	TotalRules    int              `json:"total_rules"`
	EnabledRules  int              `json:"enabled_rules"`
	DisabledRules int              `json:"disabled_rules"`
	LastUpdate    time.Time        `json:"last_update"`
	UpdateConfig  RuleUpdateConfig `json:"update_config"`
	Conflicts     []RuleConflict   `json:"conflicts,omitempty"`
}

// RuleConflict represents a detected conflict between rules.
type RuleConflict struct {
	RuleID1  string `json:"rule_id_1"`
	RuleID2  string `json:"rule_id_2"`
	PackID1  string `json:"pack_id_1"`
	PackID2  string `json:"pack_id_2"`
	Conflict string `json:"conflict"`
	Severity string `json:"severity"`
}

// RuleUpdateResult reports the outcome of a rule update check.
type RuleUpdateResult struct {
	PackID     string      `json:"pack_id"`
	OldVersion RuleVersion `json:"old_version"`
	NewVersion RuleVersion `json:"new_version"`
	Updated    bool        `json:"updated"`
	Downloaded int         `json:"downloaded_rules"`
	Error      string      `json:"error,omitempty"`
}
