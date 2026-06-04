package yararules

import (
	"embed"
	"os"
	"strings"
)

// DefaultRuleSource is the embedded fallback rule set shipped with the backend.
//
//go:embed default.yar
var DefaultRuleSource string

//go:embed traffic_cve_webshell.yar
var TrafficCVERuleSource string

// communityFS holds the embedded community YARA rules from Neo23x0/signature-base.
//
//go:embed community/*.yar
var communityFS embed.FS

// CommunityEnabled reports whether community YARA rules should be included.
// Controlled by MEOW_TRAFFIC_YARA_COMMUNITY env var.
//   - "1" or "true" → enabled
//   - "0" or "false" (or unset) → disabled (default)
func CommunityEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_YARA_COMMUNITY")))
	return v == "1" || v == "true"
}

// CommunityRuleSources reads and returns all embedded community rules concatenated.
// Returns empty string if community rules are disabled.
func CommunityRuleSources() string {
	if !CommunityEnabled() {
		return ""
	}
	return readCommunityRules()
}

func readCommunityRules() string {
	entries, err := communityFS.ReadDir("community")
	if err != nil {
		return ""
	}
	var builder strings.Builder
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			continue
		}
		data, err := communityFS.ReadFile("community/" + name)
		if err != nil {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString("\n\n")
		}
		builder.Write(data)
	}
	return builder.String()
}

// AllRuleSources returns all embedded rule sources concatenated.
// Includes community rules when MEOW_TRAFFIC_YARA_COMMUNITY is enabled.
func AllRuleSources() string {
	sources := DefaultRuleSource + "\n\n" + TrafficCVERuleSource
	if community := CommunityRuleSources(); community != "" {
		sources += "\n\n" + community
	}
	return sources
}
