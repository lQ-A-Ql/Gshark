package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// countYARARules counts the number of "rule " declarations in YARA content.
func countYARARules(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "rule ") {
			// Ensure it's a rule declaration, not inside a string
			if brace := strings.Index(trimmed, "{"); brace > 4 {
				name := strings.TrimSpace(trimmed[4:brace])
				if name != "" {
					count++
				}
			}
		}
	}
	return count
}

// extractRuleEntries parses YARA content and returns rule entries.
func extractRuleEntries(content string) []model.RuleEntry {
	var entries []model.RuleEntry
	lines := strings.Split(content, "\n")

	currentRule := ""
	inMeta := false
	fields := map[string]string{}

	flush := func() {
		if currentRule == "" {
			return
		}
		entry := model.RuleEntry{
			ID:      currentRule,
			Name:    fields["description"],
			Enabled: true,
		}
		if entry.Name == "" {
			entry.Name = currentRule
		}
		entry.Category = fields["family"]
		if entry.Category == "" {
			entry.Category = fields["project"]
		}
		entry.Severity = normalizeYaraLevel(fields["severity"])
		if entry.Severity == "" {
			entry.Severity = "medium"
		}
		entries = append(entries, entry)
		currentRule = ""
		inMeta = false
		fields = map[string]string{}
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "rule ") {
			flush()
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentRule = strings.TrimSpace(parts[1])
				if brace := strings.Index(currentRule, "{"); brace >= 0 {
					currentRule = strings.TrimSpace(currentRule[:brace])
				}
			}
			continue
		}
		if currentRule == "" {
			continue
		}
		switch {
		case line == "meta:":
			inMeta = true
			continue
		case strings.HasSuffix(line, "strings:") || strings.HasSuffix(line, "condition:"):
			inMeta = false
			continue
		case line == "}":
			flush()
			continue
		}
		if !inMeta {
			continue
		}
		key, value, ok := parseYaraMetaAssignment(line)
		if !ok {
			continue
		}
		fields[strings.ToLower(key)] = value
	}
	flush()
	return entries
}
