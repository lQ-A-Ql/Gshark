package yararules

import _ "embed"

// DefaultRuleSource is the embedded fallback rule set shipped with the backend.
//
//go:embed default.yar
var DefaultRuleSource string

//go:embed traffic_cve_webshell.yar
var TrafficCVERuleSource string

// AllRuleSources returns all embedded rule sources concatenated.
func AllRuleSources() string {
	return DefaultRuleSource + "\n\n" + TrafficCVERuleSource
}
