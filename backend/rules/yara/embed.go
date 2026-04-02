package yararules

import _ "embed"

// DefaultRuleSource is the embedded fallback rule set shipped with the backend.
//
//go:embed default.yar
var DefaultRuleSource string
