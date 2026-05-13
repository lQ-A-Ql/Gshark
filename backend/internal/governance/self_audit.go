package governance

// ShouldTriggerSelfAudit reports whether the given Dev_Round number should
// trigger a Self_Audit pass before the next round begins.
//
// The rule, defined in .kiro/specs/iterative-dev-governance/design.md, is
// that Self_Audit fires exactly on positive multiples of ten (10, 20, 30…).
// Round zero is intentionally excluded so that the very first round of a
// fresh governance run does not spuriously trigger an audit.
func ShouldTriggerSelfAudit(roundNumber int) bool {
	return roundNumber > 0 && roundNumber%10 == 0
}
