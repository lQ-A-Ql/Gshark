// Package governance defines the data types and helper utilities used by the
// iterative dev governance workflow described in
// .kiro/specs/iterative-dev-governance/design.md.
//
// The governance package does not introduce any HTTP routes or runtime
// dependencies; it only provides pure data types and deterministic helpers
// (archive path resolution, self-audit triggering, task selection, report
// rendering) that the Governance_Agent uses to drive its Dev_Round loop.
package governance

import "time"

// Priority represents the severity tier of an Architecture_Defect. The four
// defined levels match the P0/P1/P2/P3 ordering used in the Defect_Register:
// P0 is the highest priority, P3 the lowest.
type Priority string

// Priority level constants. These string values are stable and are used as
// defect identifiers prefixes (e.g. "P0-1") in the Defect_Register.
const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
)

// DefectStatus captures whether a Defect_Register entry is still outstanding
// or has been closed by a completed Dev_Round.
type DefectStatus string

// DefectStatus constants.
const (
	DefectOpen     DefectStatus = "open"
	DefectResolved DefectStatus = "resolved"
)

// DefectEntry is a single row in the Defect_Register. It carries both the
// static metadata of an Architecture_Defect (ID, priority, description, key
// files) and its runtime resolution state.
//
// ResolvedAt is a pointer so that unresolved entries can leave it nil.
// ResolvedIn records the round number in which the defect was closed; it is
// zero for open defects.
type DefectEntry struct {
	ID          string       // e.g. "P0-1"
	Priority    Priority     // P0 | P1 | P2 | P3
	Title       string       // short human-readable title
	Description string       // detailed defect description
	KeyFiles    []string     // primary source files involved
	Status      DefectStatus // open | resolved
	ResolvedAt  *time.Time   // nil while Status == DefectOpen
	ResolvedIn  int          // round number in which it was closed; 0 when open
}

// DefectRegister is the collection of all tracked Architecture_Defects. It is
// treated as an append-only input to the Round Controller; Self_Audit may
// reorder task selection but must not remove entries.
type DefectRegister struct {
	Entries []DefectEntry
}

// ValidationAttempt records a single execution of a validation command during
// a Dev_Round. When the first attempt passes this slice will contain exactly
// one element; when the agent had to retry a fix, each retry is appended.
type ValidationAttempt struct {
	AttemptNumber int    // 1-based attempt index within a Dev_Round
	Output        string // captured stdout/stderr of the attempt
	Pass          bool   // true if this attempt passed
}

// ValidationResult aggregates all attempts for a single validation command
// (e.g. `go test ./...`, `pnpm run ci`, `gofmt -l .`). Pass reflects the
// outcome of the final attempt.
type ValidationResult struct {
	Command  string              // verbatim command that was run
	Pass     bool                // result of the final attempt
	Output   string              // combined output of the final attempt
	Attempts []ValidationAttempt // full history, ordered by AttemptNumber
}

// RoundReport is the in-memory model of a Dev_Round's daily governance
// report. Rendering helpers in report_render.go convert it into the Markdown
// written under docs/audit-development-report-archive-YYYY-MM-DD/.
type RoundReport struct {
	RoundNumber     int                // monotonically increasing round counter
	Author          string             // conventionally "Codex"
	Timestamp       time.Time          // local time the round completed
	Timezone        string             // conventionally "+08:00"
	Defect          DefectEntry        // defect addressed in this round
	ModifiedFiles   []string           // every source file touched during the round
	Validations     []ValidationResult // one per validation command run
	RisksAndDefects string             // free-form 当前缺陷与风险 section body
	NextSteps       string             // free-form 下一步建议 section body
}

// DefectClosure is a single row of the Self_Audit defect closure table. It
// ties a resolved defect to the round and date in which it was closed.
type DefectClosure struct {
	DefectID    string    // e.g. "P0-1"
	Title       string    // copied from DefectEntry.Title for convenience
	ResolvedAt  time.Time // local time the defect was closed
	RoundNumber int       // round number in which it was closed
}

// SelfAuditReport is the in-memory model of the every-ten-rounds Drift_Check
// report appended under a `## Self-Audit Round N` heading.
//
// DriftDetected / PriorityAdjusted indicate whether the audit required any
// corrective action; DriftDescription and DirectionNote carry the explanatory
// text rendered into the report.
type SelfAuditReport struct {
	RoundNumber      int              // the round number that triggered the audit
	Timestamp        time.Time        // when the audit was performed
	CompletedDefects []DefectClosure  // defects closed during this audit window
	DriftDetected    bool             // true if the audit found topic drift
	DriftDescription string           // explanation when DriftDetected is true
	PriorityAdjusted bool             // true if task-selection order was changed
	DirectionNote    string           // free-form next-phase direction note
	CIGateResult     ValidationResult // result of `./scripts/check-all.ps1`
}

// ArchivePath describes the on-disk layout of a single day's Report_Archive.
// All three paths share the same YYYY-MM-DD date stamp derived from Date.
//
// Paths are expressed with forward slashes so that they are stable across
// platforms; callers are expected to join them with the project root using
// filepath.Join when touching the filesystem.
type ArchivePath struct {
	Date       time.Time // calendar date the archive belongs to
	Directory  string    // docs/audit-development-report-archive-YYYY-MM-DD/
	ReportFile string    // <Directory>/dev-governance-report-YYYY-MM-DD.md
	ReadmeFile string    // <Directory>/README.md
}
