package model

import "time"

// ---------------------------------------------------------------------------
// Hunting Playbook
// ---------------------------------------------------------------------------

// PlaybookStepType describes the kind of action a playbook step performs.
type PlaybookStepType string

const (
	PlaybookStepTypeThreatHunt  PlaybookStepType = "threat_hunt"
	PlaybookStepTypeFilterQuery PlaybookStepType = "filter_query"
	PlaybookStepTypeYARAScan    PlaybookStepType = "yara_scan"
	PlaybookStepTypeC2Analysis  PlaybookStepType = "c2_analysis"
	PlaybookStepTypeAPTAnalysis PlaybookStepType = "apt_analysis"
	PlaybookStepTypeCustom      PlaybookStepType = "custom"
)

// PlaybookStepCondition defines a threshold condition that must be met for a
// step to be considered successful.
type PlaybookStepCondition struct {
	Field    string `json:"field"`    // e.g. "hits_count", "severity_high"
	Operator string `json:"operator"` // "gt", "gte", "lt", "lte", "eq", "neq"
	Value    string `json:"value"`    // string-encoded numeric or literal
}

// PlaybookStep is a single step inside a hunting playbook.
type PlaybookStep struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	Type        PlaybookStepType        `json:"type"`
	Config      map[string]any          `json:"config,omitempty"`
	Conditions  []PlaybookStepCondition `json:"conditions,omitempty"`
	Enabled     bool                    `json:"enabled"`
}

// PlaybookStatus represents the execution state of a playbook.
type PlaybookStatus string

const (
	PlaybookStatusDraft    PlaybookStatus = "draft"
	PlaybookStatusReady    PlaybookStatus = "ready"
	PlaybookStatusRunning  PlaybookStatus = "running"
	PlaybookStatusComplete PlaybookStatus = "complete"
	PlaybookStatusFailed   PlaybookStatus = "failed"
)

// HuntingPlaybook is a reusable, structured threat-hunting workflow that
// defines an ordered sequence of detection steps, each with its own
// configuration and pass/fail conditions.
type HuntingPlaybook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Author      string         `json:"author,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Steps       []PlaybookStep `json:"steps"`
	Status      PlaybookStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// PlaybookStepResult captures the outcome of executing a single step.
type PlaybookStepResult struct {
	StepID      string        `json:"step_id"`
	StepName    string        `json:"step_name"`
	Status      string        `json:"status"` // "pass", "fail", "skip", "error"
	HitsCount   int           `json:"hits_count"`
	Hits        []ThreatHit   `json:"hits,omitempty"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration_ms"`
	ConditionOK bool          `json:"condition_ok"`
}

// PlaybookRunResult captures the full outcome of running a playbook.
type PlaybookRunResult struct {
	PlaybookID   string               `json:"playbook_id"`
	PlaybookName string               `json:"playbook_name"`
	Status       PlaybookStatus       `json:"status"`
	StepResults  []PlaybookStepResult `json:"step_results"`
	TotalHits    int                  `json:"total_hits"`
	Duration     time.Duration        `json:"duration_ms"`
	StartedAt    time.Time            `json:"started_at"`
	CompletedAt  time.Time            `json:"completed_at"`
}

// ---------------------------------------------------------------------------
// Saved Search
// ---------------------------------------------------------------------------

// SavedSearch stores a reusable query configuration for threat hunting.
type SavedSearch struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Query       string    `json:"query"`
	Filters     []string  `json:"filters,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	HitCount    int       `json:"hit_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Hypothesis Tracking
// ---------------------------------------------------------------------------

// HypothesisStatus represents the lifecycle state of a hunting hypothesis.
type HypothesisStatus string

const (
	HypothesisStatusOpen          HypothesisStatus = "open"
	HypothesisStatusInvestigating HypothesisStatus = "investigating"
	HypothesisStatusConfirmed     HypothesisStatus = "confirmed"
	HypothesisStatusRefuted       HypothesisStatus = "refuted"
	HypothesisStatusInconclusive  HypothesisStatus = "inconclusive"
)

// HypothesisEvidence links a piece of evidence to a hypothesis.
type HypothesisEvidence struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Source      string    `json:"source"`           // e.g. "threat_hunt", "yara", "manual"
	RefID       string    `json:"ref_id,omitempty"` // e.g. ThreatHit ID, packet ID
	Strength    string    `json:"strength"`         // "supports", "contradicts", "neutral"
	CreatedAt   time.Time `json:"created_at"`
}

// Hypothesis tracks a threat hunting hypothesis through its lifecycle,
// from initial formation through investigation to conclusion.
type Hypothesis struct {
	ID          string               `json:"id"`
	Title       string               `json:"title"`
	Description string               `json:"description,omitempty"`
	Status      HypothesisStatus     `json:"status"`
	PlaybookID  string               `json:"playbook_id,omitempty"`
	Evidence    []HypothesisEvidence `json:"evidence,omitempty"`
	Conclusion  string               `json:"conclusion,omitempty"`
	Tags        []string             `json:"tags,omitempty"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}
