package governance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefectEvidence records the concrete proof that a governance defect was
// closed. It intentionally mirrors the report-audit needs instead of runtime
// product state: every resolved defect must point to a commit, changed files,
// validation commands, and at least one focused evidence test.
type DefectEvidence struct {
	ClosedByCommit     string   `json:"closedByCommit,omitempty"`
	ClosedAt           string   `json:"closedAt,omitempty"`
	ModifiedFiles      []string `json:"modifiedFiles,omitempty"`
	ValidationCommands []string `json:"validationCommands,omitempty"`
	EvidenceTests      []string `json:"evidenceTests,omitempty"`
	ReportPath         string   `json:"reportPath,omitempty"`
}

// DefectRegisterFile is the machine-readable on-disk governance register.
// docs/governance-defect-register.json is the canonical project instance.
type DefectRegisterFile struct {
	SchemaVersion int                   `json:"schemaVersion"`
	UpdatedAt     string                `json:"updatedAt"`
	Entries       []DefectRegisterEntry `json:"entries"`
}

// DefectRegisterEntry is the serializable counterpart of DefectEntry, extended
// with closure evidence required for report trust verification.
type DefectRegisterEntry struct {
	ID          string         `json:"id"`
	Priority    Priority       `json:"priority"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	KeyFiles    []string       `json:"keyFiles,omitempty"`
	Status      DefectStatus   `json:"status"`
	ResolvedIn  int            `json:"resolvedIn,omitempty"`
	Evidence    DefectEvidence `json:"evidence,omitempty"`
}

// LoadDefectRegisterFile reads and decodes a JSON governance defect register
// from path. The decoder rejects unknown fields so typos in the canonical docs
// register fail loudly in tests.
func LoadDefectRegisterFile(path string) (DefectRegisterFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefectRegisterFile{}, fmt.Errorf("governance: read defect register %q: %w", path, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var register DefectRegisterFile
	if err := decoder.Decode(&register); err != nil {
		return DefectRegisterFile{}, fmt.Errorf("governance: decode defect register %q: %w", path, err)
	}
	return register, nil
}

// ValidateDefectRegister checks the semantic invariants that make the defect
// register useful as an audit source. Resolved defects require concrete
// evidence; open defects must not claim closure proof.
func ValidateDefectRegister(register DefectRegisterFile) error {
	if register.SchemaVersion <= 0 {
		return fmt.Errorf("schemaVersion must be positive")
	}
	seen := make(map[string]struct{}, len(register.Entries))
	for _, entry := range register.Entries {
		if strings.TrimSpace(entry.ID) == "" {
			return fmt.Errorf("defect entry has empty id")
		}
		if _, ok := seen[entry.ID]; ok {
			return fmt.Errorf("duplicate defect id %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if entry.Priority != PriorityP0 && entry.Priority != PriorityP1 && entry.Priority != PriorityP2 && entry.Priority != PriorityP3 {
			return fmt.Errorf("%s has invalid priority %q", entry.ID, entry.Priority)
		}
		if strings.TrimSpace(entry.Title) == "" {
			return fmt.Errorf("%s has empty title", entry.ID)
		}
		switch entry.Status {
		case DefectResolved:
			if err := validateResolvedEvidence(entry); err != nil {
				return err
			}
		case DefectOpen:
			if hasClosureEvidence(entry.Evidence) || entry.ResolvedIn != 0 {
				return fmt.Errorf("%s is open but contains closure evidence", entry.ID)
			}
		default:
			return fmt.Errorf("%s has invalid status %q", entry.ID, entry.Status)
		}
	}
	return nil
}

// ValidateDefectRegisterAgainstRoot checks the register invariants plus the
// existence of every path referenced by closure evidence. Commit existence is
// intentionally left to git-level checks so the helper stays deterministic in
// exported source archives.
func ValidateDefectRegisterAgainstRoot(root string, register DefectRegisterFile) error {
	if err := ValidateDefectRegister(register); err != nil {
		return err
	}
	for _, entry := range register.Entries {
		if entry.Status != DefectResolved {
			continue
		}
		for _, file := range append([]string{}, entry.Evidence.ModifiedFiles...) {
			if err := validateRepoRelativePath(root, file); err != nil {
				return fmt.Errorf("%s modified file evidence invalid: %w", entry.ID, err)
			}
		}
		if entry.Evidence.ReportPath != "" {
			if err := validateRepoRelativePathSyntax(entry.Evidence.ReportPath); err != nil {
				return fmt.Errorf("%s report evidence invalid: %w", entry.ID, err)
			}
		}
	}
	return nil
}

func validateResolvedEvidence(entry DefectRegisterEntry) error {
	evidence := entry.Evidence
	if entry.ResolvedIn <= 0 {
		return fmt.Errorf("%s is resolved but resolvedIn is not positive", entry.ID)
	}
	if strings.TrimSpace(evidence.ClosedByCommit) == "" {
		return fmt.Errorf("%s is resolved but missing closedByCommit", entry.ID)
	}
	if strings.TrimSpace(evidence.ClosedAt) == "" {
		return fmt.Errorf("%s is resolved but missing closedAt", entry.ID)
	}
	if len(evidence.ModifiedFiles) == 0 {
		return fmt.Errorf("%s is resolved but missing modifiedFiles", entry.ID)
	}
	if len(evidence.ValidationCommands) == 0 {
		return fmt.Errorf("%s is resolved but missing validationCommands", entry.ID)
	}
	if len(evidence.EvidenceTests) == 0 {
		return fmt.Errorf("%s is resolved but missing evidenceTests", entry.ID)
	}
	if strings.TrimSpace(evidence.ReportPath) == "" {
		return fmt.Errorf("%s is resolved but missing reportPath", entry.ID)
	}
	return nil
}

func hasClosureEvidence(evidence DefectEvidence) bool {
	return strings.TrimSpace(evidence.ClosedByCommit) != "" ||
		strings.TrimSpace(evidence.ClosedAt) != "" ||
		len(evidence.ModifiedFiles) > 0 ||
		len(evidence.ValidationCommands) > 0 ||
		len(evidence.EvidenceTests) > 0 ||
		strings.TrimSpace(evidence.ReportPath) != ""
}

func validateRepoRelativePath(root, path string) error {
	if err := validateRepoRelativePathSyntax(path); err != nil {
		return err
	}
	fullPath := filepath.Join(root, filepath.Clean(filepath.FromSlash(path)))
	if _, err := os.Stat(fullPath); err != nil {
		return fmt.Errorf("path %q does not exist: %w", path, err)
	}
	return nil
}

func validateRepoRelativePathSyntax(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return fmt.Errorf("path %q must be repo-relative", path)
	}
	return nil
}
