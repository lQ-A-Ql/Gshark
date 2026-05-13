package governance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDefectRegisterRequiresClosureEvidence(t *testing.T) {
	register := DefectRegisterFile{
		SchemaVersion: 1,
		Entries: []DefectRegisterEntry{
			{
				ID:       "P1-99",
				Priority: PriorityP1,
				Title:    "missing evidence",
				Status:   DefectResolved,
			},
		},
	}

	err := ValidateDefectRegister(register)
	if err == nil {
		t.Fatal("ValidateDefectRegister succeeded for resolved defect without evidence")
	}
	if !strings.Contains(err.Error(), "resolvedIn") {
		t.Fatalf("expected resolvedIn error, got %v", err)
	}
}

func TestValidateDefectRegisterRejectsOpenClosureEvidence(t *testing.T) {
	register := DefectRegisterFile{
		SchemaVersion: 1,
		Entries: []DefectRegisterEntry{
			{
				ID:       "P2-99",
				Priority: PriorityP2,
				Title:    "open defect",
				Status:   DefectOpen,
				Evidence: DefectEvidence{ClosedByCommit: "abc123"},
			},
		},
	}

	err := ValidateDefectRegister(register)
	if err == nil {
		t.Fatal("ValidateDefectRegister succeeded for open defect with closure evidence")
	}
	if !strings.Contains(err.Error(), "open but contains closure evidence") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDefectRegisterAgainstRootChecksEvidencePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "backend", "internal", "governance"), 0o755); err != nil {
		t.Fatalf("create source dir: %v", err)
	}
	sourcePath := filepath.Join(root, "backend", "internal", "governance", "models.go")
	if err := os.WriteFile(sourcePath, []byte("package governance\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatalf("create docs dir: %v", err)
	}
	reportPath := filepath.Join(root, "docs", "report.md")
	if err := os.WriteFile(reportPath, []byte("# report\n"), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	register := DefectRegisterFile{
		SchemaVersion: 1,
		Entries: []DefectRegisterEntry{
			{
				ID:         "P1-1",
				Priority:   PriorityP1,
				Title:      "BackendBridge split",
				Status:     DefectResolved,
				ResolvedIn: 1,
				Evidence: DefectEvidence{
					ClosedByCommit:     "c2cb8d2eab1f9b7840640013c4bd06cc7f181319",
					ClosedAt:           "2026-05-13T03:20:24+08:00",
					ModifiedFiles:      []string{"backend/internal/governance/models.go"},
					ValidationCommands: []string{"cd backend && go test ./..."},
					EvidenceTests:      []string{"go test ./internal/governance"},
					ReportPath:         "docs/report.md",
				},
			},
		},
	}

	if err := ValidateDefectRegisterAgainstRoot(root, register); err != nil {
		t.Fatalf("ValidateDefectRegisterAgainstRoot returned error: %v", err)
	}
}

func TestCanonicalDefectRegisterIsValid(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	registerPath := filepath.Join(root, "docs", "governance-defect-register.json")
	register, err := LoadDefectRegisterFile(registerPath)
	if err != nil {
		t.Fatalf("LoadDefectRegisterFile: %v", err)
	}
	if err := ValidateDefectRegisterAgainstRoot(root, register); err != nil {
		t.Fatalf("ValidateDefectRegisterAgainstRoot: %v", err)
	}
}
