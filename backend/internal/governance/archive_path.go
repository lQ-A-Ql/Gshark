package governance

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ResolveArchivePath returns the deterministic on-disk layout for the
// Report_Archive belonging to the given calendar date.
//
// The returned paths use forward slashes and are relative to the project
// root, matching the convention documented on ArchivePath. Date formatting
// uses Go's reference layout "2006-01-02", which produces zero-padded
// YYYY-MM-DD strings regardless of the month or day value.
func ResolveArchivePath(date time.Time) ArchivePath {
	dateStr := date.Format("2006-01-02")
	dir := fmt.Sprintf("docs/audit-development-report-archive-%s/", dateStr)
	return ArchivePath{
		Date:       date,
		Directory:  dir,
		ReportFile: dir + "dev-governance-report-" + dateStr + ".md",
		ReadmeFile: dir + "README.md",
	}
}

// archiveReadmeStubTemplate is the minimal Markdown header seeded into a
// freshly created Report_Archive directory's README.md. The two %s
// placeholders are filled with the same YYYY-MM-DD date stamp that identifies
// the containing directory so that human reviewers can confirm at a glance
// which calendar day an archive belongs to.
const archiveReadmeStubTemplate = "# 开发治理日报归档 - %s\n" +
	"\n" +
	"本目录存放 %s 当日 Governance_Agent 的 Round_Report 与 Self_Audit 记录。\n"

// CreateArchiveDirectory creates the Report_Archive directory for the given
// calendar date beneath root and seeds it with a README.md index stub.
//
// The layout is derived from ResolveArchivePath(date): the directory is
// joined with root using filepath.Join so that the function works on every
// platform, and os.MkdirAll is used so that callers can safely invoke the
// helper multiple times for the same date without racing on directory
// creation. Any filesystem error is returned verbatim.
//
// Requirement 1.4 mandates that both the directory and its README.md exist
// before a Round_Report is written; this helper is the single authoritative
// entry point for that precondition. The README.md is written only when it
// does not already exist so that repeated invocations on the same date are
// idempotent — humans may hand-edit the index stub between rounds and those
// edits must survive subsequent calls.
func CreateArchiveDirectory(root string, date time.Time) error {
	path := ResolveArchivePath(date)
	fullDir := filepath.Join(root, filepath.FromSlash(path.Directory))
	if err := os.MkdirAll(fullDir, 0o755); err != nil {
		return fmt.Errorf("governance: create archive directory %q: %w", fullDir, err)
	}
	readmePath := filepath.Join(fullDir, "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		// README already exists; do not overwrite so that any
		// curator edits made between rounds are preserved.
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("governance: stat archive README %q: %w", readmePath, err)
	}
	dateStr := date.Format("2006-01-02")
	content := []byte(fmt.Sprintf(archiveReadmeStubTemplate, dateStr, dateStr))
	if err := os.WriteFile(readmePath, content, 0o644); err != nil {
		return fmt.Errorf("governance: write archive README %q: %w", readmePath, err)
	}
	return nil
}
