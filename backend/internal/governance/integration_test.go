package governance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCreateArchiveDirectory_CreatesDirAndReadme is a filesystem integration
// test for CreateArchiveDirectory. It is intentionally example-based rather
// than a property test: the cases we care about are concrete calendar dates
// (a regular mid-month day and a year-end edge) and the behaviour we assert
// is I/O that fast-check style generators add no value to.
//
// Validates: Requirements 1.4 — "WHEN a Report_Archive directory for the
// current date does not exist, THE Governance_Agent SHALL create the
// directory and a README.md index file before writing the Round_Report."
func TestCreateArchiveDirectory_CreatesDirAndReadme(t *testing.T) {
	cases := []struct {
		name string
		date time.Time
	}{
		{
			// Regular mid-month weekday. Exercises the common happy
			// path with zero padding on both month and day segments.
			name: "regular-mid-month-date",
			date: time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			// Year-end edge date. Exercises the boundary where a
			// naive implementation could truncate or mis-format the
			// trailing day, and also confirms two distinct invocations
			// in the same test run do not interfere with each other
			// (each tc uses its own t.TempDir()).
			name: "year-end-date",
			date: time.Date(2026, time.December, 31, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()

			if err := CreateArchiveDirectory(root, tc.date); err != nil {
				t.Fatalf("CreateArchiveDirectory returned error: %v", err)
			}

			// Resolve the expected on-disk layout via the same helper
			// the implementation uses so that the test tracks the
			// single source of truth instead of hard-coding the path
			// format (which is exercised separately by Property 1).
			path := ResolveArchivePath(tc.date)
			fullDir := filepath.Join(root, filepath.FromSlash(path.Directory))
			readmePath := filepath.Join(fullDir, "README.md")

			info, err := os.Stat(fullDir)
			if err != nil {
				t.Fatalf("stat archive directory %q: %v", fullDir, err)
			}
			if !info.IsDir() {
				t.Fatalf("archive path %q exists but is not a directory", fullDir)
			}

			readmeInfo, err := os.Stat(readmePath)
			if err != nil {
				t.Fatalf("stat README %q: %v", readmePath, err)
			}
			if readmeInfo.IsDir() {
				t.Fatalf("expected README.md to be a regular file, got directory at %q", readmePath)
			}

			data, err := os.ReadFile(readmePath)
			if err != nil {
				t.Fatalf("read README %q: %v", readmePath, err)
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				t.Fatalf("README %q has empty content", readmePath)
			}

			// The stub must reference the calendar date the archive
			// belongs to so reviewers can confirm the directory's
			// provenance without cross-checking the directory name.
			dateStr := tc.date.Format("2006-01-02")
			if !strings.Contains(string(data), dateStr) {
				t.Fatalf("README content does not reference date %q; got:\n%s", dateStr, string(data))
			}
		})
	}
}

// TestUpdateDocsReadme_AppendsArchiveEntry is a filesystem integration test
// for UpdateDocsReadme. A small docs/README.md is seeded into a temporary
// root with a minimal archive description table, and the helper is then
// asked to register a brand-new archive directory. The test verifies both
// that the new directory name surfaces in the rewritten file and that
// invoking the helper a second time with the same ArchivePath does not
// duplicate the entry — that idempotence property is what lets callers
// invoke UpdateDocsReadme unconditionally at the end of every Dev_Round
// without having to track prior state.
//
// Validates: Requirements 8.2 — "WHEN creating a new Report_Archive
// directory, THE Governance_Agent SHALL update docs/README.md to include
// the new archive in the recommended reading order and the archive
// description table."
func TestUpdateDocsReadme_AppendsArchiveEntry(t *testing.T) {
	root := t.TempDir()
	docsDir := filepath.Join(root, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		t.Fatalf("create docs dir: %v", err)
	}

	// Seed a minimal docs/README.md that already contains an archive
	// description table with one historical entry. The shape mirrors the
	// real docs/README.md so the helper's table-aware branch is exercised.
	seed := "# 文档索引\n" +
		"\n" +
		"## 归档目录\n" +
		"\n" +
		"| 归档目录 | 说明 |\n" +
		"|---|---|\n" +
		"| docs/audit-development-report-archive-2026-05-02/ | 示例历史归档 |\n"
	readmePath := filepath.Join(docsDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed docs/README.md: %v", err)
	}

	newDate := time.Date(2026, time.June, 1, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	archive := ResolveArchivePath(newDate)
	expected := "docs/audit-development-report-archive-2026-06-01/"

	if err := UpdateDocsReadme(root, archive); err != nil {
		t.Fatalf("UpdateDocsReadme returned error: %v", err)
	}

	after, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read updated docs/README.md: %v", err)
	}
	if !strings.Contains(string(after), expected) {
		t.Fatalf("updated docs/README.md does not contain %q; got:\n%s", expected, string(after))
	}
	// The pre-existing entry must be preserved so that historical archive
	// links in the index are not silently dropped.
	if !strings.Contains(string(after), "docs/audit-development-report-archive-2026-05-02/") {
		t.Fatalf("updated docs/README.md lost the pre-existing 2026-05-02 entry; got:\n%s", string(after))
	}

	// Idempotence: calling the helper a second time with the same archive
	// path must not duplicate the entry. We count occurrences of the new
	// directory string and require exactly one after the second call.
	if err := UpdateDocsReadme(root, archive); err != nil {
		t.Fatalf("UpdateDocsReadme (second call) returned error: %v", err)
	}
	afterSecond, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read docs/README.md after second call: %v", err)
	}
	if count := strings.Count(string(afterSecond), expected); count != 1 {
		t.Fatalf("expected exactly one occurrence of %q after idempotent re-invocation, got %d; content:\n%s",
			expected, count, string(afterSecond))
	}
}
