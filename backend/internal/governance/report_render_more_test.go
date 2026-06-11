package governance

import (
	"strings"
	"testing"
)

func TestCacheKeyDeterministicAndHandlesUnmarshalableValues(t *testing.T) {
	a := CacheKey(map[string]any{"b": 2, "a": 1})
	b := CacheKey(map[string]any{"a": 1, "b": 2})
	if a == "" || a != b {
		t.Fatalf("CacheKey should be deterministic for JSON maps: %q %q", a, b)
	}
	if got := CacheKey(make(chan int)); got == "" {
		t.Fatal("CacheKey should produce fallback hash for unmarshalable values")
	}
}

func TestInsertArchiveBulletCoversNewSectionBulletAndTableStyles(t *testing.T) {
	bullet := "- `docs/audit-development-report-archive-2026-06-11/`：Governance_Agent Round_Report 归档。"
	noSection := insertArchiveBullet("# Docs\n", bullet)
	if !strings.Contains(noSection, archiveDescriptionHeader) || !strings.Contains(noSection, "2026-06-11") {
		t.Fatalf("insert without section failed:\n%s", noSection)
	}

	withBullets := insertArchiveBullet(archiveDescriptionHeader+"\n\n- `old/`\n\n## Next\n", bullet)
	if !strings.Contains(withBullets, "- `old/`\n"+bullet) {
		t.Fatalf("bullet insertion did not stay with list:\n%s", withBullets)
	}

	withEmptySection := insertArchiveBullet(archiveDescriptionHeader+"\n\n## Next\n", bullet)
	if !strings.Contains(withEmptySection, archiveDescriptionHeader+"\n\n"+bullet+"\n## Next") {
		t.Fatalf("empty section insertion failed:\n%s", withEmptySection)
	}

	tableDoc := archiveDescriptionHeader + "\n\n| 路径 | 说明 |\n|---|---|\n| old/ | old |\n"
	withTable := insertArchiveBullet(tableDoc, bullet)
	if !strings.Contains(withTable, "| docs/audit-development-report-archive-2026-06-11/ | Governance_Agent") {
		t.Fatalf("table insertion failed:\n%s", withTable)
	}
	if got := extractDirFromBullet(bullet); got != "docs/audit-development-report-archive-2026-06-11/" {
		t.Fatalf("extractDirFromBullet() = %q", got)
	}
	if got := extractDirFromBullet("- no code span"); got != "" {
		t.Fatalf("extractDirFromBullet without backticks = %q", got)
	}
}
