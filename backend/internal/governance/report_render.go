package governance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultTimezone is the project-wide canonical timezone suffix used in every
// Round_Report header and every Progress Update heading. The value is fixed
// by Requirements 1.3 / 1.5 and mirrors the existing Report_Archive corpus.
const defaultTimezone = "+08:00"

// RenderRoundReport renders a RoundReport as a single Markdown document
// following the template declared in design.md.
//
// The produced string always contains the five required sections — 本轮目标、
// 已完成改动、验证记录、当前缺陷与风险、下一步建议 — in that order, and the
// first ten lines always include the author and timestamp header lines in
// the exact format mandated by Requirements 1.3.
//
// Rendering is a pure function of the input report; no filesystem or network
// I/O is performed here.
func RenderRoundReport(report RoundReport) string {
	tz := report.Timezone
	if strings.TrimSpace(tz) == "" {
		tz = defaultTimezone
	}
	dateStr := report.Timestamp.Format("2006-01-02")
	tsStr := report.Timestamp.Format("2006-01-02 15:04:05") + " " + tz

	author := report.Author
	if strings.TrimSpace(author) == "" {
		author = "Codex"
	}

	var b strings.Builder

	// Document header: title + signature + timestamp must land inside the
	// first ten lines so that Property 3 holds unconditionally.
	fmt.Fprintf(&b, "# 开发治理日报 - %s\n", dateStr)
	b.WriteString("\n")
	fmt.Fprintf(&b, "署名: %s\n", author)
	fmt.Fprintf(&b, "日期: %s\n", tsStr)
	b.WriteString("\n")

	// 本轮目标
	b.WriteString("## 本轮目标\n\n")
	b.WriteString(renderRoundGoal(report.Defect))
	b.WriteString("\n")

	// 已完成改动
	b.WriteString("## 已完成改动\n\n")
	b.WriteString(renderModifiedFiles(report.ModifiedFiles))
	b.WriteString("\n")

	// 验证记录
	b.WriteString("## 验证记录\n\n")
	b.WriteString(renderValidations(report.Validations))
	b.WriteString("\n")

	// 当前缺陷与风险
	b.WriteString("## 当前缺陷与风险\n\n")
	b.WriteString(renderFreeform(report.RisksAndDefects))
	b.WriteString("\n")

	// 下一步建议
	b.WriteString("## 下一步建议\n\n")
	b.WriteString(renderFreeform(report.NextSteps))
	b.WriteString("\n")

	return b.String()
}

// renderRoundGoal produces the body of the 本轮目标 section. When the defect
// entry has an ID/Priority/Title, the body starts with a priority-tagged
// line such as "P0: tshark capability 降级策略" (Requirements 8.4) followed
// by the defect's detailed description when available.
func renderRoundGoal(defect DefectEntry) string {
	var lines []string
	if defect.Priority != "" && strings.TrimSpace(defect.Title) != "" {
		lines = append(lines, fmt.Sprintf("- %s: %s", defect.Priority, defect.Title))
	} else if defect.ID != "" {
		lines = append(lines, fmt.Sprintf("- %s", defect.ID))
	}
	if desc := strings.TrimSpace(defect.Description); desc != "" {
		lines = append(lines, "", desc)
	}
	if len(lines) == 0 {
		return "(无)\n"
	}
	return strings.Join(lines, "\n") + "\n"
}

// renderModifiedFiles emits one "- <path>" bullet per file in the slice,
// preserving caller order. The resulting text guarantees Property 4: every
// path in ModifiedFiles appears verbatim as a substring of the section.
func renderModifiedFiles(files []string) string {
	if len(files) == 0 {
		return "(本轮无代码改动)\n"
	}
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	return b.String()
}

// renderValidations renders every Validation_Baseline command, its overall
// pass/fail state, and the full attempt history. Output is rendered inside
// a fenced code block so that command output containing Markdown special
// characters cannot disturb the surrounding document structure.
func renderValidations(results []ValidationResult) string {
	if len(results) == 0 {
		return "(未记录验证结果)\n"
	}
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "- `%s` — %s\n", r.Command, passLabel(r.Pass))
		attempts := r.Attempts
		if len(attempts) == 0 {
			// Synthesize a single attempt from the top-level fields so that
			// callers that do not populate Attempts still produce a
			// traceable record in the report.
			attempts = []ValidationAttempt{{AttemptNumber: 1, Output: r.Output, Pass: r.Pass}}
		}
		for _, a := range attempts {
			fmt.Fprintf(&b, "  - 尝试 %d: %s\n", a.AttemptNumber, passLabel(a.Pass))
			if trimmed := strings.TrimRight(a.Output, "\n"); trimmed != "" {
				b.WriteString("    ```\n")
				for _, line := range strings.Split(trimmed, "\n") {
					b.WriteString("    ")
					b.WriteString(line)
					b.WriteString("\n")
				}
				b.WriteString("    ```\n")
			}
		}
	}
	return b.String()
}

// passLabel converts a boolean outcome into the textual marker used in the
// 验证记录 section. Using a helper keeps the label consistent across
// top-level results and individual attempts.
func passLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

// renderFreeform echoes a caller-supplied free-form section body back into
// the report verbatim, guaranteeing a trailing newline so that subsequent
// section headings remain properly separated. When the body is empty a
// neutral placeholder is emitted so that the section never collapses to
// zero content lines.
func renderFreeform(body string) string {
	if strings.TrimSpace(body) == "" {
		return "(无)\n"
	}
	if strings.HasSuffix(body, "\n") {
		return body
	}
	return body + "\n"
}

// RenderSelfAuditHeading returns the canonical Markdown heading that
// introduces a Self_Audit section, satisfying Property 8: for every
// roundNumber N the output equals fmt.Sprintf("## Self-Audit Round %d", N).
func RenderSelfAuditHeading(roundNumber int) string {
	return fmt.Sprintf("## Self-Audit Round %d", roundNumber)
}

// RenderProgressUpdateHeading returns the Markdown heading used to append a
// subsequent same-day Dev_Round onto an existing Round_Report (Requirements
// 1.5). The timezone suffix is hard-coded to "+08:00" per the design
// specification; the caller is expected to supply a time value whose wall
// clock already matches that zone.
func RenderProgressUpdateHeading(t time.Time) string {
	return fmt.Sprintf("## Progress Update - %s %s",
		t.Format("2006-01-02 15:04:05"), defaultTimezone)
}

// RenderSelfAuditReport renders a SelfAuditReport as the Markdown block that
// gets appended to the current day's Round_Report under a
// "## Self-Audit Round N" heading.
//
// The closure table at the bottom lists every entry in report.CompletedDefects,
// which is what Property 10 / Requirements 8.6 require: each DefectID and
// its RoundNumber must appear in the rendered output.
func RenderSelfAuditReport(report SelfAuditReport) string {
	var b strings.Builder

	b.WriteString(RenderSelfAuditHeading(report.RoundNumber))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "自检时间: %s %s\n\n",
		report.Timestamp.Format("2006-01-02 15:04:05"), defaultTimezone)

	b.WriteString("### 本阶段完成的 Defect_Register 条目\n\n")
	if len(report.CompletedDefects) == 0 {
		b.WriteString("(本阶段无缺陷关闭)\n\n")
	} else {
		for _, c := range report.CompletedDefects {
			fmt.Fprintf(&b, "- %s %s（关闭于 %s，第 %d 轮）\n",
				c.DefectID, c.Title,
				c.ResolvedAt.Format("2006-01-02"), c.RoundNumber)
		}
		b.WriteString("\n")
	}

	b.WriteString("### 主题偏移检查\n\n")
	if report.DriftDetected {
		b.WriteString("检测到主题偏移：\n\n")
		b.WriteString(renderFreeform(report.DriftDescription))
	} else {
		b.WriteString("未检测到主题偏移，主线能力交付（入侵检测、威胁流量分析、证据链）节奏正常。\n")
	}
	b.WriteString("\n")

	b.WriteString("### Defect_Register 优先级重排\n\n")
	if report.PriorityAdjusted {
		b.WriteString("本轮自检对剩余 Defect_Register 的优先级进行了调整。\n")
	} else {
		b.WriteString("本轮自检未调整剩余 Defect_Register 的优先级。\n")
	}
	b.WriteString("\n")

	b.WriteString("### 下一阶段执行方向\n\n")
	b.WriteString(renderFreeform(report.DirectionNote))
	b.WriteString("\n")

	b.WriteString("### CI_Gate 结果\n\n")
	b.WriteString(renderValidations([]ValidationResult{report.CIGateResult}))
	b.WriteString("\n")

	b.WriteString("### 缺陷关闭汇总表\n\n")
	b.WriteString("| 缺陷 ID | 描述 | 关闭日期 | 轮次 |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, c := range report.CompletedDefects {
		fmt.Fprintf(&b, "| %s | %s | %s | %d |\n",
			c.DefectID, c.Title,
			c.ResolvedAt.Format("2006-01-02"), c.RoundNumber)
	}

	return b.String()
}

// CacheKey returns a deterministic, collision-resistant cache key for an
// arbitrary params value. The canonical bytes are produced by encoding/json
// (which sorts map keys alphabetically and emits struct fields in
// declaration order), hashed with SHA-256, and rendered as a lowercase hex
// string via fmt.Sprintf.
//
// When json.Marshal cannot encode the value (channels, functions, cyclic
// graphs, and similar), CacheKey falls back to fmt.Sprintf("%#v", params)
// so that the function remains total. Any two inputs that disagree under
// both encoders will therefore still produce distinct keys with
// overwhelming probability, satisfying the determinism and collision
// resistance expectations of Property 12.
func CacheKey(params interface{}) string {
	var canonical []byte
	if b, err := json.Marshal(params); err == nil {
		canonical = b
	} else {
		canonical = []byte(fmt.Sprintf("%#v", params))
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum)
}

// archiveDescriptionHeader is the Markdown heading that introduces the
// archive description section in docs/README.md. When the existing document
// already contains this heading (or the legacy "归档说明" variant) the
// helper appends a new bullet/row under it; otherwise a fresh section is
// appended at the end of the file.
const archiveDescriptionHeader = "## 归档说明"

// UpdateDocsReadme appends a description entry for the archive at path to
// the project's docs/README.md so that reviewers can discover the new
// Report_Archive from the top-level index (Requirements 8.2).
//
// Semantics:
//
//   - If docs/README.md does not yet contain a reference to the archive's
//     directory string (e.g. "docs/audit-development-report-archive-2026-06-01/"),
//     a new bullet of the form
//     "- `<directory>`：Governance_Agent Round_Report 归档。"
//     is appended under the existing "## 归档说明" heading. The bullet is
//     inserted after the last contiguous bullet line in that section so that
//     the entries remain grouped.
//   - If docs/README.md does not contain a "## 归档说明" heading at all, a
//     new section with that heading and a single bullet is appended at the
//     end of the file.
//   - If the archive's directory string is already present anywhere in
//     docs/README.md, the function returns nil without modifying the file.
//     Repeated invocations with the same ArchivePath are therefore
//     idempotent, which lets callers invoke the helper unconditionally
//     at the end of every Dev_Round.
//
// The docs/README.md file is resolved relative to root via filepath.Join so
// that the helper works on every platform and can be pointed at temporary
// roots in tests. Filesystem errors are wrapped with context so that they
// can be surfaced in Round_Report 验证记录 sections.
func UpdateDocsReadme(root string, path ArchivePath) error {
	readmePath := filepath.Join(root, "docs", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("governance: read docs/README.md %q: %w", readmePath, err)
	}
	original := string(data)

	entry := strings.TrimSuffix(path.Directory, "/")
	if entry == "" {
		return fmt.Errorf("governance: archive path has empty Directory")
	}

	// Idempotence guard: once the archive's directory string appears in the
	// document we treat the entry as already curated and leave the file
	// untouched. The substring check uses the trailing-slash-free form so
	// that both "docs/audit-development-report-archive-2026-06-01/" and the
	// bare directory name in a table cell match.
	if strings.Contains(original, entry) {
		return nil
	}

	bullet := fmt.Sprintf("- `%s/`：Governance_Agent Round_Report 归档。", entry)
	updated := insertArchiveBullet(original, bullet)

	if updated == original {
		// insertArchiveBullet fell through without modification; this should
		// not happen given the Contains check above, but guard against it so
		// that a silent no-op never gets written back.
		return nil
	}

	if err := os.WriteFile(readmePath, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("governance: write docs/README.md %q: %w", readmePath, err)
	}
	return nil
}

// insertArchiveBullet returns a copy of doc with bullet appended to the
// archive-description section. When the section header is present, bullet
// is placed after the last consecutive "- " bullet line beneath it; when it
// is absent, a fresh section is appended at the end of the document.
func insertArchiveBullet(doc, bullet string) string {
	lines := strings.Split(doc, "\n")
	headerIdx := findSectionHeader(lines, archiveDescriptionHeader, "## 归档目录")
	if headerIdx < 0 {
		// No existing section; append a new one at the end. We guarantee at
		// least one blank line before the new heading so that the resulting
		// Markdown renders cleanly even when the original document did not
		// end with a trailing newline.
		var b strings.Builder
		b.WriteString(strings.TrimRight(doc, "\n"))
		b.WriteString("\n\n")
		b.WriteString(archiveDescriptionHeader)
		b.WriteString("\n\n")
		b.WriteString(bullet)
		b.WriteString("\n")
		return b.String()
	}

	// Locate the last contiguous bullet line beneath the header so that the
	// new entry joins the existing list instead of landing on a stray blank
	// line. Scanning stops at the next heading (any "#" prefixed line) or
	// the end of the document.
	lastBullet := -1
	firstBullet := -1
	for i := headerIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			break
		}
		if strings.HasPrefix(trimmed, "- ") {
			if firstBullet < 0 {
				firstBullet = i
			}
			lastBullet = i
			continue
		}
		if trimmed == "" {
			continue
		}
		// Tables or other non-bullet content: remember the line so we can
		// append after it.
		lastBullet = i
	}

	insertAt := lastBullet + 1
	if lastBullet < 0 {
		// Header found but no content beneath it; insert directly after the
		// header (skipping a single blank line if one is present) so the new
		// bullet becomes the first entry.
		insertAt = headerIdx + 1
		if insertAt < len(lines) && strings.TrimSpace(lines[insertAt]) == "" {
			insertAt++
		}
	}

	// Handle table-style archive description tables: detect existing table
	// rows and append a Markdown row instead of a bullet so the output keeps
	// the caller's chosen style.
	if firstBullet < 0 && lastBullet >= 0 && strings.HasPrefix(strings.TrimSpace(lines[lastBullet]), "|") {
		dir := extractDirFromBullet(bullet)
		row := fmt.Sprintf("| %s | Governance_Agent Round_Report 归档。 |", dir)
		newLines := make([]string, 0, len(lines)+1)
		newLines = append(newLines, lines[:insertAt]...)
		newLines = append(newLines, row)
		newLines = append(newLines, lines[insertAt:]...)
		return strings.Join(newLines, "\n")
	}

	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:insertAt]...)
	newLines = append(newLines, bullet)
	newLines = append(newLines, lines[insertAt:]...)
	return strings.Join(newLines, "\n")
}

// findSectionHeader returns the index of the first line in lines whose
// trimmed content equals any of the supplied heading strings, or -1 when
// none is found.
func findSectionHeader(lines []string, headings ...string) int {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, h := range headings {
			if trimmed == h {
				return i
			}
		}
	}
	return -1
}

// extractDirFromBullet parses the directory string out of a bullet line of
// the shape "- `docs/audit-development-report-archive-YYYY-MM-DD/`：…".
// Returns the empty string when no backtick-quoted path is present.
func extractDirFromBullet(bullet string) string {
	start := strings.Index(bullet, "`")
	if start < 0 {
		return ""
	}
	end := strings.Index(bullet[start+1:], "`")
	if end < 0 {
		return ""
	}
	return bullet[start+1 : start+1+end]
}
