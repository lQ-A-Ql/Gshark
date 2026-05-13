package governance

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// -----------------------------------------------------------------------------
// Generators
// -----------------------------------------------------------------------------

// randomRoundReport wraps RoundReport with a testing/quick Generate hook.
// testing/quick cannot synthesise time.Time or heterogeneous struct fields on
// its own, so the wrapper builds a fully-populated RoundReport with fields
// drawn from simpler primitive sources. The fields are chosen to exercise
// the branches in RenderRoundReport without ever colliding with the literal
// section headings the renderer emits (which would otherwise confuse the
// `strings.Index`-based ordering checks in Property 2 or the substring check
// in Property 4).
type randomRoundReport struct {
	RoundReport
}

// Generate satisfies quick.Generator. Timezone is intentionally pinned to
// "+08:00" to keep Property 3's timestamp regex strict — the renderer
// honours whatever value the caller supplies, so any other zone would
// legitimately change the rendered suffix and weaken the header invariant.
func (randomRoundReport) Generate(r *rand.Rand, size int) reflect.Value {
	// Reuse the randomTime generator declared in archive_path_test.go so
	// the date/time distribution matches Property 1/9 tests and naturally
	// exercises zero-padded month/day values.
	rtv := randomTime{}.Generate(r, size)
	rt := rtv.Interface().(randomTime)

	// Generate 0..5 modified file paths. Paths are constrained to a shape
	// that cannot accidentally contain Markdown section headings, so
	// Property 4's substring check is not fooled by collisions between
	// user data and the renderer's own headings.
	numFiles := r.Intn(6)
	files := make([]string, 0, numFiles)
	for i := 0; i < numFiles; i++ {
		files = append(files, fmt.Sprintf(
			"backend/internal/pkg%d/file_%d_%d.go",
			r.Intn(32), i, r.Intn(1_000_000),
		))
	}

	// Priority is picked from the four canonical tiers. Title and
	// Description are random integer-suffixed strings that do not contain
	// any of the five required section headings.
	priorities := []Priority{PriorityP0, PriorityP1, PriorityP2, PriorityP3}
	priority := priorities[r.Intn(len(priorities))]
	defect := DefectEntry{
		ID:          fmt.Sprintf("%s-%d", priority, r.Intn(20)+1),
		Priority:    priority,
		Title:       fmt.Sprintf("random defect title %d", r.Intn(1_000_000)),
		Description: fmt.Sprintf("random defect description %d", r.Intn(1_000_000)),
		Status:      DefectOpen,
	}

	validations := []ValidationResult{{
		Command: "go test ./...",
		Pass:    r.Intn(2) == 0,
		Output:  fmt.Sprintf("validation output %d", r.Intn(1_000_000)),
	}}

	report := RoundReport{
		RoundNumber:     r.Intn(1000) + 1,
		Author:          "Codex",
		Timestamp:       rt.Time,
		Timezone:        "+08:00",
		Defect:          defect,
		ModifiedFiles:   files,
		Validations:     validations,
		RisksAndDefects: fmt.Sprintf("risks body %d", r.Intn(1_000_000)),
		NextSteps:       fmt.Sprintf("next steps body %d", r.Intn(1_000_000)),
	}
	return reflect.ValueOf(randomRoundReport{RoundReport: report})
}

// positiveInt is a testing/quick Generator that produces strictly positive
// int values. It is used by Property 8 where the Self-Audit round number is
// required to be positive.
type positiveInt int

// Generate satisfies quick.Generator. The value range is [1, MaxInt32] which
// is wide enough to exercise multi-digit formatting without risking int
// overflow on 32-bit platforms.
func (positiveInt) Generate(r *rand.Rand, _ int) reflect.Value {
	n := r.Intn(math.MaxInt32) + 1
	return reflect.ValueOf(positiveInt(n))
}

// randomSelfAuditReport wraps SelfAuditReport so testing/quick can produce
// values with a non-empty CompletedDefects slice, which is the precondition
// of Property 10.
type randomSelfAuditReport struct {
	SelfAuditReport
}

// Generate satisfies quick.Generator. CompletedDefects is guaranteed to hold
// at least one closure so the property's "non-empty" precondition always
// holds. Defect IDs follow the "P<tier>-<n>" shape and round numbers are
// drawn from a range wide enough to exercise multi-digit decimal formatting.
func (randomSelfAuditReport) Generate(r *rand.Rand, size int) reflect.Value {
	rt := randomTime{}.Generate(r, size).Interface().(randomTime)

	count := r.Intn(5) + 1 // [1, 5]
	closures := make([]DefectClosure, 0, count)
	for i := 0; i < count; i++ {
		closures = append(closures, DefectClosure{
			DefectID:    fmt.Sprintf("P%d-%d", r.Intn(4), r.Intn(99)+1),
			Title:       fmt.Sprintf("closed defect %d", r.Intn(1_000_000)),
			ResolvedAt:  rt.Time,
			RoundNumber: r.Intn(1_000_000) + 1,
		})
	}

	report := SelfAuditReport{
		RoundNumber:      (r.Intn(100) + 1) * 10,
		Timestamp:        rt.Time,
		CompletedDefects: closures,
		DriftDetected:    r.Intn(2) == 0,
		DriftDescription: fmt.Sprintf("drift note %d", r.Intn(1_000_000)),
		PriorityAdjusted: r.Intn(2) == 0,
		DirectionNote:    fmt.Sprintf("direction note %d", r.Intn(1_000_000)),
		CIGateResult: ValidationResult{
			Command: "./scripts/check-all.ps1",
			Pass:    r.Intn(2) == 0,
			Output:  fmt.Sprintf("ci output %d", r.Intn(1_000_000)),
		},
	}
	return reflect.ValueOf(randomSelfAuditReport{SelfAuditReport: report})
}

// -----------------------------------------------------------------------------
// Property 2
// -----------------------------------------------------------------------------

// Feature: iterative-dev-governance, Property 2: Round_Report contains all required sections in order
//
// Validates: Requirements 1.2
//
// For any RoundReport, RenderRoundReport must emit the five required section
// headings — 本轮目标、已完成改动、验证记录、当前缺陷与风险、下一步建议 — and
// they must appear in that order in the rendered Markdown.
func TestRenderRoundReport_SectionsInOrder(t *testing.T) {
	requiredHeadings := []string{
		"## 本轮目标",
		"## 已完成改动",
		"## 验证记录",
		"## 当前缺陷与风险",
		"## 下一步建议",
	}

	property := func(rr randomRoundReport) bool {
		out := RenderRoundReport(rr.RoundReport)

		indices := make([]int, len(requiredHeadings))
		for i, h := range requiredHeadings {
			idx := strings.Index(out, h)
			if idx < 0 {
				t.Logf("required heading %q missing from rendered report", h)
				return false
			}
			indices[i] = idx
		}
		for i := 1; i < len(indices); i++ {
			if indices[i] <= indices[i-1] {
				t.Logf("heading order violated: %q at %d came before %q at %d",
					requiredHeadings[i], indices[i],
					requiredHeadings[i-1], indices[i-1])
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 2 failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Property 3
// -----------------------------------------------------------------------------

// headerTimestampRe matches the canonical 日期 line. The "+" in "+08:00" is
// a regex meta-character and must be escaped.
var headerTimestampRe = regexp.MustCompile(`^日期: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00$`)

// Feature: iterative-dev-governance, Property 3: Round_Report header contains author and timestamp
//
// Validates: Requirements 1.3
//
// For any RoundReport, the first ten lines of the rendered report must
// contain both `署名: Codex` and a line matching
// `日期: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00`.
func TestRenderRoundReport_HeaderHasAuthorAndTimestamp(t *testing.T) {
	property := func(rr randomRoundReport) bool {
		out := RenderRoundReport(rr.RoundReport)
		// Limit to the first ten lines. strings.SplitN with n=11 yields
		// at most eleven parts; we only inspect the first ten so that
		// extra tail content cannot satisfy the invariant retroactively.
		parts := strings.SplitN(out, "\n", 11)
		head := parts
		if len(head) > 10 {
			head = head[:10]
		}

		var sawAuthor, sawTimestamp bool
		for _, line := range head {
			if line == "署名: Codex" {
				sawAuthor = true
			}
			if headerTimestampRe.MatchString(line) {
				sawTimestamp = true
			}
		}
		if !sawAuthor {
			t.Logf("author line `署名: Codex` not found in first 10 lines: %q", head)
			return false
		}
		if !sawTimestamp {
			t.Logf("timestamp line matching %s not found in first 10 lines: %q",
				headerTimestampRe, head)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 3 failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Property 4
// -----------------------------------------------------------------------------

// extractSection returns the body of the Markdown section whose `## `
// heading equals `heading`. The body is everything between the heading line
// and the next `## ` heading (or end-of-document). Returns ("", false) when
// the heading is absent.
func extractSection(rendered, heading string) (string, bool) {
	start := strings.Index(rendered, heading)
	if start < 0 {
		return "", false
	}
	// Skip past the heading line itself.
	from := start + len(heading)
	// Find the next "## " that begins on its own line after the heading.
	rest := rendered[from:]
	rel := strings.Index(rest, "\n## ")
	if rel < 0 {
		return rest, true
	}
	return rest[:rel], true
}

// Feature: iterative-dev-governance, Property 4: Modified files are all listed in 已完成改动
//
// Validates: Requirements 1.6
//
// For any RoundReport, every path in ModifiedFiles must appear as a
// substring of the rendered 已完成改动 section.
func TestRenderRoundReport_ModifiedFilesListed(t *testing.T) {
	property := func(rr randomRoundReport) bool {
		out := RenderRoundReport(rr.RoundReport)
		section, ok := extractSection(out, "## 已完成改动")
		if !ok {
			t.Logf("`## 已完成改动` section missing from rendered report")
			return false
		}
		for _, f := range rr.ModifiedFiles {
			if !strings.Contains(section, f) {
				t.Logf("modified file %q missing from 已完成改动 section:\n%s", f, section)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 4 failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Property 5
// -----------------------------------------------------------------------------

// progressHeadingRe matches the canonical Progress Update heading. The `+`
// in `+08:00` is a regex meta-character and must be escaped. `^` / `$`
// anchor the match to the entire heading so stray prefixes/suffixes fail.
var progressHeadingRe = regexp.MustCompile(`^## Progress Update - \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00$`)

// Feature: iterative-dev-governance, Property 5: Progress Update heading uses correct format
//
// Validates: Requirements 1.5
//
// For any time.Time, RenderProgressUpdateHeading must produce a string that
// matches `## Progress Update - YYYY-MM-DD HH:MM:SS +08:00` with correct
// zero-padding on every date and time component.
func TestRenderProgressUpdateHeading_Format(t *testing.T) {
	property := func(rt randomTime) bool {
		got := RenderProgressUpdateHeading(rt.Time)
		if !progressHeadingRe.MatchString(got) {
			t.Logf("heading %q did not match %s (for time %s)",
				got, progressHeadingRe, rt.Time.Format(time.RFC3339Nano))
			return false
		}
		// Cross-check the embedded date/time against the canonical form
		// produced by time.Format to catch regressions where the regex
		// happens to accept something other than the intended encoding.
		want := "## Progress Update - " + rt.Time.Format("2006-01-02 15:04:05") + " +08:00"
		if got != want {
			t.Logf("heading %q did not equal canonical form %q", got, want)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 5 failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Property 8
// -----------------------------------------------------------------------------

// Feature: iterative-dev-governance, Property 8: Self-Audit heading contains correct round number
//
// Validates: Requirements 3.2
//
// For any positive integer N, RenderSelfAuditHeading(N) must equal exactly
// fmt.Sprintf("## Self-Audit Round %d", N).
func TestRenderSelfAuditHeading_Format(t *testing.T) {
	property := func(n positiveInt) bool {
		got := RenderSelfAuditHeading(int(n))
		want := fmt.Sprintf("## Self-Audit Round %d", int(n))
		if got != want {
			t.Logf("RenderSelfAuditHeading(%d) = %q, want %q", int(n), got, want)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 8 failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Property 10
// -----------------------------------------------------------------------------

// Feature: iterative-dev-governance, Property 10: Defect closure table contains all resolved defects
//
// Validates: Requirements 8.6
//
// For any SelfAuditReport with a non-empty CompletedDefects slice, the
// rendered output of RenderSelfAuditReport must contain every
// DefectClosure.DefectID and its RoundNumber (as a decimal string).
func TestRenderSelfAuditReport_ClosureTableComplete(t *testing.T) {
	property := func(rr randomSelfAuditReport) bool {
		out := RenderSelfAuditReport(rr.SelfAuditReport)
		for _, c := range rr.CompletedDefects {
			if !strings.Contains(out, c.DefectID) {
				t.Logf("DefectID %q missing from rendered self-audit report:\n%s",
					c.DefectID, out)
				return false
			}
			roundStr := fmt.Sprintf("%d", c.RoundNumber)
			if !strings.Contains(out, roundStr) {
				t.Logf("RoundNumber %q (for %s) missing from rendered self-audit report:\n%s",
					roundStr, c.DefectID, out)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 10 failed: %v", err)
	}
}
