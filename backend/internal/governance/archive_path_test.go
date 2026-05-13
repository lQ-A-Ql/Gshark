package governance

import (
	"math/rand"
	"reflect"
	"regexp"
	"testing"
	"testing/quick"
	"time"
)

// archivePathDirRe is the canonical form expected from
// ResolveArchivePath(date).Directory. The fixed prefix and trailing slash are
// literal, and the YYYY-MM-DD segment must be zero-padded to 4/2/2 digits
// respectively.
var archivePathDirRe = regexp.MustCompile(`^docs/audit-development-report-archive-\d{4}-\d{2}-\d{2}/$`)

// randomTime is a testing/quick Generator helper that produces a time.Time
// value covering roughly the year range 1 — 9999 in UTC. testing/quick cannot
// generate time.Time out of the box, so we wrap it in a named type that
// implements quick.Generator.
type randomTime struct {
	time.Time
}

// Generate satisfies quick.Generator. It picks a random calendar date in
// 0001-01-01 .. 9999-12-31 (UTC) by sampling a year and a day-of-year, which
// keeps generation cheap while still exercising leap years, month rollovers,
// and single-digit month/day values that must be zero-padded.
func (randomTime) Generate(r *rand.Rand, _ int) reflect.Value {
	// Year range: [1, 9999]. Using 1 as the low bound keeps us inside
	// time.Time's representable range while still producing 4-digit years
	// whose formatted form must be zero-padded (e.g. year 1 -> "0001").
	year := r.Intn(9999) + 1
	// Day-of-year: [0, 365]. time.Date normalises overflow into the next
	// month/year, so feeding any value in this range always yields a valid
	// calendar date — including Feb 29 on leap years and Dec 31 when the
	// sampled day lands there.
	dayOfYear := r.Intn(366)
	// Sub-day components exercise the HH:MM:SS formatter indirectly via
	// the Directory path (which only uses YYYY-MM-DD) but keep the
	// generator useful for neighbouring properties that reuse it.
	hour := r.Intn(24)
	minute := r.Intn(60)
	second := r.Intn(60)
	nanos := r.Intn(int(time.Second))
	t := time.Date(year, time.January, 1+dayOfYear, hour, minute, second, nanos, time.UTC)
	return reflect.ValueOf(randomTime{Time: t})
}

// Feature: iterative-dev-governance, Property 1: Archive path date formatting is correct
//
// Validates: Requirements 1.1
//
// For any valid time.Time, ResolveArchivePath(date).Directory must match
// `docs/audit-development-report-archive-YYYY-MM-DD/` with zero-padded
// four-digit year, two-digit month, and two-digit day.
func TestResolveArchivePath_DirectoryDateFormatting(t *testing.T) {
	property := func(rt randomTime) bool {
		got := ResolveArchivePath(rt.Time).Directory
		if !archivePathDirRe.MatchString(got) {
			t.Logf("directory %q did not match regex %s for date %s",
				got, archivePathDirRe, rt.Time.Format(time.RFC3339Nano))
			return false
		}
		// Also cross-check the embedded date literally matches the
		// zero-padded form produced by time.Format to guard against a
		// regression where the regex accidentally accepts something
		// other than the intended canonical encoding.
		want := "docs/audit-development-report-archive-" + rt.Time.Format("2006-01-02") + "/"
		if got != want {
			t.Logf("directory %q did not equal canonical form %q", got, want)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 1 failed: %v", err)
	}
}

// Feature: iterative-dev-governance, Property 9: Report writer does not append across date boundaries
//
// Validates: Requirements 8.3
//
// For any pair of time.Time values, the ReportFile paths returned by
// ResolveArchivePath must differ whenever the two inputs format to different
// YYYY-MM-DD strings, and must be identical when they format to the same
// YYYY-MM-DD string. This encodes the invariant that the report writer never
// appends a new round to a file belonging to a different calendar date: the
// path itself is the boundary, so two inputs on the same UTC day share a
// destination while inputs on different days resolve to distinct files.
func TestResolveArchivePath_NoCrossDateAppend(t *testing.T) {
	property := func(a, b randomTime) bool {
		dateA := a.Time.Format("2006-01-02")
		dateB := b.Time.Format("2006-01-02")
		fileA := ResolveArchivePath(a.Time).ReportFile
		fileB := ResolveArchivePath(b.Time).ReportFile

		if dateA != dateB {
			// Different calendar days must resolve to different report
			// files. If they happen to match, the writer would append
			// across a date boundary, violating Requirement 8.3.
			if fileA == fileB {
				t.Logf("different dates %q vs %q produced identical ReportFile %q",
					dateA, dateB, fileA)
				return false
			}
			return true
		}
		// Contrapositive: identical calendar days must resolve to the
		// same report file so same-day rounds share a destination.
		if fileA != fileB {
			t.Logf("same date %q produced different ReportFile values %q vs %q",
				dateA, fileA, fileB)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 9 failed: %v", err)
	}
}
