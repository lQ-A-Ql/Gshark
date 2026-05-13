package governance

import (
	"fmt"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// priorityOrdinal converts a Priority constant to the integer ordering used
// by Property 6: P0 is the highest priority (ordinal 0) and P3 is the lowest
// (ordinal 3). Any unknown value is mapped to a sentinel above the valid
// range so that generator bugs surface as explicit test failures rather than
// silent ordering anomalies.
func priorityOrdinal(p Priority) int {
	switch p {
	case PriorityP0:
		return 0
	case PriorityP1:
		return 1
	case PriorityP2:
		return 2
	case PriorityP3:
		return 3
	default:
		return 99
	}
}

// genDefectEntry builds a rapid generator that produces a random DefectEntry
// suitable for Property 6. It only randomises the fields that influence task
// selection (Priority, Status, ID); the descriptive fields are left empty
// since the property does not depend on them and omitting them keeps shrunk
// counter-examples readable.
//
// The Status is skewed toward DefectOpen (roughly 3:1) so that most generated
// registers contain at least one open defect, which is the interesting case
// for the property. The fully-resolved case is still reachable — and is
// exercised explicitly by the ok==false branch of the assertion.
//
// IDs are generated in the canonical "P<priority>-<n>" form (e.g. "P0-3")
// with n drawn from a bounded range so that within-priority tie-breaking by
// lexicographic ID order is properly exercised.
func genDefectEntry() *rapid.Generator[DefectEntry] {
	return rapid.Custom(func(t *rapid.T) DefectEntry {
		priorities := []Priority{PriorityP0, PriorityP1, PriorityP2, PriorityP3}
		prio := rapid.SampledFrom(priorities).Draw(t, "priority")

		// Skew toward open (3:1) by drawing from a 4-element slice
		// containing three open values and one resolved value.
		statuses := []DefectStatus{DefectOpen, DefectOpen, DefectOpen, DefectResolved}
		status := rapid.SampledFrom(statuses).Draw(t, "status")

		// ID suffix in [0, 19] gives enough variety to exercise
		// lexicographic ordering without bloating counter-examples.
		idSuffix := rapid.IntRange(0, 19).Draw(t, "id_suffix")
		id := fmt.Sprintf("%s-%d", prio, idSuffix)

		return DefectEntry{
			ID:       id,
			Priority: prio,
			Status:   status,
		}
	})
}

// Feature: iterative-dev-governance, Property 6: Task selector always returns highest-priority open defect
//
// Validates: Requirements 2.4, 4.1
//
// For any DefectRegister containing a mix of P0–P3 entries with random
// open/resolved status:
//
//   - If at least one entry is open, NextTask must return ok=true and a
//     DefectEntry whose Priority has the minimum ordinal (P0 < P1 < P2 < P3)
//     among all open entries, and the returned entry itself must still be
//     open and must actually exist in the input register.
//   - If no entry is open (empty register or all entries resolved), NextTask
//     must return ok=false and the zero-valued DefectEntry.
func TestNextTask_ReturnsHighestPriorityOpenDefect(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		entries := rapid.SliceOfN(genDefectEntry(), 0, 20).Draw(t, "entries")
		register := DefectRegister{Entries: entries}

		got, ok := NextTask(register)

		// Compute the minimum open-priority ordinal independently of the
		// implementation so the assertion cannot silently agree with a
		// buggy selector.
		minOrdinal := -1
		hasOpen := false
		for _, e := range entries {
			if e.Status != DefectOpen {
				continue
			}
			ord := priorityOrdinal(e.Priority)
			if !hasOpen || ord < minOrdinal {
				minOrdinal = ord
				hasOpen = true
			}
		}

		if !hasOpen {
			if ok {
				t.Fatalf("expected ok=false when no open defects exist, got ok=true entry=%+v", got)
			}
			if !reflect.DeepEqual(got, DefectEntry{}) {
				t.Fatalf("expected zero-valued DefectEntry when ok=false, got %+v", got)
			}
			return
		}

		if !ok {
			t.Fatalf("expected ok=true when open defects exist, got ok=false (entries=%+v)", entries)
		}
		if got.Status != DefectOpen {
			t.Fatalf("NextTask returned a non-open defect: %+v", got)
		}
		if gotOrd := priorityOrdinal(got.Priority); gotOrd != minOrdinal {
			t.Fatalf("NextTask returned priority %s (ordinal %d); expected ordinal %d (entries=%+v)",
				got.Priority, gotOrd, minOrdinal, entries)
		}

		// The returned entry must be one of the inputs, not a fabricated
		// value that merely happens to satisfy the priority check.
		found := false
		for _, e := range entries {
			if reflect.DeepEqual(e, got) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("NextTask returned entry %+v not present in register entries=%+v", got, entries)
		}
	})
}
