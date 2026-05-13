package governance

import "sort"

// priorityOrder lists the Priority values in the exact order the
// Round_Controller must consider them: P0 first, P3 last. Keeping it as a
// package-level slice makes the iteration order explicit and keeps NextTask
// independent of any map iteration randomness.
var priorityOrder = []Priority{
	PriorityP0,
	PriorityP1,
	PriorityP2,
	PriorityP3,
}

// NextTask returns the highest-priority open defect in the register along
// with ok=true, or a zero-valued DefectEntry with ok=false when every entry
// has been resolved.
//
// The selection rule, taken from design.md Property 6 and Requirements 2.4 /
// 4.1, is:
//
//  1. Iterate priorities in the fixed order P0 → P1 → P2 → P3.
//  2. Within a priority tier, pick the first open defect by lexicographic ID
//     order (defect IDs follow the "P<n>-<m>" pattern).
//  3. If no tier has an open defect, return the zero value with ok=false.
//
// NextTask is a pure function: it does not mutate the input register.
func NextTask(register DefectRegister) (DefectEntry, bool) {
	for _, p := range priorityOrder {
		var candidates []DefectEntry
		for _, entry := range register.Entries {
			if entry.Priority == p && entry.Status == DefectOpen {
				candidates = append(candidates, entry)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].ID < candidates[j].ID
		})
		return candidates[0], true
	}
	return DefectEntry{}, false
}
