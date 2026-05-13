package governance

import (
	"testing"
	"testing/quick"
)

// Feature: iterative-dev-governance, Property 7: Self-Audit trigger fires exactly on multiples of ten
//
// Validates: Requirements 3.1
//
// For any integer n, ShouldTriggerSelfAudit(n) must return true if and only
// if n > 0 && n%10 == 0. The property is verified via:
//
//  1. A small hand-picked edge-case table covering 0, 1, 9, 10, 11, -1, -10,
//     20, 99, and 100 — these make the boundary behaviour (zero, negative
//     multiples of ten, and the first/last multiple in a decade) explicit
//     and easy to read in failure output.
//  2. A testing/quick.Check pass over randomly generated int values. Note
//     that quick.Check on `func(n int) bool` generates negative, zero, and
//     positive values, so the random pass exercises the `n > 0` guard in
//     addition to the `n%10 == 0` clause.
func TestShouldTriggerSelfAudit(t *testing.T) {
	// Hand-picked edge cases. Each entry exercises a specific boundary
	// documented in design.md (Self-Audit Trigger section).
	edgeCases := []struct {
		n    int
		want bool
	}{
		{0, false},   // zero is not a positive multiple of ten
		{1, false},   // first positive non-multiple
		{9, false},   // last positive value before the first trigger
		{10, true},   // first positive multiple of ten
		{11, false},  // immediately after a trigger
		{-1, false},  // negative non-multiple
		{-10, false}, // negative multiple — excluded by the n > 0 guard
		{20, true},   // second positive multiple
		{99, false},  // positive non-multiple near 100
		{100, true},  // larger positive multiple of ten
	}
	for _, tc := range edgeCases {
		if got := ShouldTriggerSelfAudit(tc.n); got != tc.want {
			t.Errorf("ShouldTriggerSelfAudit(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}

	// Property: for any int n, ShouldTriggerSelfAudit(n) == (n > 0 && n%10 == 0).
	// testing/quick generates both negative and non-negative ints, so the
	// guard on n > 0 is exercised naturally without a custom generator.
	property := func(n int) bool {
		want := n > 0 && n%10 == 0
		got := ShouldTriggerSelfAudit(n)
		if got != want {
			t.Logf("ShouldTriggerSelfAudit(%d) = %v, want %v", n, got, want)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatalf("Property 7 failed: %v", err)
	}
}
