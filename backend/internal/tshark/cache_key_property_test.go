package tshark

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: iterative-dev-governance, Property 12: Field scan cache key is deterministic and collision-resistant
//
// Validates: Requirements 4.3
//
// cacheKey turns a fieldScanCacheParams value into the hex digest used as the
// key in the field-scan cache. Two properties must hold for any random
// parameter value produced by rapid:
//
//  1. Determinism — calling cacheKey twice with the same input returns the
//     same digest. Any non-determinism (e.g. map iteration order, time, or
//     pointer addresses leaking into the digest) would cause cache misses
//     for otherwise-identical scans.
//  2. Collision resistance under distinctness — two parameter values that
//     differ in at least one field must produce different digests. A
//     collision here would let one scan's rows serve a different scan,
//     leaking results across display filters, occurrences, aggregators, or
//     even distinct pcap files.
//
// Each field is drawn independently with rapid.String(), which generates the
// full Unicode range including empty strings, so the test also covers the
// edge cases where individual fields are blank.
func TestCacheKey_DeterministicAndCollisionResistant(t *testing.T) {
	genParams := rapid.Custom(func(t *rapid.T) fieldScanCacheParams {
		return fieldScanCacheParams{
			FilePath:      rapid.String().Draw(t, "file_path"),
			DisplayFilter: rapid.String().Draw(t, "display_filter"),
			Occurrence:    rapid.String().Draw(t, "occurrence"),
			Aggregator:    rapid.String().Draw(t, "aggregator"),
		}
	})

	// (1) Determinism: cacheKey(p) == cacheKey(p) for any p.
	rapid.Check(t, func(t *rapid.T) {
		p := genParams.Draw(t, "params")
		k1 := cacheKey(p)
		k2 := cacheKey(p)
		if k1 != k2 {
			t.Fatalf("cacheKey not deterministic: %q vs %q for %+v", k1, k2, p)
		}
	})

	// (2) Collision resistance: for any two distinct parameter values a and
	// b (distinct = at least one field differs), cacheKey(a) != cacheKey(b).
	rapid.Check(t, func(t *rapid.T) {
		a := genParams.Draw(t, "a")
		b := genParams.Draw(t, "b")
		if a == b {
			return
		}
		ka := cacheKey(a)
		kb := cacheKey(b)
		if ka == kb {
			t.Fatalf("cacheKey collision: %+v and %+v both produced %q", a, b, ka)
		}
	})
}
