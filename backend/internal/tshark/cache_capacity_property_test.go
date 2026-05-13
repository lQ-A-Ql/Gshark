package tshark

import (
	"container/list"
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

// Feature: iterative-dev-governance, Property 14: Field scan cache never exceeds configured capacity
//
// Validates: Requirements 6.5
//
// The field-scan cache must never grow beyond its configured maxSize no
// matter how many distinct cache keys are inserted. LRU eviction should
// drop least-recently-used keys the moment a new key would push the total
// count above the cap. This property protects long analyst sessions from
// unbounded memory growth (P2-4 defect).
//
// Strategy: for a random maxSize in [1, 1000] and a random insertion
// sequence of up to 3×maxSize distinct keys, verify that len(entries)
// never exceeds maxSize after any store. Keys are synthesised from an
// incrementing counter so each insertion creates a genuinely new key and
// stresses the eviction path on every iteration.
func TestFieldScanCacheCapacityInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		maxSize := rapid.IntRange(1, 1000).Draw(t, "maxSize")
		numInserts := rapid.IntRange(0, maxSize*3).Draw(t, "numInserts")

		// Snapshot and restore the shared cache state so this property
		// test does not leak into — or inherit from — sibling tests.
		fieldScanCache.mu.Lock()
		origEntries := fieldScanCache.entries
		origByFile := fieldScanCache.byFile
		origLRU := fieldScanCache.lru
		origLRUIndex := fieldScanCache.lruIndex
		origKeyFilePath := fieldScanCache.keyFilePath
		origMaxSize := fieldScanCache.maxSize

		fieldScanCache.entries = map[string][]*fieldScanCacheEntry{}
		fieldScanCache.byFile = map[string]map[string]struct{}{}
		fieldScanCache.lru = list.New()
		fieldScanCache.lruIndex = map[string]*list.Element{}
		fieldScanCache.keyFilePath = map[string]string{}
		fieldScanCache.maxSize = maxSize
		fieldScanCache.mu.Unlock()

		defer func() {
			fieldScanCache.mu.Lock()
			fieldScanCache.entries = origEntries
			fieldScanCache.byFile = origByFile
			fieldScanCache.lru = origLRU
			fieldScanCache.lruIndex = origLRUIndex
			fieldScanCache.keyFilePath = origKeyFilePath
			fieldScanCache.maxSize = origMaxSize
			fieldScanCache.mu.Unlock()
		}()

		for i := 0; i < numInserts; i++ {
			key := fmt.Sprintf("pbt-key-%d", i)
			// Rotate over a handful of synthetic file paths so byFile
			// cleanup during eviction is exercised alongside the primary
			// entry map.
			filePath := fmt.Sprintf("pbt-file-%d.pcap", i%7)
			storeFieldScanCacheEntry(
				key,
				filePath,
				[]string{"frame.number"},
				[][]string{{fmt.Sprintf("%d", i)}},
			)

			fieldScanCache.mu.Lock()
			size := len(fieldScanCache.entries)
			lruLen := fieldScanCache.lru.Len()
			indexLen := len(fieldScanCache.lruIndex)
			fieldScanCache.mu.Unlock()

			if size > maxSize {
				t.Fatalf("entries map exceeded capacity after insert %d: size=%d maxSize=%d", i+1, size, maxSize)
			}
			if lruLen != size {
				t.Fatalf("lru length %d diverged from entries size %d after insert %d", lruLen, size, i+1)
			}
			if indexLen != size {
				t.Fatalf("lruIndex length %d diverged from entries size %d after insert %d", indexLen, size, i+1)
			}
		}
	})
}
