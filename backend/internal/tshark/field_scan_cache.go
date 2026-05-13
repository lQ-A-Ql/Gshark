package tshark

import (
	"container/list"
	"strings"
	"sync"
)

// maxFieldScanCacheEntries bounds the number of distinct top-level cache keys
// retained by fieldScanCache. A long analyst session that touches many
// (pcap × display-filter × occurrence × aggregator) combinations previously
// grew the cache without bound (P2-4 defect in iterative-dev-governance). A
// 256-entry ceiling keeps the working set small enough for typical sessions
// while still reusing projections for recently-active scans.
const maxFieldScanCacheEntries = 256

// fieldScanCache stores projected field-scan rows keyed by the deterministic
// cacheKey digest of fieldScanCacheParams. The byFile secondary index maps
// each filePath to the set of cacheKey strings that originated from that file,
// enabling O(1) purge-by-filePath in ClearFieldScanCache without scanning the
// entire primary map.
//
// Eviction: the cache tracks access order via lru (front = most-recently-used)
// with lruIndex providing O(1) element lookup. Any insertion of a new key
// above maxSize evicts the least-recently-used keys first. Lookups that find
// an entry promote that key to the front. keyFilePath enables O(1) byFile
// cleanup when a key is evicted.
var fieldScanCache = struct {
	mu          sync.Mutex
	entries     map[string][]*fieldScanCacheEntry
	byFile      map[string]map[string]struct{}
	lru         *list.List
	lruIndex    map[string]*list.Element
	keyFilePath map[string]string
	maxSize     int
}{
	entries:     map[string][]*fieldScanCacheEntry{},
	byFile:      map[string]map[string]struct{}{},
	lru:         list.New(),
	lruIndex:    map[string]*list.Element{},
	keyFilePath: map[string]string{},
	maxSize:     maxFieldScanCacheEntries,
}

// ClearFieldScanCache drops cached field-scan rows. A blank filePath wipes
// every entry (and resets the LRU state). A non-blank filePath drops only the
// entries that originated from that file path.
func ClearFieldScanCache(filePath string) {
	normalizedPath := strings.TrimSpace(filePath)
	fieldScanCache.mu.Lock()
	defer fieldScanCache.mu.Unlock()

	if normalizedPath == "" {
		fieldScanCache.entries = map[string][]*fieldScanCacheEntry{}
		fieldScanCache.byFile = map[string]map[string]struct{}{}
		fieldScanCache.lru.Init()
		fieldScanCache.lruIndex = map[string]*list.Element{}
		fieldScanCache.keyFilePath = map[string]string{}
		return
	}

	keys, ok := fieldScanCache.byFile[normalizedPath]
	if !ok {
		return
	}
	for key := range keys {
		delete(fieldScanCache.entries, key)
		if elem, present := fieldScanCache.lruIndex[key]; present {
			fieldScanCache.lru.Remove(elem)
			delete(fieldScanCache.lruIndex, key)
		}
		delete(fieldScanCache.keyFilePath, key)
	}
	delete(fieldScanCache.byFile, normalizedPath)
}

// findFieldScanCacheEntry searches the cached entries for the given key and
// returns the narrowest superset that can project the requested fields. On a
// hit the key is promoted to the front of the LRU list so it survives the
// next eviction sweep.
func findFieldScanCacheEntry(key string, fields []string) (*fieldScanCacheEntry, []int, bool) {
	fieldScanCache.mu.Lock()
	defer fieldScanCache.mu.Unlock()

	entries := fieldScanCache.entries[key]
	if len(entries) == 0 {
		return nil, nil, false
	}

	var (
		bestEntry   *fieldScanCacheEntry
		bestIndices []int
		bestWidth   int
	)
	for _, entry := range entries {
		indices, ok := buildFieldProjection(entry.fieldIndex, fields)
		if !ok {
			continue
		}
		if bestEntry == nil || len(entry.fields) < bestWidth {
			bestEntry = entry
			bestIndices = indices
			bestWidth = len(entry.fields)
		}
	}
	if bestEntry == nil {
		return nil, nil, false
	}
	touchFieldScanCacheLRULocked(key)
	return bestEntry, bestIndices, true
}

// storeFieldScanCacheEntry inserts (or refreshes) a cache entry under key. A
// brand-new key triggers LRU eviction when the cache is already at capacity;
// an existing key refreshes in place without evicting anything. In all cases
// the key ends up at the front of the LRU list.
func storeFieldScanCacheEntry(key string, filePath string, fields []string, rows [][]string) {
	entry := &fieldScanCacheEntry{
		fields:     append([]string(nil), fields...),
		fieldIndex: make(map[string]int, len(fields)),
		rows:       rows,
	}
	for idx, field := range fields {
		entry.fieldIndex[field] = idx
	}

	fieldScanCache.mu.Lock()
	defer fieldScanCache.mu.Unlock()

	_, keyExisted := fieldScanCache.entries[key]
	if !keyExisted {
		evictFieldScanCacheLRULocked()
	}

	existing := fieldScanCache.entries[key]
	for _, item := range existing {
		if sameFieldScanFields(item.fields, fields) {
			item.rows = rows
			item.fieldIndex = entry.fieldIndex
			touchFieldScanCacheLRULocked(key)
			return
		}
	}
	fieldScanCache.entries[key] = append(existing, entry)
	touchFieldScanCacheLRULocked(key)

	if filePath != "" {
		keys, ok := fieldScanCache.byFile[filePath]
		if !ok {
			keys = map[string]struct{}{}
			fieldScanCache.byFile[filePath] = keys
		}
		keys[key] = struct{}{}
		fieldScanCache.keyFilePath[key] = filePath
	}
}

// replayCachedFieldRows invokes onRow for every cached row, projecting it
// through indices so the caller only sees the columns they requested.
func replayCachedFieldRows(entry *fieldScanCacheEntry, indices []int, onRow func([]string)) {
	if onRow == nil {
		return
	}
	for _, row := range entry.rows {
		projected := make([]string, len(indices))
		for i, idx := range indices {
			if idx >= 0 && idx < len(row) {
				projected[i] = row[idx]
			}
		}
		onRow(projected)
	}
}

// buildFieldProjection returns, for each requested field, the column index of
// that field within a cached entry. If any field is absent, ok is false so
// findFieldScanCacheEntry can fall back to another candidate (or a fresh
// tshark scan).
func buildFieldProjection(fieldIndex map[string]int, fields []string) ([]int, bool) {
	indices := make([]int, 0, len(fields))
	for _, field := range fields {
		idx, ok := fieldIndex[field]
		if !ok {
			return nil, false
		}
		indices = append(indices, idx)
	}
	return indices, true
}

// touchFieldScanCacheLRULocked promotes key to the front of the LRU list,
// inserting it when it is not yet tracked. Callers MUST hold fieldScanCache.mu.
func touchFieldScanCacheLRULocked(key string) {
	if elem, ok := fieldScanCache.lruIndex[key]; ok {
		fieldScanCache.lru.MoveToFront(elem)
		return
	}
	elem := fieldScanCache.lru.PushFront(key)
	fieldScanCache.lruIndex[key] = elem
}

// evictFieldScanCacheLRULocked removes least-recently-used keys while the
// number of top-level keys is at or above maxSize, making room for at least
// one additional key. Callers MUST hold fieldScanCache.mu.
//
// The loop is bounded by lru.Len(); once the LRU list is empty the cache is
// already below any positive maxSize and further iteration would be a no-op.
func evictFieldScanCacheLRULocked() {
	maxSize := fieldScanCache.maxSize
	if maxSize <= 0 {
		maxSize = maxFieldScanCacheEntries
	}
	for len(fieldScanCache.entries) >= maxSize && fieldScanCache.lru.Len() > 0 {
		back := fieldScanCache.lru.Back()
		if back == nil {
			return
		}
		key, _ := back.Value.(string)
		fieldScanCache.lru.Remove(back)
		delete(fieldScanCache.lruIndex, key)
		delete(fieldScanCache.entries, key)
		if filePath, ok := fieldScanCache.keyFilePath[key]; ok {
			if keys, present := fieldScanCache.byFile[filePath]; present {
				delete(keys, key)
				if len(keys) == 0 {
					delete(fieldScanCache.byFile, filePath)
				}
			}
			delete(fieldScanCache.keyFilePath, key)
		}
	}
}
