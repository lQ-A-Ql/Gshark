package tshark

import "strings"

// Field-scan normalization helpers.
//
// These utilities are the single source of truth for trimming, deduping, and
// padding field-scan inputs before they reach the tshark subprocess or the
// field-scan cache. Keeping them in a dedicated file clarifies the shape of
// the data flowing through scanFieldRowsWithOptions and makes it easier to
// reason about cache-key determinism (every caller shares the exact same
// normalization).

// normalizeFieldScanOptions trims whitespace from option strings and applies
// the tshark defaults used whenever an option is blank. The returned value
// feeds into buildFieldScanCacheParams, which is hashed to form the cache
// key — so any change here affects cache-lookup equality.
func normalizeFieldScanOptions(opts fieldScanOptions) fieldScanOptions {
	return fieldScanOptions{
		DisplayFilter: strings.TrimSpace(opts.DisplayFilter),
		Occurrence:    FirstNonEmpty(strings.TrimSpace(opts.Occurrence), "f"),
		Aggregator:    FirstNonEmpty(strings.TrimSpace(opts.Aggregator), ","),
	}
}

// normalizeFieldScanFields trims, drops blanks, and dedupes the supplied
// field slice while preserving caller-supplied order. The order is part of
// the output contract: planFieldScanByCapabilities relies on it to build a
// stable projection from tshark fields back to requested columns.
func normalizeFieldScanFields(fields []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.TrimSpace(field)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// normalizeFieldScanRow pads or truncates parts so its length matches the
// expected width. tshark occasionally emits rows with fewer separators than
// requested fields (trailing empty columns collapse), and defensive callers
// must never index out of range.
func normalizeFieldScanRow(parts []string, width int) []string {
	if len(parts) == width {
		return parts
	}
	if len(parts) > width {
		return parts[:width]
	}
	out := make([]string, width)
	copy(out, parts)
	return out
}

// sameFieldScanFields returns true when left and right contain the same
// fields in the same order. Used by the cache to detect exact column-set
// hits versus superset hits that need projection.
func sameFieldScanFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// unionFieldScanFields merges multiple field groups into a single trimmed,
// deduped slice, preserving first-seen order. Warm-plan construction relies
// on this to combine per-protocol field lists without repeating any field.
func unionFieldScanFields(groups ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 256)
	for _, group := range groups {
		for _, field := range group {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			out = append(out, field)
		}
	}
	return out
}
