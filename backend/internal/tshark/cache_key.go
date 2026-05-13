package tshark

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// fieldScanCacheParams captures every scan parameter that influences the
// content of a cached field scan result. Any new scan parameter that can
// change the produced rows must be added here so cacheKey remains the single
// canonical digest of the cache inputs.
//
// The field ordering is stable by contract: encoding/json serialises struct
// fields in declaration order, which — combined with deterministic primitive
// encoding — makes the resulting JSON (and therefore the SHA-256 digest) a
// total function of the parameter values.
type fieldScanCacheParams struct {
	FilePath      string
	DisplayFilter string
	Occurrence    string
	Aggregator    string
}

// cacheKey returns a deterministic, collision-resistant hex string for the
// supplied scan parameters.
//
// Determinism: the same params value always produces the same key, because
// encoding/json marshals struct fields in declaration order and we hash the
// resulting bytes with SHA-256. If json.Marshal ever returns an error for an
// unexpected future field type, we fall back to fmt.Sprintf("%#v", params) so
// the function stays total; %#v is deterministic for value types composed of
// strings.
func cacheKey(params fieldScanCacheParams) string {
	encoded, err := json.Marshal(params)
	if err != nil {
		encoded = []byte(fmt.Sprintf("%#v", params))
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum)
}

// buildFieldScanCacheParams assembles a fieldScanCacheParams value from the
// same trimmed/normalised inputs the cache lookup path requires. Keeping the
// normalisation centralised here guarantees that every reader and writer
// computes the same cache key for the same logical scan.
func buildFieldScanCacheParams(filePath string, opts fieldScanOptions) fieldScanCacheParams {
	return fieldScanCacheParams{
		FilePath:      strings.TrimSpace(filePath),
		DisplayFilter: opts.DisplayFilter,
		Occurrence:    opts.Occurrence,
		Aggregator:    opts.Aggregator,
	}
}
