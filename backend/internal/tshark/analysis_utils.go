package tshark

import (
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// Generic analysis utilities shared across tshark analyzers.
//
// These helpers are deliberately protocol-agnostic: conversation bucket
// sorting, hex-byte parsing/formatting, and a flexible integer parser that
// accepts decimal or 0x-prefixed hex. They live outside the field-scan
// pipeline because multiple analyzers (industrial, vehicle, media) rely on
// them, and keeping them here prevents analysis_helpers.go from growing into
// a grab-bag again.

// conversationCount is the canonical intermediate representation for
// accumulating per-conversation counts before they are sorted and exposed as
// model.AnalysisConversation values.
type conversationCount struct {
	Label    string
	Protocol string
	Count    int
}

// sortConversationBuckets converts a label-keyed conversationCount map into a
// slice sorted by descending count, with label ascending as the tie-breaker.
// The total ordering keeps top-K output stable across runs.
func sortConversationBuckets(input map[string]conversationCount) []model.AnalysisConversation {
	items := make([]model.AnalysisConversation, 0, len(input))
	for _, item := range input {
		items = append(items, model.AnalysisConversation{
			Label:    item.Label,
			Protocol: item.Protocol,
			Count:    item.Count,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})
	return items
}

// previewHexBytes renders up to limit bytes from a colon-, space-, or
// whitespace-separated hex-byte string, appending ":..." when truncation
// occurs. A non-positive limit disables truncation.
func previewHexBytes(raw string, limit int) string {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return ""
	}
	if limit <= 0 || len(parts) <= limit {
		return strings.Join(parts, ":")
	}
	return strings.Join(parts[:limit], ":") + ":..."
}

// parseFlexibleInt accepts either a decimal integer or a 0x-prefixed hex
// integer and returns the parsed int value. On parse failure the zero value
// is returned so callers can treat empty/bad input as "no value".
func parseFlexibleInt(raw string) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		if value, err := strconv.ParseInt(trimmed[2:], 16, 64); err == nil {
			return int(value)
		}
	}
	if value, err := strconv.Atoi(trimmed); err == nil {
		return value
	}
	return 0
}

// splitHexBytes splits a hex-byte string on colons, spaces, tabs, or line
// breaks and returns the non-empty tokens. This is the inverse of
// normalizeHexBytes for input that mixes separators.
func splitHexBytes(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// normalizeHexBytes splits raw into hex tokens and rejoins them with colons,
// producing a canonical "AA:BB:CC" representation regardless of the input's
// original separator style.
func normalizeHexBytes(raw string) string {
	parts := splitHexBytes(raw)
	return strings.Join(parts, ":")
}

// formatHex uppercases the hex portion of a 0x-prefixed value (lowercase x
// becomes uppercase X). Non-prefixed input is returned trimmed only. The
// upper-case form keeps CAN / UDS / OBD renderings consistent with the rest
// of the vehicle/industrial analyzers' output conventions.
func formatHex(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "0x") {
		return "0X" + trimmed[2:]
	}
	return trimmed
}
