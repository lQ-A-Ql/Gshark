package tshark

import (
	"fmt"
	"sort"
	"strings"
)

// Field-scan capability-degradation note builders.
//
// When a tshark build lacks one or more optional fields requested by a
// feature, the field-scan planner quietly drops them from the query and
// returns blanks for the affected columns. To keep operators informed, the
// HTTP layer surfaces a human-readable note per feature that enumerates the
// missing fields. These helpers centralize the note-rendering contract so
// the wording stays consistent across features (USB / media / industrial).

// appendTSharkFieldDegradationNote appends a degradation note to the notes
// slice when any optional fields were missing. It is safe to call with an
// empty missingOptional slice — the slice is returned unchanged.
func appendTSharkFieldDegradationNote(notes []string, scope string, missingOptional []string) []string {
	note := buildTSharkFieldDegradationNote(scope, missingOptional)
	if note == "" {
		return notes
	}
	return append(notes, note)
}

// buildTSharkFieldDegradationNote renders a single Chinese-language note
// describing how many optional fields the current tshark build lacks within
// the supplied scope. The note caps the displayed field list at eight items
// (the remainder is summarized as "等，另有 N 个字段"), which is enough to
// give operators a grip on the degradation without overwhelming the UI.
func buildTSharkFieldDegradationNote(scope string, missingOptional []string) string {
	fields := normalizeFieldScanFields(missingOptional)
	if len(fields) == 0 {
		return ""
	}
	sort.Strings(fields)
	displayFields := fields
	const maxDisplayedFields = 8
	if len(displayFields) > maxDisplayedFields {
		displayFields = displayFields[:maxDisplayedFields]
	}
	more := ""
	if hidden := len(fields) - len(displayFields); hidden > 0 {
		more = fmt.Sprintf(" 等，另有 %d 个字段", hidden)
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "TShark 字段扫描"
	}
	return fmt.Sprintf("%s：当前 tshark 缺少 %d 个可选字段（%s%s），相关列已按空值降级；如该页结果异常偏少，建议升级 Wireshark/tshark 或切换 tshark 路径。",
		scope,
		len(fields),
		strings.Join(displayFields, ", "),
		more,
	)
}
