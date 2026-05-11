package engine

import (
	"fmt"
	"strconv"
	"strings"
)

func threatLevelToSeverity(level string) string {
	switch level {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func confidenceToSeverity(confidence int) string {
	if confidence <= 0 {
		return "info"
	}
	if confidence >= 85 {
		return "critical"
	}
	if confidence >= 70 {
		return "high"
	}
	if confidence >= 45 {
		return "medium"
	}
	return "low"
}

func evidenceCaveats(confidence int, sourceModule string) []string {
	var caveats []string
	if confidence <= 0 {
		caveats = append(caveats, "缺少置信度字段，当前仅作为线索展示。")
	} else if confidence < 45 {
		caveats = append(caveats, "低置信信号，必须结合上下文人工复核。")
	} else if confidence < 75 {
		caveats = append(caveats, "中置信信号，不应单独作为强归因结论。")
	}
	if sourceModule == "" {
		caveats = append(caveats, "缺少来源模块标识，证据链追溯能力受限。")
	}
	return caveats
}

func normalizeServiceID(serviceID string) string {
	trimmed := strings.ToLower(strings.TrimSpace(serviceID))
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "0x") {
		return trimmed
	}
	if parsed, err := strconv.ParseInt(trimmed, 0, 64); err == nil {
		return fmt.Sprintf("0x%02x", parsed)
	}
	return trimmed
}

func compactStrings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
