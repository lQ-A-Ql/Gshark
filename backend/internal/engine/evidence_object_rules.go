package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func objectEvidenceProfile(obj model.ObjectFile) (confidence int, kind string, severity string) {
	lowerMagic := strings.ToLower(strings.TrimSpace(obj.Magic))
	lowerMime := strings.ToLower(strings.TrimSpace(obj.MIME))

	switch {
	case strings.HasPrefix(lowerMagic, "pe/") || strings.Contains(lowerMagic, "portable executable") || strings.Contains(lowerMagic, "dos") || strings.Contains(lowerMagic, "mz") || strings.Contains(lowerMagic, "elf") ||
		strings.Contains(lowerMime, "dosexec") || strings.Contains(lowerMime, "executable") || strings.Contains(lowerMime, "elf"):
		return 58, "executable", "medium"
	case strings.Contains(lowerMagic, "zip") || strings.Contains(lowerMagic, "gzip") || strings.Contains(lowerMagic, "rar") || strings.Contains(lowerMagic, "7z") ||
		strings.Contains(lowerMime, "zip") || strings.Contains(lowerMime, "gzip") || strings.Contains(lowerMime, "rar") || strings.Contains(lowerMime, "7z"):
		return 30, "archive", "info"
	case strings.Contains(lowerMagic, "pdf") || strings.Contains(lowerMagic, "ole") || strings.Contains(lowerMagic, "doc") ||
		strings.Contains(lowerMime, "pdf") || strings.Contains(lowerMime, "msword") || strings.Contains(lowerMime, "officedocument"):
		return 28, "document", "info"
	case strings.HasPrefix(lowerMime, "image/") || strings.Contains(lowerMagic, "png") || strings.Contains(lowerMagic, "jpeg") || strings.Contains(lowerMagic, "gif"):
		return 0, "image", "info"
	case strings.HasPrefix(lowerMime, "text/") || strings.Contains(lowerMagic, "text"):
		return 0, "text", "info"
	default:
		return 12, "unknown", "info"
	}
}
