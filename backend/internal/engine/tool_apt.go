package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildAPTAnalysisFromThreatHits(hits []model.ThreatHit, existing model.APTAnalysis) model.APTAnalysis {
	analysis := existing
	for _, hit := range hits {
		if hit.Rule == "" {
			continue
		}
		record := model.APTEvidenceRecord{
			SourceModule:  "threat-hunting",
			EvidenceType: classifyThreatHitEvidenceType(hit),
			EvidenceValue: hit.Rule,
			Confidence:    threatHitLevelToConfidence(hit.Level),
			Summary:       hit.Rule + " (" + hit.Category + ")",
			Tags:          []string{hit.Category, hit.Level},
		}
		if hit.PacketID > 0 {
			record.PacketID = hit.PacketID
		}
		analysis.Evidence = append(analysis.Evidence, record)
		analysis.TotalEvidence++
	}
	return analysis
}

func buildAPTAnalysisFromObjects(objects []model.ObjectFile, existing model.APTAnalysis) model.APTAnalysis {
	analysis := existing
	for _, obj := range objects {
		if obj.Name == "" {
			continue
		}
		record := model.APTEvidenceRecord{
			SourceModule:  "object-export",
			EvidenceType: classifyObjectFileEvidenceType(obj),
			EvidenceValue: obj.Name,
			Confidence:    objectFileConfidence(obj),
			Summary:       obj.Name + " (" + obj.MIME + ")",
			Tags:          []string{obj.Source},
		}
		if obj.PacketID > 0 {
			record.PacketID = obj.PacketID
		}
		analysis.Evidence = append(analysis.Evidence, record)
		analysis.TotalEvidence++
	}
	return analysis
}

func classifyThreatHitEvidenceType(hit model.ThreatHit) string {
	lower := strings.ToLower(hit.Category)
	switch {
	case strings.Contains(lower, "yara"):
		return "yara-hit"
	case strings.Contains(lower, "shell") || strings.Contains(lower, "cmd"):
		return "command-detection"
	case strings.Contains(lower, "base64"):
		return "encoding-detection"
	case strings.Contains(lower, "404"):
		return "anomaly-detection"
	default:
		return "rule-match"
	}
}

func threatHitLevelToConfidence(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 55
	case "low":
		return 35
	default:
		return 25
	}
}

func classifyObjectFileEvidenceType(obj model.ObjectFile) string {
	lower := strings.ToLower(obj.Name)
	switch {
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll"):
		return "executable"
	case strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd"):
		return "script"
	case strings.HasSuffix(lower, ".hta") || strings.HasSuffix(lower, ".vbs"):
		return "script"
	case strings.HasSuffix(lower, ".doc") || strings.HasSuffix(lower, ".docx") || strings.HasSuffix(lower, ".xls") || strings.HasSuffix(lower, ".xlsx"):
		return "document"
	case strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".rar") || strings.HasSuffix(lower, ".7z"):
		return "archive"
	default:
		return "file"
	}
}

func objectFileConfidence(obj model.ObjectFile) int {
	lower := strings.ToLower(obj.Name)
	switch {
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll"):
		return 70
	case strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".bat"):
		return 65
	case strings.HasSuffix(lower, ".hta") || strings.HasSuffix(lower, ".vbs"):
		return 60
	default:
		return 40
	}
}
