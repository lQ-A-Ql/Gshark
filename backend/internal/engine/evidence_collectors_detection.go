package engine

import (
	"context"
	"fmt"

	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Service) gatherThreatEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	hits := s.ThreatHuntWithContext(ctx, nil)
	records := make([]model.EvidenceRecord, 0, len(hits))
	for _, hit := range hits {
		severity := threatLevelToSeverity(hit.Level)
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("threat:%d:%d", hit.ID, hit.PacketID),
			Module:       "hunting",
			SourceModule: "threat-hunting",
			PacketID:     hit.PacketID,
			SourceType:   hit.Category,
			Summary:      hit.Rule,
			Value:        hit.Match,
			Severity:     severity,
			Tags:         dedupeStrings([]string{hit.Category, hit.Level, hit.Rule}),
			Caveats:      []string{"规则命中仅代表检测信号，需要结合上下文、payload 与会话行为复核。"},
		})
	}
	return records, nil
}

func (s *Service) gatherC2Evidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.C2SampleAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	var records []model.EvidenceRecord
	for _, family := range []model.C2FamilyAnalysis{analysis.CS, analysis.VShell} {
		for i, ind := range family.Candidates {
			confidence := clampConfidence(ind.Confidence)
			tags := append([]string{}, ind.Tags...)
			tags = append(tags, ind.ActorHints...)
			if ind.Channel != "" {
				tags = append([]string{ind.Channel}, tags...)
			}
			records = append(records, model.EvidenceRecord{
				ID:           fmt.Sprintf("c2:%d:%s:%s:%d", ind.PacketID, ind.Family, ind.IndicatorType, i),
				Module:       "c2",
				SourceModule: "c2-analysis",
				PacketID:     ind.PacketID,
				StreamID:     ind.StreamID,
				Family:       ind.Family,
				SourceType:   ind.IndicatorType,
				Summary:      ind.Summary,
				Value:        ind.IndicatorValue,
				Confidence:   confidence,
				Severity:     confidenceToSeverity(confidence),
				Source:       ind.Source,
				Destination:  ind.Destination,
				Host:         ind.Host,
				URI:          ind.URI,
				Tags:         dedupeStrings(tags),
				Caveats:      evidenceCaveats(confidence, "c2-analysis"),
			})
		}
	}
	return records, nil
}

func (s *Service) gatherAPTEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.APTAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]model.EvidenceRecord, 0, len(analysis.Evidence))
	for i, ev := range analysis.Evidence {
		confidence := clampConfidence(ev.Confidence)
		tags := append([]string{}, ev.Tags...)
		tags = append(tags, ev.TransportTraits...)
		tags = append(tags, ev.InfrastructureHints...)
		tags = append(tags, ev.TTPTags...)
		if ev.SampleFamily != "" {
			tags = append([]string{ev.SampleFamily}, tags...)
		}
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("apt:%d:%s:%s:%d", ev.PacketID, ev.ActorID, ev.SourceModule, i),
			Module:       "apt",
			SourceModule: ev.SourceModule,
			PacketID:     ev.PacketID,
			StreamID:     ev.StreamID,
			Family:       ev.Family,
			ActorID:      ev.ActorID,
			ActorName:    ev.ActorName,
			SourceType:   ev.EvidenceType,
			Summary:      ev.Summary,
			Value:        ev.EvidenceValue,
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Source:       ev.Source,
			Destination:  ev.Destination,
			Host:         ev.Host,
			URI:          ev.URI,
			Tags:         dedupeStrings(tags),
			Caveats:      evidenceCaveats(confidence, ev.SourceModule),
		})
	}
	return records, nil
}

func (s *Service) gatherIndustrialEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.IndustrialAnalysisWithContext(ctx)
	if err != nil {
		return nil, err
	}
	var records []model.EvidenceRecord
	for _, hit := range analysis.RuleHits {
		severity := threatLevelToSeverity(hit.Level)
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("industrial:%s:%d", hit.Rule, hit.PacketID),
			Module:       "industrial",
			SourceModule: "industrial-analysis",
			PacketID:     hit.PacketID,
			SourceType:   hit.FunctionName,
			Summary:      hit.Rule,
			Value:        hit.Evidence,
			Severity:     severity,
			Source:       hit.Source,
			Destination:  hit.Destination,
			Tags:         dedupeStrings([]string{hit.FunctionName, hit.Target}),
			Caveats:      []string{"工控规则命中需要结合设备角色和网络拓扑复核。"},
		})
	}
	for _, sw := range analysis.SuspiciousWrites {
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("industrial:write:%s:%d", sw.Target, sw.SamplePacketID),
			Module:       "industrial",
			SourceModule: "industrial-analysis",
			PacketID:     sw.SamplePacketID,
			SourceType:   "suspicious-write",
			Summary:      fmt.Sprintf("Modbus 可疑写操作: %s (功能码 %d)", sw.FunctionName, sw.FunctionCode),
			Value:        fmt.Sprintf("写入次数: %d, 样本值: %v", sw.WriteCount, sw.SampleValues),
			Severity:     "medium",
			Tags:         dedupeStrings([]string{sw.FunctionName, sw.Target}),
			Caveats:      []string{"高频写入可能对应灯控、阀门切换或寄存器篡改，需要结合设备角色判断。"},
		})
	}
	return records, nil
}
