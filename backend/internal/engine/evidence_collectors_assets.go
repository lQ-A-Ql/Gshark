package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Service) gatherWebShellEvidence() ([]model.EvidenceRecord, error) {
	sources, err := s.ListStreamPayloadSources(50)
	if err != nil {
		return nil, err
	}
	var records []model.EvidenceRecord
	for _, src := range sources {
		if src.Confidence < 30 {
			continue
		}
		confidence := clampConfidence(src.Confidence)
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("webshell:%d:%s", src.PacketID, src.ID),
			Module:       "misc",
			SourceModule: "webshell-decoder",
			PacketID:     src.PacketID,
			StreamID:     src.StreamID,
			SourceType:   src.SourceType,
			Summary:      fmt.Sprintf("可疑 WebShell 来源: %s %s", src.Method, src.URI),
			Value:        src.Preview,
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Source:       src.Host,
			Host:         src.Host,
			URI:          src.URI,
			Tags:         dedupeStrings(append([]string{src.SourceType}, src.Signals...)),
			Caveats:      evidenceCaveats(confidence, "webshell-decoder"),
		})
	}
	return records, nil
}

func (s *Service) gatherObjectEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	objects := s.ObjectsWithContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records := make([]model.EvidenceRecord, 0, len(objects))
	for _, obj := range objects {
		confidence, kind, severity := objectEvidenceProfile(obj)
		caveats := []string{
			"对象提取结果需要结合来源协议、文件扩展、magic 与上下文流量综合判断，单独出现文件对象不等于恶意投递。",
		}
		if confidence > 0 {
			caveats = append(caveats, evidenceCaveats(confidence, "object-export")...)
		}
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("object:%d", obj.ID),
			Module:       "object",
			SourceModule: "object-export",
			PacketID:     obj.PacketID,
			SourceType:   "object-file",
			Summary:      obj.Name,
			Value:        fmt.Sprintf("%s (%d bytes)", obj.MIME, obj.SizeBytes),
			Confidence:   confidence,
			Severity:     severity,
			Tags:         dedupeStrings(compactStrings([]string{kind, obj.Magic, obj.MIME, obj.Source})),
			Caveats:      dedupeStrings(caveats),
		})
	}
	return records, nil
}

func (s *Service) gatherMediaEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.MediaAnalysis()
	if err != nil {
		return nil, err
	}
	var records []model.EvidenceRecord
	for _, session := range analysis.Sessions {
		confidence := 30
		if session.PacketCount > 10 {
			confidence = 45
		}
		if session.PacketCount > 100 {
			confidence = 55
		}
		mediaType := strings.TrimSpace(session.MediaType)
		if mediaType == "video" {
			confidence += 5
		}
		confidence = clampConfidence(confidence)

		summary := fmt.Sprintf("媒体会话: %s/%s %s:%d -> %s:%d",
			firstNonEmpty(session.Application, "RTP"),
			firstNonEmpty(session.Codec, "unknown"),
			firstNonEmpty(session.Source, "src"), session.SourcePort,
			firstNonEmpty(session.Destination, "dst"), session.DestinationPort,
		)
		value := fmt.Sprintf("%d packets, %s", session.PacketCount, mediaType)
		if session.StartTime != "" && session.EndTime != "" {
			value += fmt.Sprintf(", %s ~ %s", session.StartTime, session.EndTime)
		}

		caveats := []string{
			"媒体会话提取依赖 RTP/RTSP 协议识别与 ffmpeg 解码能力，非标准端口或加密流可能遗漏。",
		}
		if confidence < 50 {
			caveats = append(caveats, "低包数会话可能是探测噪声而非真实媒体流。")
		}

		tags := compactStrings([]string{"media", mediaType, session.Codec, session.Application})
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("media:%s:%d:%d", session.ID, session.SourcePort, session.DestinationPort),
			Module:       "media",
			SourceModule: "media-analysis",
			SourceType:   "media-session",
			Summary:      summary,
			Value:        value,
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Source:       session.Source,
			Destination:  session.Destination,
			Tags:         dedupeStrings(tags),
			Caveats:      dedupeStrings(caveats),
		})
	}
	s.captureCtl.mu.RLock()
	transcriptions := make(map[string]model.MediaTranscription, len(s.mediaCtl.mediaSpeech))
	for k, v := range s.mediaCtl.mediaSpeech {
		transcriptions[k] = v
	}
	s.captureCtl.mu.RUnlock()
	for _, tr := range transcriptions {
		if strings.TrimSpace(tr.Text) == "" {
			continue
		}
		confidence := 50
		if len(tr.Segments) > 5 {
			confidence = 60
		}
		confidence = clampConfidence(confidence)
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("media:transcription:%s", tr.Token),
			Module:       "media",
			SourceModule: "speech-to-text",
			SourceType:   "media-transcription",
			Summary:      fmt.Sprintf("语音转写: %s", tr.Title),
			Value:        truncateString(tr.Text, 200),
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Tags:         dedupeStrings([]string{"media", "transcription", tr.Engine, tr.Language}),
			Caveats: []string{
				"语音转写依赖外部 Vosk 运行时和声学模型，转写质量受音频编码、比特率和背景噪声影响，结果应作为辅助参考。",
			},
		})
	}
	return records, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (s *Service) gatherVehicleEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.VehicleAnalysisWithContext(ctx)
	if err != nil {
		return nil, err
	}

	records := make([]model.EvidenceRecord, 0, len(analysis.UDS.Transactions))
	for idx, tx := range analysis.UDS.Transactions {
		confidence, shouldEmit := vehicleEvidenceConfidence(tx)
		if !shouldEmit {
			continue
		}

		packetID := tx.ResponsePacketID
		if packetID == 0 {
			packetID = tx.RequestPacketID
		}

		summary := buildUDSEvidenceSummary(tx)
		valueParts := []string{
			joinNonEmpty(" → ", tx.SourceAddress, tx.TargetAddress),
			firstNonEmpty(tx.DataIdentifier, tx.SubFunction, tx.DTC),
			firstNonEmpty(tx.ResponseSummary, tx.RequestSummary),
		}
		caveats := append([]string{
			"车机诊断事务需要结合 ECU 角色、测试工况和会话阶段复核，不应脱离 DoIP / CAN 上下文单独解读。",
		}, evidenceCaveats(confidence, "vehicle-analysis")...)

		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("vehicle:uds:%d:%s:%d", packetID, normalizeServiceID(tx.ServiceID), idx),
			Module:       "vehicle",
			SourceModule: "vehicle-analysis",
			PacketID:     packetID,
			SourceType:   "uds-transaction",
			Summary:      summary,
			Value:        strings.Join(compactStrings(valueParts), " / "),
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Source:       tx.SourceAddress,
			Destination:  tx.TargetAddress,
			Tags: dedupeStrings(compactStrings([]string{
				"UDS",
				normalizeServiceID(tx.ServiceID),
				tx.ServiceName,
				tx.Status,
				tx.NegativeCode,
				tx.DataIdentifier,
				tx.SubFunction,
				tx.DTC,
			})),
			Caveats: dedupeStrings(caveats),
		})
	}
	return records, nil
}

func (s *Service) gatherUSBEvidence(ctx context.Context) ([]model.EvidenceRecord, error) {
	analysis, err := s.USBAnalysisWithContext(ctx)
	if err != nil {
		return nil, err
	}

	records := make([]model.EvidenceRecord, 0, len(analysis.MassStorage.WriteOperations))
	for idx, op := range analysis.MassStorage.WriteOperations {
		confidence := 60
		if strings.TrimSpace(op.Status) != "" && !isBenignUSBMassStorageStatus(op.Status) {
			confidence = 78
		}
		if op.DataResidue > 0 {
			confidence = maxInt(confidence, 72)
		}

		caveats := append([]string{
			"USB 存储写入不必然代表恶意，需要结合终端角色、介质来源与上下文判断是否属于数据投递或外传行为。",
		}, evidenceCaveats(confidence, "usb-analysis")...)

		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("usb:mass-storage-write:%d:%d", op.PacketID, idx),
			Module:       "usb",
			SourceModule: "usb-analysis",
			PacketID:     op.PacketID,
			SourceType:   "mass-storage-write",
			Summary:      buildUSBEvidenceSummary(op),
			Value:        buildUSBEvidenceValue(op),
			Confidence:   confidence,
			Severity:     confidenceToSeverity(confidence),
			Source:       op.Device,
			Destination:  op.Endpoint,
			Tags: dedupeStrings(compactStrings([]string{
				"USB",
				"Mass Storage",
				"write",
				op.Command,
				op.Device,
				op.LUN,
				op.Status,
			})),
			Caveats: dedupeStrings(caveats),
		})
	}
	return records, nil
}
