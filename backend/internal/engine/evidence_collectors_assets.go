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
	objects := s.ObjectsWithContext(ctx)
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

func (s *Service) gatherVehicleEvidence() ([]model.EvidenceRecord, error) {
	analysis, err := s.VehicleAnalysis()
	if err != nil {
		return nil, err
	}

	records := make([]model.EvidenceRecord, 0, len(analysis.UDS.Transactions))
	for idx, tx := range analysis.UDS.Transactions {
		confidence, shouldEmit := vehicleEvidenceConfidence(tx)
		if !shouldEmit {
			continue
		}

		packetID := tx.RequestPacketID
		if packetID == 0 {
			packetID = tx.ResponsePacketID
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

func (s *Service) gatherUSBEvidence() ([]model.EvidenceRecord, error) {
	analysis, err := s.USBAnalysis()
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
