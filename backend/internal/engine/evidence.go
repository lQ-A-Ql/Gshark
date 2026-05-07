package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Service) GatherEvidence(ctx context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error) {
	var records []model.EvidenceRecord
	var notes []string

	modules := filter.Modules
	hasModule := func(name string) bool {
		if len(modules) == 0 {
			return true
		}
		for _, m := range modules {
			if m == name {
				return true
			}
		}
		return false
	}

	if hasModule("hunting") {
		if hits, err := s.gatherThreatEvidence(ctx); err == nil {
			records = append(records, hits...)
		} else {
			notes = append(notes, fmt.Sprintf("威胁狩猎证据收集失败: %v", err))
		}
	}

	if hasModule("c2") {
		if c2, err := s.gatherC2Evidence(ctx); err == nil {
			records = append(records, c2...)
		} else {
			notes = append(notes, fmt.Sprintf("C2 证据收集失败: %v", err))
		}
	}

	if hasModule("apt") {
		if apt, err := s.gatherAPTEvidence(ctx); err == nil {
			records = append(records, apt...)
		} else {
			notes = append(notes, fmt.Sprintf("APT 证据收集失败: %v", err))
		}
	}

	if hasModule("industrial") {
		if ind, err := s.gatherIndustrialEvidence(); err == nil {
			records = append(records, ind...)
		} else {
			notes = append(notes, fmt.Sprintf("工控证据收集失败: %v", err))
		}
	}

	if hasModule("object") {
		if obj, err := s.gatherObjectEvidence(ctx); err == nil {
			records = append(records, obj...)
		} else {
			notes = append(notes, fmt.Sprintf("对象证据收集失败: %v", err))
		}
	}

	if hasModule("vehicle") {
		if vehicle, err := s.gatherVehicleEvidence(); err == nil {
			records = append(records, vehicle...)
		} else {
			notes = append(notes, fmt.Sprintf("车机证据收集失败: %v", err))
		}
	}

	if hasModule("usb") {
		if usb, err := s.gatherUSBEvidence(); err == nil {
			records = append(records, usb...)
		} else {
			notes = append(notes, fmt.Sprintf("USB 证据收集失败: %v", err))
		}
	}

	return model.EvidenceResponse{
		Records: records,
		Total:   len(records),
		Notes:   notes,
	}, nil
}

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

func (s *Service) gatherIndustrialEvidence() ([]model.EvidenceRecord, error) {
	analysis, err := s.IndustrialAnalysis()
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
		records = append(records, model.EvidenceRecord{
			ID:           fmt.Sprintf("object:%d", obj.ID),
			Module:       "object",
			SourceModule: "object-export",
			PacketID:     obj.PacketID,
			SourceType:   obj.Magic,
			Summary:      obj.Name,
			Value:        fmt.Sprintf("%s (%d bytes)", obj.MIME, obj.SizeBytes),
			Severity:     "info",
			Tags:         dedupeStrings([]string{obj.Magic, obj.MIME, obj.Source}),
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

func vehicleEvidenceConfidence(tx model.UDSTransaction) (int, bool) {
	serviceID := normalizeServiceID(tx.ServiceID)
	base, riskyService := udsServiceEvidenceBase(serviceID)
	status := strings.ToLower(strings.TrimSpace(tx.Status))

	if tx.NegativeCode != "" {
		if base == 0 {
			base = 66
		}
		if riskyService {
			base += 6
		}
		return clampConfidence(base), true
	}

	switch status {
	case "orphan-response":
		if base == 0 {
			base = 55
		}
		return clampConfidence(base), true
	case "request-only":
		if base == 0 {
			base = 58
		}
		return clampConfidence(base), true
	case "positive":
		if riskyService {
			if base == 0 {
				base = 68
			}
			return clampConfidence(base), true
		}
		return 0, false
	default:
		if base == 0 {
			base = 52
		}
		return clampConfidence(base), true
	}
}

func udsServiceEvidenceBase(serviceID string) (int, bool) {
	switch normalizeServiceID(serviceID) {
	case "0x27":
		return 82, true
	case "0x2e", "0x2f":
		return 80, true
	case "0x34", "0x36":
		return 85, true
	case "0x37":
		return 76, true
	case "0x31":
		return 74, true
	case "0x10":
		return 60, true
	default:
		return 0, false
	}
}

func buildUDSEvidenceSummary(tx model.UDSTransaction) string {
	serviceLabel := strings.TrimSpace(joinNonEmpty(" ", tx.ServiceID, tx.ServiceName))
	if serviceLabel == "" {
		serviceLabel = "UDS"
	}

	status := strings.ToLower(strings.TrimSpace(tx.Status))
	switch {
	case tx.NegativeCode != "":
		return fmt.Sprintf("UDS 负响应: %s / %s", serviceLabel, udsNegativeResponseLabel(tx.NegativeCode))
	case status == "orphan-response":
		return fmt.Sprintf("UDS 孤立响应: %s", serviceLabel)
	case status == "request-only":
		return fmt.Sprintf("UDS 请求未配对: %s", serviceLabel)
	default:
		return fmt.Sprintf("UDS 高价值事务: %s", serviceLabel)
	}
}

func buildUSBEvidenceSummary(op model.USBMassStorageOperation) string {
	command := firstNonEmpty(op.Command, "WRITE")
	summary := fmt.Sprintf("USB 存储写入: %s", command)
	if device := strings.TrimSpace(op.Device); device != "" {
		summary += " / " + device
	}
	if lun := strings.TrimSpace(op.LUN); lun != "" {
		summary += " / " + lun
	}
	if status := strings.TrimSpace(op.Status); status != "" && !isBenignUSBMassStorageStatus(status) {
		summary += " / status=" + status
	}
	return summary
}

func buildUSBEvidenceValue(op model.USBMassStorageOperation) string {
	parts := []string{
		fmt.Sprintf("len=%d", op.TransferLength),
		joinNonEmpty(" → ", op.Device, op.Endpoint),
	}
	if op.RequestFrame > 0 || op.ResponseFrame > 0 {
		parts = append(parts, fmt.Sprintf("frames=%d/%d", op.RequestFrame, op.ResponseFrame))
	}
	if op.LatencyMs > 0 {
		parts = append(parts, fmt.Sprintf("latency=%.1fms", op.LatencyMs))
	}
	if op.DataResidue > 0 {
		parts = append(parts, fmt.Sprintf("residue=%d", op.DataResidue))
	}
	if status := strings.TrimSpace(op.Status); status != "" {
		parts = append(parts, "status="+status)
	}
	return strings.Join(compactStrings(parts), " / ")
}

func isBenignUSBMassStorageStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "ok", "good", "unknown":
		return true
	default:
		return false
	}
}

func udsNegativeResponseLabel(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "0x10":
		return "一般拒绝"
	case "0x11":
		return "服务不支持"
	case "0x12":
		return "子功能不支持"
	case "0x13":
		return "消息长度错误"
	case "0x22":
		return "条件不满足"
	case "0x24":
		return "请求序列错误"
	case "0x31":
		return "请求超出范围"
	case "0x33":
		return "安全访问被拒"
	case "0x35":
		return "密钥无效"
	case "0x36":
		return "尝试次数超限"
	case "0x37":
		return "延时未到"
	case "0x70":
		return "上传下载不接受"
	case "0x71":
		return "传输数据暂停"
	case "0x72":
		return "一般编程失败"
	case "0x73":
		return "错误的区块序列"
	case "0x78":
		return "响应挂起"
	case "0x7e":
		return "会话不支持子功能"
	case "0x7f":
		return "会话不支持服务"
	default:
		if strings.TrimSpace(code) == "" {
			return "负响应"
		}
		return code
	}
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
