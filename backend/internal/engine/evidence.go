package engine

import (
	"context"
	"fmt"

	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Service) GatherEvidence(ctx context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error) {
	records := make([]model.EvidenceRecord, 0)
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
