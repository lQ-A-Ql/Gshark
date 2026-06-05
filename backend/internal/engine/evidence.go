package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

type evidenceCollector struct {
	module  string
	note    string
	collect func(context.Context) ([]model.EvidenceRecord, error)
}

func (s *Service) GatherEvidence(ctx context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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

	collectors := []evidenceCollector{
		{module: "hunting", note: "威胁狩猎证据收集失败", collect: s.gatherThreatEvidence},
		{module: "c2", note: "C2 证据收集失败", collect: s.gatherC2Evidence},
		{module: "apt", note: "APT 证据收集失败", collect: s.gatherAPTEvidence},
		{module: "industrial", note: "工控证据收集失败", collect: s.gatherIndustrialEvidence},
		{module: "object", note: "对象证据收集失败", collect: s.gatherObjectEvidence},
		{module: "vehicle", note: "车机证据收集失败", collect: s.gatherVehicleEvidence},
		{module: "usb", note: "USB 证据收集失败", collect: s.gatherUSBEvidence},
		{module: "media", note: "媒体证据收集失败", collect: s.gatherMediaEvidence},
		{module: "misc", note: "WebShell 证据收集失败", collect: func(context.Context) ([]model.EvidenceRecord, error) {
			return s.gatherWebShellEvidence()
		}},
	}

	for _, collector := range collectors {
		if !hasModule(collector.module) {
			continue
		}
		collected, err := s.gatherEvidenceWithTiming(ctx, collector.module, collector.collect)
		if err == nil {
			records = append(records, collected...)
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return model.EvidenceResponse{}, err
		}
		notes = append(notes, fmt.Sprintf("%s: %v", collector.note, err))
	}

	return model.EvidenceResponse{
		Records: records,
		Total:   len(records),
		Notes:   notes,
	}, nil
}

func (s *Service) gatherEvidenceWithTiming(ctx context.Context, module string, collect func(context.Context) ([]model.EvidenceRecord, error)) ([]model.EvidenceRecord, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		s.emitEvidenceTiming(module, start, 0, "canceled")
		return nil, err
	}
	records, err := collect(ctx)
	status := "ok"
	if err != nil {
		status = "error"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			status = "canceled"
		}
	}
	s.emitEvidenceTiming(module, start, len(records), status)
	return records, err
}

func (s *Service) emitEvidenceTiming(module string, start time.Time, records int, status string) {
	durationMs := time.Since(start).Milliseconds()
	if durationMs < 0 {
		durationMs = 0
	}
	s.emitStatus(fmt.Sprintf("__evidence_timing__:%s:%d:%d:%s", module, durationMs, records, status))
}
