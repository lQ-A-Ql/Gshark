package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// idCounter is a package-level atomic counter for generating unique IDs.
var idCounter int64

func nextID(prefix string) string {
	n := atomic.AddInt64(&idCounter, 1)
	return fmt.Sprintf("%s_%d", prefix, n)
}

// ListPlaybooks returns all stored playbooks.
func (s *Service) ListPlaybooks() []model.HuntingPlaybook {
	s.playbookMu.RLock()
	defer s.playbookMu.RUnlock()
	out := make([]model.HuntingPlaybook, 0, len(s.playbooks))
	for _, pb := range s.playbooks {
		out = append(out, *pb)
	}
	return out
}

// GetPlaybook returns a single playbook by ID.
func (s *Service) GetPlaybook(id string) (*model.HuntingPlaybook, bool) {
	s.playbookMu.RLock()
	defer s.playbookMu.RUnlock()
	pb, ok := s.playbooks[id]
	if !ok {
		return nil, false
	}
	copy := *pb
	return &copy, true
}

// CreatePlaybook stores a new playbook.
func (s *Service) CreatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error) {
	if strings.TrimSpace(pb.Name) == "" {
		return nil, fmt.Errorf("playbook name is required")
	}
	if len(pb.Steps) == 0 {
		return nil, fmt.Errorf("playbook must have at least one step")
	}

	now := time.Now().UTC()
	if strings.TrimSpace(pb.ID) == "" {
		pb.ID = nextID("pb")
	}
	pb.CreatedAt = now
	pb.UpdatedAt = now
	if pb.Status == "" {
		pb.Status = model.PlaybookStatusReady
	}

	// Normalize step IDs.
	for i := range pb.Steps {
		if strings.TrimSpace(pb.Steps[i].ID) == "" {
			pb.Steps[i].ID = fmt.Sprintf("step_%d", i+1)
		}
		if pb.Steps[i].Config == nil {
			pb.Steps[i].Config = map[string]any{}
		}
	}

	s.playbookMu.Lock()
	s.playbooks[pb.ID] = &pb
	s.playbookMu.Unlock()

	copy := pb
	return &copy, nil
}

// UpdatePlaybook replaces an existing playbook.
func (s *Service) UpdatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error) {
	if strings.TrimSpace(pb.ID) == "" {
		return nil, fmt.Errorf("playbook ID is required")
	}
	s.playbookMu.Lock()
	existing, ok := s.playbooks[pb.ID]
	if !ok {
		s.playbookMu.Unlock()
		return nil, fmt.Errorf("playbook %s not found", pb.ID)
	}
	pb.CreatedAt = existing.CreatedAt
	pb.UpdatedAt = time.Now().UTC()
	s.playbooks[pb.ID] = &pb
	s.playbookMu.Unlock()
	copy := pb
	return &copy, nil
}

// DeletePlaybook removes a playbook by ID.
func (s *Service) DeletePlaybook(id string) bool {
	s.playbookMu.Lock()
	defer s.playbookMu.Unlock()
	if _, ok := s.playbooks[id]; !ok {
		return false
	}
	delete(s.playbooks, id)
	delete(s.lastRun, id)
	return true
}

// GetPlaybookLastRun returns the last run result for a playbook.
func (s *Service) GetPlaybookLastRun(playbookID string) (*model.PlaybookRunResult, bool) {
	s.playbookMu.RLock()
	defer s.playbookMu.RUnlock()
	result, ok := s.lastRun[playbookID]
	if !ok {
		return nil, false
	}
	copy := *result
	return &copy, true
}

// RunPlaybook executes a playbook against the loaded capture.
func (s *Service) RunPlaybook(ctx context.Context, playbookID string) (*model.PlaybookRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	s.playbookMu.RLock()
	pb, ok := s.playbooks[playbookID]
	if !ok {
		s.playbookMu.RUnlock()
		return nil, fmt.Errorf("playbook %s not found", playbookID)
	}
	pbCopy := *pb
	s.playbookMu.RUnlock()

	ctx, finishTask := s.TrackCaptureTask(ctx, "playbook-"+playbookID)
	defer finishTask()

	startedAt := time.Now().UTC()
	s.emitStatus(fmt.Sprintf("剧本执行开始: %s", pbCopy.Name))

	result := &model.PlaybookRunResult{
		PlaybookID:   pbCopy.ID,
		PlaybookName: pbCopy.Name,
		Status:       model.PlaybookStatusRunning,
		StartedAt:    startedAt,
	}

	for i, step := range pbCopy.Steps {
		if ctx.Err() != nil {
			result.Status = model.PlaybookStatusFailed
			result.StepResults = append(result.StepResults, model.PlaybookStepResult{
				StepID:   step.ID,
				StepName: step.Name,
				Status:   "error",
				Error:    "cancelled",
			})
			break
		}

		if !step.Enabled {
			result.StepResults = append(result.StepResults, model.PlaybookStepResult{
				StepID:   step.ID,
				StepName: step.Name,
				Status:   "skip",
			})
			continue
		}

		s.emitStatus(fmt.Sprintf("剧本 [%d/%d] %s", i+1, len(pbCopy.Steps), step.Name))
		stepResult := s.executePlaybookStep(ctx, step)
		result.StepResults = append(result.StepResults, stepResult)
		result.TotalHits += stepResult.HitsCount
	}

	completedAt := time.Now().UTC()
	result.CompletedAt = completedAt
	result.Duration = completedAt.Sub(startedAt)

	if result.Status == model.PlaybookStatusRunning {
		result.Status = model.PlaybookStatusComplete
		for _, sr := range result.StepResults {
			if sr.Status == "error" {
				result.Status = model.PlaybookStatusFailed
				break
			}
		}
	}

	// Update playbook status.
	s.playbookMu.Lock()
	s.lastRun[playbookID] = result
	if pb, ok := s.playbooks[playbookID]; ok {
		pb.Status = result.Status
	}
	s.playbookMu.Unlock()

	s.emitStatus(fmt.Sprintf("剧本执行完成: %s (%d 命中)", pbCopy.Name, result.TotalHits))

	copy := *result
	return &copy, nil
}

// executePlaybookStep runs a single playbook step and returns its result.
func (s *Service) executePlaybookStep(ctx context.Context, step model.PlaybookStep) model.PlaybookStepResult {
	stepStart := time.Now()
	result := model.PlaybookStepResult{
		StepID:   step.ID,
		StepName: step.Name,
	}

	var hits []model.ThreatHit
	var err error

	switch step.Type {
	case model.PlaybookStepTypeThreatHunt:
		hits, err = s.executeStepThreatHunt(ctx, step)
	case model.PlaybookStepTypeFilterQuery:
		hits, err = s.executeStepFilterQuery(ctx, step)
	case model.PlaybookStepTypeYARAScan:
		hits, err = s.executeStepYARAScan(ctx, step)
	case model.PlaybookStepTypeC2Analysis:
		hits, err = s.executeStepC2Analysis(ctx, step)
	case model.PlaybookStepTypeAPTAnalysis:
		hits, err = s.executeStepAPTAnalysis(ctx, step)
	case model.PlaybookStepTypeCustom:
		hits, err = s.executeStepCustom(ctx, step)
	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	result.Duration = time.Since(stepStart)

	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}

	result.Hits = hits
	result.HitsCount = len(hits)

	// Evaluate conditions.
	result.ConditionOK = evaluateStepConditions(step.Conditions, hits)
	if result.ConditionOK {
		result.Status = "pass"
	} else {
		result.Status = "fail"
	}

	return result
}

// executeStepThreatHunt runs threat hunting with the prefixes from step config.
func (s *Service) executeStepThreatHunt(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	var prefixes []string
	if raw, ok := step.Config["prefixes"]; ok {
		switch v := raw.(type) {
		case []any:
			for _, item := range v {
				if str, ok := item.(string); ok {
					prefixes = append(prefixes, str)
				}
			}
		case []string:
			prefixes = v
		case string:
			for _, p := range strings.Split(v, ",") {
				p := strings.TrimSpace(p)
				if p != "" {
					prefixes = append(prefixes, p)
				}
			}
		}
	}

	hunter := newThreatHunter(prefixes, 1)
	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			hunter.Observe(packet)
			return nil
		})
	}
	return hunter.Results(), nil
}

// executeStepFilterQuery applies a display filter and counts matching packets.
func (s *Service) executeStepFilterQuery(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	filter, _ := step.Config["filter"].(string)
	if strings.TrimSpace(filter) == "" {
		return nil, fmt.Errorf("filter_query step requires 'filter' config")
	}

	category, _ := step.Config["category"].(string)
	if category == "" {
		category = "filter-match"
	}

	rule, _ := step.Config["rule"].(string)
	if rule == "" {
		rule = "Display Filter Match"
	}

	var hits []model.ThreatHit
	if s.packetStore != nil {
		var nextID int64 = 1
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if matchDisplayFilter(packet, filter) {
				hits = append(hits, model.ThreatHit{
					ID:       nextID,
					PacketID: packet.ID,
					Category: category,
					Rule:     rule,
					Level:    "medium",
					Preview:  previewText(packet.Info),
					Match:    filter,
				})
				nextID++
			}
			return nil
		})
	}
	return hits, nil
}

// executeStepYARAScan runs YARA scanning against extracted objects.
func (s *Service) executeStepYARAScan(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	objects := s.ObjectsWithContext(ctx)
	if len(objects) == 0 {
		return nil, nil
	}
	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()
	if !yc.Enabled {
		return nil, fmt.Errorf("YARA is not enabled")
	}
	hits, scanErr := s.executeYaraScan(ctx, yc, objects)
	return hits, scanErr
}

// executeStepC2Analysis runs C2 detection analysis.
func (s *Service) executeStepC2Analysis(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	result, err := s.C2SampleAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	var hits []model.ThreatHit
	var nextID int64 = 1
	for _, c := range result.CS.Candidates {
		hits = append(hits, model.ThreatHit{
			ID:       nextID,
			PacketID: c.PacketID,
			Category: "c2",
			Rule:     "C2 " + c.IndicatorType,
			Level:    severityFromConfidence(c.Confidence),
			Preview:  c.Summary,
			Match:    c.IndicatorValue,
		})
		nextID++
	}
	for _, c := range result.VShell.Candidates {
		hits = append(hits, model.ThreatHit{
			ID:       nextID,
			PacketID: c.PacketID,
			Category: "c2-vshell",
			Rule:     "VShell " + c.IndicatorType,
			Level:    severityFromConfidence(c.Confidence),
			Preview:  c.Summary,
			Match:    c.IndicatorValue,
		})
		nextID++
	}
	return hits, nil
}

// executeStepAPTAnalysis runs APT detection analysis.
func (s *Service) executeStepAPTAnalysis(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	result, err := s.APTAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	var hits []model.ThreatHit
	var nextID int64 = 1
	for _, e := range result.Evidence {
		hits = append(hits, model.ThreatHit{
			ID:       nextID,
			PacketID: e.PacketID,
			Category: "apt",
			Rule:     "APT " + e.EvidenceType,
			Level:    severityFromConfidence(e.Confidence),
			Preview:  e.Summary,
			Match:    e.EvidenceValue,
		})
		nextID++
	}
	return hits, nil
}

// executeStepCustom runs a custom step (placeholder for user-defined logic).
func (s *Service) executeStepCustom(ctx context.Context, step model.PlaybookStep) ([]model.ThreatHit, error) {
	// Custom steps can specify a "command" in config that maps to built-in detections.
	command, _ := step.Config["command"].(string)
	switch command {
	case "dns_tunnel":
		return s.runDNSTunnelDetection(ctx)
	case "brute_force":
		return s.runBruteForceDetection(ctx)
	case "data_exfil":
		return s.runDataExfiltrationDetection(ctx)
	default:
		return nil, nil
	}
}

func (s *Service) runDNSTunnelDetection(ctx context.Context) ([]model.ThreatHit, error) {
	h := newThreatHunter(nil, 1)
	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			h.observeDNSTunnel(packet)
			return nil
		})
	}
	return h.Results(), nil
}

func (s *Service) runBruteForceDetection(ctx context.Context) ([]model.ThreatHit, error) {
	h := newThreatHunter(nil, 1)
	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			h.observeBruteForce(packet)
			return nil
		})
	}
	return h.Results(), nil
}

func (s *Service) runDataExfiltrationDetection(ctx context.Context) ([]model.ThreatHit, error) {
	h := newThreatHunter(nil, 1)
	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			h.observeDataExfiltration(packet)
			return nil
		})
	}
	return h.Results(), nil
}

// matchDisplayFilter performs basic field matching against a packet.
func matchDisplayFilter(packet model.Packet, filter string) bool {
	lower := strings.ToLower(filter)
	info := strings.ToLower(packet.Info)
	proto := strings.ToLower(packet.Protocol)
	src := strings.ToLower(packet.SourceIP)
	dst := strings.ToLower(packet.DestIP)
	port := strconv.Itoa(packet.DestPort)

	// Simple contains-based matching for common filter patterns.
	for _, part := range strings.Split(lower, "&&") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched := false
		if strings.Contains(info, part) || strings.Contains(proto, part) ||
			strings.Contains(src, part) || strings.Contains(dst, part) ||
			port == part {
			matched = true
		}
		if !matched {
			return false
		}
	}
	return true
}

// evaluateStepConditions checks whether step conditions are met by the hits.
func evaluateStepConditions(conditions []model.PlaybookStepCondition, hits []model.ThreatHit) bool {
	if len(conditions) == 0 {
		return true // no conditions = always pass
	}
	for _, cond := range conditions {
		actual := resolveConditionField(cond.Field, hits)
		if !compareCondition(actual, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

// resolveConditionField extracts a numeric value from hits based on the field name.
func resolveConditionField(field string, hits []model.ThreatHit) int {
	switch field {
	case "hits_count":
		return len(hits)
	case "severity_high":
		count := 0
		for _, h := range hits {
			if h.Level == "high" || h.Level == "critical" {
				count++
			}
		}
		return count
	case "severity_medium":
		count := 0
		for _, h := range hits {
			if h.Level == "medium" {
				count++
			}
		}
		return count
	default:
		return len(hits)
	}
}

// compareCondition performs a numeric comparison.
func compareCondition(actual int, operator, valueStr string) bool {
	target, err := strconv.Atoi(valueStr)
	if err != nil {
		target = 0
	}
	switch operator {
	case "gt":
		return actual > target
	case "gte":
		return actual >= target
	case "lt":
		return actual < target
	case "lte":
		return actual <= target
	case "eq":
		return actual == target
	case "neq":
		return actual != target
	default:
		return actual >= target
	}
}
