package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ---------------------------------------------------------------------------
// Playbook CRUD tests
// ---------------------------------------------------------------------------

func TestCreatePlaybookRequiresName(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	_, err := svc.CreatePlaybook(model.HuntingPlaybook{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestCreatePlaybookRequiresSteps(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	_, err := svc.CreatePlaybook(model.HuntingPlaybook{Name: "test"})
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
}

func TestCreateAndListPlaybooks(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	pb, err := svc.CreatePlaybook(model.HuntingPlaybook{
		Name:        "CTF Flag Hunt",
		Description: "Hunt for CTF flags",
		Steps: []model.PlaybookStep{
			{ID: "s1", Name: "Flag prefix scan", Type: model.PlaybookStepTypeThreatHunt, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("CreatePlaybook() error = %v", err)
	}
	if pb.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if pb.Status != model.PlaybookStatusReady {
		t.Fatalf("expected status ready, got %s", pb.Status)
	}

	list := svc.ListPlaybooks()
	if len(list) != 1 {
		t.Fatalf("expected 1 playbook, got %d", len(list))
	}
	if list[0].Name != "CTF Flag Hunt" {
		t.Fatalf("unexpected name: %s", list[0].Name)
	}
}

func TestGetPlaybook(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	created, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name:  "test",
		Steps: []model.PlaybookStep{{Name: "step1", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}},
	})

	got, ok := svc.GetPlaybook(created.ID)
	if !ok {
		t.Fatal("expected to find playbook")
	}
	if got.Name != "test" {
		t.Fatalf("unexpected name: %s", got.Name)
	}

	_, ok = svc.GetPlaybook("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestUpdatePlaybook(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	created, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name:  "original",
		Steps: []model.PlaybookStep{{Name: "step1", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}},
	})

	updated, err := svc.UpdatePlaybook(model.HuntingPlaybook{
		ID:    created.ID,
		Name:  "updated",
		Steps: []model.PlaybookStep{{Name: "step1", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}},
	})
	if err != nil {
		t.Fatalf("UpdatePlaybook() error = %v", err)
	}
	if updated.Name != "updated" {
		t.Fatalf("expected name 'updated', got %s", updated.Name)
	}
}

func TestDeletePlaybook(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	created, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name:  "to-delete",
		Steps: []model.PlaybookStep{{Name: "step1", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}},
	})

	if !svc.DeletePlaybook(created.ID) {
		t.Fatal("expected delete to succeed")
	}
	if svc.DeletePlaybook(created.ID) {
		t.Fatal("expected delete to fail on already-deleted")
	}
	if len(svc.ListPlaybooks()) != 0 {
		t.Fatal("expected empty list after delete")
	}
}

// ---------------------------------------------------------------------------
// Playbook execution tests
// ---------------------------------------------------------------------------

func TestRunPlaybookWithThreatHuntStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// Add test packets with a flag.
	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "flag{test_flag}", Payload: "flag{test_flag}", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
		{ID: 2, Info: "normal traffic", SourceIP: "10.0.0.1", DestIP: "10.0.0.3", DestPort: 443, Protocol: "HTTPS"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Flag Hunt",
		Steps: []model.PlaybookStep{
			{
				ID:      "flag-scan",
				Name:    "Scan for flags",
				Type:    model.PlaybookStepTypeThreatHunt,
				Enabled: true,
				Config:  map[string]any{"prefixes": []any{"flag{"}},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
	if result.StepResults[0].HitsCount == 0 {
		t.Fatal("expected at least 1 hit from flag scan")
	}
	if result.TotalHits == 0 {
		t.Fatal("expected total hits > 0")
	}
}

func TestRunPlaybookWithDisabledStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Mixed",
		Steps: []model.PlaybookStep{
			{ID: "s1", Name: "Disabled step", Type: model.PlaybookStepTypeThreatHunt, Enabled: false},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.StepResults[0].Status != "skip" {
		t.Fatalf("expected skip status, got %s", result.StepResults[0].Status)
	}
}

func TestRunPlaybookNotFound(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	_, err := svc.RunPlaybook(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent playbook")
	}
}

func TestRunPlaybookWithConditions(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "flag{test}", Payload: "flag{test}", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Conditional",
		Steps: []model.PlaybookStep{
			{
				ID:      "s1",
				Name:    "Flag scan with condition",
				Type:    model.PlaybookStepTypeThreatHunt,
				Enabled: true,
				Config:  map[string]any{"prefixes": []any{"flag{"}},
				Conditions: []model.PlaybookStepCondition{
					{Field: "hits_count", Operator: "gte", Value: "1"},
				},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.StepResults[0].Status != "pass" {
		t.Fatalf("expected pass, got %s", result.StepResults[0].Status)
	}
	if !result.StepResults[0].ConditionOK {
		t.Fatal("expected condition to be OK")
	}
}

func TestRunPlaybookConditionFails(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "FailCondition",
		Steps: []model.PlaybookStep{
			{
				ID:      "s1",
				Name:    "Empty scan",
				Type:    model.PlaybookStepTypeThreatHunt,
				Enabled: true,
				Conditions: []model.PlaybookStepCondition{
					{Field: "hits_count", Operator: "gt", Value: "100"},
				},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.StepResults[0].Status != "fail" {
		t.Fatalf("expected fail, got %s", result.StepResults[0].Status)
	}
}

// ---------------------------------------------------------------------------
// Playbook last run tests
// ---------------------------------------------------------------------------

func TestGetPlaybookLastRun(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name:  "test",
		Steps: []model.PlaybookStep{{Name: "s1", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}},
	})

	_, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}

	lastRun, ok := svc.GetPlaybookLastRun(pb.ID)
	if !ok {
		t.Fatal("expected last run to exist")
	}
	if lastRun.PlaybookID != pb.ID {
		t.Fatalf("expected playbook ID %s, got %s", pb.ID, lastRun.PlaybookID)
	}
}

// ---------------------------------------------------------------------------
// Saved search tests
// ---------------------------------------------------------------------------

func TestCreateSavedSearch(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	_, err := svc.CreateSavedSearch(model.SavedSearch{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	ss, err := svc.CreateSavedSearch(model.SavedSearch{
		Name:  "Suspicious DNS",
		Query: "dns",
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch() error = %v", err)
	}
	if ss.ID == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestListAndGetSavedSearch(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	svc.CreateSavedSearch(model.SavedSearch{Name: "s1", Query: "q1"})
	svc.CreateSavedSearch(model.SavedSearch{Name: "s2", Query: "q2"})

	list := svc.ListSavedSearches()
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestDeleteSavedSearch(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	ss, _ := svc.CreateSavedSearch(model.SavedSearch{Name: "s1", Query: "q1"})
	if !svc.DeleteSavedSearch(ss.ID) {
		t.Fatal("expected delete to succeed")
	}
	if len(svc.ListSavedSearches()) != 0 {
		t.Fatal("expected empty list")
	}
}

func TestExecuteSavedSearch(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "flag{test}", Payload: "flag{test}", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	ss, _ := svc.CreateSavedSearch(model.SavedSearch{Name: "flags", Query: "flag{"})
	_, hits, err := svc.ExecuteSavedSearch(ss.ID)
	if err != nil {
		t.Fatalf("ExecuteSavedSearch() error = %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least 1 hit")
	}
}

// ---------------------------------------------------------------------------
// Hypothesis tests
// ---------------------------------------------------------------------------

func TestCreateHypothesis(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	_, err := svc.CreateHypothesis(model.Hypothesis{})
	if err == nil {
		t.Fatal("expected error for empty title")
	}

	h, err := svc.CreateHypothesis(model.Hypothesis{
		Title:       "C2 beacon suspected",
		Description: "Regular 10s interval connections to unknown IP",
	})
	if err != nil {
		t.Fatalf("CreateHypothesis() error = %v", err)
	}
	if h.Status != model.HypothesisStatusOpen {
		t.Fatalf("expected status open, got %s", h.Status)
	}
}

func TestListHypothesesWithStatusFilter(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	svc.CreateHypothesis(model.Hypothesis{Title: "h1"})
	svc.CreateHypothesis(model.Hypothesis{Title: "h2"})

	all := svc.ListHypotheses("")
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}

	open := svc.ListHypotheses("open")
	if len(open) != 2 {
		t.Fatalf("expected 2 open, got %d", len(open))
	}

	closed := svc.ListHypotheses("confirmed")
	if len(closed) != 0 {
		t.Fatalf("expected 0 confirmed, got %d", len(closed))
	}
}

func TestUpdateHypothesisStatus(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	h, _ := svc.CreateHypothesis(model.Hypothesis{Title: "test"})

	updated, err := svc.UpdateHypothesisStatus(h.ID, model.HypothesisStatusConfirmed, "Found C2 traffic")
	if err != nil {
		t.Fatalf("UpdateHypothesisStatus() error = %v", err)
	}
	if updated.Status != model.HypothesisStatusConfirmed {
		t.Fatalf("expected confirmed, got %s", updated.Status)
	}
	if updated.Conclusion != "Found C2 traffic" {
		t.Fatalf("unexpected conclusion: %s", updated.Conclusion)
	}
}

func TestAddHypothesisEvidence(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	h, _ := svc.CreateHypothesis(model.Hypothesis{Title: "test"})

	updated, err := svc.AddHypothesisEvidence(h.ID, model.HypothesisEvidence{
		Description: "Repeated 401 responses from single IP",
		Source:      "threat_hunt",
		Strength:    "supports",
	})
	if err != nil {
		t.Fatalf("AddHypothesisEvidence() error = %v", err)
	}
	if len(updated.Evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(updated.Evidence))
	}
	if updated.Evidence[0].Strength != "supports" {
		t.Fatalf("unexpected strength: %s", updated.Evidence[0].Strength)
	}
}

func TestDeleteHypothesis(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	h, _ := svc.CreateHypothesis(model.Hypothesis{Title: "to-delete"})
	if !svc.DeleteHypothesis(h.ID) {
		t.Fatal("expected delete to succeed")
	}
	if svc.DeleteHypothesis(h.ID) {
		t.Fatal("expected delete to fail on already-deleted")
	}
}

// ---------------------------------------------------------------------------
// Step condition evaluation tests
// ---------------------------------------------------------------------------

func TestEvaluateStepConditionsEmpty(t *testing.T) {
	if !evaluateStepConditions(nil, nil) {
		t.Fatal("expected empty conditions to pass")
	}
}

func TestEvaluateStepConditionsHitsCount(t *testing.T) {
	hits := []model.ThreatHit{
		{Level: "high"}, {Level: "medium"}, {Level: "low"},
	}
	cond := []model.PlaybookStepCondition{
		{Field: "hits_count", Operator: "gte", Value: "3"},
	}
	if !evaluateStepConditions(cond, hits) {
		t.Fatal("expected condition to pass")
	}

	cond[0].Value = "10"
	if evaluateStepConditions(cond, hits) {
		t.Fatal("expected condition to fail")
	}
}

func TestEvaluateStepConditionsSeverityHigh(t *testing.T) {
	hits := []model.ThreatHit{
		{Level: "high"}, {Level: "high"}, {Level: "medium"},
	}
	cond := []model.PlaybookStepCondition{
		{Field: "severity_high", Operator: "eq", Value: "2"},
	}
	if !evaluateStepConditions(cond, hits) {
		t.Fatal("expected condition to pass")
	}
}

// ---------------------------------------------------------------------------
// Display filter matching tests
// ---------------------------------------------------------------------------

func TestMatchDisplayFilter(t *testing.T) {
	pkt := model.Packet{
		Info:     "HTTP GET /test",
		Protocol: "HTTP",
		SourceIP: "10.0.0.1",
		DestIP:   "10.0.0.2",
		DestPort: 80,
	}

	if !matchDisplayFilter(pkt, "http") {
		t.Fatal("expected match for http")
	}
	if !matchDisplayFilter(pkt, "80") {
		t.Fatal("expected match for port 80")
	}
	if matchDisplayFilter(pkt, "dns") {
		t.Fatal("expected no match for dns")
	}
}

// ---------------------------------------------------------------------------
// Step execution tests
// ---------------------------------------------------------------------------

func TestRunPlaybookWithFilterQueryStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "HTTP GET /login", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
		{ID: 2, Info: "DNS query example.com", SourceIP: "10.0.0.1", DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS"},
		{ID: 3, Info: "HTTP POST /api", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Filter Query Test",
		Steps: []model.PlaybookStep{
			{
				ID:      "fq1",
				Name:    "HTTP traffic filter",
				Type:    model.PlaybookStepTypeFilterQuery,
				Enabled: true,
				Config:  map[string]any{"filter": "http"},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
	if result.StepResults[0].HitsCount != 2 {
		t.Fatalf("expected 2 hits for http filter, got %d", result.StepResults[0].HitsCount)
	}
}

func TestRunPlaybookWithFilterQueryStepMissingFilter(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Bad Filter",
		Steps: []model.PlaybookStep{
			{
				ID:      "fq1",
				Name:    "Empty filter",
				Type:    model.PlaybookStepTypeFilterQuery,
				Enabled: true,
				Config:  map[string]any{},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.StepResults[0].Status != "error" {
		t.Fatalf("expected error status, got %s", result.StepResults[0].Status)
	}
}

func TestRunPlaybookWithYARAScanStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// YARA scan with no objects loaded — should return 0 hits without error.
	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "YARA Scan",
		Steps: []model.PlaybookStep{
			{
				ID:      "yara1",
				Name:    "YARA object scan",
				Type:    model.PlaybookStepTypeYARAScan,
				Enabled: true,
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if result.StepResults[0].HitsCount != 0 {
		t.Fatalf("expected 0 hits with no objects, got %d", result.StepResults[0].HitsCount)
	}
}

func TestRunPlaybookWithC2AnalysisStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// C2 analysis without loaded pcap — should complete without error.
	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "C2 Analysis",
		Steps: []model.PlaybookStep{
			{
				ID:      "c2-1",
				Name:    "C2 detection",
				Type:    model.PlaybookStepTypeC2Analysis,
				Enabled: true,
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
}

func TestRunPlaybookWithAPTAnalysisStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// APT analysis without loaded pcap — should complete without error.
	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "APT Analysis",
		Steps: []model.PlaybookStep{
			{
				ID:      "apt-1",
				Name:    "APT detection",
				Type:    model.PlaybookStepTypeAPTAnalysis,
				Enabled: true,
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
}

func TestRunPlaybookWithCustomStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// Custom step with unknown command — returns nil (no hits, no error).
	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Custom Default",
		Steps: []model.PlaybookStep{
			{
				ID:      "custom-1",
				Name:    "Unknown custom command",
				Type:    model.PlaybookStepTypeCustom,
				Enabled: true,
				Config:  map[string]any{"command": "unknown_command"},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if result.StepResults[0].HitsCount != 0 {
		t.Fatalf("expected 0 hits for unknown custom command, got %d", result.StepResults[0].HitsCount)
	}
}

func TestRunPlaybookWithDNSTunnelStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// Add DNS packets with long subdomain labels (potential tunnel signal).
	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "DNS query", SourceIP: "10.0.0.1", DestIP: "8.8.8.8", DestPort: 53, Protocol: "DNS",
			Payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"},
		{ID: 2, Info: "normal HTTP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "DNS Tunnel",
		Steps: []model.PlaybookStep{
			{
				ID:      "dns-t1",
				Name:    "DNS tunnel detection",
				Type:    model.PlaybookStepTypeCustom,
				Enabled: true,
				Config:  map[string]any{"command": "dns_tunnel"},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
}

func TestRunPlaybookWithBruteForceStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// Add HTTP auth-like packets.
	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "POST /login 401 Unauthorized", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
		{ID: 2, Info: "POST /login 401 Unauthorized", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
		{ID: 3, Info: "POST /login 200 OK", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 80, Protocol: "HTTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Brute Force",
		Steps: []model.PlaybookStep{
			{
				ID:      "bf-1",
				Name:    "Brute force detection",
				Type:    model.PlaybookStepTypeCustom,
				Enabled: true,
				Config:  map[string]any{"command": "brute_force"},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
}

func TestRunPlaybookWithDataExfiltrationStep(t *testing.T) {
	svc := NewService(nil)
	t.Cleanup(func() { _ = svc.captureCtl.packetStore.Close() })

	// Add packets that may trigger data exfiltration detection.
	if err := svc.captureCtl.packetStore.Append([]model.Packet{
		{ID: 1, Info: "POST /upload HTTP/1.1", SourceIP: "10.0.0.1", DestIP: "45.33.32.156", DestPort: 443, Protocol: "HTTPS"},
		{ID: 2, Info: "FTP STOR secret.zip", SourceIP: "10.0.0.1", DestIP: "45.33.32.156", DestPort: 21, Protocol: "FTP"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	pb, _ := svc.CreatePlaybook(model.HuntingPlaybook{
		Name: "Data Exfil",
		Steps: []model.PlaybookStep{
			{
				ID:      "de-1",
				Name:    "Data exfiltration detection",
				Type:    model.PlaybookStepTypeCustom,
				Enabled: true,
				Config:  map[string]any{"command": "data_exfil"},
			},
		},
	})

	result, err := svc.RunPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("RunPlaybook() error = %v", err)
	}
	if result.Status != model.PlaybookStatusComplete {
		t.Fatalf("expected status complete, got %s", result.Status)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.StepResults))
	}
}
