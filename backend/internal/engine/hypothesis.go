package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ListHypotheses returns all hypotheses, optionally filtered by status.
func (s *Service) ListHypotheses(statusFilter string) []model.Hypothesis {
	s.hypothesisMu.RLock()
	defer s.hypothesisMu.RUnlock()
	out := make([]model.Hypothesis, 0, len(s.hypotheses))
	for _, h := range s.hypotheses {
		if statusFilter != "" && string(h.Status) != statusFilter {
			continue
		}
		out = append(out, *h)
	}
	return out
}

// GetHypothesis returns a hypothesis by ID.
func (s *Service) GetHypothesis(id string) (*model.Hypothesis, bool) {
	s.hypothesisMu.RLock()
	defer s.hypothesisMu.RUnlock()
	h, ok := s.hypotheses[id]
	if !ok {
		return nil, false
	}
	copy := *h
	return &copy, true
}

// CreateHypothesis stores a new hypothesis.
func (s *Service) CreateHypothesis(h model.Hypothesis) (*model.Hypothesis, error) {
	if strings.TrimSpace(h.Title) == "" {
		return nil, fmt.Errorf("hypothesis title is required")
	}

	now := time.Now().UTC()
	if strings.TrimSpace(h.ID) == "" {
		h.ID = nextID("hyp")
	}
	h.CreatedAt = now
	h.UpdatedAt = now
	if h.Status == "" {
		h.Status = model.HypothesisStatusOpen
	}

	s.hypothesisMu.Lock()
	s.hypotheses[h.ID] = &h
	s.hypothesisMu.Unlock()

	copy := h
	return &copy, nil
}

// UpdateHypothesis replaces an existing hypothesis.
func (s *Service) UpdateHypothesis(h model.Hypothesis) (*model.Hypothesis, error) {
	if strings.TrimSpace(h.ID) == "" {
		return nil, fmt.Errorf("hypothesis ID is required")
	}
	s.hypothesisMu.Lock()
	existing, ok := s.hypotheses[h.ID]
	if !ok {
		s.hypothesisMu.Unlock()
		return nil, fmt.Errorf("hypothesis %s not found", h.ID)
	}
	h.CreatedAt = existing.CreatedAt
	h.UpdatedAt = time.Now().UTC()
	s.hypotheses[h.ID] = &h
	s.hypothesisMu.Unlock()
	copy := h
	return &copy, nil
}

// DeleteHypothesis removes a hypothesis by ID.
func (s *Service) DeleteHypothesis(id string) bool {
	s.hypothesisMu.Lock()
	defer s.hypothesisMu.Unlock()
	if _, ok := s.hypotheses[id]; !ok {
		return false
	}
	delete(s.hypotheses, id)
	return true
}

// AddHypothesisEvidence adds a piece of evidence to a hypothesis.
func (s *Service) AddHypothesisEvidence(hypothesisID string, evidence model.HypothesisEvidence) (*model.Hypothesis, error) {
	if strings.TrimSpace(evidence.ID) == "" {
		evidence.ID = nextID("ev")
	}
	evidence.CreatedAt = time.Now().UTC()

	s.hypothesisMu.Lock()
	h, ok := s.hypotheses[hypothesisID]
	if !ok {
		s.hypothesisMu.Unlock()
		return nil, fmt.Errorf("hypothesis %s not found", hypothesisID)
	}
	h.Evidence = append(h.Evidence, evidence)
	h.UpdatedAt = time.Now().UTC()
	copy := *h
	s.hypothesisMu.Unlock()
	return &copy, nil
}

// UpdateHypothesisStatus changes the status of a hypothesis.
func (s *Service) UpdateHypothesisStatus(id string, status model.HypothesisStatus, conclusion string) (*model.Hypothesis, error) {
	s.hypothesisMu.Lock()
	h, ok := s.hypotheses[id]
	if !ok {
		s.hypothesisMu.Unlock()
		return nil, fmt.Errorf("hypothesis %s not found", id)
	}
	h.Status = status
	if conclusion != "" {
		h.Conclusion = conclusion
	}
	h.UpdatedAt = time.Now().UTC()
	copy := *h
	s.hypothesisMu.Unlock()
	return &copy, nil
}
