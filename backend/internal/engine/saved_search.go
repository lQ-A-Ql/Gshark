package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ListSavedSearches returns all saved searches.
func (s *Service) ListSavedSearches() []model.SavedSearch {
	s.searchMu.RLock()
	defer s.searchMu.RUnlock()
	out := make([]model.SavedSearch, 0, len(s.savedSearches))
	for _, ss := range s.savedSearches {
		out = append(out, *ss)
	}
	return out
}

// GetSavedSearch returns a saved search by ID.
func (s *Service) GetSavedSearch(id string) (*model.SavedSearch, bool) {
	s.searchMu.RLock()
	defer s.searchMu.RUnlock()
	ss, ok := s.savedSearches[id]
	if !ok {
		return nil, false
	}
	copy := *ss
	return &copy, true
}

// CreateSavedSearch stores a new saved search.
func (s *Service) CreateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error) {
	if strings.TrimSpace(ss.Name) == "" {
		return nil, fmt.Errorf("saved search name is required")
	}
	if strings.TrimSpace(ss.Query) == "" {
		return nil, fmt.Errorf("saved search query is required")
	}

	now := time.Now().UTC()
	if strings.TrimSpace(ss.ID) == "" {
		ss.ID = nextID("ss")
	}
	ss.CreatedAt = now
	ss.UpdatedAt = now

	s.searchMu.Lock()
	s.savedSearches[ss.ID] = &ss
	s.searchMu.Unlock()

	copy := ss
	return &copy, nil
}

// UpdateSavedSearch replaces an existing saved search.
func (s *Service) UpdateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error) {
	if strings.TrimSpace(ss.ID) == "" {
		return nil, fmt.Errorf("saved search ID is required")
	}
	s.searchMu.Lock()
	existing, ok := s.savedSearches[ss.ID]
	if !ok {
		s.searchMu.Unlock()
		return nil, fmt.Errorf("saved search %s not found", ss.ID)
	}
	ss.CreatedAt = existing.CreatedAt
	ss.UpdatedAt = time.Now().UTC()
	s.savedSearches[ss.ID] = &ss
	s.searchMu.Unlock()
	copy := ss
	return &copy, nil
}

// DeleteSavedSearch removes a saved search by ID.
func (s *Service) DeleteSavedSearch(id string) bool {
	s.searchMu.Lock()
	defer s.searchMu.Unlock()
	if _, ok := s.savedSearches[id]; !ok {
		return false
	}
	delete(s.savedSearches, id)
	return true
}

// ExecuteSavedSearch runs a saved search and returns the matching threat hits.
func (s *Service) ExecuteSavedSearch(id string) (*model.SavedSearch, []model.ThreatHit, error) {
	s.searchMu.RLock()
	ss, ok := s.savedSearches[id]
	if !ok {
		s.searchMu.RUnlock()
		return nil, nil, fmt.Errorf("saved search %s not found", id)
	}
	ssCopy := *ss
	s.searchMu.RUnlock()

	prefixes := []string{ssCopy.Query}
	prefixes = append(prefixes, ssCopy.Filters...)

	hits := s.ThreatHuntWithContext(nil, prefixes)

	// Update hit count.
	s.searchMu.Lock()
	if existing, ok := s.savedSearches[id]; ok {
		existing.HitCount = len(hits)
		existing.UpdatedAt = time.Now().UTC()
	}
	s.searchMu.Unlock()

	return &ssCopy, hits, nil
}
