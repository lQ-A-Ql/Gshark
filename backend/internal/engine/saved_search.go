package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ListSavedSearches returns all saved searches.
func (s *Service) ListSavedSearches() []model.SavedSearch {
	s.savedSearchCtl.searchMu.RLock()
	defer s.savedSearchCtl.searchMu.RUnlock()
	out := make([]model.SavedSearch, 0, len(s.savedSearchCtl.savedSearches))
	for _, ss := range s.savedSearchCtl.savedSearches {
		out = append(out, *ss)
	}
	return out
}

// GetSavedSearch returns a saved search by ID.
func (s *Service) GetSavedSearch(id string) (*model.SavedSearch, bool) {
	s.savedSearchCtl.searchMu.RLock()
	defer s.savedSearchCtl.searchMu.RUnlock()
	ss, ok := s.savedSearchCtl.savedSearches[id]
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
	s.savedSearchCtl.searchMu.Lock()
	s.savedSearchCtl.savedSearches[ss.ID] = &ss
	s.savedSearchCtl.searchMu.Unlock()

	copy := ss
	return &copy, nil
}

// UpdateSavedSearch replaces an existing saved search.
func (s *Service) UpdateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error) {
	if strings.TrimSpace(ss.ID) == "" {
		return nil, fmt.Errorf("saved search ID is required")
	}
	s.savedSearchCtl.searchMu.Lock()
	existing, ok := s.savedSearchCtl.savedSearches[ss.ID]
	if !ok {
		s.savedSearchCtl.searchMu.Unlock()
		return nil, fmt.Errorf("saved search %s not found", ss.ID)
	}
	ss.CreatedAt = existing.CreatedAt
	ss.UpdatedAt = time.Now().UTC()
	s.savedSearchCtl.savedSearches[ss.ID] = &ss
	s.savedSearchCtl.searchMu.Unlock()
	copy := ss
	return &copy, nil
}

// DeleteSavedSearch removes a saved search by ID.
func (s *Service) DeleteSavedSearch(id string) bool {
	s.savedSearchCtl.searchMu.Lock()
	defer s.savedSearchCtl.searchMu.Unlock()
	if _, ok := s.savedSearchCtl.savedSearches[id]; !ok {
		return false
	}
	delete(s.savedSearchCtl.savedSearches, id)
	return true
}

// ExecuteSavedSearch runs a saved search and returns the matching threat hits.
func (s *Service) ExecuteSavedSearch(id string) (*model.SavedSearch, []model.ThreatHit, error) {
	s.savedSearchCtl.searchMu.RLock()
	ss, ok := s.savedSearchCtl.savedSearches[id]
	if !ok {
		s.savedSearchCtl.searchMu.RUnlock()
		return nil, nil, fmt.Errorf("saved search %s not found", id)
	}
	ssCopy := *ss
	s.savedSearchCtl.searchMu.RUnlock()

	prefixes := []string{ssCopy.Query}
	prefixes = append(prefixes, ssCopy.Filters...)

	hits := s.ThreatHuntWithContext(nil, prefixes)
	// Update hit count.
	s.savedSearchCtl.searchMu.Lock()
	if existing, ok := s.savedSearchCtl.savedSearches[id]; ok {
		existing.HitCount = len(hits)
		existing.UpdatedAt = time.Now().UTC()
	}
	s.savedSearchCtl.searchMu.Unlock()

	return &ssCopy, hits, nil
}
