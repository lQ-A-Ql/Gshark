package transport

import (
	"os"
	"strings"
)

func (s *Server) registerUploadedFile(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	s.uploadMu.Lock()
	s.uploadedFiles[path] = struct{}{}
	toDelete := s.collectUploadedFilesForCleanupLocked(path, s.activeUploadedPCAP)
	s.uploadMu.Unlock()
	deleteFiles(toDelete)
}

func (s *Server) promoteUploadedFile(path string) {
	path = strings.TrimSpace(path)

	s.uploadMu.Lock()
	var oldActive string
	if s.activeUploadedPCAP != "" && s.activeUploadedPCAP != path {
		oldActive = s.activeUploadedPCAP
		delete(s.uploadedFiles, s.activeUploadedPCAP)
	}
	if _, ok := s.uploadedFiles[path]; ok {
		s.activeUploadedPCAP = path
	} else {
		s.activeUploadedPCAP = ""
	}
	toDelete := s.collectUploadedFilesForCleanupLocked(s.activeUploadedPCAP)
	s.uploadMu.Unlock()
	if oldActive != "" {
		toDelete = append(toDelete, oldActive)
	}
	deleteFiles(toDelete)
}

func (s *Server) cleanupUploadedFiles() {
	s.uploadMu.Lock()
	toDelete := make([]string, 0, len(s.uploadedFiles))
	for path := range s.uploadedFiles {
		toDelete = append(toDelete, path)
	}
	s.uploadedFiles = map[string]struct{}{}
	s.activeUploadedPCAP = ""
	s.uploadMu.Unlock()
	deleteFiles(toDelete)
}

func (s *Server) collectUploadedFilesForCleanupLocked(keep ...string) []string {
	keepSet := make(map[string]struct{}, len(keep))
	for _, item := range keep {
		item = strings.TrimSpace(item)
		if item != "" {
			keepSet[item] = struct{}{}
		}
	}

	var toDelete []string
	for path := range s.uploadedFiles {
		if _, ok := keepSet[path]; ok {
			continue
		}
		toDelete = append(toDelete, path)
		delete(s.uploadedFiles, path)
	}
	return toDelete
}

func deleteFiles(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		_ = os.Remove(path)
	}
}
