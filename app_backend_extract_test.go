//go:build dev || production

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractedBackendMatchesVerifiesFileContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel-backend.exe")
	original := []byte("embedded backend")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("write backend: %v", err)
	}

	digest := sha256.Sum256(original)
	if !extractedBackendMatches(path, digest) {
		t.Fatal("expected matching extracted backend to verify")
	}

	if err := os.WriteFile(path, []byte("tampered backend"), 0o644); err != nil {
		t.Fatalf("tamper backend: %v", err)
	}
	if extractedBackendMatches(path, digest) {
		t.Fatal("expected tampered extracted backend to fail verification")
	}
}
