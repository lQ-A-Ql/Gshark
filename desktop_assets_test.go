//go:build dev || production

package main

import "testing"

func TestEmbeddedDesktopAssets(t *testing.T) {
	requiredAssets := []string{
		"frontend/dist/sentinel-backend.exe",
		"frontend/dist/rules/yara/default.yar",
	}

	for _, path := range requiredAssets {
		data, err := assets.ReadFile(path)
		if err != nil {
			t.Fatalf("embedded desktop asset %q is missing; run cd frontend && pnpm run build:wails: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("embedded desktop asset %q is empty", path)
		}
	}
}
