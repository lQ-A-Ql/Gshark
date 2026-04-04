//go:build production

package main

import "testing"

func TestProductionBuildEnablesSelfUpdate(t *testing.T) {
	t.Parallel()

	if !selfUpdateEnabledBuild {
		t.Fatalf("expected production build to enable self update")
	}
	if currentBuildMode != "production" {
		t.Fatalf("currentBuildMode = %q, want %q", currentBuildMode, "production")
	}
}
