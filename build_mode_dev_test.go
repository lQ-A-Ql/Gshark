//go:build dev

package main

import "testing"

func TestDevBuildDisablesSelfUpdate(t *testing.T) {
	t.Parallel()

	if selfUpdateEnabledBuild {
		t.Fatalf("expected dev build to disable self update")
	}
	if currentBuildMode != "dev" {
		t.Fatalf("currentBuildMode = %q, want %q", currentBuildMode, "dev")
	}
}
