//go:build dev || production

package main

import "testing"

func TestNormalizeSemanticVersion(t *testing.T) {
	t.Parallel()

	if got := normalizeSemanticVersion("gshark.v0.0.3.exe"); got != "v0.0.3" {
		t.Fatalf("normalizeSemanticVersion() = %q, want %q", got, "v0.0.3")
	}
	if got := normalizeSemanticVersion("release-2026"); got != "" {
		t.Fatalf("normalizeSemanticVersion() = %q, want empty", got)
	}
}

func TestHasNewerRelease(t *testing.T) {
	t.Parallel()

	if !hasNewerRelease("v0.0.2", "v0.0.3") {
		t.Fatalf("expected newer release to be detected")
	}
	if hasNewerRelease("v0.0.3", "v0.0.3") {
		t.Fatalf("expected equal versions to be treated as up to date")
	}
	if hasNewerRelease("v0.1.0", "v0.0.9") {
		t.Fatalf("expected newer current version to remain up to date")
	}
}

func TestSelectReleaseAssetPrefersWindowsExecutable(t *testing.T) {
	t.Parallel()

	release := githubRelease{
		Assets: []githubReleaseAsset{
			{Name: "gshark-v0.0.3-linux.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
			{Name: "gshark.v0.0.3.exe", BrowserDownloadURL: "https://example.com/windows"},
			{Name: "gshark-v0.0.3-windows.zip", BrowserDownloadURL: "https://example.com/windows-zip"},
		},
	}

	asset := selectReleaseAsset(release)
	if asset == nil {
		t.Fatalf("selectReleaseAsset() returned nil")
	}
	if asset.Name != "gshark.v0.0.3.exe" {
		t.Fatalf("selectReleaseAsset() = %q, want %q", asset.Name, "gshark.v0.0.3.exe")
	}
}

func TestExtractReleaseVersionFallsBackToAssetName(t *testing.T) {
	t.Parallel()

	release := githubRelease{
		TagName: "gshark",
		Name:    "gshark release",
		Assets: []githubReleaseAsset{
			{Name: "gshark.v0.0.2.exe"},
		},
	}

	if got := extractReleaseVersion(release); got != "v0.0.2" {
		t.Fatalf("extractReleaseVersion() = %q, want %q", got, "v0.0.2")
	}
}

func TestResolveUpdateManifestURLPrefersExplicitValue(t *testing.T) {
	original := appManifestURL
	appManifestURL = "https://updates.example.com/gshark/version.json"
	t.Cleanup(func() {
		appManifestURL = original
	})

	if got := resolveUpdateManifestURL("lQ-A-Ql/Gshark"); got != "https://updates.example.com/gshark/version.json" {
		t.Fatalf("resolveUpdateManifestURL() = %q, want explicit manifest URL", got)
	}
}

func TestResolveUpdateManifestURLBuildsRawGitHubURL(t *testing.T) {
	original := appManifestURL
	appManifestURL = ""
	t.Cleanup(func() {
		appManifestURL = original
	})
	t.Setenv("GSHARK_UPDATE_MANIFEST_URL", "")
	t.Setenv("GSHARK_UPDATE_MANIFEST_REF", "release/version.json")

	got := resolveUpdateManifestURL("lQ-A-Ql/Gshark")
	want := "https://raw.githubusercontent.com/lQ-A-Ql/Gshark/release/version.json"
	if got != want {
		t.Fatalf("resolveUpdateManifestURL() = %q, want %q", got, want)
	}
}

func TestNormalizeSHA256(t *testing.T) {
	t.Parallel()

	input := "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	got := normalizeSHA256(input)
	want := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if got != want {
		t.Fatalf("normalizeSHA256() = %q, want %q", got, want)
	}
	if got := normalizeSHA256("invalid"); got != "" {
		t.Fatalf("normalizeSHA256() = %q, want empty", got)
	}
}
