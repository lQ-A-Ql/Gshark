package tool

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeAllowedDir(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{filepath.FromSlash("/usr/bin"), filepath.FromSlash("/usr/bin")},
		{filepath.FromSlash("/usr/bin/"), filepath.FromSlash("/usr/bin")},
		{filepath.FromSlash("/"), ""},
		{"\\", ""},
		{".", ""},
		{`C:\Tools\tshark`, `C:\Tools\tshark`},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			struct {
				in   string
				want string
			}{`C:\`, ""},
			struct {
				in   string
				want string
			}{`C:`, ""},
		)
	}

	for _, c := range cases {
		got := NormalizeAllowedDir(c.in)
		if got != c.want {
			t.Errorf("NormalizeAllowedDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAllowedDirs_DedupesAndCleans(t *testing.T) {
	in := []string{filepath.FromSlash("/a"), filepath.FromSlash("/a/"), " /a ", filepath.FromSlash("/b"), "", filepath.FromSlash("/")}
	want := []string{filepath.FromSlash("/a"), filepath.FromSlash("/b")}
	got := NormalizeAllowedDirs(in)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAllowedDirList_AddRemoveContains(t *testing.T) {
	a := NewAllowedDirList([]string{"/usr/bin"})
	if !a.Add("/usr/local/bin") {
		t.Fatal("expected Add to change list")
	}
	if a.Add("/usr/local/bin") {
		t.Fatal("expected duplicate Add to leave list unchanged")
	}

	if !a.Contains("/usr/local/bin/foo") {
		t.Fatal("expected child path to be contained")
	}
	if a.Contains("/opt/other") {
		t.Fatal("expected unrelated path not to be contained")
	}

	if !a.Remove("/usr/local/bin") {
		t.Fatal("expected Remove to change list")
	}
	if a.Remove("/usr/local/bin") {
		t.Fatal("expected removing absent dir to leave list unchanged")
	}
	if a.Contains("/usr/local/bin/foo") {
		t.Fatal("expected removed dir no longer to contain paths")
	}
}

func TestAllowedDirList_MatchingDir(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tshark")
	if err := writeFakeFile(bin); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	a := NewAllowedDirList([]string{dir})
	if got := a.MatchingDir(bin); got != filepath.Clean(dir) {
		t.Fatalf("MatchingDir(%q) = %q, want %q", bin, got, filepath.Clean(dir))
	}
	if got := a.MatchingDir(dir); got != filepath.Clean(dir) {
		t.Fatalf("MatchingDir(%q) = %q, want %q", dir, got, filepath.Clean(dir))
	}
	nestedDir := filepath.Join(dir, "nested")
	nestedBin := filepath.Join(nestedDir, "tshark")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	if err := writeFakeFile(nestedBin); err != nil {
		t.Fatalf("write nested fake binary: %v", err)
	}
	if got := a.MatchingDir(nestedBin); got != filepath.Clean(dir) {
		t.Fatalf("MatchingDir should match parent allowed dirs, got %q, want %q", got, filepath.Clean(dir))
	}
}

func writeFakeFile(path string) error {
	return os.WriteFile(path, []byte("fake"), 0o644)
}
