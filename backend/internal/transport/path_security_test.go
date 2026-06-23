package transport

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafePathUnder(t *testing.T) {
	abs := func(parts ...string) string {
		if runtime.GOOS == "windows" {
			return filepath.Join(append([]string{"C:\\"}, parts...)...)
		}
		return filepath.Join(append([]string{"/"}, parts...)...)
	}
	base := abs("data", "captures")
	absFile := abs("data", "captures", "foo.pcap")
	absNested := abs("data", "captures", "2026", "foo.pcap")
	escaped := abs("data", "other", "foo.pcap")
	traversal := abs("data", "captures", "..", "other", "foo.pcap")

	tests := []struct {
		name      string
		base      string
		candidate string
		wantErr   bool
	}{
		{"absolute under base", base, absFile, false},
		{"absolute nested", base, absNested, false},
		{"escapes base", base, escaped, true},
		{"traversal escapes", base, traversal, true},
		{"empty candidate", base, "", true},
		{"nul byte", base, filepath.Join(base, "foo\x00.pcap"), true},
		{"relative rejected", base, "foo.pcap", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafePathUnder(tt.base, tt.candidate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SafePathUnder(%q, %q) error = %v, wantErr %v", tt.base, tt.candidate, err, tt.wantErr)
			}
			if err == nil && got == "" {
				t.Fatalf("expected non-empty cleaned path")
			}
		})
	}
}

func TestSafePathUnderEmptyBase(t *testing.T) {
	if runtime.GOOS == "windows" {
		_, err := SafePathUnder("", `C:\foo.pcap`)
		if err != nil {
			t.Fatalf("expected absolute path with empty base to succeed, got %v", err)
		}
		_, err = SafePathUnder("", "foo.pcap")
		if err == nil {
			t.Fatalf("expected relative path to fail")
		}
		return
	}
	_, err := SafePathUnder("", "/foo.pcap")
	if err != nil {
		t.Fatalf("expected absolute path with empty base to succeed, got %v", err)
	}
	_, err = SafePathUnder("", "foo.pcap")
	if err == nil {
		t.Fatalf("expected relative path to fail")
	}
}

func TestIsSafeRelativePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"foo.pcap", true},
		{"sub/foo.pcap", true},
		{"", false},
		{"../foo.pcap", false},
		{"foo/../bar", false},
		{"/abs/foo.pcap", false},
		{"foo\x00bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsSafeRelativePath(tt.path); got != tt.want {
				t.Fatalf("IsSafeRelativePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
