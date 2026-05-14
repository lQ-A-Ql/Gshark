package architecture

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackendArchitectureBoundaries(t *testing.T) {
	root := backendRoot(t)

	t.Run("model has no high-level internal dependencies", func(t *testing.T) {
		for _, path := range goFiles(t, filepath.Join(root, "internal", "model")) {
			for _, imported := range importsFor(t, path) {
				if containsAny(imported, []string{
					"/internal/engine",
					"/internal/transport",
					"/internal/tshark",
					"/internal/plugin",
					"/internal/miscpkg",
				}) {
					t.Fatalf("%s imports forbidden high-level package %q", rel(root, path), imported)
				}
			}
		}
	})

	t.Run("transport does not depend on tshark internals", func(t *testing.T) {
		for _, path := range goFiles(t, filepath.Join(root, "internal", "transport")) {
			for _, imported := range importsFor(t, path) {
				if strings.Contains(imported, "/internal/tshark") {
					t.Fatalf("%s imports tshark internals through %q", rel(root, path), imported)
				}
			}
		}
	})

	t.Run("investigation report builders stay pure", func(t *testing.T) {
		for _, path := range goFiles(t, filepath.Join(root, "internal", "engine")) {
			name := filepath.Base(path)
			if !strings.HasPrefix(name, "analysis_report") {
				continue
			}
			for _, imported := range importsFor(t, path) {
				if containsAny(imported, []string{"/internal/tshark", "/internal/transport"}) {
					t.Fatalf("%s imports forbidden report dependency %q", rel(root, path), imported)
				}
			}
			body := readFile(t, path)
			if containsAny(body, []string{"LoadPCAP", "BeginCapture", "packetStore", "NewRunner", "tshark."}) {
				t.Fatalf("%s mixes report building with capture/tshark state", rel(root, path))
			}
		}
	})

	t.Run("investigation report rule metadata stays registry owned", func(t *testing.T) {
		allowed := map[string]struct{}{
			"analysis_report_rules.go":  {},
			"analysis_report_shared.go": {},
		}
		for _, path := range goFiles(t, filepath.Join(root, "internal", "engine")) {
			name := filepath.Base(path)
			if !strings.HasPrefix(name, "analysis_report") {
				continue
			}
			if _, ok := allowed[name]; ok {
				continue
			}
			body := readFile(t, path)
			if strings.Contains(body, "withReportRule(") {
				t.Fatalf("%s writes report rule metadata directly; use withReportRuleID and internal/report", rel(root, path))
			}
			if containsAny(body, []string{"RuleID:", "Reason:", "Caveats:"}) {
				t.Fatalf("%s defines report rule metadata outside internal/report", rel(root, path))
			}
		}
	})

	t.Run("report package stays dependency-light", func(t *testing.T) {
		for _, path := range goFiles(t, filepath.Join(root, "internal", "report")) {
			for _, imported := range importsFor(t, path) {
				if containsAny(imported, []string{"/internal/engine", "/internal/transport", "/internal/tshark"}) {
					t.Fatalf("%s imports forbidden report dependency %q", rel(root, path), imported)
				}
			}
		}
	})

	t.Run("evidence files stay transport free", func(t *testing.T) {
		for _, path := range goFiles(t, filepath.Join(root, "internal", "engine")) {
			if !strings.HasPrefix(filepath.Base(path), "evidence") {
				continue
			}
			for _, imported := range importsFor(t, path) {
				if containsAny(imported, []string{"/internal/transport", "/internal/tshark", "net/http"}) {
					t.Fatalf("%s imports forbidden evidence dependency %q", rel(root, path), imported)
				}
			}
		}
	})

	t.Run("evidence types are only referenced by engine and transport", func(t *testing.T) {
		// Evidence value types (EvidenceRecord, EvidenceResponse, EvidenceFilter,
		// APTEvidenceRecord) are declared in the shared model package but
		// semantically belong to the evidence pipeline. Only the engine owner
		// (which produces them) and the transport consumer (which ships them
		// over HTTP) may reference them directly. Any other internal package
		// must interact via exported helper functions on engine.Service.
		//
		// Validates Requirements 6.2 (P2-1: report/evidence package boundary
		// enforcement).
		internalDir := filepath.Join(root, "internal")
		allowedOwners := map[string]struct{}{
			filepath.Join(internalDir, "engine"):    {},
			filepath.Join(internalDir, "transport"): {},
			// model itself declares the types.
			filepath.Join(internalDir, "model"): {},
			// this boundary test file legitimately names them in string form.
			filepath.Join(internalDir, "architecture"): {},
		}
		evidenceTypeNames := []string{
			"model.EvidenceRecord",
			"model.EvidenceResponse",
			"model.EvidenceFilter",
			"model.APTEvidenceRecord",
		}

		err := filepath.WalkDir(internalDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if _, ok := allowedOwners[path]; ok {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") {
				return nil
			}
			body := readFile(t, path)
			for _, typeName := range evidenceTypeNames {
				if strings.Contains(body, typeName) {
					t.Fatalf("%s references evidence type %s; evidence types must stay within engine/transport/model (P2-1 boundary)", rel(root, path), typeName)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk internal for evidence boundary: %v", err)
		}
	})
}

func backendRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve current test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func goFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func importsFor(t *testing.T, path string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports for %s: %v", path, err)
	}
	out := make([]string, 0, len(parsed.Imports))
	for _, spec := range parsed.Imports {
		out = append(out, strings.Trim(spec.Path.Value, `"`))
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func rel(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}
