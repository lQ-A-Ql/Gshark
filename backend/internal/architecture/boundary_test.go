package architecture

import (
	"go/ast"
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

	t.Run("transport handlers use context-aware long running service calls", func(t *testing.T) {
		transportFiles := goFiles(t, filepath.Join(root, "internal", "transport"))
		assertFileCovered(t, root, transportFiles, filepath.Join("internal", "transport", "http_server.go"))
		assertFileCovered(t, root, transportFiles, filepath.Join("internal", "transport", "http_capture.go"))
		forbidden := []string{
			"s.analysis.GlobalTrafficStats()",
			"s.analysis.IndustrialAnalysis()",
			"s.analysis.VehicleAnalysis()",
			"s.analysis.USBAnalysis()",
			"s.media.TranscribeMediaArtifact(payload.Token, payload.Force)",
			"s.toolAnalysis.ListNTLMSessionMaterials()",
			"s.toolAnalysis.ListSMB3SessionCandidates()",
			"s.toolAnalysis.RunWinRMDecrypt(req)",
		}
		for _, path := range transportFiles {
			body := readFile(t, path)
			for _, call := range forbidden {
				if strings.Contains(body, call) {
					t.Fatalf("%s calls %s; transport handlers must pass request context to long-running service methods", rel(root, path), call)
				}
			}
		}
	})

	t.Run("engine root files have domain ownership", func(t *testing.T) {
		engineDir := filepath.Join(root, "internal", "engine")
		owners := engineDomainOwners()
		for _, path := range goFiles(t, engineDir) {
			if filepath.Dir(path) != engineDir {
				continue
			}
			name := filepath.Base(path)
			if _, ok := owners[name]; !ok {
				t.Fatalf("%s is missing from engine domain ownership map", rel(root, path))
			}
		}
	})

	t.Run("new large engine root files must be explicitly grandfathered", func(t *testing.T) {
		engineDir := filepath.Join(root, "internal", "engine")
		grandfathered := grandfatheredLargeEngineFiles()
		const largeFileLineLimit = 650
		for _, path := range goFiles(t, engineDir) {
			if filepath.Dir(path) != engineDir {
				continue
			}
			name := filepath.Base(path)
			lines := countLines(readFile(t, path))
			if lines <= largeFileLineLimit {
				continue
			}
			if _, ok := grandfathered[name]; !ok {
				t.Fatalf("%s has %d lines; split or explicitly add to large-file exception list", rel(root, path), lines)
			}
		}
	})

	t.Run("engine pure logic subpackages stay dependency light", func(t *testing.T) {
		pureLogicPackages := []string{
			filepath.Join(root, "internal", "engine", "payloadinspect"),
		}
		for _, dir := range pureLogicPackages {
			for _, path := range goFiles(t, dir) {
				for _, imported := range importsFor(t, path) {
					if containsAny(imported, []string{
						"/internal/engine",
						"/internal/transport",
						"/internal/tshark",
						"/internal/miscpkg",
						"/internal/plugin",
						"net/http",
						"os/exec",
					}) {
						t.Fatalf("%s imports forbidden pure-logic dependency %q", rel(root, path), imported)
					}
				}
			}
		}
	})

	t.Run("engine service uses explicit controllers instead of embedded state", func(t *testing.T) {
		servicePath := filepath.Join(root, "internal", "engine", "service.go")
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, servicePath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel(root, servicePath), err)
		}
		serviceStruct := findStructType(parsed, "Service")
		if serviceStruct == nil {
			t.Fatalf("%s is missing Service struct", rel(root, servicePath))
		}

		wantControllers := map[string]string{
			"captureCtl":     "captureController",
			"filterCtl":      "displayFilterController",
			"streamCtl":      "streamController",
			"analysisCtl":    "analysisController",
			"objectCtl":      "objectController",
			"mediaCtl":       "mediaController",
			"huntingCtl":     "yaraHuntingController",
			"runtimeCtl":     "toolRuntimeController",
			"mcpCtl":         "mcpController",
			"playbookCtl":    "playbookController",
			"savedSearchCtl": "savedSearchController",
			"hypothesisCtl":  "hypothesisController",
		}
		seen := map[string]string{}
		for _, field := range serviceStruct.Fields.List {
			if len(field.Names) == 0 {
				t.Fatalf("Service anonymously embeds %s; state must be grouped behind explicit controller fields", exprString(field.Type))
			}
			name := field.Names[0].Name
			if _, ok := wantControllers[name]; ok {
				seen[name] = exprString(field.Type)
			}
			if _, ok := engineServiceStateTypes()[exprString(field.Type)]; ok {
				t.Fatalf("Service field %s directly uses %s; use explicit controller composition", name, exprString(field.Type))
			}
		}
		for field, wantType := range wantControllers {
			if got := seen[field]; got != wantType {
				t.Fatalf("Service.%s type = %q, want %q", field, got, wantType)
			}
		}
	})

	t.Run("engine controllers do not embed other controllers or service", func(t *testing.T) {
		typesPath := filepath.Join(root, "internal", "engine", "service_types.go")
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, typesPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel(root, typesPath), err)
		}
		stateTypes := engineServiceStateTypes()
		for controller, state := range map[string]string{
			"captureController":       "captureState",
			"displayFilterController": "displayFilterState",
			"streamController":        "streamState",
			"analysisController":      "analysisCache",
			"objectController":        "objectState",
			"mediaController":         "mediaState",
			"yaraHuntingController":   "yaraHuntingState",
			"toolRuntimeController":   "toolRuntimeState",
			"mcpController":           "mcpState",
			"playbookController":      "playbookStatePB",
			"savedSearchController":   "savedSearchStateSS",
			"hypothesisController":    "hypothesisStateHT",
		} {
			structType := findStructType(parsed, controller)
			if structType == nil {
				t.Fatalf("%s missing controller type %s", rel(root, typesPath), controller)
			}
			if len(structType.Fields.List) != 1 || len(structType.Fields.List[0].Names) != 0 || exprString(structType.Fields.List[0].Type) != state {
				t.Fatalf("%s must anonymously embed only %s", controller, state)
			}
			for _, field := range structType.Fields.List {
				fieldType := exprString(field.Type)
				if fieldType == "Service" || fieldType == "*Service" {
					t.Fatalf("%s embeds Service; controllers must not depend on the facade", controller)
				}
				if _, ok := stateTypes[fieldType]; ok && fieldType != state {
					t.Fatalf("%s embeds cross-domain state %s; controllers must own one state group", controller, fieldType)
				}
			}
		}
	})

	t.Run("service facade cross-controller access stays audited", func(t *testing.T) {
		engineDir := filepath.Join(root, "internal", "engine")
		allowed := allowedServiceCrossControllerMethods()
		controllers := []string{
			"captureCtl",
			"filterCtl",
			"streamCtl",
			"analysisCtl",
			"objectCtl",
			"mediaCtl",
			"huntingCtl",
			"runtimeCtl",
			"mcpCtl",
			"playbookCtl",
			"savedSearchCtl",
			"hypothesisCtl",
		}
		for _, path := range goFiles(t, engineDir) {
			if filepath.Dir(path) != engineDir {
				continue
			}
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel(root, path), err)
			}
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil || len(fn.Recv.List) == 0 || !isServiceReceiver(fn.Recv.List[0]) {
					continue
				}
				seen := map[string]struct{}{}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					sel, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					ident, ok := sel.X.(*ast.Ident)
					if !ok || ident.Name != "s" {
						return true
					}
					for _, controller := range controllers {
						if sel.Sel.Name == controller {
							seen[controller] = struct{}{}
						}
					}
					return true
				})
				if len(seen) <= 1 {
					continue
				}
				key := filepath.Base(path) + ":" + fn.Name.Name
				if _, ok := allowed[key]; !ok {
					t.Fatalf("%s touches %d controller fields; move implementation behind a controller helper or add an audited exception", key, len(seen))
				}
			}
		}
	})
}

func engineDomainOwners() map[string]string {
	return map[string]string{
		"analysis.go":                           "analysis_evidence",
		"analysis_limiter.go":                   "analysis_evidence",
		"analysis_metrics.go":                   "analysis_evidence",
		"analysis_report.go":                    "analysis_evidence",
		"analysis_report_industrial_vehicle.go": "protocol_tools",
		"analysis_report_login.go":              "analysis_evidence",
		"analysis_report_rules.go":              "analysis_evidence",
		"analysis_report_shared.go":             "analysis_evidence",
		"analysis_report_shiro.go":              "analysis_evidence",
		"analysis_report_smtp_mysql.go":         "analysis_evidence",
		"analysis_report_usb_c2.go":             "analysis_evidence",
		"c2_decrypt.go":                         "c2_webshell",
		"dga_detection.go":                      "analysis_evidence",
		"display_filter_index.go":               "capture_stream_store",
		"dnp3_analysis.go":                      "protocol_tools",
		"events.go":                             "capture_stream_store",
		"evidence.go":                           "analysis_evidence",
		"evidence_collectors_assets.go":         "analysis_evidence",
		"evidence_collectors_detection.go":      "analysis_evidence",
		"evidence_object_rules.go":              "analysis_evidence",
		"evidence_rules.go":                     "analysis_evidence",
		"evidence_usb_rules.go":                 "analysis_evidence",
		"evidence_vehicle_rules.go":             "analysis_evidence",
		"filter.go":                             "capture_stream_store",
		"hypothesis.go":                         "analysis_evidence",
		"ioc_import.go":                         "analysis_evidence",
		"ioc_match.go":                          "analysis_evidence",
		"malleable_c2_profiles.go":              "c2_webshell",
		"mcp_config.go":                         "runtime_integration",
		"media_playback.go":                     "media_speech",
		"mitre_attack_mapping.go":               "analysis_evidence",
		"object_mapping.go":                     "runtime_integration",
		"packet_store.go":                       "capture_stream_store",
		"playbook.go":                           "analysis_evidence",
		"raw_stream_index.go":                   "capture_stream_store",
		"rtp.go":                                "media_speech",
		"rule_manager.go":                       "yara_hunting_rules",
		"saved_search.go":                       "analysis_evidence",
		"service.go":                            "capture_stream_store",
		"service_analysis.go":                   "analysis_evidence",
		"service_capture.go":                    "capture_stream_store",
		"service_streams.go":                    "capture_stream_store",
		"service_tools.go":                      "runtime_integration",
		"service_types.go":                      "capture_stream_store",
		"shared_helpers.go":                     "runtime_integration",
		"speech_to_text.go":                     "media_speech",
		"stream_decoder.go":                     "stream_payload",
		"stream_decoder_extended.go":            "stream_payload",
		"stream_payload_inspector.go":           "stream_payload",
		"stream_payload_sources.go":             "stream_payload",
		"threat_hunt_stream.go":                 "yara_hunting_rules",
		"tool_apt.go":                           "analysis_evidence",
		"tool_bruteforce.go":                    "protocol_tools",
		"tool_c2.go":                            "c2_webshell",
		"tool_http_login.go":                    "protocol_tools",
		"tool_iec104.go":                        "protocol_tools",
		"tool_misc.go":                          "runtime_integration",
		"tool_mysql.go":                         "protocol_tools",
		"tool_ntlm.go":                          "protocol_tools",
		"tool_runtime.go":                       "runtime_integration",
		"tool_shiro.go":                         "protocol_tools",
		"tool_smb3.go":                          "protocol_tools",
		"tool_smtp.go":                          "protocol_tools",
		"tool_udp_tunnel.go":                    "protocol_tools",
		"tool_winrm.go":                         "protocol_tools",
		"vshell_websocket_decrypt.go":           "c2_webshell",
		"yara_batch.go":                         "yara_hunting_rules",
		"yara_stream_targets.go":                "yara_hunting_rules",
	}
}

func grandfatheredLargeEngineFiles() map[string]struct{} {
	return map[string]struct{}{
		"c2_decrypt.go":             {},
		"dnp3_analysis.go":          {},
		"packet_store.go":           {},
		"service_analysis.go":       {},
		"service_capture.go":        {},
		"speech_to_text.go":         {},
		"stream_decoder.go":         {},
		"stream_payload_sources.go": {},
		"threat_hunt_stream.go":     {},
		"tool_c2.go":                {},
		"tool_http_login.go":        {},
		"tool_iec104.go":            {},
		"tool_winrm.go":             {},
		"yara_batch.go":             {},
	}
}

func allowedServiceCrossControllerMethods() map[string]struct{} {
	return map[string]struct{}{
		"evidence_collectors_assets.go:gatherMediaEvidence":    {},
		"media_playback.go:MediaPlaybackWithContext":           {},
		"service_analysis.go:APTAnalysis":                      {},
		"service_analysis.go:AddVehicleDBC":                    {},
		"service_analysis.go:C2SampleAnalysis":                 {},
		"service_analysis.go:GlobalTrafficStatsWithContext":    {},
		"service_analysis.go:IndustrialAnalysisWithContext":    {},
		"service_analysis.go:MediaArtifact":                    {},
		"service_analysis.go:RemoveVehicleDBC":                 {},
		"service_analysis.go:USBAnalysisWithOptions":           {},
		"service_analysis.go:VehicleAnalysisWithContext":       {},
		"service_analysis.go:VehicleDBCProfiles":               {},
		"service_analysis.go:mediaAnalysisCold":                {},
		"service_analysis.go:mediaAnalysisWithForce":           {},
		"service_capture.go:ClearCapture":                      {},
		"service_capture.go:commitLoadedCapture":               {},
		"service_capture.go:loadPCAPLocked":                    {},
		"service_capture.go:resetAnalysisCachesLocked":         {},
		"service_capture.go:resetCaptureAnalysisStateLocked":   {},
		"service_capture.go:startCaptureEnrichment":            {},
		"service_streams.go:HTTPStream":                        {},
		"service_streams.go:RawStream":                         {},
		"service_streams.go:RawStreamPage":                     {},
		"service_streams.go:UpdateStreamPayloads":              {},
		"service_streams.go:cacheStream":                       {},
		"service_streams.go:countStreamOverrides":              {},
		"service_streams.go:peekRawStreamInMemory":             {},
		"service_streams.go:streamWithOverrides":               {},
		"service_tools.go:ObjectsWithContext":                  {},
		"service_tools.go:StreamIDs":                           {},
		"service_tools.go:filteredPacketIndex":                 {},
		"speech_to_text.go:CancelMediaBatchTranscription":      {},
		"speech_to_text.go:ExportMediaBatchTranscription":      {},
		"speech_to_text.go:MediaBatchTranscriptionStatus":      {},
		"speech_to_text.go:StartMediaBatchTranscription":       {},
		"speech_to_text.go:mediaSessionForArtifact":            {},
		"speech_to_text.go:runSpeechBatchTask":                 {},
		"speech_to_text.go:transcribeMediaArtifactWithContext": {},
		"tool_runtime.go:SetToolRuntimeConfig":                 {},
		"tool_runtime.go:ToolRuntimeConfig":                    {},
	}
}

func isServiceReceiver(field *ast.Field) bool {
	if field == nil {
		return false
	}
	star, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "Service"
}
func engineServiceStateTypes() map[string]struct{} {
	return map[string]struct{}{
		"captureState":       {},
		"displayFilterState": {},
		"streamState":        {},
		"analysisCache":      {},
		"objectState":        {},
		"mediaState":         {},
		"yaraHuntingState":   {},
		"toolRuntimeState":   {},
		"mcpState":           {},
		"playbookStatePB":    {},
		"savedSearchStateSS": {},
		"hypothesisStateHT":  {},
	}
}

func assertFileCovered(t *testing.T, root string, files []string, relative string) {
	t.Helper()
	want := filepath.ToSlash(relative)
	for _, path := range files {
		if rel(root, path) == want {
			return
		}
	}
	t.Fatalf("architecture scan did not cover %s", want)
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

func findStructType(file *ast.File, name string) *ast.StructType {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				return structType
			}
		}
	}
	return nil
}

func exprString(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func countLines(body string) int {
	if body == "" {
		return 0
	}
	return strings.Count(body, "\n") + 1
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
