package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
)

var registeredAPIRouteContractCases = map[string]string{
	"/health":                                     "TestHandlerRegistersCoreReadRoutes",
	"/api/runtime/identity":                       "TestHandlerRegistersCoreReadRoutes",
	"/api/tools/tshark":                           "TestToolRuntimeConfigContract",
	"/api/tools/runtime-config":                   "TestToolRuntimeConfigContract",
	"/api/mcp/config":                             "TestMCPConfigContract",
	"/api/mcp":                                    "TestMCPRouteContractInitializeAndTools",
	"/api/tools/ffmpeg":                           "TestToolRuntimeConfigContract",
	"/api/tools/speech-to-text":                   "TestMediaAPIContract",
	"/api/tools/misc/modules":                     "TestHandleMiscModulesReturnsBuiltinsAndCustomModules",
	"/api/tools/misc/import":                      "TestHandleImportMiscModulePackageAndInvoke",
	"/api/tools/misc/packages/":                   "TestHandleImportMiscModulePackageAndInvoke",
	"/api/events":                                 "TestHandlerAllowsEventStreamAccessTokenAndRejectsWrongToken",
	"/api/capture/start":                          "TestHandlerRegistersMutatingRouteMethodPolicy",
	"/api/capture/stop":                           "TestHandlerRegistersMutatingRouteMethodPolicy",
	"/api/capture/prepare-replacement":            "TestHandleCapturePrepareReplacement",
	"/api/capture/close":                          "TestHandlerRegistersMutatingRouteMethodPolicy",
	"/api/capture/status":                         "TestCaptureStatusContract",
	"/api/capture/upload":                         "TestHandleCaptureUploadSmallFileSucceeds",
	"/api/packets":                                "TestHandlerRegistersPacketStreamRoutes",
	"/api/packets/page":                           "TestPacketsPageContract",
	"/api/packets/locate":                         "TestPacketLocateContract",
	"/api/packet":                                 "TestPacketDetailContract",
	"/api/hunting":                                "TestHuntingObjectsAndC2APIContract",
	"/api/hunting/config":                         "TestHuntingObjectsAndC2APIContract",
	"/api/objects":                                "TestHuntingObjectsAndC2APIContract",
	"/api/objects/download":                       "TestHuntingObjectsAndC2APIContract",
	"/api/streams/http":                           "TestHandlerRegistersPacketStreamRoutes",
	"/api/streams/raw":                            "TestHandlerRegistersPacketStreamRoutes",
	"/api/streams/raw/page":                       "TestHandlerRegistersPacketStreamRoutes",
	"/api/streams/decode":                         "TestHandlerRegistersStreamMutationRoutes",
	"/api/streams/inspect":                        "TestHandlerRegistersStreamMutationRoutes",
	"/api/streams/payload-sources":                "TestHandleStreamPayloadSourcesReturnsInitializedPayload",
	"/api/streams/payloads":                       "TestHandlerRegistersStreamMutationRoutes",
	"/api/streams/index":                          "TestStreamIndexContract",
	"/api/packet/raw":                             "TestPacketRawContract",
	"/api/packet/layers":                          "TestPacketLayersContract",
	"/api/stats/traffic/global":                   "TestGlobalTrafficStatsContract",
	"/api/analysis/industrial":                    "TestIndustrialAnalysisContract",
	"/api/analysis/vehicle":                       "TestVehicleAnalysisContract",
	"/api/analysis/vehicle/dbc":                   "TestVehicleAnalysisContract",
	"/api/analysis/media":                         "TestMediaAPIContract",
	"/api/analysis/usb":                           "TestUSBAnalysisContract",
	"/api/c2-analysis":                            "TestC2AnalysisContract",
	"/api/c2-analysis/decrypt":                    "TestHuntingObjectsAndC2APIContract",
	"/api/apt-analysis":                           "TestHandleAPTAnalysisReturnsInitializedPayload",
	"/api/evidence":                               "TestEvidenceContractEmptyCapture",
	"/api/analysis/media/export":                  "TestMediaAPIContract",
	"/api/analysis/media/play":                    "TestMediaAPIContract",
	"/api/analysis/media/transcribe":              "TestHandleMediaArtifactTranscriptionUsesCanceledRequestContext",
	"/api/analysis/media/transcribe/batch":        "TestMediaAPIContract",
	"/api/analysis/media/transcribe/batch/cancel": "TestMediaAPIContract",
	"/api/analysis/media/transcribe/batch/export": "TestMediaAPIContract",
	"/api/tls":                                    "TestTLSAPIContract",
	"/api/audit/logs":                             "TestHandleAuditLogsReturnsRecordedEntries",
	"/api/tools/ntlm-sessions":                    "TestHandlerRegistersToolRoutes",
	"/api/tools/http-login-analysis":              "TestHandlerRegistersToolRoutes",
	"/api/tools/smtp-analysis":                    "TestHandlerRegistersToolRoutes",
	"/api/tools/mysql-analysis":                   "TestHandlerRegistersToolRoutes",
	"/api/tools/shiro-rememberme":                 "TestHandlerRegistersToolRoutes",
	"/api/tools/udp-tunnel":                       "TestHandlerRegistersToolRoutes",
	"/api/tools/bruteforce":                       "TestHandlerRegistersToolRoutes",
	"/api/tools/winrm-decrypt":                    "TestHandlerRegistersToolRoutes",
	"/api/tools/winrm-decrypt/export":             "TestHandlerRegistersToolRoutes",
	"/api/tools/smb3-session-candidates":          "TestHandlerRegistersToolRoutes",
	"/api/tools/smb3-random-session-key":          "TestHandlerRegistersToolRoutes",
	"/api/rules/status":                           "TestRulesAPIContract",
	"/api/rules/config":                           "TestRulesAPIContract",
	"/api/rules/pack/toggle":                      "TestRulesAPIContract",
	"/api/rules/check-updates":                    "TestRulesAPIContract",
	"/api/rules/download":                         "TestRulesAPIContract",
	"/api/rules/conflicts":                        "TestRulesAPIContract",
	"/api/rules/validate":                         "TestRulesAPIContract",
	"/api/playbooks":                              "TestPlaybookAPIContract",
	"/api/playbooks/":                             "TestPlaybookAPIContract",
	"/api/hunting/saved-searches":                 "TestHuntingWorkspaceAPIContract",
	"/api/hunting/saved-searches/":                "TestHuntingWorkspaceAPIContract",
	"/api/hunting/hypotheses":                     "TestHuntingWorkspaceAPIContract",
	"/api/hunting/hypotheses/":                    "TestHuntingWorkspaceAPIContract",
}

func TestRegisteredAPIRoutesHaveContractCases(t *testing.T) {
	registered := registeredRoutesFromSource(t)
	missing := make([]string, 0)
	for _, route := range registered {
		if _, ok := registeredAPIRouteContractCases[route]; !ok {
			missing = append(missing, route)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("registered routes missing contract cases: %s", strings.Join(missing, ", "))
	}
}

func registeredRoutesFromSource(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)
	seen := map[string]struct{}{}
	for _, file := range []string{"http_server.go", "misc_modules.go"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, match := range re.FindAllStringSubmatch(string(data), -1) {
			seen[match[1]] = struct{}{}
		}
	}
	routes := make([]string, 0, len(seen))
	for route := range seen {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	return routes
}

func TestHuntingObjectsAndC2APIContract(t *testing.T) {
	tmpFile := writeTempObjectFile(t)
	detection := &apiContractDetectionService{
		objects: []model.ObjectFile{{ID: 7, PacketID: 3, Name: "object.txt", SizeBytes: 5, MIME: "text/plain", Source: "http", Path: tmpFile}},
	}
	analysis := &apiContractC2DecryptService{}
	server := &Server{detection: detection, analysis: analysis}

	rec := httptest.NewRecorder()
	server.handleHunting(rec, httptest.NewRequest(http.MethodGet, "/api/hunting?prefix=flag&prefix=cmd", nil))
	requireStatus(t, rec, http.StatusOK)
	var hits []model.ThreatHit
	if err := json.Unmarshal(rec.Body.Bytes(), &hits); err != nil || len(hits) != 1 {
		t.Fatalf("decode hunting hits err=%v hits=%+v", err, hits)
	}
	if strings.Join(detection.prefixes, ",") != "flag,cmd" {
		t.Fatalf("prefixes = %#v, want flag/cmd", detection.prefixes)
	}

	rec = httptest.NewRecorder()
	server.handleHunting(rec, httptest.NewRequest(http.MethodPost, "/api/hunting", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleHuntingConfig(rec, httptest.NewRequest(http.MethodGet, "/api/hunting/config", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "prefixes", "yara_enabled", "yara_bin", "yara_rules", "yara_timeout_ms")

	rec = httptest.NewRecorder()
	server.handleHuntingConfig(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/config", strings.NewReader(`{"prefixes":["demo"],"yara_enabled":true}`)))
	requireStatus(t, rec, http.StatusOK)
	if len(detection.config.Prefixes) != 1 || detection.config.Prefixes[0] != "demo" {
		t.Fatalf("config = %+v, want posted prefix", detection.config)
	}

	rec = httptest.NewRecorder()
	server.handleHuntingConfig(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/config", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleObjects(rec, httptest.NewRequest(http.MethodGet, "/api/objects", nil))
	requireStatus(t, rec, http.StatusOK)
	var objects []model.ObjectFile
	if err := json.Unmarshal(rec.Body.Bytes(), &objects); err != nil || len(objects) != 1 {
		t.Fatalf("decode objects err=%v objects=%+v", err, objects)
	}

	rec = httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodGet, "/api/objects/download?ids=7", nil))
	requireStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("objects download content-type = %q, want application/zip", got)
	}

	rec = httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodDelete, "/api/objects/download", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleC2Decrypt(rec, httptest.NewRequest(http.MethodPost, "/api/c2-analysis/decrypt", strings.NewReader(`{"family":"cs"}`)))
	requireStatus(t, rec, http.StatusOK)
	payload := decodeJSONMap(t, rec)
	requireJSONKeys(t, payload, "family", "status", "total_candidates", "decrypted_count", "failed_count", "records", "notes")

	rec = httptest.NewRecorder()
	server.handleC2Decrypt(rec, httptest.NewRequest(http.MethodGet, "/api/c2-analysis/decrypt", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleC2Decrypt(rec, httptest.NewRequest(http.MethodPost, "/api/c2-analysis/decrypt", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestHandleHuntingUsesCanceledRequestContext(t *testing.T) {
	detection := &apiContractDetectionService{}
	server := &Server{detection: detection}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := httptest.NewRecorder()
	server.handleHunting(rec, httptest.NewRequest(http.MethodGet, "/api/hunting", nil).WithContext(ctx))

	requireStatus(t, rec, http.StatusOK)
	if detection.ctxErr != context.Canceled {
		t.Fatalf("ctxErr = %v, want context.Canceled", detection.ctxErr)
	}
}

func TestHandleObjectsUsesCanceledRequestContext(t *testing.T) {
	detection := &apiContractDetectionService{}
	server := &Server{detection: detection}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := httptest.NewRecorder()
	server.handleObjects(rec, httptest.NewRequest(http.MethodGet, "/api/objects", nil).WithContext(ctx))

	requireStatus(t, rec, http.StatusOK)
	if detection.ctxErr != context.Canceled {
		t.Fatalf("ctxErr = %v, want context.Canceled", detection.ctxErr)
	}
}

func TestHandleC2DecryptUsesCanceledRequestContext(t *testing.T) {
	analysis := &apiContractC2DecryptService{returnContextError: true}
	server := &Server{analysis: analysis}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := httptest.NewRecorder()
	server.handleC2Decrypt(rec, httptest.NewRequest(http.MethodPost, "/api/c2-analysis/decrypt", strings.NewReader(`{"family":"cs"}`)).WithContext(ctx))

	requireStatus(t, rec, http.StatusRequestTimeout)
	if analysis.ctxErr != context.Canceled {
		t.Fatalf("ctxErr = %v, want context.Canceled", analysis.ctxErr)
	}
}

func TestMediaAPIContract(t *testing.T) {
	mediaFile := writeTempMediaFile(t)
	media := &apiContractMediaService{artifactPath: mediaFile, playbackPath: mediaFile}
	server := &Server{media: media}

	rec := httptest.NewRecorder()
	server.handleMediaAnalysis(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "total_media_packets", "protocols", "applications", "sessions", "notes")

	rec = httptest.NewRecorder()
	server.handleMediaArtifactDownload(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/export?token=artifact-1", nil))
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "artifact.bin") {
		t.Fatalf("download content-disposition = %q", rec.Header().Get("Content-Disposition"))
	}

	rec = httptest.NewRecorder()
	server.handleMediaArtifactDownload(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/export", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleMediaArtifactPlayback(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/play?token=artifact-1", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleMediaArtifactPlayback(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/play", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleMediaArtifactTranscription(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe", strings.NewReader(`{"token":"artifact-1","force":true}`)))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "token", "session_id", "title", "text", "language", "engine", "status", "cached", "duration_seconds")

	rec = httptest.NewRecorder()
	server.handleMediaArtifactTranscription(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleMediaArtifactTranscription(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscription(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe/batch", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "task_id", "total", "queued", "running", "completed", "failed", "skipped", "done", "cancelled", "items")

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscription(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe/batch", strings.NewReader(`{"force":true}`)))
	requireStatus(t, rec, http.StatusOK)
	if !media.batchForce {
		t.Fatal("batch force flag was not passed to service")
	}

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscription(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe/batch", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscription(rec, httptest.NewRequest(http.MethodDelete, "/api/analysis/media/transcribe/batch", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscriptionCancel(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe/batch/cancel", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscriptionCancel(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe/batch/cancel", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscriptionExport(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe/batch/export?format=json", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscriptionExport(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe/batch/export?format=txt", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleMediaBatchTranscriptionExport(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/transcribe/batch/export?format=csv", nil))
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestHandleMediaArtifactPlaybackUsesCanceledRequestContext(t *testing.T) {
	media := &apiContractMediaService{returnPlaybackContextError: true}
	server := &Server{media: media}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := httptest.NewRecorder()
	server.handleMediaArtifactPlayback(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/media/play?token=artifact-1", nil).WithContext(ctx))

	requireStatus(t, rec, http.StatusBadRequest)
	if media.playbackCtxErr != context.Canceled {
		t.Fatalf("playback ctx err = %v, want context.Canceled", media.playbackCtxErr)
	}
}

func TestTLSAPIContract(t *testing.T) {
	runtime := &apiContractRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleTLS(rec, httptest.NewRequest(http.MethodGet, "/api/tls", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "ssl_key_log_file", "rsa_private_key", "target_ip_port")

	rec = httptest.NewRecorder()
	server.handleTLS(rec, httptest.NewRequest(http.MethodPost, "/api/tls", strings.NewReader(`{"ssl_key_log_file":"keys.log","target_ip_port":"10.0.0.1:443"}`)))
	requireStatus(t, rec, http.StatusOK)
	if runtime.tls.SSLKeyLogFile != "keys.log" || runtime.tls.TargetIPPort != "10.0.0.1:443" {
		t.Fatalf("tls config = %+v, want posted values", runtime.tls)
	}

	rec = httptest.NewRecorder()
	server.handleTLS(rec, httptest.NewRequest(http.MethodPost, "/api/tls", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleTLS(rec, httptest.NewRequest(http.MethodPut, "/api/tls", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestRulesAPIContract(t *testing.T) {
	server := &Server{ruleManager: engine.NewRuleManager(t.TempDir())}
	server.ruleManager.LoadBuiltinPacks()
	ruleHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("rule demo_rule { condition: true }\n"))
	}))
	t.Cleanup(ruleHTTP.Close)

	rec := httptest.NewRecorder()
	server.handleRulesStatus(rec, httptest.NewRequest(http.MethodGet, "/api/rules/status", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "packs", "total_rules", "enabled_rules", "disabled_rules", "last_update", "update_config")

	rec = httptest.NewRecorder()
	server.handleRulesStatus(rec, httptest.NewRequest(http.MethodPost, "/api/rules/status", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleRulesConfig(rec, httptest.NewRequest(http.MethodGet, "/api/rules/config", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleRulesConfig(rec, httptest.NewRequest(http.MethodPost, "/api/rules/config", strings.NewReader(`{"remote_url":"`+ruleHTTP.URL+`","auto_update":true}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleRulesConfig(rec, httptest.NewRequest(http.MethodPost, "/api/rules/config", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleRulesPackToggle(rec, httptest.NewRequest(http.MethodPost, "/api/rules/pack/toggle", strings.NewReader(`{"pack_id":"builtin-community","enabled":true}`)))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "status", "pack_id", "enabled")

	rec = httptest.NewRecorder()
	server.handleRulesPackToggle(rec, httptest.NewRequest(http.MethodPost, "/api/rules/pack/toggle", strings.NewReader(`{"enabled":true}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleRulesCheckUpdates(rec, httptest.NewRequest(http.MethodPost, "/api/rules/check-updates", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleRulesDownload(rec, httptest.NewRequest(http.MethodPost, "/api/rules/download", strings.NewReader(`{"pack_id":"remote-demo","url":"`+ruleHTTP.URL+`/demo.yar"}`)))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "id", "name", "source", "version", "enabled", "rule_count", "checksum", "updated_at")

	rec = httptest.NewRecorder()
	server.handleRulesDownload(rec, httptest.NewRequest(http.MethodPost, "/api/rules/download", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleRulesConflicts(rec, httptest.NewRequest(http.MethodGet, "/api/rules/conflicts", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "conflicts", "count")

	rec = httptest.NewRecorder()
	server.handleRulesValidate(rec, httptest.NewRequest(http.MethodPost, "/api/rules/validate", strings.NewReader(`{"content":"rule ok { condition: true }"}`)))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "valid", "errors", "count")

	rec = httptest.NewRecorder()
	server.handleRulesValidate(rec, httptest.NewRequest(http.MethodPost, "/api/rules/validate", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestPlaybookAPIContract(t *testing.T) {
	playbook := newAPIContractPlaybookService()
	server := &Server{playbook: playbook}
	valid := `{"id":"pb-1","name":"Demo","steps":[{"id":"step-1","name":"Hunt","type":"threat_hunt","enabled":true}]}`

	rec := httptest.NewRecorder()
	server.handlePlaybooks(rec, httptest.NewRequest(http.MethodGet, "/api/playbooks", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handlePlaybooks(rec, httptest.NewRequest(http.MethodPost, "/api/playbooks", strings.NewReader(valid)))
	requireStatus(t, rec, http.StatusCreated)

	rec = httptest.NewRecorder()
	server.handlePlaybooks(rec, httptest.NewRequest(http.MethodPost, "/api/playbooks", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handlePlaybooks(rec, httptest.NewRequest(http.MethodPut, "/api/playbooks", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodGet, "/api/playbooks/pb-1", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodPut, "/api/playbooks/pb-1", strings.NewReader(`{"name":"Updated","steps":[{"name":"Hunt","type":"threat_hunt","enabled":true}]}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodPost, "/api/playbooks/pb-1/run", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodGet, "/api/playbooks/pb-1/last-run", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodGet, "/api/playbooks/missing", nil))
	requireStatus(t, rec, http.StatusNotFound)

	rec = httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodDelete, "/api/playbooks/pb-1", nil))
	requireStatus(t, rec, http.StatusOK)
}

func TestHandlePlaybookRunUsesCanceledRequestContext(t *testing.T) {
	playbook := newAPIContractPlaybookService()
	playbook.playbooks["pb-1"] = &model.HuntingPlaybook{ID: "pb-1", Name: "Demo", Steps: []model.PlaybookStep{{ID: "step-1", Name: "Hunt", Type: model.PlaybookStepTypeThreatHunt, Enabled: true}}}
	playbook.returnContextError = true
	server := &Server{playbook: playbook}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := httptest.NewRecorder()
	server.handlePlaybookRoute(rec, httptest.NewRequest(http.MethodPost, "/api/playbooks/pb-1/run", nil).WithContext(ctx))

	requireStatus(t, rec, http.StatusBadRequest)
	if playbook.runCtxErr != context.Canceled {
		t.Fatalf("run ctx err = %v, want context.Canceled", playbook.runCtxErr)
	}
}

func TestHuntingWorkspaceAPIContract(t *testing.T) {
	playbook := newAPIContractPlaybookService()
	server := &Server{playbook: playbook}

	rec := httptest.NewRecorder()
	server.handleSavedSearches(rec, httptest.NewRequest(http.MethodGet, "/api/hunting/saved-searches", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleSavedSearches(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/saved-searches", strings.NewReader(`{"id":"ss-1","name":"Find flag","query":"flag{"}`)))
	requireStatus(t, rec, http.StatusCreated)

	rec = httptest.NewRecorder()
	server.handleSavedSearches(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/saved-searches", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleSavedSearchRoute(rec, httptest.NewRequest(http.MethodGet, "/api/hunting/saved-searches/ss-1", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleSavedSearchRoute(rec, httptest.NewRequest(http.MethodPut, "/api/hunting/saved-searches/ss-1", strings.NewReader(`{"name":"Updated","query":"cmd"}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleSavedSearchRoute(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/saved-searches/ss-1/execute", nil))
	requireStatus(t, rec, http.StatusOK)
	requireJSONKeys(t, decodeJSONMap(t, rec), "search", "hits", "total")

	rec = httptest.NewRecorder()
	server.handleSavedSearchRoute(rec, httptest.NewRequest(http.MethodDelete, "/api/hunting/saved-searches/ss-1", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleHypotheses(rec, httptest.NewRequest(http.MethodGet, "/api/hunting/hypotheses?status=open", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleHypotheses(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses", strings.NewReader(`{"id":"hyp-1","title":"C2 exists"}`)))
	requireStatus(t, rec, http.StatusCreated)

	rec = httptest.NewRecorder()
	server.handleHypotheses(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodGet, "/api/hunting/hypotheses/hyp-1", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses/hyp-1/evidence", strings.NewReader(`{"description":"beacon","source":"c2","strength":"supports"}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses/hyp-1/evidence", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses/hyp-1/status", strings.NewReader(`{"status":"confirmed","conclusion":"matched"}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodPost, "/api/hunting/hypotheses/hyp-1/status", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleHypothesisRoute(rec, httptest.NewRequest(http.MethodDelete, "/api/hunting/hypotheses/hyp-1", nil))
	requireStatus(t, rec, http.StatusOK)
}

func writeTempObjectFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/object.txt"
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write object: %v", err)
	}
	return path
}

func writeTempMediaFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/artifact.bin"
	if err := os.WriteFile(path, []byte("media"), 0o644); err != nil {
		t.Fatalf("write media: %v", err)
	}
	return path
}

type apiContractDetectionService struct {
	prefixes []string
	config   model.HuntingRuntimeConfig
	objects  []model.ObjectFile
	ctxErr   error
}

func (s *apiContractDetectionService) ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit {
	s.ctxErr = ctx.Err()
	s.prefixes = append([]string(nil), prefixes...)
	return []model.ThreatHit{{ID: 1, PacketID: 7, Rule: "contract", Level: "info"}}
}

func (s *apiContractDetectionService) ObjectsWithContext(ctx context.Context) []model.ObjectFile {
	s.ctxErr = ctx.Err()
	return append([]model.ObjectFile(nil), s.objects...)
}

func (s *apiContractDetectionService) GetHuntingRuntimeConfig() model.HuntingRuntimeConfig {
	if s.config.Prefixes == nil {
		s.config.Prefixes = []string{"flag{"}
	}
	return s.config
}

func (s *apiContractDetectionService) SetHuntingRuntimeConfig(cfg model.HuntingRuntimeConfig) model.HuntingRuntimeConfig {
	s.config = cfg
	return s.config
}

type apiContractC2DecryptService struct {
	contractAnalysisService
	ctxErr             error
	returnContextError bool
}

func (s *apiContractC2DecryptService) C2Decrypt(ctx context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error) {
	s.ctxErr = ctx.Err()
	if s.returnContextError {
		return model.C2DecryptResult{}, s.ctxErr
	}
	return model.C2DecryptResult{
		Family:          req.Family,
		Status:          "ok",
		TotalCandidates: 1,
		DecryptedCount:  1,
		Records:         []model.C2DecryptedRecord{{PacketID: 7, Confidence: 80}},
		Notes:           []string{"contract"},
	}, nil
}

type apiContractMediaService struct {
	contractMediaService
	artifactPath               string
	playbackPath               string
	playbackCtxErr             error
	returnPlaybackContextError bool
	batchForce                 bool
}

func (s *apiContractMediaService) MediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{
		TotalMediaPackets: 1,
		Protocols:         []model.TrafficBucket{{Label: "RTP", Count: 1}},
		Applications:      []model.TrafficBucket{},
		Sessions:          []model.MediaSession{{ID: "media-1", MediaType: "audio"}},
		Notes:             []string{"contract"},
	}, nil
}

func (s *apiContractMediaService) MediaArtifact(token string) (string, string, error) {
	if strings.TrimSpace(token) == "" {
		return "", "", errors.New("missing token")
	}
	return s.artifactPath, "artifact.bin", nil
}

func (s *apiContractMediaService) MediaPlaybackWithContext(ctx context.Context, token string) (string, string, error) {
	s.playbackCtxErr = ctx.Err()
	if s.returnPlaybackContextError {
		return "", "", s.playbackCtxErr
	}
	if strings.TrimSpace(token) == "" {
		return "", "", errors.New("missing token")
	}
	return s.playbackPath, "artifact.mp4", nil
}

func (s *apiContractMediaService) TranscribeMediaArtifactWithContext(context.Context, string, bool) (model.MediaTranscription, error) {
	return model.MediaTranscription{
		Token:           "artifact-1",
		SessionID:       "media-1",
		Title:           "Demo",
		Text:            "hello",
		Language:        "en",
		Engine:          "vosk",
		Status:          "done",
		DurationSeconds: 1.5,
	}, nil
}

func (s *apiContractMediaService) MediaBatchTranscriptionStatus() model.SpeechBatchTaskStatus {
	return model.SpeechBatchTaskStatus{TaskID: "batch-1", Total: 1, Completed: 1, Done: true, Items: []model.SpeechBatchTaskItem{{Token: "artifact-1", Status: "done"}}}
}

func (s *apiContractMediaService) StartMediaBatchTranscription(force bool) (model.SpeechBatchTaskStatus, error) {
	s.batchForce = force
	return s.MediaBatchTranscriptionStatus(), nil
}

func (s *apiContractMediaService) CancelMediaBatchTranscription() model.SpeechBatchTaskStatus {
	status := s.MediaBatchTranscriptionStatus()
	status.Cancelled = true
	return status
}

func (s *apiContractMediaService) ExportMediaBatchTranscription() model.MediaTranscriptionBatchExport {
	return model.MediaTranscriptionBatchExport{
		TaskID:   "batch-1",
		Engine:   "vosk",
		Language: "en",
		Items:    []model.MediaTranscriptionBatchItem{{Token: "artifact-1", SessionID: "media-1", Title: "Demo", Text: "hello", Status: "done"}},
	}
}

type apiContractRuntimeService struct {
	contractToolRuntimeService
	tls model.TLSConfig
}

func (s *apiContractRuntimeService) TLSConfig() model.TLSConfig { return s.tls }

func (s *apiContractRuntimeService) SetTLSConfig(cfg model.TLSConfig) { s.tls = cfg }

type apiContractPlaybookService struct {
	playbooks          map[string]*model.HuntingPlaybook
	lastRun            map[string]*model.PlaybookRunResult
	searches           map[string]*model.SavedSearch
	hypotheses         map[string]*model.Hypothesis
	runCtxErr          error
	returnContextError bool
}

func newAPIContractPlaybookService() *apiContractPlaybookService {
	return &apiContractPlaybookService{
		playbooks:  map[string]*model.HuntingPlaybook{},
		lastRun:    map[string]*model.PlaybookRunResult{},
		searches:   map[string]*model.SavedSearch{},
		hypotheses: map[string]*model.Hypothesis{},
	}
}

func (s *apiContractPlaybookService) ListPlaybooks() []model.HuntingPlaybook {
	out := make([]model.HuntingPlaybook, 0, len(s.playbooks))
	for _, item := range s.playbooks {
		out = append(out, *item)
	}
	return out
}

func (s *apiContractPlaybookService) GetPlaybook(id string) (*model.HuntingPlaybook, bool) {
	item, ok := s.playbooks[id]
	if !ok {
		return nil, false
	}
	copy := *item
	return &copy, true
}

func (s *apiContractPlaybookService) CreatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error) {
	if strings.TrimSpace(pb.Name) == "" || len(pb.Steps) == 0 {
		return nil, errors.New("playbook name and steps are required")
	}
	if pb.ID == "" {
		pb.ID = "pb-created"
	}
	now := time.Now().UTC()
	pb.CreatedAt = now
	pb.UpdatedAt = now
	s.playbooks[pb.ID] = &pb
	return &pb, nil
}

func (s *apiContractPlaybookService) UpdatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error) {
	if _, ok := s.playbooks[pb.ID]; !ok {
		return nil, errors.New("playbook not found")
	}
	pb.UpdatedAt = time.Now().UTC()
	s.playbooks[pb.ID] = &pb
	return &pb, nil
}

func (s *apiContractPlaybookService) DeletePlaybook(id string) bool {
	if _, ok := s.playbooks[id]; !ok {
		return false
	}
	delete(s.playbooks, id)
	return true
}

func (s *apiContractPlaybookService) RunPlaybook(ctx context.Context, playbookID string) (*model.PlaybookRunResult, error) {
	s.runCtxErr = ctx.Err()
	if s.returnContextError {
		return nil, s.runCtxErr
	}
	if _, ok := s.playbooks[playbookID]; !ok {
		return nil, errors.New("playbook not found")
	}
	result := &model.PlaybookRunResult{PlaybookID: playbookID, PlaybookName: "Demo", Status: model.PlaybookStatusComplete, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}
	s.lastRun[playbookID] = result
	return result, nil
}

func (s *apiContractPlaybookService) GetPlaybookLastRun(playbookID string) (*model.PlaybookRunResult, bool) {
	result, ok := s.lastRun[playbookID]
	if !ok {
		return nil, false
	}
	copy := *result
	return &copy, true
}

func (s *apiContractPlaybookService) ListSavedSearches() []model.SavedSearch {
	out := make([]model.SavedSearch, 0, len(s.searches))
	for _, item := range s.searches {
		out = append(out, *item)
	}
	return out
}

func (s *apiContractPlaybookService) GetSavedSearch(id string) (*model.SavedSearch, bool) {
	item, ok := s.searches[id]
	if !ok {
		return nil, false
	}
	copy := *item
	return &copy, true
}

func (s *apiContractPlaybookService) CreateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error) {
	if strings.TrimSpace(ss.Name) == "" || strings.TrimSpace(ss.Query) == "" {
		return nil, errors.New("saved search name and query are required")
	}
	if ss.ID == "" {
		ss.ID = "ss-created"
	}
	now := time.Now().UTC()
	ss.CreatedAt = now
	ss.UpdatedAt = now
	s.searches[ss.ID] = &ss
	return &ss, nil
}

func (s *apiContractPlaybookService) UpdateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error) {
	if _, ok := s.searches[ss.ID]; !ok {
		return nil, errors.New("saved search not found")
	}
	ss.UpdatedAt = time.Now().UTC()
	s.searches[ss.ID] = &ss
	return &ss, nil
}

func (s *apiContractPlaybookService) DeleteSavedSearch(id string) bool {
	if _, ok := s.searches[id]; !ok {
		return false
	}
	delete(s.searches, id)
	return true
}

func (s *apiContractPlaybookService) ExecuteSavedSearch(id string) (*model.SavedSearch, []model.ThreatHit, error) {
	search, ok := s.searches[id]
	if !ok {
		return nil, nil, errors.New("saved search not found")
	}
	return search, []model.ThreatHit{{ID: 1, Rule: "saved-search"}}, nil
}

func (s *apiContractPlaybookService) ListHypotheses(statusFilter string) []model.Hypothesis {
	out := make([]model.Hypothesis, 0, len(s.hypotheses))
	for _, item := range s.hypotheses {
		if statusFilter != "" && string(item.Status) != statusFilter {
			continue
		}
		out = append(out, *item)
	}
	return out
}

func (s *apiContractPlaybookService) GetHypothesis(id string) (*model.Hypothesis, bool) {
	item, ok := s.hypotheses[id]
	if !ok {
		return nil, false
	}
	copy := *item
	return &copy, true
}

func (s *apiContractPlaybookService) CreateHypothesis(h model.Hypothesis) (*model.Hypothesis, error) {
	if strings.TrimSpace(h.Title) == "" {
		return nil, errors.New("hypothesis title is required")
	}
	if h.ID == "" {
		h.ID = "hyp-created"
	}
	if h.Status == "" {
		h.Status = model.HypothesisStatusOpen
	}
	now := time.Now().UTC()
	h.CreatedAt = now
	h.UpdatedAt = now
	s.hypotheses[h.ID] = &h
	return &h, nil
}

func (s *apiContractPlaybookService) UpdateHypothesis(h model.Hypothesis) (*model.Hypothesis, error) {
	if _, ok := s.hypotheses[h.ID]; !ok {
		return nil, errors.New("hypothesis not found")
	}
	h.UpdatedAt = time.Now().UTC()
	s.hypotheses[h.ID] = &h
	return &h, nil
}

func (s *apiContractPlaybookService) DeleteHypothesis(id string) bool {
	if _, ok := s.hypotheses[id]; !ok {
		return false
	}
	delete(s.hypotheses, id)
	return true
}

func (s *apiContractPlaybookService) AddHypothesisEvidence(hypothesisID string, evidence model.HypothesisEvidence) (*model.Hypothesis, error) {
	item, ok := s.hypotheses[hypothesisID]
	if !ok {
		return nil, errors.New("hypothesis not found")
	}
	if evidence.ID == "" {
		evidence.ID = "ev-1"
	}
	item.Evidence = append(item.Evidence, evidence)
	return item, nil
}

func (s *apiContractPlaybookService) UpdateHypothesisStatus(id string, status model.HypothesisStatus, conclusion string) (*model.Hypothesis, error) {
	item, ok := s.hypotheses[id]
	if !ok {
		return nil, errors.New("hypothesis not found")
	}
	item.Status = status
	item.Conclusion = conclusion
	return item, nil
}
