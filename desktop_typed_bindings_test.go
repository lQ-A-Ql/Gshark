//go:build dev || production

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopStreamTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/streams/http":
			_, _ = w.Write([]byte(`{"stream_id":7,"chunks":[]}`))
		case "/api/streams/raw/page":
			_, _ = w.Write([]byte(`{"stream_id":8,"chunks":[]}`))
		case "/api/streams/decode":
			var payload desktopStreamDecodeRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if payload.Decoder != "Base64" || payload.Payload != "YQ==" {
				t.Fatalf("unexpected decode payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`{"decoder":"Base64","summary":"ok"}`))
		case "/api/packet/raw":
			_, _ = w.Write([]byte(`{"raw_hex":"ff"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.GetHttpStream(7); err != nil {
		t.Fatalf("GetHttpStream error = %v", err)
	}
	if _, err := app.GetRawStreamPage("tcp", 8, 0, 32); err != nil {
		t.Fatalf("GetRawStreamPage error = %v", err)
	}
	if _, err := app.DecodeStreamPayload(desktopStreamDecodeRequest{Decoder: "Base64", Payload: "YQ=="}); err != nil {
		t.Fatalf("DecodeStreamPayload error = %v", err)
	}
	if _, err := app.GetPacketRawHex(9); err != nil {
		t.Fatalf("GetPacketRawHex error = %v", err)
	}

	for _, want := range []string{
		"GET /api/streams/http?streamId=7",
		"GET /api/streams/raw/page?protocol=TCP&streamId=8&cursor=0&limit=32",
		"POST /api/streams/decode",
		"GET /api/packet/raw?id=9",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func TestDesktopPacketTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/packets/locate":
			_, _ = w.Write([]byte(`{"packet_id":42,"cursor":100,"total":200,"found":true}`))
		case "/api/packet":
			_, _ = w.Write([]byte(`{"id":42,"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","protocol":"TCP","display_protocol":"HTTP","length":128}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.LocatePacketPage(42, 50, "http && tcp"); err != nil {
		t.Fatalf("LocatePacketPage error = %v", err)
	}
	packet, err := app.GetPacket(42)
	if err != nil {
		t.Fatalf("GetPacket error = %v", err)
	}
	if packet["id"] != float64(42) {
		t.Fatalf("unexpected packet payload: %#v", packet)
	}

	for _, want := range []string{
		"GET /api/packets/locate?id=42&limit=50&filter=http+%26%26+tcp",
		"GET /api/packet?id=42",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func TestDesktopHuntingTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/hunting":
			_, _ = w.Write([]byte(`[{"id":7,"packet_id":99,"category":"CTF","rule":"Flag","level":"high","preview":"flag{demo}","match":"flag{"}]`))
		case "/api/hunting/config":
			_, _ = w.Write([]byte(`{"prefixes":["flag{"],"yara_enabled":true,"yara_bin":"C:/Tools/yara.exe","yara_rules":"C:/rules","yara_timeout_ms":25000}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.ListThreatHits([]string{"flag{", "ctf{", " "}); err != nil {
		t.Fatalf("ListThreatHits error = %v", err)
	}
	if _, err := app.GetHuntingRuntimeConfig(); err != nil {
		t.Fatalf("GetHuntingRuntimeConfig error = %v", err)
	}
	if _, err := app.UpdateHuntingRuntimeConfig(desktopHuntingRuntimeConfig{
		Prefixes:      []string{"flag{"},
		YaraEnabled:   true,
		YaraBin:       "C:/Tools/yara.exe",
		YaraRules:     "C:/rules",
		YaraTimeoutMS: 25000,
	}); err != nil {
		t.Fatalf("UpdateHuntingRuntimeConfig error = %v", err)
	}

	for _, want := range []string{
		"GET /api/hunting?prefix=flag%7B&prefix=ctf%7B",
		"GET /api/hunting/config",
		"POST /api/hunting/config",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func TestDesktopVehicleDBCTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/analysis/vehicle/dbc":
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`[{"path":"car.dbc","name":"car","message_count":2,"signal_count":8}]`))
			case http.MethodPost:
				var payload desktopVehicleDBCRequest
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode DBC add body: %v", err)
				}
				if payload.Path != "truck.dbc" {
					t.Fatalf("unexpected DBC add payload: %#v", payload)
				}
				_, _ = w.Write([]byte(`[{"path":"truck.dbc","name":"truck","message_count":3,"signal_count":12}]`))
			case http.MethodDelete:
				if r.URL.Query().Get("path") != "truck.dbc" {
					t.Fatalf("unexpected DBC delete path: %q", r.URL.RawQuery)
				}
				_, _ = w.Write([]byte(`[]`))
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.ListVehicleDBCProfiles(); err != nil {
		t.Fatalf("ListVehicleDBCProfiles error = %v", err)
	}
	if _, err := app.AddVehicleDBC("truck.dbc"); err != nil {
		t.Fatalf("AddVehicleDBC error = %v", err)
	}
	if _, err := app.RemoveVehicleDBC("truck.dbc"); err != nil {
		t.Fatalf("RemoveVehicleDBC error = %v", err)
	}

	for _, want := range []string{
		"GET /api/analysis/vehicle/dbc",
		"POST /api/analysis/vehicle/dbc",
		"DELETE /api/analysis/vehicle/dbc?path=truck.dbc",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func TestDesktopPluginTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/plugins":
			_, _ = w.Write([]byte(`[{"id":"echo","name":"Echo","enabled":true,"capabilities":["packet.read"]}]`))
		case "/api/plugins/source":
			if r.Method == http.MethodPost {
				var payload desktopPluginSourceRequest
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode plugin source body: %v", err)
				}
				if payload.ID != "echo" || payload.ConfigPath != "cfg2" {
					t.Fatalf("unexpected plugin source payload: %#v", payload)
				}
				_, _ = w.Write([]byte(`{"id":"echo","config_path":"cfg2","entry":"echo.js"}`))
				return
			}
			if r.URL.Query().Get("id") != "echo" {
				t.Fatalf("unexpected plugin source query: %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"echo","config_path":"cfg","logic_path":"logic","entry":"echo.js"}`))
		case "/api/plugins/add":
			var payload desktopPluginRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode plugin add body: %v", err)
			}
			if payload.ID != "new" || len(payload.Capabilities) != 1 || payload.Capabilities[0] != "packet.read" {
				t.Fatalf("unexpected plugin add payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`{"id":"new","name":"New","enabled":false,"capabilities":["packet.read"]}`))
		case "/api/plugins/delete":
			if r.URL.Query().Get("id") != "old" {
				t.Fatalf("unexpected plugin delete query: %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"old","deleted":true}`))
		case "/api/plugins/toggle":
			if r.URL.Query().Get("id") != "echo" {
				t.Fatalf("unexpected plugin toggle query: %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"echo","enabled":false}`))
		case "/api/plugins/bulk":
			var payload desktopPluginBulkRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode plugin bulk body: %v", err)
			}
			if len(payload.IDs) != 1 || payload.IDs[0] != "echo" || !payload.Enabled {
				t.Fatalf("unexpected plugin bulk payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`[{"id":"echo","enabled":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.ListPlugins(); err != nil {
		t.Fatalf("ListPlugins error = %v", err)
	}
	if _, err := app.GetPluginSource("echo"); err != nil {
		t.Fatalf("GetPluginSource error = %v", err)
	}
	if _, err := app.SavePluginSource(desktopPluginSourceRequest{ID: "echo", ConfigPath: "cfg2", Entry: "echo.js"}); err != nil {
		t.Fatalf("SavePluginSource error = %v", err)
	}
	if _, err := app.AddPlugin(desktopPluginRequest{ID: "new", Name: "New", Capabilities: []string{"packet.read"}}); err != nil {
		t.Fatalf("AddPlugin error = %v", err)
	}
	if _, err := app.DeletePlugin("old"); err != nil {
		t.Fatalf("DeletePlugin error = %v", err)
	}
	if _, err := app.TogglePlugin("echo"); err != nil {
		t.Fatalf("TogglePlugin error = %v", err)
	}
	if _, err := app.SetPluginsEnabled([]string{"echo"}, true); err != nil {
		t.Fatalf("SetPluginsEnabled error = %v", err)
	}

	for _, want := range []string{
		"GET /api/plugins",
		"GET /api/plugins/source?id=echo",
		"POST /api/plugins/source",
		"POST /api/plugins/add",
		"POST /api/plugins/delete?id=old",
		"POST /api/plugins/toggle?id=echo",
		"POST /api/plugins/bulk",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func TestDesktopMiscTypedBindingsProxyExpectedBackendRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tools/misc/modules":
			_, _ = w.Write([]byte(`[{"id":"webshell.decoder","kind":"decoder","title":"WebShell Decoder","summary":"decode payload","tags":["webshell"]}]`))
		case "/api/tools/misc/packages/demo.module":
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected MISC package method: %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"id":"demo.module","deleted":true}`))
		case "/api/tools/misc/packages/runner.module/invoke":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected MISC invoke method: %s", r.Method)
			}
			var payload desktopMiscModuleRunRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode MISC invoke payload: %v", err)
			}
			if payload.Values["keyword"] != "cmd.exe" {
				t.Fatalf("unexpected MISC invoke values: %#v", payload.Values)
			}
			_, _ = w.Write([]byte(`{"message":"module complete","text":"ok"}`))
		case "/api/tools/misc/import":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected MISC import method: %s", r.Method)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Fatalf("read MISC import file: %v", err)
			}
			defer file.Close()
			raw, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("read MISC import body: %v", err)
			}
			if header.Filename != "module.zip" || string(raw) != "zip-bytes" {
				t.Fatalf("unexpected MISC import file filename=%q body=%q", header.Filename, string(raw))
			}
			_, _ = w.Write([]byte(`{"module":{"id":"imported.module","title":"Imported Module"},"installed_path":"C:/modules/imported.module","message":"模块包导入成功"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	moduleZip := filepath.Join(t.TempDir(), "module.zip")
	if err := os.WriteFile(moduleZip, []byte("zip-bytes"), 0o644); err != nil {
		t.Fatalf("write temp module zip: %v", err)
	}

	app := newTestDesktopApp(server.URL)
	payload, err := app.ListMiscModules()
	if err != nil {
		t.Fatalf("ListMiscModules error = %v", err)
	}
	if rows, ok := payload.([]any); !ok || len(rows) != 1 {
		t.Fatalf("unexpected MISC modules payload: %#v", payload)
	}
	if _, err := app.DeleteMiscModulePackage("demo.module"); err != nil {
		t.Fatalf("DeleteMiscModulePackage error = %v", err)
	}
	runPayload, err := app.RunMiscModulePackage("runner.module", map[string]string{"keyword": "cmd.exe"})
	if err != nil {
		t.Fatalf("RunMiscModulePackage error = %v", err)
	}
	if payload, ok := runPayload.(map[string]any); !ok || payload["message"] != "module complete" {
		t.Fatalf("unexpected MISC run payload: %#v", runPayload)
	}
	importPayload, err := app.ImportMiscModulePackageFromPath(moduleZip)
	if err != nil {
		t.Fatalf("ImportMiscModulePackageFromPath error = %v", err)
	}
	if payload, ok := importPayload.(map[string]any); !ok || payload["message"] != "模块包导入成功" {
		t.Fatalf("unexpected MISC import payload: %#v", importPayload)
	}

	if seen["GET /api/tools/misc/modules"] != 1 {
		t.Fatalf("expected MISC modules route once, seen=%#v", seen)
	}
	if seen["DELETE /api/tools/misc/packages/demo.module"] != 1 {
		t.Fatalf("expected MISC package delete route once, seen=%#v", seen)
	}
	if seen["POST /api/tools/misc/packages/runner.module/invoke"] != 1 {
		t.Fatalf("expected MISC package invoke route once, seen=%#v", seen)
	}
	if seen["POST /api/tools/misc/import"] != 1 {
		t.Fatalf("expected MISC package import route once, seen=%#v", seen)
	}
}

func TestBackendProxyClientUsesPerRequestContextTimeout(t *testing.T) {
	client := newBackendProxyClientWithBaseURL("http://127.0.0.1:1", "")
	if client.client.Timeout != 0 {
		t.Fatalf("backend proxy http client timeout = %s, want context-controlled timeout", client.client.Timeout)
	}
}

func TestDesktopObjectToolingAndAnalysisTypedBindingsProxyExpectedRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/objects":
			_, _ = w.Write([]byte(`[]`))
		case "/api/objects/download":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("zip"))
		case "/api/tools/winrm-decrypt":
			_, _ = w.Write([]byte(`{"result_id":"res-1","port":5985}`))
		case "/api/tools/winrm-decrypt/export":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("text"))
		case "/api/tools/smb3-random-session-key":
			_, _ = w.Write([]byte(`{"random_session_key":"aa"}`))
		case "/api/tools/http-login-analysis":
			_, _ = w.Write([]byte(`{"total_attempts":0}`))
		case "/api/analysis/usb":
			_, _ = w.Write([]byte(`{"records":[]}`))
		case "/api/c2-analysis/decrypt":
			_, _ = w.Write([]byte(`{"family":"vshell","status":"ok"}`))
		case "/api/evidence":
			_, _ = w.Write([]byte(`{"records":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.ListObjects(); err != nil {
		t.Fatalf("ListObjects error = %v", err)
	}
	blob, err := app.DownloadObjectsZip([]int{1, 2})
	if err != nil {
		t.Fatalf("DownloadObjectsZip error = %v", err)
	}
	if decoded, _ := base64.StdEncoding.DecodeString(blob.DataBase64); string(decoded) != "zip" {
		t.Fatalf("unexpected object zip body %q", decoded)
	}
	if _, err := app.RunWinRMDecrypt(desktopWinRMDecryptRequest{Port: 5985}); err != nil {
		t.Fatalf("RunWinRMDecrypt error = %v", err)
	}
	if text, err := app.GetWinRMDecryptResultText("res-1"); err != nil || text != "text" {
		t.Fatalf("GetWinRMDecryptResultText text=%q err=%v", text, err)
	}
	if _, err := app.GenerateSMB3RandomSessionKey(desktopSMB3RandomSessionKeyRequest{Username: "u"}); err != nil {
		t.Fatalf("GenerateSMB3RandomSessionKey error = %v", err)
	}
	if _, err := app.GetHTTPLoginAnalysis(); err != nil {
		t.Fatalf("GetHTTPLoginAnalysis error = %v", err)
	}
	if _, err := app.GetUSBAnalysis("auto", 20000); err != nil {
		t.Fatalf("GetUSBAnalysis error = %v", err)
	}
	if _, err := app.DecryptC2Traffic(desktopC2DecryptRequest{Family: "vshell"}); err != nil {
		t.Fatalf("DecryptC2Traffic error = %v", err)
	}
	if _, err := app.GetEvidenceWithFilter([]string{"vehicle", "usb"}); err != nil {
		t.Fatalf("GetEvidenceWithFilter error = %v", err)
	}

	for _, wantPrefix := range []string{
		"GET /api/objects",
		"POST /api/objects/download",
		"POST /api/tools/winrm-decrypt",
		"GET /api/tools/winrm-decrypt/export?result_id=res-1",
		"POST /api/tools/smb3-random-session-key",
		"GET /api/tools/http-login-analysis",
		"GET /api/analysis/usb?",
		"POST /api/c2-analysis/decrypt",
		"GET /api/evidence?",
	} {
		if !hasSeenRoutePrefix(seen, wantPrefix) {
			t.Fatalf("expected backend route prefix %q, seen=%#v", wantPrefix, seen)
		}
	}
}

func TestDesktopMediaTypedBindingsProxyExpectedRoutes(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/analysis/media":
			_, _ = w.Write([]byte(`{"total_media_packets":2,"sessions":[]}`))
		case "/api/analysis/media/transcribe":
			var payload desktopMediaTranscriptionRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode transcription body: %v", err)
			}
			if payload.Token != "tok/1" || !payload.Force {
				t.Fatalf("unexpected transcription payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`{"token":"tok/1","status":"completed","text":"ok"}`))
		case "/api/analysis/media/transcribe/batch":
			if r.Method == http.MethodPost {
				var payload desktopMediaBatchTranscriptionRequest
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode batch body: %v", err)
				}
				if payload.Force {
					t.Fatalf("unexpected forced batch payload: %#v", payload)
				}
			}
			_, _ = w.Write([]byte(`{"task_id":"task-1","done":true}`))
		case "/api/analysis/media/transcribe/batch/cancel":
			_, _ = w.Write([]byte(`{"task_id":"task-1","cancelled":true,"done":true}`))
		case "/api/analysis/media/transcribe/batch/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/analysis/media/export":
			w.Header().Set("Content-Type", "audio/wav")
			_, _ = w.Write([]byte("artifact"))
		case "/api/analysis/media/play":
			w.Header().Set("Content-Type", "audio/mp4")
			_, _ = w.Write([]byte("playback"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	if _, err := app.GetMediaAnalysis(true); err != nil {
		t.Fatalf("GetMediaAnalysis error = %v", err)
	}
	if _, err := app.TranscribeMediaArtifact("tok/1", true); err != nil {
		t.Fatalf("TranscribeMediaArtifact error = %v", err)
	}
	if _, err := app.StartMediaBatchTranscription(false); err != nil {
		t.Fatalf("StartMediaBatchTranscription error = %v", err)
	}
	if _, err := app.GetMediaBatchTranscriptionStatus(); err != nil {
		t.Fatalf("GetMediaBatchTranscriptionStatus error = %v", err)
	}
	if _, err := app.CancelMediaBatchTranscription(); err != nil {
		t.Fatalf("CancelMediaBatchTranscription error = %v", err)
	}
	if blob, err := app.ExportMediaBatchTranscription("json"); err != nil {
		t.Fatalf("ExportMediaBatchTranscription error = %v", err)
	} else if decoded, _ := base64.StdEncoding.DecodeString(blob.DataBase64); string(decoded) != `{"items":[]}` {
		t.Fatalf("unexpected batch export body %q", decoded)
	}
	if blob, err := app.DownloadMediaArtifact("tok/1"); err != nil {
		t.Fatalf("DownloadMediaArtifact error = %v", err)
	} else if decoded, _ := base64.StdEncoding.DecodeString(blob.DataBase64); string(decoded) != "artifact" {
		t.Fatalf("unexpected media artifact body %q", decoded)
	}
	if blob, err := app.GetMediaPlaybackBlob("tok/1"); err != nil {
		t.Fatalf("GetMediaPlaybackBlob error = %v", err)
	} else if decoded, _ := base64.StdEncoding.DecodeString(blob.DataBase64); string(decoded) != "playback" {
		t.Fatalf("unexpected media playback body %q", decoded)
	}

	for _, want := range []string{
		"GET /api/analysis/media?refresh=1",
		"POST /api/analysis/media/transcribe",
		"POST /api/analysis/media/transcribe/batch",
		"GET /api/analysis/media/transcribe/batch",
		"POST /api/analysis/media/transcribe/batch/cancel",
		"GET /api/analysis/media/transcribe/batch/export?format=json",
		"GET /api/analysis/media/export?token=tok%2F1",
		"GET /api/analysis/media/play?token=tok%2F1",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected backend route %q once, seen=%#v", want, seen)
		}
	}
}

func hasSeenRoutePrefix(seen map[string]int, prefix string) bool {
	for route, count := range seen {
		if count > 0 && strings.HasPrefix(route, prefix) {
			return true
		}
	}
	return false
}
