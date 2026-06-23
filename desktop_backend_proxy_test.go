//go:build dev || production

package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/desktopruntime"
)

func TestDesktopRuntimeDecodesJSON(t *testing.T) {
	rt := desktopruntime.NewWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]string
	if err := rt.GetJSON(ctx, "/health", &payload); err != nil {
		t.Fatalf("GetJSON() error = %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestDesktopRuntimeNormalizesBackendErrorMessage(t *testing.T) {
	rt := desktopruntime.NewWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"capture file is not accessible"}`, http.StatusBadRequest)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]string
	err := rt.GetJSON(ctx, "/api/capture/start", &payload)
	if err == nil {
		t.Fatal("expected normalized backend error")
	}
	if err.Error() != "capture file is not accessible" {
		t.Fatalf("unexpected normalized backend error: %q", err.Error())
	}
}

func TestDesktopRuntimeGetsCaptureStatus(t *testing.T) {
	rt := desktopruntime.NewWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/capture/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"file_path":"C:\\capture.pcapng","has_capture":true,"packet_count":1509}`))
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]any
	if err := rt.GetJSON(ctx, "/api/capture/status", &payload); err != nil {
		t.Fatalf("GetJSON() error = %v", err)
	}
	if payload["file_path"] != `C:\capture.pcapng` || payload["has_capture"] != true || payload["packet_count"] != float64(1509) {
		t.Fatalf("unexpected capture status payload: %#v", payload)
	}
}

func TestDesktopTypedJSONProxiesRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/analysis/industrial" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	app := newTestDesktopApp(handler)
	payload, err := app.GetIndustrialAnalysis(false)
	if err != nil {
		t.Fatalf("GetIndustrialAnalysis() error = %v", err)
	}
	if payload.(map[string]any)["ok"] != true {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestDesktopTypedBlobAndTextHelpers(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/objects/download":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected objects download method %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="objects.zip"`)
			_, _ = w.Write([]byte("zip"))
		case "/api/tools/winrm-decrypt/export":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("plain text"))
		case "/api/analysis/media/transcribe/batch/export":
			if r.URL.Query().Get("format") != "srt" {
				t.Fatalf("unexpected batch export format %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", `attachment; filename="transcription.srt"`)
			_, _ = w.Write([]byte("srt"))
		case "/api/analysis/media/export":
			if r.URL.Query().Get("token") != "media-1" {
				t.Fatalf("unexpected media export token %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="artifact.bin"`)
			_, _ = w.Write([]byte("artifact"))
		case "/api/analysis/media/play":
			if r.URL.Query().Get("token") != "media-1" {
				t.Fatalf("unexpected media play token %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "audio/wav")
			_, _ = w.Write([]byte("wav"))
		default:
			http.NotFound(w, r)
		}
	})

	app := newTestDesktopApp(handler)
	blob, err := app.DownloadObjectsZip([]int{1, 2})
	if err != nil {
		t.Fatalf("DownloadObjectsZip() error = %v", err)
	}
	if blob.ContentType != "application/zip" || blob.Filename != "objects.zip" || blob.Size != 3 {
		t.Fatalf("unexpected blob metadata: %#v", blob)
	}
	decoded, err := base64.StdEncoding.DecodeString(blob.DataBase64)
	if err != nil || string(decoded) != "zip" {
		t.Fatalf("unexpected blob body decoded=%q err=%v", decoded, err)
	}

	text, err := app.GetWinRMDecryptResultText("res-1")
	if err != nil {
		t.Fatalf("GetWinRMDecryptResultText() error = %v", err)
	}
	if text != "plain text" {
		t.Fatalf("unexpected text response %q", text)
	}
	winrmBlob, err := app.ExportWinRMDecryptResult("res-1")
	if err != nil {
		t.Fatalf("ExportWinRMDecryptResult() error = %v", err)
	}
	if winrmBlob.ContentType != "text/plain; charset=utf-8" || winrmBlob.Size != int64(len("plain text")) {
		t.Fatalf("unexpected WinRM export blob metadata: %#v", winrmBlob)
	}
	batchBlob, err := app.ExportMediaBatchTranscription("SRT")
	if err != nil {
		t.Fatalf("ExportMediaBatchTranscription() error = %v", err)
	}
	if batchBlob.ContentType != "text/plain" || batchBlob.Filename != "transcription.srt" || batchBlob.Size != 3 {
		t.Fatalf("unexpected batch export blob metadata: %#v", batchBlob)
	}
	artifactBlob, err := app.DownloadMediaArtifact("media-1")
	if err != nil {
		t.Fatalf("DownloadMediaArtifact() error = %v", err)
	}
	if artifactBlob.ContentType != "application/octet-stream" || artifactBlob.Filename != "artifact.bin" || artifactBlob.Size != int64(len("artifact")) {
		t.Fatalf("unexpected media artifact blob metadata: %#v", artifactBlob)
	}
	playbackBlob, err := app.GetMediaPlaybackBlob("media-1")
	if err != nil {
		t.Fatalf("GetMediaPlaybackBlob() error = %v", err)
	}
	if playbackBlob.ContentType != "audio/wav" || playbackBlob.Size != 3 {
		t.Fatalf("unexpected media playback blob metadata: %#v", playbackBlob)
	}
}

func TestDesktopRuntimeBlobReadLimit(t *testing.T) {
	rt := desktopruntime.NewWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/blob/exact":
			_, _ = w.Write([]byte("123"))
		case "/api/blob/over":
			_, _ = w.Write([]byte("1234"))
		default:
			http.NotFound(w, r)
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, err := rt.DoRaw(ctx, http.MethodGet, "/api/blob/exact", nil, "", 3)
	if err != nil {
		t.Fatalf("DoRaw exact limit error = %v", err)
	}
	if string(raw.Body) != "123" {
		t.Fatalf("unexpected exact limit body %q", raw.Body)
	}

	_, err = rt.DoRaw(ctx, http.MethodGet, "/api/blob/over", nil, "", 3)
	if err == nil {
		t.Fatal("expected blob size limit error")
	}
	if !strings.Contains(err.Error(), "blob response too large") || !strings.Contains(err.Error(), "/api/blob/over") {
		t.Fatalf("unexpected blob size error: %v", err)
	}
}

func TestDesktopTypedMiscImportMultipart(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tools/misc/import" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		reader, err := r.MultipartReader()
		if err != nil {
			t.Fatalf("MultipartReader() error = %v", err)
		}
		values := map[string]string{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("NextPart() error = %v", err)
			}
			body, _ := io.ReadAll(part)
			values[part.FormName()] = string(body)
			if part.FormName() == "file" {
				if part.FileName() != "module.zip" {
					t.Fatalf("unexpected file part filename=%q", part.FileName())
				}
			}
		}
		if values["file"] != "zip" {
			t.Fatalf("unexpected multipart values: %#v", values)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"imported":true}`))
	})

	packagePath := filepath.Join(t.TempDir(), "module.zip")
	if err := os.WriteFile(packagePath, []byte("zip"), 0o600); err != nil {
		t.Fatalf("write temp module package: %v", err)
	}

	app := newTestDesktopApp(handler)
	payload, err := app.ImportMiscModulePackageFromPath(packagePath)
	if err != nil {
		t.Fatalf("ImportMiscModulePackageFromPath() error = %v", err)
	}
	if payload.(map[string]any)["imported"] != true {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestDesktopTypedToolAllowedDirBindings(t *testing.T) {
	seen := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.String()
		seen[key]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tools/tshark/allow-dir":
			_, _ = w.Write([]byte(`{"available":true,"path":"C:\\Tools\\tshark.exe","message":"ok","extra_allowed_dir":"C:\\Tools"}`))
		case "/api/tools/tshark/allowed-dirs":
			_, _ = w.Write([]byte(`{"dirs":["C:\\Tools"]}`))
		case "/api/tools/tshark/allowed-dirs/remove":
			_, _ = w.Write([]byte(`{"available":true,"path":"tshark","message":"removed"}`))
		case "/api/tools/allow-dir":
			_, _ = w.Write([]byte(`{"config":{"ffmpeg_allowed_dirs":["C:\\FFmpeg"]},"ffmpeg":{"available":true,"path":"ffmpeg","message":"ok"}}`))
		case "/api/tools/allowed-dirs":
			_, _ = w.Write([]byte(`{"dirs":["C:\\FFmpeg"]}`))
		case "/api/tools/allowed-dirs/remove":
			_, _ = w.Write([]byte(`{"config":{"ffmpeg_allowed_dirs":[]},"ffmpeg":{"available":true,"path":"ffmpeg","message":"removed"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	app := newTestDesktopApp(handler)

	if _, err := app.AllowTSharkDir(`C:\Tools`); err != nil {
		t.Fatalf("AllowTSharkDir() error = %v", err)
	}
	tsharkDirs, err := app.ListTSharkAllowedDirs()
	if err != nil {
		t.Fatalf("ListTSharkAllowedDirs() error = %v", err)
	}
	if len(tsharkDirs.Dirs) != 1 || tsharkDirs.Dirs[0] != `C:\Tools` {
		t.Fatalf("unexpected tshark dirs: %#v", tsharkDirs)
	}
	if _, err := app.RemoveTSharkAllowedDir(`C:\Tools`); err != nil {
		t.Fatalf("RemoveTSharkAllowedDir() error = %v", err)
	}
	if _, err := app.AllowToolDir("ffmpeg", `C:\FFmpeg`); err != nil {
		t.Fatalf("AllowToolDir() error = %v", err)
	}
	toolDirs, err := app.ListToolAllowedDirs("ffmpeg")
	if err != nil {
		t.Fatalf("ListToolAllowedDirs() error = %v", err)
	}
	if len(toolDirs.Dirs) != 1 || toolDirs.Dirs[0] != `C:\FFmpeg` {
		t.Fatalf("unexpected tool dirs: %#v", toolDirs)
	}
	if _, err := app.RemoveToolAllowedDir("ffmpeg", `C:\FFmpeg`); err != nil {
		t.Fatalf("RemoveToolAllowedDir() error = %v", err)
	}

	for _, want := range []string{
		"POST /api/tools/tshark/allow-dir",
		"GET /api/tools/tshark/allowed-dirs",
		"DELETE /api/tools/tshark/allowed-dirs/remove",
		"POST /api/tools/allow-dir",
		"GET /api/tools/allowed-dirs?tool=ffmpeg",
		"DELETE /api/tools/allowed-dirs/remove",
	} {
		if seen[want] != 1 {
			t.Fatalf("expected route %q once, seen=%#v", want, seen)
		}
	}
}

func TestValidateDesktopBackendRequestRejectsUnsafeInputs(t *testing.T) {
	cases := []desktopBackendRequest{
		{Method: "PATCH", Path: "/api/objects"},
		{Method: "GET", Path: "http://127.0.0.1:1/api/objects"},
		{Method: "GET", Path: "/api/../secrets"},
		{Method: "GET", Path: "/admin"},
		{Method: "GET", Path: `\api\objects`},
	}
	for _, tc := range cases {
		if _, _, err := validateDesktopBackendRequest(tc); err == nil {
			t.Fatalf("validateDesktopBackendRequest(%#v) succeeded, want error", tc)
		}
	}
}

func TestDesktopPingBackendDataPlaneReportsPartialFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/runtime/identity":
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	})

	app := newTestDesktopApp(handler)
	probe := app.PingBackendDataPlane()
	if probe.Ready || !probe.HealthOK || probe.IdentityOK || !strings.Contains(probe.Message, "runtime identity probe failed") {
		t.Fatalf("unexpected probe: %#v", probe)
	}
}

func newTestDesktopApp(handler http.Handler) *DesktopApp {
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"test runtime handler not configured for `+r.URL.Path+`"}`, http.StatusNotFound)
		})
	}
	return &DesktopApp{
		backendAuthToken: "secret-token",
		backendStatus:    "running",
		backendRuntime:   desktopruntime.NewWithHandler(handler),
	}
}
