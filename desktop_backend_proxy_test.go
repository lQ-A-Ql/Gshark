//go:build dev || production

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBackendProxyClientInjectsAuthorizationAndDecodesJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := newBackendProxyClientWithBaseURL(server.URL, "secret-token")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]string
	if err := client.getJSON(ctx, "/health", &payload); err != nil {
		t.Fatalf("getJSON() error = %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestBackendProxyClientNormalizesBackendErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"capture file is not accessible"}`, http.StatusBadRequest)
	}))
	defer server.Close()

	client := newBackendProxyClientWithBaseURL(server.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]string
	err := client.getJSON(ctx, "/api/capture/start", &payload)
	if err == nil {
		t.Fatal("expected normalized backend error")
	}
	if err.Error() != "capture file is not accessible" {
		t.Fatalf("unexpected normalized backend error: %q", err.Error())
	}
}

func TestBackendProxyClientGetsCaptureStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/capture/status" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"file_path":"C:\\capture.pcapng","has_capture":true,"packet_count":1509}`))
	}))
	defer server.Close()

	client := newBackendProxyClientWithBaseURL(server.URL, "secret-token")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var payload map[string]any
	if err := client.getJSON(ctx, "/api/capture/status", &payload); err != nil {
		t.Fatalf("getJSON() error = %v", err)
	}
	if payload["file_path"] != `C:\capture.pcapng` || payload["has_capture"] != true || payload["packet_count"] != float64(1509) {
		t.Fatalf("unexpected capture status payload: %#v", payload)
	}
}

func TestDesktopInvokeBackendJSONProxiesRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/analysis/industrial" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if payload["refresh"] != true {
			t.Fatalf("unexpected request body: %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	payload, err := app.InvokeBackendJSON(desktopBackendRequest{
		Method:   http.MethodPost,
		Path:     "/api/analysis/industrial",
		BodyKind: "json",
		JSONBody: map[string]any{"refresh": true},
	})
	if err != nil {
		t.Fatalf("InvokeBackendJSON() error = %v", err)
	}
	if payload.(map[string]any)["ok"] != true {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestDesktopInvokeBackendBlobAndText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/objects/download":
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="objects.zip"`)
			_, _ = w.Write([]byte("zip"))
		case "/api/tools/winrm-decrypt/export":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("plain text"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	blob, err := app.InvokeBackendBlob(desktopBackendRequest{Method: http.MethodPost, Path: "/api/objects/download"})
	if err != nil {
		t.Fatalf("InvokeBackendBlob() error = %v", err)
	}
	if blob.ContentType != "application/zip" || blob.Filename != "objects.zip" || blob.Size != 3 {
		t.Fatalf("unexpected blob metadata: %#v", blob)
	}
	decoded, err := base64.StdEncoding.DecodeString(blob.DataBase64)
	if err != nil || string(decoded) != "zip" {
		t.Fatalf("unexpected blob body decoded=%q err=%v", decoded, err)
	}

	text, err := app.InvokeBackendText(desktopBackendRequest{Path: "/api/tools/winrm-decrypt/export?result_id=res-1"})
	if err != nil {
		t.Fatalf("InvokeBackendText() error = %v", err)
	}
	if text != "plain text" {
		t.Fatalf("unexpected text response %q", text)
	}
}

func TestBackendProxyClientBlobReadLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/blob/exact":
			_, _ = w.Write([]byte("123"))
		case "/api/blob/over":
			_, _ = w.Write([]byte("1234"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newBackendProxyClientWithBaseURL(server.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, err := client.doRawLimited(ctx, http.MethodGet, "/api/blob/exact", nil, "", 3)
	if err != nil {
		t.Fatalf("doRawLimited exact limit error = %v", err)
	}
	if string(raw.Body) != "123" {
		t.Fatalf("unexpected exact limit body %q", raw.Body)
	}

	_, err = client.doRawLimited(ctx, http.MethodGet, "/api/blob/over", nil, "", 3)
	if err == nil {
		t.Fatal("expected blob size limit error")
	}
	if !strings.Contains(err.Error(), "桌面 IPC blob 响应过大") || !strings.Contains(err.Error(), "/api/blob/over") {
		t.Fatalf("unexpected blob size error: %v", err)
	}
}

func TestDesktopInvokeBackendMultipart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				if part.FileName() != "module.zip" || part.Header.Get("Content-Type") != "application/zip" {
					t.Fatalf("unexpected file part filename=%q content-type=%q", part.FileName(), part.Header.Get("Content-Type"))
				}
			}
		}
		if values["label"] != "decoder" || values["file"] != "zip" {
			t.Fatalf("unexpected multipart values: %#v", values)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"imported":true}`))
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	payload, err := app.InvokeBackendJSON(desktopBackendRequest{
		Method:   http.MethodPost,
		Path:     "/api/tools/misc/import",
		BodyKind: "multipart",
		Multipart: []desktopMultipartPart{
			{Name: "label", Value: "decoder"},
			{Name: "file", Filename: "module.zip", ContentType: "application/zip", DataBase64: base64.StdEncoding.EncodeToString([]byte("zip"))},
		},
	})
	if err != nil {
		t.Fatalf("InvokeBackendJSON multipart error = %v", err)
	}
	if payload.(map[string]any)["imported"] != true {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestValidateDesktopBackendRequestRejectsUnsafeInputs(t *testing.T) {
	cases := []desktopBackendRequest{
		{Method: "PUT", Path: "/api/objects"},
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/runtime/identity":
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	app := newTestDesktopApp(server.URL)
	probe := app.PingBackendDataPlane()
	if probe.Ready || !probe.HealthOK || probe.IdentityOK || !strings.Contains(probe.Message, "runtime identity probe failed") {
		t.Fatalf("unexpected probe: %#v", probe)
	}
}

func newTestDesktopApp(baseURL string) *DesktopApp {
	return &DesktopApp{
		backendAuthToken: "secret-token",
		backendBaseURL:   baseURL,
		backendStatus:    "running",
	}
}
