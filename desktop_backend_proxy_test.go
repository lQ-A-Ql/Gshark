//go:build dev || production

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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
