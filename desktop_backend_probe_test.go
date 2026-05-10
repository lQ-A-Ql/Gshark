//go:build dev || production

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeReusableBackendAtAcceptsExpectedIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/runtime/identity":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"service":"gshark-sentinel","version":"dev","auth_enabled":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := server.Listener.Addr().String()
	if err := probeReusableBackendAt(ctx, addr, server.URL, ""); err != nil {
		t.Fatalf("probeReusableBackendAt() error = %v", err)
	}
}

func TestProbeReusableBackendAtRejectsUnexpectedIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/runtime/identity":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"service":"other-service","version":"dev","auth_enabled":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := server.Listener.Addr().String()
	if err := probeReusableBackendAt(ctx, addr, server.URL, ""); err == nil {
		t.Fatal("expected identity mismatch error")
	}
}

func TestProbeReusableBackendAtReportsAuthMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/runtime/identity":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := server.Listener.Addr().String()
	err := probeReusableBackendAt(ctx, addr, server.URL, "")
	if err == nil {
		t.Fatal("expected auth mismatch error")
	}
	if err.Error() != "runtime identity probe failed: backend requires a matching GSHARK_BACKEND_TOKEN" {
		t.Fatalf("unexpected auth mismatch error: %v", err)
	}
}
