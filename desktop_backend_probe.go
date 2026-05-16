//go:build dev || production

package main

import (
	"context"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"strings"
)

func probeReusableBackend(ctx context.Context, token string) error {
	return probeReusableBackendAt(ctx, "127.0.0.1:17891", backendBaseURL, token)
}

func probeReusableBackendAt(ctx context.Context, addr, baseURL, token string) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()

	parsed, err := neturl.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid backend base URL: %w", err)
	}
	client := newBackendProxyClientWithBaseURL(parsed.String(), token)
	var health map[string]string
	if err := client.getJSON(ctx, "/health", &health); err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}

	var identity runtimeIdentity
	if err := client.getJSON(ctx, "/api/runtime/identity", &identity); err != nil {
		if strings.Contains(err.Error(), "unauthorized") {
			return fmt.Errorf("runtime identity probe failed: backend requires a matching GSHARK_BACKEND_TOKEN")
		}
		return fmt.Errorf("runtime identity probe failed: %w", err)
	}
	if !strings.EqualFold(identity.Service, "gshark-sentinel") {
		return fmt.Errorf("runtime identity mismatch: unexpected service %q", identity.Service)
	}
	fmt.Fprintf(os.Stdout, "desktop startup: reusable backend identity service=%q build_id=%q exe=%q cwd=%q started_at=%q\n", identity.Service, identity.BuildID, identity.ExecutablePath, identity.WorkingDir, identity.StartedAt)
	return nil
}
