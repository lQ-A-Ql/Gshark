//go:build dev || production

package main

import "testing"

func TestParseDesktopBackendEvent(t *testing.T) {
	cases := []struct {
		name          string
		eventName     string
		rawData       string
		wantRuntime   string
		wantForwarded bool
	}{
		{
			name:          "ready",
			eventName:     "ready",
			rawData:       `{"message":"ready"}`,
			wantRuntime:   "gshark:backend:ready",
			wantForwarded: true,
		},
		{
			name:          "status",
			eventName:     "status",
			rawData:       `{"message":"解析完成"}`,
			wantRuntime:   "gshark:backend:status",
			wantForwarded: true,
		},
		{
			name:          "packet",
			eventName:     "packet",
			rawData:       `{"id":7}`,
			wantRuntime:   "gshark:backend:packet",
			wantForwarded: true,
		},
		{
			name:          "error",
			eventName:     "error",
			rawData:       `{"message":"boom"}`,
			wantRuntime:   "gshark:backend:error",
			wantForwarded: true,
		},
		{
			name:          "message ignored",
			eventName:     "message",
			rawData:       `{"message":"ignored"}`,
			wantForwarded: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtimeEvent, _, ok := parseDesktopBackendEvent(tc.eventName, tc.rawData)
			if ok != tc.wantForwarded {
				t.Fatalf("forwarded = %v, want %v", ok, tc.wantForwarded)
			}
			if runtimeEvent != tc.wantRuntime {
				t.Fatalf("runtime event = %q, want %q", runtimeEvent, tc.wantRuntime)
			}
		})
	}
}

func TestParseDesktopBackendEventMalformedData(t *testing.T) {
	runtimeEvent, payload, ok := parseDesktopBackendEvent("status", "not-json")
	if !ok {
		t.Fatal("expected malformed event to be forwarded")
	}
	if runtimeEvent != "gshark:backend:status" {
		t.Fatalf("runtime event = %q", runtimeEvent)
	}
	message, _ := payload.(map[string]any)["message"].(string)
	if message != "not-json" {
		t.Fatalf("malformed payload = %#v", payload)
	}
}
