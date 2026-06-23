//go:build dev || production

package main

import "testing"

func TestEmitDesktopBackendRuntimeEventNamePolicy(t *testing.T) {
	cases := []struct {
		name      string
		eventName string
		wantName  string
		want      bool
	}{
		{name: "ready", eventName: "ready", wantName: "meow:backend:ready", want: true},
		{name: "status", eventName: "status", wantName: "meow:backend:status", want: true},
		{name: "packet", eventName: "packet", wantName: "meow:backend:packet", want: true},
		{name: "error", eventName: "error", wantName: "meow:backend:error", want: true},
		{name: "message ignored", eventName: "message", want: false},
		{name: "empty ignored", eventName: "   ", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, got := desktopBackendRuntimeEventName(tc.eventName)
			if got != tc.want {
				t.Fatalf("desktopBackendRuntimeEventName() ok = %v, want %v", got, tc.want)
			}
			if gotName != tc.wantName {
				t.Fatalf("desktopBackendRuntimeEventName() name = %q, want %q", gotName, tc.wantName)
			}
		})
	}
}
