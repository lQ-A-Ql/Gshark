package engine

import (
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestFilterOutlierIntervals(t *testing.T) {
	tests := []struct {
		name     string
		input    []float64
		wantLen  int
	}{
		{
			name:    "no outliers",
			input:   []float64{10, 11, 10, 12, 10},
			wantLen: 5,
		},
		{
			name:    "removes values above 2x median",
			input:   []float64{10, 11, 10, 25, 10},
			wantLen: 4,
		},
		{
			name:    "TCP retransmission outlier filtered",
			input:   []float64{9.3, 11.3, 10.1, 11.1, 10.1, 9.2, 10.4, 11.4, 10.4, 9.3, 9.1, 11.3, 22.0},
			wantLen: 12,
		},
		{
			name:    "too few items returns as-is",
			input:   []float64{10, 25},
			wantLen: 2,
		},
		{
			name:    "empty input",
			input:   []float64{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterOutlierIntervals(tt.input)
			if len(result) != tt.wantLen {
				t.Fatalf("filterOutlierIntervals(%v) returned %d items, want %d", tt.input, len(result), tt.wantLen)
			}
		})
	}
}

func TestStreamHasTCPProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protos   []string
		expected bool
	}{
		{"TCP", []string{"TCP"}, true},
		{"HTTP", []string{"HTTP"}, true},
		{"WebSocket", []string{"WebSocket"}, true},
		{"TLS", []string{"TLS"}, true},
		{"mixed HTTP and WebSocket", []string{"HTTP", "WebSocket", "TCP"}, true},
		{"DNS only", []string{"DNS"}, false},
		{"UDP only", []string{"UDP"}, false},
		{"OTHER only", []string{"OTHER"}, false},
		{"empty", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets := make([]model.Packet, len(tt.protos))
			for i, p := range tt.protos {
				packets[i] = model.Packet{Protocol: p}
			}
			if got := streamHasTCPProtocol(packets); got != tt.expected {
				t.Fatalf("streamHasTCPProtocol(%v) = %v, want %v", tt.protos, got, tt.expected)
			}
		})
	}
}

func TestC2StreamKeyUsesStreamIDOnly(t *testing.T) {
	// Verify that the stream map groups packets by stream ID alone,
	// regardless of protocol (HTTP handshake + WebSocket data in same stream).
	packets := []model.Packet{
		{ID: 1, StreamID: 208, Protocol: "HTTP", Timestamp: "10:00:00.000", SourceIP: "a", DestIP: "b", DestPort: 8443},
		{ID: 2, StreamID: 208, Protocol: "WebSocket", Timestamp: "10:00:02.000", SourceIP: "a", DestIP: "b", DestPort: 8443},
		{ID: 3, StreamID: 208, Protocol: "TCP", Timestamp: "10:00:05.000", SourceIP: "a", DestIP: "b", DestPort: 8443},
		{ID: 4, StreamID: 999, Protocol: "HTTP", Timestamp: "10:00:00.000", SourceIP: "c", DestIP: "d", DestPort: 80},
	}

	streams := map[string][]model.Packet{}
	for _, p := range packets {
		if p.StreamID != 0 {
			key := "stream:" + formatStreamID(p.StreamID)
			streams[key] = append(streams[key], p)
		}
	}

	// All 3 packets with stream ID 208 should be in the same group
	stream208 := streams["stream:208"]
	if len(stream208) != 3 {
		t.Fatalf("expected 3 packets in stream:208, got %d", len(stream208))
	}

	// Stream 999 should have 1 packet
	stream999 := streams["stream:999"]
	if len(stream999) != 1 {
		t.Fatalf("expected 1 packet in stream:999, got %d", len(stream999))
	}
}

func formatStreamID(id int64) string {
	return fmt.Sprintf("%d", id)
}
