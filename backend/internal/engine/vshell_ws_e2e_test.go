package engine

import (
	"context"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestVShellWebSocketFromRealPCAP(t *testing.T) {
	svc := NewService(NopEmitter{})
	t.Cleanup(func() { _ = svc.packetStore.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pcapPath := `C:\Users\QAQ\Downloads\challenge (2)\新建文件夹\challenge.pcap`
	if err := svc.LoadPCAP(ctx, model.ParseOptions{FilePath: pcapPath, FastList: true}); err != nil {
		t.Skipf("LoadPCAP error (sample pcap not present in this environment): %v", err)
	}

	result, err := svc.C2SampleAnalysis(context.Background())
	if err != nil {
		t.Fatalf("C2 analysis error: %v", err)
	}

	hasWebSocketHandshake := false
	hasHeartbeat := false
	for _, c := range result.VShell.Candidates {
		if c.Confidence >= 80 {
			hasWebSocketHandshake = true
		}
	}
	for _, bp := range result.VShell.BeaconPatterns {
		if bp.Name == "heartbeat-interval" {
			hasHeartbeat = true
		}
	}

	if !hasWebSocketHandshake {
		t.Errorf("expected high-confidence VShell WebSocket handshake candidate")
	}
	if !hasHeartbeat {
		t.Errorf("expected VShell heartbeat beacon pattern from WebSocket stream")
	}
}
