package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestStartCaptureEnrichmentCoversReadyFailedAndCanceledBranches(t *testing.T) {
	t.Run("ready updates packets and raw streams", func(t *testing.T) {
		oldFast := streamPacketsFastFn
		t.Cleanup(func() { streamPacketsFastFn = oldFast })

		streamPacketsFastFn = func(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(int)) error {
			if opts.ListProfile != "full_fast" || !opts.FastList || opts.EnableEnrichment {
				t.Fatalf("unexpected enrichment opts: %+v", opts)
			}
			onProgress(1)
			return onPacket(model.Packet{
				ID:            1,
				SourceIP:      "10.0.0.1",
				SourcePort:    51515,
				DestIP:        "10.0.0.2",
				DestPort:      53,
				Protocol:      "UDP",
				StreamID:      7,
				Payload:       "aa:bb:cc",
				UDPPayloadHex: "AA:BB:CC",
				IPHeaderLen:   20,
				L4HeaderLen:   8,
				Color:         model.PacketColorFeatures{Broadcast: true},
			})
		}

		svc := NewService(NopEmitter{})
		defer svc.packetStore.Close()
		svc.pcap = "capture.pcapng"
		atomic.StoreInt64(&svc.runID, 11)
		svc.startCaptureLoadStatus(11, model.ParseOptions{FilePath: "capture.pcapng"})
		if err := svc.packetStore.Append([]model.Packet{{
			ID:         1,
			SourceIP:   "10.0.0.1",
			SourcePort: 51515,
			DestIP:     "10.0.0.2",
			DestPort:   53,
			Protocol:   "UDP",
			StreamID:   7,
			Payload:    "aa:bb:cc",
		}}); err != nil {
			t.Fatalf("append packet: %v", err)
		}

		svc.startCaptureEnrichment(model.ParseOptions{FilePath: "capture.pcapng"}, 11)
		status := waitForEnrichmentPhase(t, svc, "ready")
		if status.Enrichment.Processed != 1 || status.Enrichment.Updated != 1 || status.Enrichment.LastError != "" {
			t.Fatalf("unexpected ready enrichment status: %+v", status.Enrichment)
		}
		if svc.ActiveCaptureTaskCount() != 0 {
			t.Fatalf("expected enrichment task to finish, active=%d", svc.ActiveCaptureTaskCount())
		}

		packets := svc.Packets()
		if len(packets) != 1 || packets[0].UDPPayloadHex != "AA:BB:CC" || !packets[0].Color.Broadcast {
			t.Fatalf("expected enriched packet to be persisted, got %+v", packets)
		}
		svc.mu.RLock()
		raw := svc.rawStreamIndex["UDP:7"]
		svc.mu.RUnlock()
		if raw.StreamID != 7 || len(raw.Chunks) != 1 || raw.Chunks[0].Body == "" {
			t.Fatalf("expected raw stream index to be refreshed, got %+v", raw)
		}
	})

	t.Run("stream error marks failed", func(t *testing.T) {
		oldFast := streamPacketsFastFn
		t.Cleanup(func() { streamPacketsFastFn = oldFast })
		streamPacketsFastFn = func(context.Context, model.ParseOptions, func(model.Packet) error, func(int)) error {
			return errors.New("fast parser exploded")
		}

		svc := NewService(NopEmitter{})
		defer svc.packetStore.Close()
		svc.startCaptureLoadStatus(22, model.ParseOptions{FilePath: "bad.pcapng"})

		svc.startCaptureEnrichment(model.ParseOptions{FilePath: "bad.pcapng"}, 22)
		status := waitForEnrichmentPhase(t, svc, "failed")
		if !strings.Contains(status.Enrichment.LastError, "fast parser exploded") {
			t.Fatalf("expected parser error in enrichment status, got %+v", status.Enrichment)
		}
	})

	t.Run("run replacement cancels stale enrichment", func(t *testing.T) {
		oldFast := streamPacketsFastFn
		t.Cleanup(func() { streamPacketsFastFn = oldFast })
		streamPacketsFastFn = func(context.Context, model.ParseOptions, func(model.Packet) error, func(int)) error {
			atomic.StoreInt64(&activeCanceledEnrichmentRunID, 999)
			return nil
		}

		svc := NewService(NopEmitter{})
		defer svc.packetStore.Close()
		svc.pcap = "stale.pcapng"
		atomic.StoreInt64(&svc.runID, 34)
		svc.startCaptureLoadStatus(33, model.ParseOptions{FilePath: "stale.pcapng"})

		svc.startCaptureEnrichment(model.ParseOptions{FilePath: "stale.pcapng"}, 33)
		status := waitForEnrichmentPhase(t, svc, "canceled")
		if status.Enrichment.LastError != context.Canceled.Error() {
			t.Fatalf("expected context canceled, got %+v", status.Enrichment)
		}
	})
}

var activeCanceledEnrichmentRunID int64

func TestCaptureStatusHelpersCoverCloneAndDefaults(t *testing.T) {
	if got := cloneCaptureLoadStatus(nil); got != nil {
		t.Fatalf("cloneCaptureLoadStatus(nil) = %+v", got)
	}
	original := &model.CaptureLoadStatus{
		RunID:      1,
		Phase:      "running",
		Enrichment: &model.CaptureEnrichmentStatus{Phase: "ready", Processed: 2},
	}
	clone := cloneCaptureLoadStatus(original)
	clone.Enrichment.Processed = 99
	if original.Enrichment.Processed != 2 {
		t.Fatalf("clone should deep-copy enrichment, original=%+v clone=%+v", original, clone)
	}

	for _, tc := range []struct {
		opts model.ParseOptions
		want string
	}{
		{model.ParseOptions{ListProfile: " first_screen "}, "first_screen"},
		{model.ParseOptions{ListProfile: "full_fast"}, "full_fast"},
		{model.ParseOptions{ListProfile: "compat"}, "compat"},
		{model.ParseOptions{ListProfile: "ek"}, "ek"},
		{model.ParseOptions{ListProfile: "unknown", FastList: true}, "full_fast"},
		{model.ParseOptions{}, "ek"},
	} {
		if got := normalizeCaptureListProfile(tc.opts); got != tc.want {
			t.Fatalf("normalizeCaptureListProfile(%+v) = %q, want %q", tc.opts, got, tc.want)
		}
	}

	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()
	svc.startCaptureLoadStatus(55, model.ParseOptions{FilePath: "capture.pcapng"})
	svc.setCaptureEnrichmentStatus(55, "running", 7, 3, " partial ")
	status := svc.CaptureStatus()
	if status.Load == nil || status.Load.Enrichment == nil {
		t.Fatalf("expected enrichment status, got %+v", status)
	}
	if status.Load.Enrichment.Phase != "running" || status.Load.Enrichment.Processed != 7 || status.Load.Enrichment.Updated != 3 || status.Load.Enrichment.LastError != "partial" {
		t.Fatalf("unexpected enrichment status: %+v", status.Load.Enrichment)
	}
}

func waitForEnrichmentPhase(t *testing.T, svc *Service, phase string) *model.CaptureLoadStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := svc.CaptureStatus().Load
		if status != nil && status.Enrichment != nil && status.Enrichment.Phase == phase {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for enrichment phase %q, last=%+v", phase, svc.CaptureStatus().Load)
	return nil
}
