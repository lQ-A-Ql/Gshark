package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestLoadPCAPFallsBackWhenFastListFails(t *testing.T) {
	oldEstimate := estimatePacketsFn
	oldFast := streamPacketsFastFn
	oldStream := streamPacketsFn
	oldCompat := streamPacketsCompatFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
		streamPacketsFastFn = oldFast
		streamPacketsFn = oldStream
		streamPacketsCompatFn = oldCompat
	})

	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		return 1, nil
	}

	fastCalls := 0
	streamPacketsFastFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		fastCalls++
		return errors.New("unsupported field: tcp.analysis.window_update")
	}

	streamCalls := 0
	streamPacketsFn = func(_ context.Context, _ model.ParseOptions, onPacket func(model.Packet) error, onProgress func(int)) error {
		streamCalls++
		if onProgress != nil {
			onProgress(1)
		}
		return onPacket(model.Packet{ID: 1, Protocol: "TCP", Info: "fallback packet"})
	}
	streamPacketsCompatFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		t.Fatal("compat parser should not be called in fast->ek fallback test")
		return nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	if err := svc.LoadPCAP(context.Background(), model.ParseOptions{
		FilePath: "fake.pcap",
		FastList: true,
	}); err != nil {
		t.Fatalf("LoadPCAP() error = %v", err)
	}

	if fastCalls != 1 {
		t.Fatalf("expected fast parser to be called once, got %d", fastCalls)
	}
	if streamCalls != 1 {
		t.Fatalf("expected fallback parser to be called once, got %d", streamCalls)
	}

	packets := svc.Packets()
	if len(packets) != 1 || packets[0].ID != 1 {
		t.Fatalf("expected fallback packet to be persisted, got %+v", packets)
	}
}

func TestLoadPCAPFallsBackToCompatWhenEKStillFails(t *testing.T) {
	oldEstimate := estimatePacketsFn
	oldFast := streamPacketsFastFn
	oldStream := streamPacketsFn
	oldCompat := streamPacketsCompatFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
		streamPacketsFastFn = oldFast
		streamPacketsFn = oldStream
		streamPacketsCompatFn = oldCompat
	})

	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		return 1, nil
	}

	streamPacketsFastFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		return errors.New("unsupported field list")
	}

	ekCalls := 0
	streamPacketsFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		ekCalls++
		return errors.New("ek output unsupported")
	}

	compatCalls := 0
	streamPacketsCompatFn = func(_ context.Context, _ model.ParseOptions, onPacket func(model.Packet) error, onProgress func(int)) error {
		compatCalls++
		if onProgress != nil {
			onProgress(1)
		}
		return onPacket(model.Packet{ID: 7, Protocol: "UDP", Info: "compat packet"})
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	if err := svc.LoadPCAP(context.Background(), model.ParseOptions{
		FilePath: "fake.pcap",
		FastList: true,
	}); err != nil {
		t.Fatalf("LoadPCAP() error = %v", err)
	}

	if ekCalls != 1 {
		t.Fatalf("expected ek parser to be called once, got %d", ekCalls)
	}
	if compatCalls != 1 {
		t.Fatalf("expected compat parser to be called once, got %d", compatCalls)
	}

	packets := svc.Packets()
	if len(packets) != 1 || packets[0].ID != 7 {
		t.Fatalf("expected compat fallback packet to be persisted, got %+v", packets)
	}
}

func TestLoadPCAPSkipsEstimateForLargeFastListCapture(t *testing.T) {
	oldEstimate := estimatePacketsFn
	oldFast := streamPacketsFastFn
	oldStream := streamPacketsFn
	oldCompat := streamPacketsCompatFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
		streamPacketsFastFn = oldFast
		streamPacketsFn = oldStream
		streamPacketsCompatFn = oldCompat
	})

	largeCapture := filepath.Join(t.TempDir(), "large.pcap")
	file, err := os.Create(largeCapture)
	if err != nil {
		t.Fatalf("create temp capture: %v", err)
	}
	if err := file.Truncate(skipEstimateFileSizeThreshold); err != nil {
		_ = file.Close()
		t.Fatalf("truncate temp capture: %v", err)
	}
	_ = file.Close()

	estimateCalled := false
	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		estimateCalled = true
		return 123, nil
	}

	streamPacketsFastFn = func(_ context.Context, _ model.ParseOptions, onPacket func(model.Packet) error, onProgress func(int)) error {
		if onProgress != nil {
			onProgress(1)
		}
		return onPacket(model.Packet{ID: 99, Protocol: "UDP", Info: "large fast_list packet"})
	}
	streamPacketsFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		t.Fatal("ek fallback should not be called in large fast_list estimate skip test")
		return nil
	}
	streamPacketsCompatFn = func(_ context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		t.Fatal("compat fallback should not be called in large fast_list estimate skip test")
		return nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	if err := svc.LoadPCAP(context.Background(), model.ParseOptions{
		FilePath: largeCapture,
		FastList: true,
	}); err != nil {
		t.Fatalf("LoadPCAP() error = %v", err)
	}

	if estimateCalled {
		t.Fatal("expected packet estimate to be skipped for large fast_list capture")
	}
	packets := svc.Packets()
	if len(packets) != 1 || packets[0].ID != 99 {
		t.Fatalf("expected streamed packet to be persisted, got %+v", packets)
	}
}
