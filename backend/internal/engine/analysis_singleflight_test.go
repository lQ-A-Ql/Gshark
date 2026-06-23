package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/servicecontract"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func TestGlobalTrafficStatsSingleflightCoalescesColdRequests(t *testing.T) {
	oldBuilder := buildGlobalTrafficStatsFromFileFn
	t.Cleanup(func() { buildGlobalTrafficStatsFromFileFn = oldBuilder })

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildGlobalTrafficStatsFromFileFn = func(filePath string) (model.GlobalTrafficStats, error) {
		if got := filePath; got != "capture.pcapng" {
			t.Fatalf("builder filePath = %q", got)
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.GlobalTrafficStats{TotalPackets: 7}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	errs := runConcurrentAnalysisRequests(4, func() error {
		stats, err := svc.GlobalTrafficStatsWithContext(context.Background())
		if err != nil {
			return err
		}
		if stats.TotalPackets != 7 {
			return errors.New("unexpected global traffic stats result")
		}
		return nil
	})

	waitForSingleflightStart(t, started, &calls)
	close(release)
	assertNoConcurrentErrors(t, errs, 4)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one global traffic stats builder call, got %d", got)
	}
}

func TestIndustrialAnalysisSingleflightCoalescesColdRequests(t *testing.T) {
	oldBuilder := buildIndustrialAnalysisFromFileFn
	oldWarmer := warmSpecializedFieldCacheFn
	t.Cleanup(func() {
		buildIndustrialAnalysisFromFileFn = oldBuilder
		warmSpecializedFieldCacheFn = oldWarmer
	})
	warmSpecializedFieldCacheFn = func(context.Context, string) error { return nil }

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildIndustrialAnalysisFromFileFn = func(filePath string) (model.IndustrialAnalysis, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.IndustrialAnalysis{TotalIndustrialPackets: 3}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	errs := runConcurrentAnalysisRequests(4, func() error {
		analysis, err := svc.IndustrialAnalysisWithContext(context.Background())
		if err != nil {
			return err
		}
		if analysis.TotalIndustrialPackets != 3 {
			return errors.New("unexpected industrial analysis result")
		}
		return nil
	})

	waitForSingleflightStart(t, started, &calls)
	close(release)
	assertNoConcurrentErrors(t, errs, 4)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one industrial builder call, got %d", got)
	}
}

func TestVehicleAnalysisSingleflightCoalescesColdRequests(t *testing.T) {
	oldBuilder := buildVehicleAnalysisFromFileFn
	oldWarmer := warmSpecializedFieldCacheFn
	t.Cleanup(func() {
		buildVehicleAnalysisFromFileFn = oldBuilder
		warmSpecializedFieldCacheFn = oldWarmer
	})
	warmSpecializedFieldCacheFn = func(context.Context, string) error { return nil }

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildVehicleAnalysisFromFileFn = func(filePath string, databases ...*tshark.DBCDatabase) (model.VehicleAnalysis, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.VehicleAnalysis{TotalVehiclePackets: 5}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	errs := runConcurrentAnalysisRequests(4, func() error {
		analysis, err := svc.VehicleAnalysisWithContext(context.Background())
		if err != nil {
			return err
		}
		if analysis.TotalVehiclePackets != 5 {
			return errors.New("unexpected vehicle analysis result")
		}
		return nil
	})

	waitForSingleflightStart(t, started, &calls)
	close(release)
	assertNoConcurrentErrors(t, errs, 4)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one vehicle builder call, got %d", got)
	}
}

func TestMediaAnalysisSingleflightCoalescesNonForceColdRequests(t *testing.T) {
	oldFileBuilder := buildMediaAnalysisFromFileWithConfigFn
	oldPacketBuilder := buildMediaAnalysisFromPacketStreamFn
	t.Cleanup(func() {
		buildMediaAnalysisFromFileWithConfigFn = oldFileBuilder
		buildMediaAnalysisFromPacketStreamFn = oldPacketBuilder
	})

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildMediaAnalysisFromPacketStreamFn = func(context.Context, string, int, tshark.MediaScanConfig, func(int, int, string), func(func(model.Packet) error) error) (model.MediaAnalysis, map[string]string, error) {
		return model.MediaAnalysis{}, nil, nil
	}
	buildMediaAnalysisFromFileWithConfigFn = func(context.Context, string, string, tshark.MediaScanConfig, func(int, int, string)) (model.MediaAnalysis, map[string]string, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.MediaAnalysis{TotalMediaPackets: 11}, map[string]string{}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	errs := runConcurrentAnalysisRequests(4, func() error {
		analysis, err := svc.MediaAnalysis()
		if err != nil {
			return err
		}
		if analysis.TotalMediaPackets != 11 {
			return errors.New("unexpected media analysis result")
		}
		return nil
	})

	waitForSingleflightStart(t, started, &calls)
	close(release)
	assertNoConcurrentErrors(t, errs, 4)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one media builder call, got %d", got)
	}
}

func TestC2SampleAnalysisSingleflightCoalescesColdRequests(t *testing.T) {
	oldBuilder := buildC2SampleAnalysisFromPacketsFn
	t.Cleanup(func() { buildC2SampleAnalysisFromPacketsFn = oldBuilder })

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildC2SampleAnalysisFromPacketsFn = func(context.Context, []model.Packet) (model.C2SampleAnalysis, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.C2SampleAnalysis{TotalMatchedPackets: 13}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	errs := runConcurrentAnalysisRequests(4, func() error {
		analysis, err := svc.C2SampleAnalysis(context.Background())
		if err != nil {
			return err
		}
		if analysis.TotalMatchedPackets != 13 {
			return errors.New("unexpected C2 analysis result")
		}
		return nil
	})

	waitForSingleflightStart(t, started, &calls)
	close(release)
	assertNoConcurrentErrors(t, errs, 4)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one C2 builder call, got %d", got)
	}
}

func TestWarmupAndUserAnalysisShareNormalSingleflightBuilder(t *testing.T) {
	oldBuilder := buildC2SampleAnalysisFromPacketsFn
	t.Cleanup(func() { buildC2SampleAnalysisFromPacketsFn = oldBuilder })

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildC2SampleAnalysisFromPacketsFn = func(context.Context, []model.Packet) (model.C2SampleAnalysis, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.C2SampleAnalysis{TotalMatchedPackets: 23}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	userErr := make(chan error, 1)
	go func() {
		analysis, err := svc.C2SampleAnalysis(context.Background())
		if err == nil && analysis.TotalMatchedPackets != 23 {
			err = errors.New("unexpected user C2 analysis result")
		}
		userErr <- err
	}()
	waitForSingleflightStart(t, started, &calls)

	warmupCtx := servicecontract.WithAnalysisRequestMeta(context.Background(), servicecontract.AnalysisRequestMeta{
		Source:   servicecontract.AnalysisRequestSourceWarmup,
		Priority: servicecontract.AnalysisRequestPriorityBackground,
		Target:   "c2",
	})
	warmupErr := make(chan error, 1)
	go func() {
		analysis, err := svc.C2SampleAnalysis(warmupCtx)
		if err == nil && analysis.TotalMatchedPackets != 23 {
			err = errors.New("unexpected warmup C2 analysis result")
		}
		warmupErr <- err
	}()
	time.Sleep(25 * time.Millisecond)

	close(release)
	if err := <-userErr; err != nil {
		t.Fatalf("user analysis error = %v", err)
	}
	if err := <-warmupErr; err != nil {
		t.Fatalf("warmup analysis error = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected user and warmup to share one builder, got %d calls", got)
	}
}

func TestAnalysisSingleflightCanceledWaiterDoesNotCancelSharedBuilder(t *testing.T) {
	oldBuilder := buildGlobalTrafficStatsFromFileFn
	t.Cleanup(func() { buildGlobalTrafficStatsFromFileFn = oldBuilder })

	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	buildGlobalTrafficStatsFromFileFn = func(string) (model.GlobalTrafficStats, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
		}
		<-release
		return model.GlobalTrafficStats{TotalPackets: 17}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	firstErr := make(chan error, 1)
	go func() {
		_, err := svc.GlobalTrafficStatsWithContext(context.Background())
		firstErr <- err
	}()
	waitForSingleflightStart(t, started, &calls)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.GlobalTrafficStatsWithContext(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled waiter to return context.Canceled, got %v", err)
	}
	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("shared builder owner error = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected canceled waiter not to start another builder, got %d", got)
	}
}

func TestAnalysisSingleflightFailureDoesNotPoisonCache(t *testing.T) {
	oldBuilder := buildGlobalTrafficStatsFromFileFn
	t.Cleanup(func() { buildGlobalTrafficStatsFromFileFn = oldBuilder })

	var calls int32
	buildGlobalTrafficStatsFromFileFn = func(string) (model.GlobalTrafficStats, error) {
		call := atomic.AddInt32(&calls, 1)
		if call == 1 {
			return model.GlobalTrafficStats{}, errors.New("boom")
		}
		return model.GlobalTrafficStats{TotalPackets: 19}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	if _, err := svc.GlobalTrafficStatsWithContext(context.Background()); err == nil {
		t.Fatal("expected first builder error")
	}
	stats, err := svc.GlobalTrafficStatsWithContext(context.Background())
	if err != nil {
		t.Fatalf("retry GlobalTrafficStatsWithContext() error = %v", err)
	}
	if stats.TotalPackets != 19 {
		t.Fatalf("retry stats TotalPackets = %d", stats.TotalPackets)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected retry after failure, got %d calls", got)
	}
}

func runConcurrentAnalysisRequests(n int, fn func() error) <-chan error {
	errs := make(chan error, n)
	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			ready.Done()
			<-start
			errs <- fn()
		}()
	}
	ready.Wait()
	close(start)
	return errs
}

func waitForSingleflightStart(t *testing.T, started <-chan struct{}, calls *int32) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatalf("expected builder to start, calls=%d", atomic.LoadInt32(calls))
	}
	time.Sleep(25 * time.Millisecond)
}

func assertNoConcurrentErrors(t *testing.T, errs <-chan error, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("request %d error = %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for request %d", i)
		}
	}
}
