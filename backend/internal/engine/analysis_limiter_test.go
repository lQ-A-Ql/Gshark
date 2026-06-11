package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

func TestAnalysisLimiterLimitsWarmups(t *testing.T) {
	limiter := newAnalysisLimiter(1)
	ctx := context.Background()
	releaseFirst := make(chan struct{})
	firstStarted := make(chan struct{})
	var active int32
	var maxActive int32

	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			result, err := limiter.acquire(ctx, false)
			if err != nil {
				errs <- err
				return
			}
			cur := atomic.AddInt32(&active, 1)
			for {
				seen := atomic.LoadInt32(&maxActive)
				if cur <= seen || atomic.CompareAndSwapInt32(&maxActive, seen, cur) {
					break
				}
			}
			select {
			case <-firstStarted:
			default:
				close(firstStarted)
			}
			<-releaseFirst
			atomic.AddInt32(&active, -1)
			result.release()
			errs <- nil
		}()
	}

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first warmup did not start")
	}
	time.Sleep(25 * time.Millisecond)
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("max active warmups = %d, want 1", got)
	}
	close(releaseFirst)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("warmup %d error = %v", i, err)
		}
	}
}

func TestAnalysisLimiterCanceledWaiterReleasesQueue(t *testing.T) {
	limiter := newAnalysisLimiter(1)
	first, err := limiter.acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := limiter.acquire(ctx, false)
		errCh <- err
	}()
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter err = %v", err)
	}

	first.release()
	second, err := limiter.acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("second acquire after canceled waiter: %v", err)
	}
	second.release()
}

func TestAnalysisLimiterCancelWaiterDropsCanceledAndDrainsNormal(t *testing.T) {
	limiter := newAnalysisLimiter(1)
	limiter.mu.Lock()
	blockedWarmup := &analysisLimiterWaiter{ctx: context.Background(), ready: make(chan struct{})}
	normalWaiter := &analysisLimiterWaiter{ctx: context.Background(), normal: true, ready: make(chan struct{})}
	limiter.waiters = []*analysisLimiterWaiter{blockedWarmup, normalWaiter}
	limiter.mu.Unlock()

	limiter.cancelWaiter(blockedWarmup)

	select {
	case <-normalWaiter.ready:
	default:
		t.Fatal("normal waiter was not drained after canceling blocked warmup")
	}
	if !blockedWarmup.canceled {
		t.Fatal("blocked warmup waiter was not marked canceled")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.waiters) != 0 {
		t.Fatalf("waiters left after drain: %+v", limiter.waiters)
	}
}

func TestAnalysisLimiterNormalBypassesWarmupQueue(t *testing.T) {
	limiter := newAnalysisLimiter(1)
	first, err := limiter.acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("first warmup acquire: %v", err)
	}

	warmupStarted := make(chan struct{})
	go func() {
		result, err := limiter.acquire(context.Background(), false)
		if err == nil {
			close(warmupStarted)
			result.release()
		}
	}()
	time.Sleep(25 * time.Millisecond)

	normal, err := limiter.acquire(context.Background(), true)
	if err != nil {
		t.Fatalf("normal acquire: %v", err)
	}
	normal.release()
	select {
	case <-warmupStarted:
		t.Fatal("queued warmup started before first slot was released")
	default:
	}
	first.release()
	select {
	case <-warmupStarted:
	case <-time.After(time.Second):
		t.Fatal("queued warmup did not start after release")
	}
}

func TestC2WarmupUsesLimiterAndPropagatesContext(t *testing.T) {
	oldBuilder := buildC2SampleAnalysisFromPacketsFn
	t.Cleanup(func() { buildC2SampleAnalysisFromPacketsFn = oldBuilder })

	var seenWarmup int32
	buildC2SampleAnalysisFromPacketsFn = func(ctx context.Context, _ []model.Packet) (model.C2SampleAnalysis, error) {
		if servicecontract.IsAnalysisWarmup(ctx) {
			atomic.StoreInt32(&seenWarmup, 1)
		}
		if err := ctx.Err(); err != nil {
			return model.C2SampleAnalysis{}, err
		}
		return model.C2SampleAnalysis{TotalMatchedPackets: 1}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	ctx := servicecontract.WithAnalysisRequestMeta(context.Background(), servicecontract.AnalysisRequestMeta{
		Source:   servicecontract.AnalysisRequestSourceWarmup,
		Priority: servicecontract.AnalysisRequestPriorityBackground,
		Target:   "c2",
	})
	analysis, err := svc.C2SampleAnalysis(ctx)
	if err != nil {
		t.Fatalf("C2SampleAnalysis warmup error = %v", err)
	}
	if analysis.TotalMatchedPackets != 1 {
		t.Fatalf("TotalMatchedPackets = %d", analysis.TotalMatchedPackets)
	}
	if atomic.LoadInt32(&seenWarmup) != 1 {
		t.Fatal("builder did not receive warmup meta")
	}
}

func TestWarmupTelemetryRecordsStatusAndMetrics(t *testing.T) {
	oldBuilder := buildC2SampleAnalysisFromPacketsFn
	t.Cleanup(func() { buildC2SampleAnalysisFromPacketsFn = oldBuilder })

	buildC2SampleAnalysisFromPacketsFn = func(context.Context, []model.Packet) (model.C2SampleAnalysis, error) {
		return model.C2SampleAnalysis{TotalMatchedPackets: 2}, nil
	}

	emitter := &recordingAnalysisEmitter{}
	svc := NewService(emitter)
	defer svc.packetStore.Close()
	svc.pcap = "capture.pcapng"

	ctx := servicecontract.WithAnalysisRequestMeta(context.Background(), servicecontract.AnalysisRequestMeta{
		Source:   servicecontract.AnalysisRequestSourceWarmup,
		Priority: servicecontract.AnalysisRequestPriorityBackground,
		Target:   "c2",
	})
	if _, err := svc.C2SampleAnalysis(ctx); err != nil {
		t.Fatalf("C2SampleAnalysis warmup error = %v", err)
	}

	if !emitter.hasStatusPrefix("__analysis_warmup__:c2:") {
		t.Fatalf("expected warmup telemetry status, got %#v", emitter.statuses)
	}
	snapshot := svc.analysisMetrics.snapshot()
	if snapshot.WarmupFulfilled != 1 {
		t.Fatalf("WarmupFulfilled = %d, want 1", snapshot.WarmupFulfilled)
	}
}

type recordingAnalysisEmitter struct {
	statuses []string
}

func (e *recordingAnalysisEmitter) EmitPacket(model.Packet) {}
func (e *recordingAnalysisEmitter) EmitError(string)        {}
func (e *recordingAnalysisEmitter) EmitStatus(status string) {
	e.statuses = append(e.statuses, status)
}

func (e *recordingAnalysisEmitter) hasStatusPrefix(prefix string) bool {
	for _, status := range e.statuses {
		if strings.HasPrefix(status, prefix) {
			return true
		}
	}
	return false
}
