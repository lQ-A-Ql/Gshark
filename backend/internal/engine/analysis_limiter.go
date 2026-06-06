package engine

import (
	"context"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

type analysisLimiter struct {
	mu            sync.Mutex
	maxWarmup     int
	activeWarmups int
	waiters       []*analysisLimiterWaiter
	now           func() time.Time
}

type analysisLimiterWaiter struct {
	ctx      context.Context
	normal   bool
	ready    chan struct{}
	canceled bool
}

type analysisLimiterRelease func()

type analysisLimiterAcquireResult struct {
	release    analysisLimiterRelease
	wait       time.Duration
	queueDepth int
}

func newAnalysisLimiter(maxWarmup int) *analysisLimiter {
	if maxWarmup <= 0 {
		maxWarmup = 1
	}
	return &analysisLimiter{maxWarmup: maxWarmup, now: time.Now}
}

func (l *analysisLimiter) acquire(ctx context.Context, normal bool) (analysisLimiterAcquireResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return analysisLimiterAcquireResult{}, err
	}
	if l == nil {
		return analysisLimiterAcquireResult{release: func() {}}, nil
	}
	start := l.now()
	waiter := &analysisLimiterWaiter{ctx: ctx, normal: normal, ready: make(chan struct{})}

	l.mu.Lock()
	if normal || l.canStartWarmupLocked(waiter) {
		if !normal {
			l.activeWarmups++
		}
		l.mu.Unlock()
		return analysisLimiterAcquireResult{release: l.releaseFn(normal), wait: 0}, nil
	}
	l.waiters = append(l.waiters, waiter)
	queueDepth := len(l.waiters)
	l.mu.Unlock()

	select {
	case <-waiter.ready:
		return analysisLimiterAcquireResult{release: l.releaseFn(normal), wait: l.now().Sub(start), queueDepth: queueDepth}, nil
	case <-ctx.Done():
		l.cancelWaiter(waiter)
		return analysisLimiterAcquireResult{}, ctx.Err()
	}
}

func (l *analysisLimiter) canStartWarmupLocked(waiter *analysisLimiterWaiter) bool {
	if l.activeWarmups >= l.maxWarmup {
		return false
	}
	for _, queued := range l.waiters {
		if queued == waiter {
			break
		}
		if !queued.canceled && queued.normal {
			return false
		}
	}
	return true
}

func (l *analysisLimiter) releaseFn(normal bool) analysisLimiterRelease {
	return func() {
		l.mu.Lock()
		if !normal && l.activeWarmups > 0 {
			l.activeWarmups--
		}
		l.drainLocked()
		l.mu.Unlock()
	}
}

func (l *analysisLimiter) cancelWaiter(waiter *analysisLimiterWaiter) {
	l.mu.Lock()
	waiter.canceled = true
	l.drainLocked()
	l.mu.Unlock()
}

func (l *analysisLimiter) drainLocked() {
	next := l.waiters[:0]
	for _, waiter := range l.waiters {
		if waiter.canceled || waiter.ctx.Err() != nil {
			continue
		}
		if waiter.normal {
			close(waiter.ready)
			continue
		}
		if l.canStartWarmupLocked(waiter) {
			l.activeWarmups++
			close(waiter.ready)
			continue
		}
		next = append(next, waiter)
	}
	l.waiters = next
}

func (s *Service) withLimitedAnalysis(ctx context.Context, target string, fn func(context.Context) error) error {
	if !analysisRequestIsWarmup(ctx) {
		startedAt := time.Now()
		err := fn(ctx)
		s.recordAnalysisTelemetry(ctx, target, 0, 0, time.Since(startedAt), err)
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	meta := servicecontract.AnalysisRequestMetaFromContext(ctx)
	meta.Target = target
	if meta.Priority == "" {
		meta.Priority = servicecontract.AnalysisRequestPriorityBackground
	}
	ctx = servicecontract.WithAnalysisRequestMeta(ctx, meta)
	waitStartedAt := time.Now()
	result, err := s.analysisLimiter.acquire(ctx, false)
	if err != nil {
		s.recordAnalysisTelemetry(ctx, target, 0, time.Since(waitStartedAt), 0, err)
		return err
	}
	defer result.release()
	startedAt := time.Now()
	err = fn(ctx)
	s.recordAnalysisTelemetry(ctx, target, result.queueDepth, result.wait, time.Since(startedAt), err)
	return err
}

func analysisRequestIsWarmup(ctx context.Context) bool {
	return servicecontract.IsAnalysisWarmup(ctx)
}

func limitedAnalysisValue[T any](s *Service, ctx context.Context, target string, fn func(context.Context) (T, error)) (T, error) {
	var out T
	err := s.withLimitedAnalysis(ctx, target, func(runCtx context.Context) error {
		var err error
		out, err = fn(runCtx)
		return err
	})
	return out, err
}
