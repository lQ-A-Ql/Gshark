package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

type analysisMetrics struct {
	mu sync.Mutex

	warmupQueueDepthMax int
	warmupWaitMs        []int64
	warmupDurationMs    []int64
	normalDurationMs    []int64

	warmupFulfilled int
	warmupCanceled  int
	warmupTimeouts  int
	warmupFailed    int
}

type analysisMetricsSnapshot struct {
	WarmupQueueDepthMax int
	WarmupWaitP95Ms     int64
	WarmupDurationP95Ms int64
	WarmupFulfilled     int
	WarmupCanceled      int
	WarmupTimeouts      int
	WarmupFailed        int
	NormalP95Ms         int64
}

func newAnalysisMetrics() *analysisMetrics {
	return &analysisMetrics{}
}

func (ctl *analysisController) recordMetric(sample analysisMetricSample) {
	if ctl == nil {
		return
	}
	ctl.analysisMetrics.record(sample)
}

func (m *analysisMetrics) record(sample analysisMetricSample) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if sample.Source == servicecontract.AnalysisRequestSourceWarmup {
		if sample.QueueDepth > m.warmupQueueDepthMax {
			m.warmupQueueDepthMax = sample.QueueDepth
		}
		m.warmupWaitMs = appendCappedInt64(m.warmupWaitMs, sample.WaitMs, 256)
		m.warmupDurationMs = appendCappedInt64(m.warmupDurationMs, sample.DurationMs, 256)
		switch sample.Status {
		case "ok":
			m.warmupFulfilled++
		case "timeout":
			m.warmupTimeouts++
		case "canceled":
			m.warmupCanceled++
		default:
			m.warmupFailed++
		}
		return
	}

	m.normalDurationMs = appendCappedInt64(m.normalDurationMs, sample.DurationMs, 256)
}

func (m *analysisMetrics) snapshot() analysisMetricsSnapshot {
	if m == nil {
		return analysisMetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	return analysisMetricsSnapshot{
		WarmupQueueDepthMax: m.warmupQueueDepthMax,
		WarmupWaitP95Ms:     percentileInt64(m.warmupWaitMs, 95),
		WarmupDurationP95Ms: percentileInt64(m.warmupDurationMs, 95),
		WarmupFulfilled:     m.warmupFulfilled,
		WarmupCanceled:      m.warmupCanceled,
		WarmupTimeouts:      m.warmupTimeouts,
		WarmupFailed:        m.warmupFailed,
		NormalP95Ms:         percentileInt64(m.normalDurationMs, 95),
	}
}

type analysisMetricSample struct {
	Source     servicecontract.AnalysisRequestSource
	Target     string
	QueueDepth int
	WaitMs     int64
	DurationMs int64
	Status     string
}

func (s *Service) recordAnalysisTelemetry(ctx context.Context, target string, queueDepth int, wait, duration time.Duration, err error) {
	meta := servicecontract.AnalysisRequestMetaFromContext(ctx)
	status := analysisStatusFromError(ctx, err)
	sample := analysisMetricSample{
		Source:     meta.Source,
		Target:     target,
		QueueDepth: queueDepth,
		WaitMs:     durationMilliseconds(wait),
		DurationMs: durationMilliseconds(duration),
		Status:     status,
	}
	if s != nil {
		s.analysisCtl.recordMetric(sample)
		s.emitAnalysisTelemetry(sample)
	}
}

func (s *Service) emitAnalysisTelemetry(sample analysisMetricSample) {
	if s == nil {
		return
	}
	if sample.Source == servicecontract.AnalysisRequestSourceWarmup {
		s.emitStatus(fmt.Sprintf(
			"__analysis_warmup__:%s:%d:%d:%d:%s",
			sample.Target,
			sample.QueueDepth,
			sample.WaitMs,
			sample.DurationMs,
			sample.Status,
		))
		return
	}
	s.emitStatus(fmt.Sprintf("__analysis_request__:%s:%d:%s", sample.Target, sample.DurationMs, sample.Status))
}

func analysisStatusFromError(ctx context.Context, err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) {
		return "canceled"
	}
	return "error"
}

func durationMilliseconds(duration time.Duration) int64 {
	ms := duration.Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

func appendCappedInt64(values []int64, value int64, limit int) []int64 {
	if value < 0 {
		value = 0
	}
	values = append(values, value)
	if len(values) <= limit {
		return values
	}
	return values[len(values)-limit:]
}

func percentileInt64(values []int64, percentile int) int64 {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]int64(nil), values...)
	sortInt64s(ordered)
	if percentile <= 0 {
		return ordered[0]
	}
	if percentile >= 100 {
		return ordered[len(ordered)-1]
	}
	idx := (len(ordered)*percentile + 99) / 100
	if idx <= 0 {
		idx = 1
	}
	if idx > len(ordered) {
		idx = len(ordered)
	}
	return ordered[idx-1]
}

func sortInt64s(values []int64) {
	for i := 1; i < len(values); i++ {
		current := values[i]
		j := i - 1
		for j >= 0 && values[j] > current {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = current
	}
}
