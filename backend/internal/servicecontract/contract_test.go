package servicecontract

import (
	"context"
	"testing"
)

func TestWithAnalysisRequestMetaDefaultsNilContext(t *testing.T) {
	ctx := WithAnalysisRequestMeta(nil, AnalysisRequestMeta{})

	meta := AnalysisRequestMetaFromContext(ctx)
	if meta.Source != AnalysisRequestSourceUser {
		t.Fatalf("Source = %q, want %q", meta.Source, AnalysisRequestSourceUser)
	}
	if meta.Priority != AnalysisRequestPriorityNormal {
		t.Fatalf("Priority = %q, want %q", meta.Priority, AnalysisRequestPriorityNormal)
	}
}

func TestAnalysisRequestMetaFromContextDefaultsNilAndMissing(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil", ctx: nil},
		{name: "missing", ctx: context.Background()},
		{name: "empty fields", ctx: context.WithValue(context.Background(), analysisRequestMetaKey{}, AnalysisRequestMeta{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := AnalysisRequestMetaFromContext(tt.ctx)
			if meta.Source != AnalysisRequestSourceUser || meta.Priority != AnalysisRequestPriorityNormal {
				t.Fatalf("meta = %+v, want default user/normal", meta)
			}
		})
	}
}

func TestIsAnalysisWarmupOnlyForWarmupSource(t *testing.T) {
	warmup := WithAnalysisRequestMeta(context.Background(), AnalysisRequestMeta{
		Source:   AnalysisRequestSourceWarmup,
		Priority: AnalysisRequestPriorityBackground,
		Target:   "c2",
	})
	if !IsAnalysisWarmup(warmup) {
		t.Fatal("IsAnalysisWarmup(warmup) = false, want true")
	}

	user := WithAnalysisRequestMeta(context.Background(), AnalysisRequestMeta{
		Source:   AnalysisRequestSourceUser,
		Priority: AnalysisRequestPriorityNormal,
	})
	if IsAnalysisWarmup(user) {
		t.Fatal("IsAnalysisWarmup(user) = true, want false")
	}
	if IsAnalysisWarmup(nil) {
		t.Fatal("IsAnalysisWarmup(nil) = true, want false")
	}
}
