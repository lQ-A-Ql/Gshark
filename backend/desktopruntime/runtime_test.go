package desktopruntime

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDoRawReturnsWhenContextExpires(t *testing.T) {
	rt := NewWithHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := rt.DoRaw(ctx, http.MethodGet, "/api/slow", nil, "", 0)
	if err == nil {
		t.Fatal("expected context timeout error")
	}
	if !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("DoRaw returned after %s, want context deadline to short-circuit", elapsed)
	}
}
