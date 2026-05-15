package engine

import (
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestCacheStreamStoresClone(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	stream := model.ReassembledStream{
		StreamID: 7,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{Body: "original"},
		},
		LoadMeta: &model.StreamLoadMeta{Source: "unit"},
	}
	svc.cacheStream(streamCacheKey("TCP", 7), stream)
	stream.Chunks[0].Body = "mutated"
	stream.LoadMeta.Source = "mutated"

	cached := svc.streamCache[streamCacheKey("TCP", 7)]
	if cached.Chunks[0].Body != "original" {
		t.Fatalf("cached chunk body = %q, want original", cached.Chunks[0].Body)
	}
	if cached.LoadMeta == nil || cached.LoadMeta.Source != "unit" {
		t.Fatalf("cached load meta = %+v, want cloned unit source", cached.LoadMeta)
	}
}

func TestCacheStreamEvictsOldestBeyondLimit(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	limit := streamCacheLimitValue()
	for i := 0; i < limit+1; i++ {
		svc.cacheStream(streamCacheKey("TCP", int64(i)), model.ReassembledStream{StreamID: int64(i), Protocol: "TCP"})
	}

	if len(svc.streamCache) != limit {
		t.Fatalf("stream cache size = %d, want %d", len(svc.streamCache), limit)
	}
	if _, ok := svc.streamCache[streamCacheKey("TCP", 0)]; ok {
		t.Fatal("expected oldest stream cache entry to be evicted")
	}
	lastKey := streamCacheKey("TCP", int64(limit))
	if _, ok := svc.streamCache[lastKey]; !ok {
		t.Fatalf("expected newest stream cache entry %q to remain", lastKey)
	}
}

func TestCacheStreamRefreshesExistingOrder(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	limit := streamCacheLimitValue()
	for i := 0; i < limit; i++ {
		svc.cacheStream(streamCacheKey("TCP", int64(i)), model.ReassembledStream{StreamID: int64(i), Protocol: "TCP"})
	}
	svc.cacheStream(streamCacheKey("TCP", 0), model.ReassembledStream{StreamID: 0, Protocol: "TCP"})
	svc.cacheStream(streamCacheKey("TCP", int64(limit)), model.ReassembledStream{StreamID: int64(limit), Protocol: "TCP"})

	if _, ok := svc.streamCache[streamCacheKey("TCP", 0)]; !ok {
		t.Fatal("expected refreshed stream cache entry to remain")
	}
	if _, ok := svc.streamCache[streamCacheKey("TCP", 1)]; ok {
		t.Fatal("expected next-oldest stream cache entry to be evicted")
	}
	if got := len(svc.streamCacheOrder); got != limit {
		t.Fatalf("stream cache order size = %d, want %d", got, limit)
	}
}

func TestStreamWithOverridesUsesClones(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	key := streamCacheKey("TCP", 42)
	svc.streamOverrides[key] = map[int]string{0: "patched"}
	original := model.ReassembledStream{
		StreamID: 42,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{Body: "original"},
		},
	}

	patched := svc.streamWithOverrides(key, original)
	if patched.Chunks[0].Body != "patched" {
		t.Fatalf("patched body = %q, want patched", patched.Chunks[0].Body)
	}
	if original.Chunks[0].Body != "original" {
		t.Fatalf("original body mutated to %q", original.Chunks[0].Body)
	}
}

func BenchmarkStreamCacheKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = streamCacheKey("TCP", int64(i%1024))
	}
}

func Example_streamCacheKey() {
	fmt.Println(streamCacheKey("TCP", 7))
	// Output: TCP:7
}
