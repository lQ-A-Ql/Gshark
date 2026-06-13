package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestHTTPStreamFileFallbackAndErrorBranches(t *testing.T) {
	previous := httpStreamFromFileFn
	t.Cleanup(func() {
		httpStreamFromFileFn = previous
	})

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	svc.captureCtl.pcap = "capture.pcapng"

	called := 0
	httpStreamFromFileFn = func(ctx context.Context, filePath string, streamID int64) (model.ReassembledStream, error) {
		called++
		if ctx == nil {
			t.Fatal("expected timeout context to be passed to file fallback")
		}
		if filePath != "capture.pcapng" || streamID != 12 {
			t.Fatalf("unexpected fallback args file=%q stream=%d", filePath, streamID)
		}
		return model.ReassembledStream{
			StreamID: streamID,
			Protocol: "HTTP",
			Request:  "GET /unit HTTP/1.1\r\n",
			Response: "HTTP/1.1 200 OK\r\n",
			Chunks: []model.StreamChunk{
				{PacketID: 1, Direction: "client", Body: "GET /unit HTTP/1.1\r\n"},
				{PacketID: 2, Direction: "server", Body: "HTTP/1.1 200 OK\r\n"},
			},
		}, nil
	}

	stream := svc.HTTPStream(nil, 12)
	if called != 1 {
		t.Fatalf("expected file fallback call, got %d", called)
	}
	if stream.Request == "" || stream.Response == "" {
		t.Fatalf("expected request/response from file fallback, got %+v", stream)
	}
	if stream.LoadMeta == nil || stream.LoadMeta.Source != "file" || !stream.LoadMeta.FileFallback {
		t.Fatalf("expected file fallback load meta, got %+v", stream.LoadMeta)
	}

	svcErr := NewService(NopEmitter{})
	defer svcErr.captureCtl.packetStore.Close()
	svcErr.captureCtl.pcap = "capture.pcapng"
	httpStreamFromFileFn = func(context.Context, string, int64) (model.ReassembledStream, error) {
		return model.ReassembledStream{}, errors.New("synthetic follow failure")
	}

	empty := svcErr.HTTPStream(context.Background(), 99)
	if empty.StreamID != 99 || empty.Protocol != "HTTP" || len(empty.Chunks) != 0 || empty.LoadMeta != nil {
		t.Fatalf("expected empty HTTP stream after file error, got %+v", empty)
	}
}

func TestRawStreamCacheIndexCancelAndFileErrorBranches(t *testing.T) {
	previous := rawStreamFromFileFn
	t.Cleanup(func() {
		rawStreamFromFileFn = previous
	})

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	cacheKey := streamCacheKey("TCP", 3)
	svc.streamCtl.streamCache[cacheKey] = model.ReassembledStream{
		StreamID: 3,
		Protocol: "TCP",
		Chunks:   []model.StreamChunk{{PacketID: 1, Direction: "client", Body: "old"}},
	}
	svc.streamCtl.streamOverrides[cacheKey] = map[int]string{0: "patched"}
	cached := svc.RawStream(context.Background(), " tcp ", 3)
	if len(cached.Chunks) != 1 || cached.Chunks[0].Body != "patched" {
		t.Fatalf("expected cached stream with override, got %+v", cached)
	}
	if cached.LoadMeta == nil || !cached.LoadMeta.CacheHit || cached.LoadMeta.Source != "cache" || cached.LoadMeta.OverrideCount != 1 {
		t.Fatalf("expected cache load meta with override count, got %+v", cached.LoadMeta)
	}

	indexKey := streamCacheKey("UDP", 4)
	svc.streamCtl.rawStreamIndex[indexKey] = model.ReassembledStream{
		StreamID: 4,
		Protocol: "UDP",
		Chunks:   []model.StreamChunk{{PacketID: 2, Direction: "server", Body: "aa"}},
	}
	indexed := svc.RawStream(context.Background(), "udp", 4)
	if len(indexed.Chunks) != 1 || indexed.LoadMeta == nil || !indexed.LoadMeta.IndexHit || indexed.LoadMeta.Source != "index" {
		t.Fatalf("expected indexed raw stream, got %+v", indexed)
	}
	if _, ok := svc.streamCtl.streamCache[indexKey]; !ok {
		t.Fatalf("expected indexed stream to be cached")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := svc.RawStream(ctx, "tcp", 5)
	if canceled.StreamID != 5 || canceled.Protocol != "TCP" || len(canceled.Chunks) != 0 {
		t.Fatalf("expected empty canceled raw stream, got %+v", canceled)
	}

	svcErr := NewService(NopEmitter{})
	defer svcErr.captureCtl.packetStore.Close()
	svcErr.captureCtl.pcap = "capture.pcapng"
	rawStreamFromFileFn = func(context.Context, string, string, int64) (model.ReassembledStream, error) {
		return model.ReassembledStream{}, errors.New("synthetic raw follow failure")
	}
	empty := svcErr.RawStream(context.Background(), "tcp", 8)
	if empty.StreamID != 8 || empty.Protocol != "TCP" || len(empty.Chunks) != 0 || empty.LoadMeta != nil {
		t.Fatalf("expected empty raw stream after file error, got %+v", empty)
	}
}

func TestRawStreamPageFallbackAndEmptyPatchBranches(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	rawKey := streamCacheKey("TCP", 11)
	svc.streamCtl.streamCache[rawKey] = model.ReassembledStream{
		StreamID: 11,
		Protocol: "TCP",
		Chunks: []model.StreamChunk{
			{PacketID: 1, Direction: "client", Body: "aa"},
			{PacketID: 2, Direction: "server", Body: "bb"},
		},
	}
	page, next, total := svc.RawStreamPage(nil, "tcp", 11, -5, 0)
	if total != 2 || next != 2 || len(page.Chunks) != 2 {
		t.Fatalf("unexpected RawStreamPage fallback result stream=%+v next=%d total=%d", page, next, total)
	}
	if page.LoadMeta == nil || page.LoadMeta.Source != "cache" || !page.LoadMeta.CacheHit {
		t.Fatalf("expected fallback page load meta from RawStream cache, got %+v", page.LoadMeta)
	}

	httpKey := streamCacheKey("HTTP", 12)
	svc.streamCtl.streamCache[httpKey] = model.ReassembledStream{
		StreamID: 12,
		Protocol: "HTTP",
		Chunks: []model.StreamChunk{
			{PacketID: 3, Direction: "client", Body: "GET / HTTP/1.1\r\n"},
		},
		Request: "GET / HTTP/1.1\r\n",
	}
	httpStream, err := svc.UpdateStreamPayloads(context.Background(), "http", 12, nil)
	if err != nil {
		t.Fatalf("UpdateStreamPayloads HTTP empty patches error = %v", err)
	}
	if httpStream.LoadMeta == nil || !httpStream.LoadMeta.CacheHit || httpStream.StreamID != 12 {
		t.Fatalf("expected HTTP cache stream for empty patches, got %+v", httpStream)
	}

	rawStream, err := svc.UpdateStreamPayloads(context.Background(), "tcp", 11, nil)
	if err != nil {
		t.Fatalf("UpdateStreamPayloads TCP empty patches error = %v", err)
	}
	if rawStream.LoadMeta == nil || !rawStream.LoadMeta.CacheHit || rawStream.StreamID != 11 {
		t.Fatalf("expected raw cache stream for empty patches, got %+v", rawStream)
	}
}

func TestStreamMetaAndOverrideHelperBranches(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	svc.applyOverrideCountToMeta("missing", nil)

	stream := applyChunkOverrides(model.ReassembledStream{
		StreamID: 1,
		Protocol: "TCP",
		Chunks:   []model.StreamChunk{{PacketID: 1, Direction: "client", Body: "old"}},
	}, map[int]string{-1: "ignored", 5: "ignored"})
	if stream.Chunks[0].Body != "old" {
		t.Fatalf("out-of-range overrides should be ignored, got %+v", stream)
	}

	var nilHTTP *model.ReassembledStream
	rebuildHTTPStreamBodies(nilHTTP)
	emptyHTTP := &model.ReassembledStream{Protocol: "HTTP"}
	rebuildHTTPStreamBodies(emptyHTTP)
	if emptyHTTP.Request != "" || emptyHTTP.Response != "" {
		t.Fatalf("empty HTTP rebuild should leave bodies blank, got %+v", emptyHTTP)
	}

	meta := newStreamLoadMeta("file", false, false, true, 5*time.Millisecond)
	if meta.TSharkMS <= 0 || meta.Source != "file" || !meta.FileFallback {
		t.Fatalf("expected elapsed load meta, got %+v", meta)
	}
}
