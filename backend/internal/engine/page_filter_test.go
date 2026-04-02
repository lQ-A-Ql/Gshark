package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestPacketStorePageRespectsFilter(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	packets := []model.Packet{
		{ID: 1, Protocol: "TCP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", SourcePort: 1200, DestPort: 443, Length: 90, Info: "Client Hello"},
		{ID: 2, Protocol: "HTTP", SourceIP: "10.0.0.3", DestIP: "10.0.0.4", SourcePort: 50123, DestPort: 80, Length: 512, Info: "POST /login", Payload: "username=alice", StreamID: 4},
		{ID: 3, Protocol: "HTTP", SourceIP: "10.0.0.5", DestIP: "10.0.0.6", SourcePort: 50124, DestPort: 8080, Length: 640, Info: "GET /health", StreamID: 5},
		{ID: 4, Protocol: "UDP", SourceIP: "10.0.0.7", DestIP: "10.0.0.8", SourcePort: 53000, DestPort: 53, Length: 88, Info: "DNS Standard query"},
	}
	if err := store.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	page, next, total, err := store.Page(0, 1, compilePacketFilter(`http and http.request.method == POST`))
	if err != nil {
		t.Fatalf("Page() error = %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 filtered packet, got %d", total)
	}
	if next != 1 {
		t.Fatalf("expected next cursor 1, got %d", next)
	}
	if len(page) != 1 || page[0].ID != 2 {
		t.Fatalf("expected packet #2, got %+v", page)
	}
}

func TestPacketPageCursorUsesFilteredIndex(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	if err := store.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", Info: "GET /index", DestPort: 80},
		{ID: 2, Protocol: "HTTP", Info: "GET /status", DestPort: 80},
		{ID: 3, Protocol: "TCP", Info: "TLS handshake", DestPort: 443},
		{ID: 4, Protocol: "HTTP", Info: "POST /upload", DestPort: 80},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	svc := &Service{packetStore: store}
	cursor, total, found := svc.PacketPageCursor(4, 2, "http")
	if !found {
		t.Fatal("expected packet #4 to be found in filtered results")
	}
	if total != 3 {
		t.Fatalf("expected 3 filtered packets, got %d", total)
	}
	if cursor != 2 {
		t.Fatalf("expected cursor 2 for packet #4, got %d", cursor)
	}
}

func TestThreatHuntStreamsFromPacketStore(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	packets := []model.Packet{
		{ID: 1, Protocol: "HTTP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", DestPort: 9999, Info: "GET /flag", Payload: "flag{demo}"},
		{ID: 2, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 3, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 4, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 5, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 6, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 7, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 8, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
		{ID: 9, Protocol: "HTTP", SourceIP: "198.51.100.10", DestIP: "10.0.0.2", DestPort: 80, Info: "HTTP 404 Not Found"},
	}
	if err := store.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	svc := &Service{packetStore: store}
	hits := svc.ThreatHunt([]string{"flag{"})
	if len(hits) < 2 {
		t.Fatalf("expected streamed hunt hits, got %+v", hits)
	}
	if hits[0].PacketID != 1 {
		t.Fatalf("expected first hit to point at packet #1, got %+v", hits[0])
	}
	if hits[1].PacketID != 0 {
		t.Fatalf("expected anomaly hit aggregated at capture level, got %+v", hits[1])
	}
}

func TestPacketsPageUsesTSharkDisplayFilterCache(t *testing.T) {
	oldFilter := filterFrameIDsFn
	t.Cleanup(func() {
		filterFrameIDsFn = oldFilter
	})

	filterCalls := 0
	filterFrameIDsFn = func(_ context.Context, opts model.ParseOptions) ([]int64, error) {
		filterCalls++
		if opts.FilePath != "demo.pcap" {
			t.Fatalf("unexpected file path: %q", opts.FilePath)
		}
		if opts.DisplayFilter != "tcp.port == 443" {
			t.Fatalf("unexpected display filter: %q", opts.DisplayFilter)
		}
		return []int64{2, 4}, nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "TCP", DestPort: 80, Info: "HTTP"},
		{ID: 2, Protocol: "TLS", DestPort: 443, Info: "Client Hello"},
		{ID: 3, Protocol: "UDP", DestPort: 53, Info: "DNS"},
		{ID: 4, Protocol: "TLS", DestPort: 443, Info: "Application Data"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	page, next, total := svc.PacketsPage(0, 1, "tcp.port == 443")
	if total != 2 {
		t.Fatalf("expected 2 filtered packets, got %d", total)
	}
	if next != 1 {
		t.Fatalf("expected next cursor 1, got %d", next)
	}
	if len(page) != 1 || page[0].ID != 2 {
		t.Fatalf("expected packet #2, got %+v", page)
	}

	page, next, total = svc.PacketsPage(1, 1, "tcp.port == 443")
	if total != 2 || next != 2 {
		t.Fatalf("unexpected second page meta: total=%d next=%d", total, next)
	}
	if len(page) != 1 || page[0].ID != 4 {
		t.Fatalf("expected packet #4, got %+v", page)
	}

	cursor, total, found := svc.PacketPageCursor(4, 1, "tcp.port == 443")
	if !found {
		t.Fatal("expected packet #4 to be found")
	}
	if total != 2 {
		t.Fatalf("expected 2 filtered packets, got %d", total)
	}
	if cursor != 1 {
		t.Fatalf("expected cursor 1 for packet #4, got %d", cursor)
	}

	if filterCalls != 1 {
		t.Fatalf("expected tshark filter to be cached after first lookup, got %d calls", filterCalls)
	}
}

func TestPacketsPageDoesNotFallbackToLegacyFilterWhenTSharkFilterFails(t *testing.T) {
	oldFilter := filterFrameIDsFn
	t.Cleanup(func() {
		filterFrameIDsFn = oldFilter
	})

	filterFrameIDsFn = func(context.Context, model.ParseOptions) ([]int64, error) {
		return nil, errors.New("invalid display filter")
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", DestPort: 80, Info: "GET /index"},
		{ID: 2, Protocol: "HTTP", DestPort: 80, Info: "POST /login"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	page, next, total := svc.PacketsPage(0, 10, "http")
	if len(page) != 0 || next != 0 || total != 0 {
		t.Fatalf("expected tshark failure to return an empty page, got page=%+v next=%d total=%d", page, next, total)
	}
}

func TestFilteredPacketIndexUsesAccessOrderForLRUEviction(t *testing.T) {
	oldFilter := filterFrameIDsFn
	t.Cleanup(func() {
		filterFrameIDsFn = oldFilter
	})

	filterCalls := map[string]int{}
	filterFrameIDsFn = func(_ context.Context, opts model.ParseOptions) ([]int64, error) {
		filterCalls[opts.DisplayFilter]++
		return []int64{1}, nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{{ID: 1, Protocol: "TCP", DestPort: 443}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	for i := 0; i < displayFilterCacheLimit; i++ {
		filter := "tcp.port == " + string(rune('A'+i))
		if _, err := svc.filteredPacketIndex(filter); err != nil {
			t.Fatalf("filteredPacketIndex(%q) error = %v", filter, err)
		}
	}

	hotFilter := "tcp.port == A"
	if _, err := svc.filteredPacketIndex(hotFilter); err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", hotFilter, err)
	}

	if _, err := svc.filteredPacketIndex("tcp.port == Z1"); err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", "tcp.port == Z1", err)
	}
	if _, err := svc.filteredPacketIndex("tcp.port == Z2"); err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", "tcp.port == Z2", err)
	}

	if _, err := svc.filteredPacketIndex(hotFilter); err != nil {
		t.Fatalf("filteredPacketIndex(%q) second access error = %v", hotFilter, err)
	}
	if filterCalls[hotFilter] != 1 {
		t.Fatalf("expected hot filter to remain cached, got %d lookups", filterCalls[hotFilter])
	}

	evictedFilter := "tcp.port == B"
	if _, err := svc.filteredPacketIndex(evictedFilter); err != nil {
		t.Fatalf("filteredPacketIndex(%q) post-eviction error = %v", evictedFilter, err)
	}
	if filterCalls[evictedFilter] != 2 {
		t.Fatalf("expected evicted filter to be recomputed, got %d lookups", filterCalls[evictedFilter])
	}
}
