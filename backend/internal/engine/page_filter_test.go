package engine

import (
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
