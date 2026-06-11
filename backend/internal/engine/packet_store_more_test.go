package engine

import (
	"reflect"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestPacketStoreDirectPagingAndIDLookups(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	packets := []model.Packet{
		{ID: 1, Protocol: "HTTP", Info: "GET /a", Payload: "payload-a", RawHex: "aa", StreamID: 10},
		{ID: 2, Protocol: "TCP", Info: "SYN", Payload: "payload-b", RawHex: "bb", StreamID: 11, Color: model.PacketColorFeatures{TCPSYN: true}},
		{ID: 3, Protocol: "UDP", Info: "query", Payload: "payload-c", RawHex: "cc", UDPPayloadHex: "cafe", StreamID: 12},
		{ID: 4, Protocol: "HTTP", Info: "POST /d", Payload: "payload-d", RawHex: "dd", StreamID: 13},
	}
	if err := store.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	path, count := store.meta()
	if path == "" || count != len(packets) {
		t.Fatalf("unexpected store meta path=%q count=%d", path, count)
	}
	if !store.HasID(2) || store.HasID(99) {
		t.Fatalf("unexpected HasID results")
	}
	if got := store.ExistingIDs([]int64{4, 99, 1, 0}); !reflect.DeepEqual(got, []int64{4, 1}) {
		t.Fatalf("ExistingIDs() = %v, want [4 1]", got)
	}
	if got := store.ExistingIDs(nil); got != nil {
		t.Fatalf("ExistingIDs(nil) = %v, want nil", got)
	}

	page, next, total, err := store.Page(-10, 0, nil)
	if err != nil {
		t.Fatalf("Page() error = %v", err)
	}
	if total != len(packets) || next != len(packets) || len(page) != len(packets) {
		t.Fatalf("unexpected default page metadata total=%d next=%d len=%d", total, next, len(page))
	}
	if page[1].ID != 2 || page[1].Payload != "payload-b" || !page[1].Color.TCPSYN {
		t.Fatalf("expected full packet with color to round-trip, got %+v", page[1])
	}

	page, next, total, err = store.Page(1, 2, nil)
	if err != nil {
		t.Fatalf("Page(cursor=1) error = %v", err)
	}
	if total != 4 || next != 3 || !reflect.DeepEqual(packetIDList(page), []int64{2, 3}) {
		t.Fatalf("unexpected direct page total=%d next=%d ids=%v", total, next, packetIDList(page))
	}

	page, next, total, err = store.Page(99, 2, nil)
	if err != nil {
		t.Fatalf("Page(cursor past end) error = %v", err)
	}
	if total != 4 || next != 4 || len(page) != 0 {
		t.Fatalf("expected empty past-end page, total=%d next=%d len=%d", total, next, len(page))
	}

	if got := store.idWindow(1, 2); !reflect.DeepEqual(got, []int64{2, 3}) {
		t.Fatalf("idWindow(1,2) = %v, want [2 3]", got)
	}
	if got := store.idWindow(4, 1); got != nil {
		t.Fatalf("idWindow past end = %v, want nil", got)
	}
	if got := store.idWindow(0, 0); got != nil {
		t.Fatalf("idWindow zero limit = %v, want nil", got)
	}
}

func TestPacketStorePageByIDsPreservesRequestedOrderAndSummariesStripPayload(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	if err := store.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", Payload: "payload-1", RawHex: "aa", UDPPayloadHex: "11"},
		{ID: 2, Protocol: "HTTP", Payload: "payload-2", RawHex: "bb", UDPPayloadHex: "22"},
		{ID: 3, Protocol: "TCP", Payload: "payload-3", RawHex: "cc", UDPPayloadHex: "33"},
		{ID: 4, Protocol: "UDP", Payload: "payload-4", RawHex: "dd", UDPPayloadHex: "44"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	ids := []int64{4, 2, 99, 1}
	page, next, total, err := store.PageByIDs(ids, 0, 3)
	if err != nil {
		t.Fatalf("PageByIDs() error = %v", err)
	}
	if total != len(ids) || next != 3 || !reflect.DeepEqual(packetIDList(page), []int64{4, 2}) {
		t.Fatalf("unexpected PageByIDs metadata total=%d next=%d ids=%v", total, next, packetIDList(page))
	}
	if page[0].Payload != "payload-4" || page[1].RawHex != "bb" {
		t.Fatalf("expected full packet payloads to be retained, got %+v", page)
	}

	summary, next, total, err := store.PageByIDsSummary(ids, -5, 10)
	if err != nil {
		t.Fatalf("PageByIDsSummary() error = %v", err)
	}
	if total != len(ids) || next != len(ids) || !reflect.DeepEqual(packetIDList(summary), []int64{4, 2, 1}) {
		t.Fatalf("unexpected summary metadata total=%d next=%d ids=%v", total, next, packetIDList(summary))
	}
	for _, packet := range summary {
		if packet.Payload != "" || packet.RawHex != "" || packet.UDPPayloadHex != "" {
			t.Fatalf("expected summary packet to strip payload fields, got %+v", packet)
		}
	}

	empty, next, total, err := store.PageByIDs(nil, 0, 10)
	if err != nil {
		t.Fatalf("PageByIDs(nil) error = %v", err)
	}
	if len(empty) != 0 || next != 0 || total != 0 {
		t.Fatalf("expected empty nil-id page, total=%d next=%d len=%d", total, next, len(empty))
	}
}

func TestPacketStoreReplaceWithTransfersReplacementStore(t *testing.T) {
	current, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore(current) error = %v", err)
	}
	defer current.Close()
	next, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore(next) error = %v", err)
	}
	defer next.Close()

	if err := current.Append([]model.Packet{{ID: 1, Protocol: "TCP", Info: "old"}}); err != nil {
		t.Fatalf("current.Append() error = %v", err)
	}
	if err := next.Append([]model.Packet{{ID: 7, Protocol: "HTTP", Info: "new"}}); err != nil {
		t.Fatalf("next.Append() error = %v", err)
	}
	nextPath := next.Path()

	if err := current.ReplaceWith(next); err != nil {
		t.Fatalf("ReplaceWith() error = %v", err)
	}
	if current.Path() != nextPath || current.Count() != 1 || !current.HasID(7) || current.HasID(1) {
		t.Fatalf("replacement store not transferred correctly path=%q count=%d has7=%t has1=%t", current.Path(), current.Count(), current.HasID(7), current.HasID(1))
	}
	if next.Path() != "" || next.Count() != 0 {
		t.Fatalf("expected source replacement store to be drained, path=%q count=%d", next.Path(), next.Count())
	}
	packet, ok, err := current.PacketByID(7)
	if err != nil || !ok || packet.Info != "new" {
		t.Fatalf("PacketByID(7) = %+v ok=%t err=%v", packet, ok, err)
	}
}

func TestPacketStoreClosedStoreReturnsStableEmptyResults(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	if err := store.Append([]model.Packet{{ID: 1, Protocol: "TCP"}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := store.Append([]model.Packet{{ID: 2}}); err == nil {
		t.Fatal("expected Append() on closed store to fail")
	}
	if got := store.Count(); got != 0 {
		t.Fatalf("Count() on closed store = %d, want 0", got)
	}
	if path, count := store.meta(); path != "" || count != 0 {
		t.Fatalf("meta() on closed store path=%q count=%d, want empty", path, count)
	}
	if packet, ok, err := store.PacketByID(1); err != nil || ok || packet.ID != 0 {
		t.Fatalf("PacketByID() on closed store = %+v ok=%t err=%v", packet, ok, err)
	}
	if packets, err := store.PacketsByIDs([]int64{1}); err != nil || len(packets) != 0 {
		t.Fatalf("PacketsByIDs() on closed store = %+v err=%v", packets, err)
	}
	if ports, err := store.TopUDPDestinationPorts(0, 0); err != nil || ports != nil {
		t.Fatalf("TopUDPDestinationPorts() on closed store = %+v err=%v", ports, err)
	}
}

func packetIDList(items []model.Packet) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
