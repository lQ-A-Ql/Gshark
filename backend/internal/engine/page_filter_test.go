package engine

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

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

func TestPacketStorePageSummariesStripPayload(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	if err := store.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", Info: "POST /upload", Payload: "username=alice", RawHex: "de:ad:be:ef"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	page, next, total, err := store.PageSummaries(0, 10, nil)
	if err != nil {
		t.Fatalf("PageSummaries() error = %v", err)
	}
	if total != 1 || next != 1 || len(page) != 1 {
		t.Fatalf("unexpected page metadata: total=%d next=%d len=%d", total, next, len(page))
	}
	if page[0].Payload != "" || page[0].RawHex != "" {
		t.Fatalf("expected summary page to strip payload fields, got %+v", page[0])
	}

	packet, ok, err := store.PacketByID(1)
	if err != nil {
		t.Fatalf("PacketByID() error = %v", err)
	}
	if !ok {
		t.Fatal("expected packet #1 to exist")
	}
	if packet.Payload != "username=alice" || packet.RawHex != "de:ad:be:ef" {
		t.Fatalf("expected full packet payload to remain available, got %+v", packet)
	}
}

func TestPacketStoreTopUDPDestinationPorts(t *testing.T) {
	store, err := newPacketStore()
	if err != nil {
		t.Fatalf("newPacketStore() error = %v", err)
	}
	defer store.Close()

	if err := store.Append([]model.Packet{
		{ID: 1, Protocol: "UDP", DestPort: 50000},
		{ID: 2, Protocol: "UDP", DestPort: 50000},
		{ID: 3, Protocol: "UDP", DestPort: 50000},
		{ID: 4, Protocol: "UDP", DestPort: 50002},
		{ID: 5, Protocol: "UDP", DestPort: 50002},
		{ID: 6, Protocol: "TCP", DestPort: 443},
		{ID: 7, Protocol: "UDP", DestPort: 53},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	ports, err := store.TopUDPDestinationPorts(4, 2)
	if err != nil {
		t.Fatalf("TopUDPDestinationPorts() error = %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %v", ports)
	}
	if ports[0] != 50000 || ports[1] != 50002 {
		t.Fatalf("unexpected port ranking: %v", ports)
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

func TestClearCaptureResetsPacketStore(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	if err := svc.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "TCP", Info: "demo"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.pcap = "demo.pcap"

	pathBefore := svc.packetStore.Path()
	if pathBefore == "" {
		t.Fatal("expected packet store path to be initialized")
	}

	if err := svc.ClearCapture(); err != nil {
		t.Fatalf("ClearCapture() error = %v", err)
	}

	if svc.packetStore.Count() != 0 {
		t.Fatalf("expected cleared packet store, got %d packets", svc.packetStore.Count())
	}
	if svc.pcap != "" {
		t.Fatalf("expected capture path to be cleared, got %q", svc.pcap)
	}
	if _, err := os.Stat(pathBefore); !os.IsNotExist(err) {
		t.Fatalf("expected old packet db to be removed, stat err=%v", err)
	}
}

func TestPrepareCaptureReplacementInvalidatesActiveRun(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	streamCtx, streamCancel := context.WithCancel(context.Background())
	filterCtx, filterCancel := context.WithCancel(context.Background())
	svc.mu.Lock()
	svc.cancel = streamCancel
	svc.displayFilterCache = map[string]*filteredPacketIndex{
		"tcp": newFilteredPacketIndex(filterCancel),
	}
	svc.displayFilterCacheOrder = []string{"tcp"}
	svc.mu.Unlock()
	atomic.StoreInt64(&svc.runID, 41)

	svc.PrepareCaptureReplacement()

	if got := atomic.LoadInt64(&svc.runID); got != 42 {
		t.Fatalf("expected replacement to invalidate previous runID, got %d", got)
	}
	select {
	case <-streamCtx.Done():
	default:
		t.Fatal("expected active capture context to be cancelled")
	}
	select {
	case <-filterCtx.Done():
	default:
		t.Fatal("expected display filter cache context to be cancelled")
	}
	if len(svc.displayFilterCache) != 0 {
		t.Fatalf("expected display filter cache to be cleared, got %d entries", len(svc.displayFilterCache))
	}
}

func TestClearCaptureCancelsActiveLoad(t *testing.T) {
	oldEstimate := estimatePacketsFn
	oldStream := streamPacketsFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
		streamPacketsFn = oldStream
	})

	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		return 0, nil
	}
	started := make(chan struct{})
	streamPacketsFn = func(ctx context.Context, _ model.ParseOptions, _ func(model.Packet) error, _ func(int)) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	capture := writeTempCaptureFile(t)

	done := make(chan error, 1)
	go func() {
		done <- svc.LoadPCAP(context.Background(), model.ParseOptions{FilePath: capture})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected load to start")
	}

	if err := svc.ClearCapture(); err != nil {
		t.Fatalf("ClearCapture() error = %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected active load to be canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected active load goroutine to exit after close")
	}
}

func TestPendingLoadRunHonorsCloseBeforeGoroutineStarts(t *testing.T) {
	oldEstimate := estimatePacketsFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
	})
	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		t.Fatal("estimatePacketsFn should not be called for a closed pending run")
		return 0, nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	capture := writeTempCaptureFile(t)

	runID, runCtx := svc.BeginCaptureLoad(context.Background())
	if err := svc.ClearCapture(); err != nil {
		t.Fatalf("ClearCapture() error = %v", err)
	}

	err := svc.LoadPCAPWithRun(runCtx, model.ParseOptions{FilePath: capture}, runID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected closed pending run to be canceled, got %v", err)
	}
	if got := svc.packetStore.Count(); got != 0 {
		t.Fatalf("expected no packets to be written by canceled pending run, got %d", got)
	}
}

func TestClearCaptureCancelsTrackedCaptureTasks(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	taskCtx, finishTask := svc.TrackCaptureTask(context.Background(), "unit-test-task")
	defer finishTask()
	if got := svc.ActiveCaptureTaskCount(); got != 1 {
		t.Fatalf("expected one active capture task, got %d", got)
	}

	if err := svc.ClearCapture(); err != nil {
		t.Fatalf("ClearCapture() error = %v", err)
	}

	select {
	case <-taskCtx.Done():
	default:
		t.Fatal("expected ClearCapture to cancel tracked capture task")
	}
	if got := svc.ActiveCaptureTaskCount(); got != 0 {
		t.Fatalf("expected tracked capture tasks to be cleared, got %d", got)
	}
}

func TestPrepareCaptureReplacementCancelsTrackedCaptureTasks(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	taskCtx, finishTask := svc.TrackCaptureTask(context.Background(), "replacement-task")
	defer finishTask()

	svc.PrepareCaptureReplacement()

	select {
	case <-taskCtx.Done():
	default:
		t.Fatal("expected PrepareCaptureReplacement to cancel tracked capture task")
	}
	if got := svc.ActiveCaptureTaskCount(); got != 0 {
		t.Fatalf("expected tracked capture tasks to be cleared, got %d", got)
	}
}

func TestLoadPCAPReplacementCancelsPreviousLoad(t *testing.T) {
	oldEstimate := estimatePacketsFn
	oldStream := streamPacketsFn
	t.Cleanup(func() {
		estimatePacketsFn = oldEstimate
		streamPacketsFn = oldStream
	})

	estimatePacketsFn = func(context.Context, model.ParseOptions) (int, error) {
		return 0, nil
	}
	startedFirst := make(chan struct{})
	var calls atomic.Int32
	streamPacketsFn = func(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, _ func(int)) error {
		call := calls.Add(1)
		if call == 1 {
			close(startedFirst)
			<-ctx.Done()
			return ctx.Err()
		}
		return onPacket(model.Packet{ID: 2, Protocol: "HTTP", Info: "GET /replacement", Payload: opts.FilePath})
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	first := writeTempCaptureFile(t)
	second := writeTempCaptureFile(t)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- svc.LoadPCAP(context.Background(), model.ParseOptions{FilePath: first})
	}()
	select {
	case <-startedFirst:
	case <-time.After(time.Second):
		t.Fatal("expected first load to start")
	}

	if err := svc.LoadPCAP(context.Background(), model.ParseOptions{FilePath: second}); err != nil {
		t.Fatalf("replacement LoadPCAP() error = %v", err)
	}
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected first load to be canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected first load to exit after replacement")
	}
	if got := svc.packetStore.Count(); got != 1 {
		t.Fatalf("expected replacement packet store to contain one packet, got %d", got)
	}
}

func writeTempCaptureFile(t *testing.T) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "capture-*.pcap")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := file.WriteString("placeholder"); err != nil {
		_ = file.Close()
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return file.Name()
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
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	filterCalls := 0
	scanFrameIDsFn = func(_ context.Context, opts model.ParseOptions, onID func(int64)) error {
		filterCalls++
		if opts.FilePath != "demo.pcap" {
			t.Fatalf("unexpected file path: %q", opts.FilePath)
		}
		if opts.DisplayFilter != "tcp.port == 443" {
			t.Fatalf("unexpected display filter: %q", opts.DisplayFilter)
		}
		onID(2)
		onID(4)
		return nil
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
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	scanFrameIDsFn = func(context.Context, model.ParseOptions, func(int64)) error {
		return errors.New("invalid display filter")
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

func TestPacketsPageWithErrorReturnsDisplayFilterError(t *testing.T) {
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	scanFrameIDsFn = func(context.Context, model.ParseOptions, func(int64)) error {
		return errors.New("invalid display filter")
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

	page, next, total, err := svc.PacketsPageWithError(0, 10, "http.request.method == POST and")
	if !IsDisplayFilterError(err) {
		t.Fatalf("expected display filter error, got %v", err)
	}
	if err == nil || err.Error() != "invalid display filter" {
		t.Fatalf("unexpected error text: %v", err)
	}
	if len(page) != 0 || next != 0 || total != 0 {
		t.Fatalf("expected failed tshark filter to return an empty page payload, got page=%+v next=%d total=%d", page, next, total)
	}
}

func TestPacketPageCursorWithErrorReturnsDisplayFilterError(t *testing.T) {
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	scanFrameIDsFn = func(context.Context, model.ParseOptions, func(int64)) error {
		return errors.New("invalid display filter")
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "HTTP", DestPort: 80, Info: "GET /index"},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	cursor, total, found, err := svc.PacketPageCursorWithError(1, 10, "frame.number >=")
	if !IsDisplayFilterError(err) {
		t.Fatalf("expected display filter error, got %v", err)
	}
	if cursor != 0 || total != 0 || found {
		t.Fatalf("expected failed locate meta to remain empty, got cursor=%d total=%d found=%v", cursor, total, found)
	}
}

func TestFilteredPacketIndexUsesAccessOrderForLRUEviction(t *testing.T) {
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	filterCalls := map[string]int{}
	scanFrameIDsFn = func(_ context.Context, opts model.ParseOptions, onID func(int64)) error {
		filterCalls[opts.DisplayFilter]++
		onID(1)
		return nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{{ID: 1, Protocol: "TCP", DestPort: 443}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	for i := 0; i < displayFilterCacheLimit; i++ {
		filter := "tcp.port == " + string(rune('A'+i))
		index, err := svc.filteredPacketIndex(filter)
		if err != nil {
			t.Fatalf("filteredPacketIndex(%q) error = %v", filter, err)
		}
		if _, _, _, err := index.pageWindow(0, 1); err != nil {
			t.Fatalf("pageWindow(%q) error = %v", filter, err)
		}
	}

	hotFilter := "tcp.port == A"
	index, err := svc.filteredPacketIndex(hotFilter)
	if err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", hotFilter, err)
	}
	if _, _, _, err := index.pageWindow(0, 1); err != nil {
		t.Fatalf("pageWindow(%q) error = %v", hotFilter, err)
	}

	index, err = svc.filteredPacketIndex("tcp.port == Z1")
	if err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", "tcp.port == Z1", err)
	}
	if _, _, _, err := index.pageWindow(0, 1); err != nil {
		t.Fatalf("pageWindow(%q) error = %v", "tcp.port == Z1", err)
	}
	index, err = svc.filteredPacketIndex("tcp.port == Z2")
	if err != nil {
		t.Fatalf("filteredPacketIndex(%q) error = %v", "tcp.port == Z2", err)
	}
	if _, _, _, err := index.pageWindow(0, 1); err != nil {
		t.Fatalf("pageWindow(%q) error = %v", "tcp.port == Z2", err)
	}

	index, err = svc.filteredPacketIndex(hotFilter)
	if err != nil {
		t.Fatalf("filteredPacketIndex(%q) second access error = %v", hotFilter, err)
	}
	if _, _, _, err := index.pageWindow(0, 1); err != nil {
		t.Fatalf("pageWindow(%q) second access error = %v", hotFilter, err)
	}
	if filterCalls[hotFilter] != 1 {
		t.Fatalf("expected hot filter to remain cached, got %d lookups", filterCalls[hotFilter])
	}

	evictedFilter := "tcp.port == B"
	index, err = svc.filteredPacketIndex(evictedFilter)
	if err != nil {
		t.Fatalf("filteredPacketIndex(%q) post-eviction error = %v", evictedFilter, err)
	}
	if _, _, _, err := index.pageWindow(0, 1); err != nil {
		t.Fatalf("pageWindow(%q) post-eviction error = %v", evictedFilter, err)
	}
	if filterCalls[evictedFilter] != 2 {
		t.Fatalf("expected evicted filter to be recomputed, got %d lookups", filterCalls[evictedFilter])
	}
}

func TestPacketsPageReturnsFirstWindowBeforeDisplayFilterScanCompletes(t *testing.T) {
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	firstWindowReady := make(chan struct{})
	releaseScan := make(chan struct{})
	scanFrameIDsFn = func(_ context.Context, opts model.ParseOptions, onID func(int64)) error {
		if opts.DisplayFilter != "tcp" {
			t.Fatalf("unexpected display filter: %q", opts.DisplayFilter)
		}
		onID(1)
		onID(2)
		onID(3)
		close(firstWindowReady)
		<-releaseScan
		onID(4)
		return nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.pcap = "demo.pcap"
	if err := svc.packetStore.Append([]model.Packet{
		{ID: 1, Protocol: "TCP", DestPort: 80},
		{ID: 2, Protocol: "TCP", DestPort: 443},
		{ID: 3, Protocol: "TCP", DestPort: 8080},
		{ID: 4, Protocol: "TCP", DestPort: 8443},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	type result struct {
		page  []model.Packet
		next  int
		total int
		err   error
	}
	done := make(chan result, 1)
	go func() {
		page, next, total, err := svc.PacketsPageWithError(0, 2, "tcp")
		done <- result{page: page, next: next, total: total, err: err}
	}()

	<-firstWindowReady
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("PacketsPageWithError() error = %v", got.err)
		}
		if got.next != 2 || got.total != 3 {
			t.Fatalf("expected first window metadata next=2 total=3, got next=%d total=%d", got.next, got.total)
		}
		if len(got.page) != 2 || got.page[0].ID != 1 || got.page[1].ID != 2 {
			t.Fatalf("unexpected first window packets: %+v", got.page)
		}
	default:
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("PacketsPageWithError() error = %v", got.err)
			}
			if got.next != 2 || got.total != 3 {
				t.Fatalf("expected first window metadata next=2 total=3, got next=%d total=%d", got.next, got.total)
			}
			if len(got.page) != 2 || got.page[0].ID != 1 || got.page[1].ID != 2 {
				t.Fatalf("unexpected first window packets: %+v", got.page)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("expected first page to return before the background scan completed")
		}
	}

	close(releaseScan)
	page, next, total, err := svc.PacketsPageWithError(2, 2, "tcp")
	if err != nil {
		t.Fatalf("PacketsPageWithError() second page error = %v", err)
	}
	if next != 4 || total != 4 {
		t.Fatalf("expected exact metadata after scan completion, got next=%d total=%d", next, total)
	}
	if len(page) != 2 || page[0].ID != 3 || page[1].ID != 4 {
		t.Fatalf("unexpected second page packets: %+v", page)
	}
}

func TestPacketsPageReturnsBlankWhenDisplayFilterMatchesNoPackets(t *testing.T) {
	oldScan := scanFrameIDsFn
	t.Cleanup(func() {
		scanFrameIDsFn = oldScan
	})

	scanFrameIDsFn = func(context.Context, model.ParseOptions, func(int64)) error {
		return nil
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

	page, next, total, err := svc.PacketsPageWithError(0, 10, "tcp")
	if err != nil {
		t.Fatalf("PacketsPageWithError() error = %v", err)
	}
	if len(page) != 0 || next != 0 || total != 0 {
		t.Fatalf("expected blank page for unmatched filter, got page=%+v next=%d total=%d", page, next, total)
	}
}
