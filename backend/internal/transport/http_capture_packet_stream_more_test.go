package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestHandleCaptureStartCoversValidationAndAcceptedLoad(t *testing.T) {
	server := &Server{
		capture:       &recordingCaptureStartService{loaded: make(chan captureStartCall, 1)},
		toolRuntime:   contractToolRuntimeService{},
		hub:           NewHub(),
		uploadedFiles: map[string]struct{}{},
	}

	rec := httptest.NewRecorder()
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodGet, "/api/capture/start", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodPost, "/api/capture/start", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodPost, "/api/capture/start", strings.NewReader(`{"file_path":" "}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodPost, "/api/capture/start", strings.NewReader(`{"file_path":"../secret.pcap"}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	dir := t.TempDir()
	rec = httptest.NewRecorder()
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodPost, "/api/capture/start", strings.NewReader(`{"file_path":`+quoteJSON(dir)+`}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	capturePath := filepath.Join(dir, "sample.pcapng")
	if err := os.WriteFile(capturePath, []byte("pcap"), 0o644); err != nil {
		t.Fatalf("write capture: %v", err)
	}
	server.registerUploadedFile(capturePath)

	rec = httptest.NewRecorder()
	body := `{"file_path":` + quoteJSON(capturePath) + `,"display_filter":"tcp","fast_list":true,"list_profile":"fast"}`
	server.handleCaptureStart(rec, httptest.NewRequest(http.MethodPost, "/api/capture/start", strings.NewReader(body)))
	requireStatus(t, rec, http.StatusAccepted)
	payload := decodeJSONMap(t, rec)
	if payload["status"] != "streaming" {
		t.Fatalf("capture start payload = %#v", payload)
	}

	capture := server.capture.(*recordingCaptureStartService)
	select {
	case call := <-capture.loaded:
		if call.runID != 77 {
			t.Fatalf("load run id = %d, want 77", call.runID)
		}
		if call.options.FilePath != capturePath || call.options.DisplayFilter != "tcp" || !call.options.FastList || call.options.ListProfile != "fast" {
			t.Fatalf("load options = %+v", call.options)
		}
		if call.ctx == nil || call.ctx.Err() != nil {
			t.Fatalf("load context = %v err=%v", call.ctx, call.ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("capture load goroutine did not observe accepted request")
	}
}

func TestPacketAndStreamHandlersCoverBoundaryBranches(t *testing.T) {
	capture := &recordingPacketStreamCaptureService{}
	server := &Server{capture: capture}

	rec := httptest.NewRecorder()
	server.handlePackets(rec, httptest.NewRequest(http.MethodPost, "/api/packets", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handlePackets(rec, httptest.NewRequest(http.MethodGet, "/api/packets", nil))
	requireStatus(t, rec, http.StatusOK)
	var packets []model.Packet
	if err := json.Unmarshal(rec.Body.Bytes(), &packets); err != nil || len(packets) != 1 || packets[0].ID != 11 {
		t.Fatalf("packets response = %+v err=%v body=%s", packets, err, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	server.handlePacketsPage(rec, httptest.NewRequest(http.MethodGet, "/api/packets/page?cursor=-5&limit=50000&filter=http", nil))
	requireStatus(t, rec, http.StatusOK)
	page := decodeJSONMap(t, rec)
	if page["has_more"] != true || page["filtering"] != true {
		t.Fatalf("packets page response = %#v", page)
	}
	if capture.pageCursor != 0 || capture.pageLimit != 10000 || capture.pageFilter != "http" {
		t.Fatalf("page args cursor=%d limit=%d filter=%q", capture.pageCursor, capture.pageLimit, capture.pageFilter)
	}

	rec = httptest.NewRecorder()
	server.handlePacketLocate(rec, httptest.NewRequest(http.MethodGet, "/api/packets/locate?id=11&limit=25&filter=tcp", nil))
	requireStatus(t, rec, http.StatusOK)
	if capture.locateID != 11 || capture.locateLimit != 25 || capture.locateFilter != "tcp" {
		t.Fatalf("locate args id=%d limit=%d filter=%q", capture.locateID, capture.locateLimit, capture.locateFilter)
	}

	rec = httptest.NewRecorder()
	server.handleStreamIndex(rec, httptest.NewRequest(http.MethodGet, "/api/streams/index?protocol=icmp", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleStreamIndex(rec, httptest.NewRequest(http.MethodGet, "/api/streams/index?protocol=udp", nil))
	requireStatus(t, rec, http.StatusOK)
	streamIndex := decodeJSONMap(t, rec)
	if streamIndex["protocol"] != "UDP" || capture.streamIDsProtocol != "UDP" {
		t.Fatalf("stream index response=%#v protocol=%q", streamIndex, capture.streamIDsProtocol)
	}

	rec = httptest.NewRecorder()
	server.handleHTTPStream(rec, httptest.NewRequest(http.MethodGet, "/api/streams/http?streamId=12", nil))
	requireStatus(t, rec, http.StatusOK)
	if capture.httpStreamID != 12 {
		t.Fatalf("HTTP stream id = %d", capture.httpStreamID)
	}

	rec = httptest.NewRecorder()
	server.handleRawStream(rec, httptest.NewRequest(http.MethodGet, "/api/streams/raw?streamId=13", nil))
	requireStatus(t, rec, http.StatusOK)
	if capture.rawProtocol != "TCP" || capture.rawStreamID != 13 {
		t.Fatalf("raw stream args protocol=%q streamID=%d", capture.rawProtocol, capture.rawStreamID)
	}

	rec = httptest.NewRecorder()
	server.handleRawStreamPage(rec, httptest.NewRequest(http.MethodGet, "/api/streams/raw/page?protocol=udp&streamId=14&cursor=2&limit=3", nil))
	requireStatus(t, rec, http.StatusOK)
	rawPage := decodeJSONMap(t, rec)
	if rawPage["has_more"] != true || capture.rawPageProtocol != "udp" || capture.rawPageCursor != 2 || capture.rawPageLimit != 3 {
		t.Fatalf("raw page response=%#v args=%q %d %d", rawPage, capture.rawPageProtocol, capture.rawPageCursor, capture.rawPageLimit)
	}

	rec = httptest.NewRecorder()
	server.handleStreamPayloadSources(rec, httptest.NewRequest(http.MethodGet, "/api/streams/payload-sources?limit=bad", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleStreamPayloadSources(rec, httptest.NewRequest(http.MethodGet, "/api/streams/payload-sources?limit=17", nil))
	requireStatus(t, rec, http.StatusOK)
	if capture.payloadSourceLimit != 17 {
		t.Fatalf("payload source limit = %d", capture.payloadSourceLimit)
	}

	rec = httptest.NewRecorder()
	server.handleStreamDecode(rec, httptest.NewRequest(http.MethodPost, "/api/streams/decode", strings.NewReader(`{"decoder":"base64","payload":"aGVsbG8="}`)))
	requireStatus(t, rec, http.StatusOK)
	decodePayload := decodeJSONMap(t, rec)
	if decodePayload["decoder"] != "base64" || decodePayload["text"] != "hello" {
		t.Fatalf("decode payload = %#v", decodePayload)
	}

	rec = httptest.NewRecorder()
	server.handleStreamDecode(rec, httptest.NewRequest(http.MethodPost, "/api/streams/decode", strings.NewReader(`{"decoder":"unknown","payload":"x"}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleStreamInspect(rec, httptest.NewRequest(http.MethodPost, "/api/streams/inspect", strings.NewReader(`{"payload":"cmd=whoami"}`)))
	requireStatus(t, rec, http.StatusOK)
	inspectPayload := decodeJSONMap(t, rec)
	requireJSONKeys(t, inspectPayload, "normalized_payload")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/streams/payloads", strings.NewReader(`{"protocol":"tcp","stream_id":22,"patches":[{"index":0,"body":"edited"}]}`)).WithContext(ctx)
	server.handleStreamPayloads(rec, req)
	requireStatus(t, rec, http.StatusOK)
	if capture.updateProtocol != "tcp" || capture.updateStreamID != 22 || len(capture.updatePatches) != 1 || capture.updateCtxErr != context.Canceled {
		t.Fatalf("update payload args protocol=%q streamID=%d patches=%+v ctxErr=%v", capture.updateProtocol, capture.updateStreamID, capture.updatePatches, capture.updateCtxErr)
	}

	rec = httptest.NewRecorder()
	server.handleStreamPayloads(rec, httptest.NewRequest(http.MethodPost, "/api/streams/payloads", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)
}

type captureStartCall struct {
	ctx     context.Context
	options model.ParseOptions
	runID   int64
}

type recordingCaptureStartService struct {
	contractCaptureService
	loaded chan captureStartCall
}

func (s *recordingCaptureStartService) BeginCaptureLoad(ctx context.Context) (int64, context.Context) {
	return 77, ctx
}

func (s *recordingCaptureStartService) LoadPCAPWithRun(ctx context.Context, opts model.ParseOptions, runID int64) error {
	s.loaded <- captureStartCall{ctx: ctx, options: opts, runID: runID}
	return nil
}

type recordingPacketStreamCaptureService struct {
	contractCaptureService

	pageCursor int
	pageLimit  int
	pageFilter string

	locateID     int64
	locateLimit  int
	locateFilter string

	streamIDsProtocol string
	httpStreamID      int64
	rawProtocol       string
	rawStreamID       int64
	rawPageProtocol   string
	rawPageCursor     int
	rawPageLimit      int

	payloadSourceLimit int

	updateCtxErr   error
	updateProtocol string
	updateStreamID int64
	updatePatches  []model.StreamChunkPatch
}

func (s *recordingPacketStreamCaptureService) Packets() []model.Packet {
	return []model.Packet{{ID: 11, Protocol: "TCP", Info: "demo"}}
}

func (s *recordingPacketStreamCaptureService) PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error) {
	s.pageCursor = cursor
	s.pageLimit = limit
	s.pageFilter = filter
	return []model.Packet{{ID: 11, Protocol: "HTTP"}}, 1, 3, filter != "", nil
}

func (s *recordingPacketStreamCaptureService) PacketPageCursorWithError(packetID int64, limit int, filter string) (int, int, bool, error) {
	s.locateID = packetID
	s.locateLimit = limit
	s.locateFilter = filter
	return 5, 9, true, nil
}

func (s *recordingPacketStreamCaptureService) StreamIDs(protocol string) []int64 {
	s.streamIDsProtocol = protocol
	return []int64{4, 5}
}

func (s *recordingPacketStreamCaptureService) HTTPStream(_ context.Context, streamID int64) model.ReassembledStream {
	s.httpStreamID = streamID
	return model.ReassembledStream{StreamID: streamID, Protocol: "HTTP", Chunks: []model.StreamChunk{{PacketID: 1, Direction: "client", Body: "GET /"}}}
}

func (s *recordingPacketStreamCaptureService) RawStream(_ context.Context, protocol string, streamID int64) model.ReassembledStream {
	s.rawProtocol = protocol
	s.rawStreamID = streamID
	return model.ReassembledStream{StreamID: streamID, Protocol: protocol, Chunks: []model.StreamChunk{{PacketID: 1, Direction: "client", Body: "aa"}}}
}

func (s *recordingPacketStreamCaptureService) RawStreamPage(_ context.Context, protocol string, streamID int64, cursor int, limit int) (model.ReassembledStream, int, int) {
	s.rawPageProtocol = protocol
	s.rawPageCursor = cursor
	s.rawPageLimit = limit
	return model.ReassembledStream{StreamID: streamID, Protocol: protocol, Chunks: []model.StreamChunk{{PacketID: 1, Direction: "server", Body: "bb"}}}, cursor + limit, cursor + limit + 1
}

func (s *recordingPacketStreamCaptureService) ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error) {
	s.payloadSourceLimit = limit
	return []model.StreamPayloadSource{{ID: "src-1", PacketID: 11, Payload: "cmd=whoami", Confidence: 80}}, nil
}

func (s *recordingPacketStreamCaptureService) UpdateStreamPayloads(ctx context.Context, protocol string, streamID int64, patches []model.StreamChunkPatch) (model.ReassembledStream, error) {
	s.updateCtxErr = ctx.Err()
	s.updateProtocol = protocol
	s.updateStreamID = streamID
	s.updatePatches = append([]model.StreamChunkPatch(nil), patches...)
	return model.ReassembledStream{StreamID: streamID, Protocol: protocol, Chunks: []model.StreamChunk{{PacketID: 1, Direction: "client", Body: patches[0].Body}}}, nil
}

func quoteJSON(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
