package desktopruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/transport"
)

const blobMaxBytes int64 = 50 * 1024 * 1024

type Options struct {
	MiscPackageDir string
}

type Runtime struct {
	svc     *engine.Service
	hub     *transport.Hub
	server  *transport.Server
	handler http.Handler

	mu          sync.Mutex
	subscribers map[chan Event]struct{}
	closed      bool
}

type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type RawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type MultipartPart struct {
	Name        string
	Filename    string
	ContentType string
	Value       string
	Data        []byte
}

func New(opts Options) (*Runtime, error) {
	hub := transport.NewHub()
	rt := &Runtime{
		hub:         hub,
		subscribers: map[chan Event]struct{}{},
	}
	rt.attachHubListeners(hub)

	rt.svc = engine.NewService(hub)
	rt.server = transport.NewServerWithOptions(rt.svc, hub, transport.ServerOptions{
		MiscPackageDir: strings.TrimSpace(opts.MiscPackageDir),
	})
	rt.handler = rt.server.Handler()
	return rt, nil
}

func NewWithHandler(handler http.Handler) *Runtime {
	hub := transport.NewHub()
	rt := &Runtime{
		hub:         hub,
		handler:     handler,
		subscribers: map[chan Event]struct{}{},
	}
	rt.attachHubListeners(hub)
	return rt
}

func (rt *Runtime) attachHubListeners(hub *transport.Hub) {
	hub.OnPacket(func(packet model.Packet) {
		rt.publish(Event{Type: "packet", Data: packet})
	})
	hub.OnStatus(func(status string) {
		rt.publish(Event{Type: "status", Data: map[string]string{"message": status}})
	})
	hub.OnError(func(message string) {
		rt.publish(Event{Type: "error", Data: map[string]string{"message": message}})
	})
}

func (rt *Runtime) Close(context.Context) error {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil
	}
	rt.closed = true
	for ch := range rt.subscribers {
		delete(rt.subscribers, ch)
		close(ch)
	}
	rt.mu.Unlock()
	if rt.svc != nil {
		rt.svc.StopStreaming()
		rt.svc.CancelCaptureTasks()
		rt.svc.CancelMediaBatchTranscription()
	}
	return nil
}

func (rt *Runtime) Subscribe(ctx context.Context) <-chan Event {
	ch := make(chan Event, 1024)
	if rt == nil {
		close(ch)
		return ch
	}
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		close(ch)
		return ch
	}
	rt.subscribers[ch] = struct{}{}
	rt.mu.Unlock()
	rt.trySend(ch, Event{Type: "ready", Data: map[string]any{}})

	go func() {
		<-ctx.Done()
		rt.mu.Lock()
		if _, ok := rt.subscribers[ch]; ok {
			delete(rt.subscribers, ch)
			close(ch)
		}
		rt.mu.Unlock()
	}()
	return ch
}

func (rt *Runtime) Ready() bool {
	if rt == nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return !rt.closed && rt.handler != nil
}

func (rt *Runtime) Health(ctx context.Context) (map[string]any, error) {
	var payload map[string]any
	if err := rt.GetJSON(ctx, "/health", &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (rt *Runtime) Identity(ctx context.Context) (map[string]any, error) {
	var payload map[string]any
	if err := rt.GetJSON(ctx, "/api/runtime/identity", &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (rt *Runtime) GetJSON(ctx context.Context, path string, dest any) error {
	return rt.DoJSON(ctx, http.MethodGet, path, nil, dest)
}

func (rt *Runtime) PostJSON(ctx context.Context, path string, payload any, dest any) error {
	return rt.DoJSON(ctx, http.MethodPost, path, payload, dest)
}

func (rt *Runtime) PutJSON(ctx context.Context, path string, payload any, dest any) error {
	return rt.DoJSON(ctx, http.MethodPut, path, payload, dest)
}

func (rt *Runtime) DeleteJSON(ctx context.Context, path string, dest any) error {
	return rt.DoJSON(ctx, http.MethodDelete, path, nil, dest)
}

func (rt *Runtime) DeleteJSONWithBody(ctx context.Context, path string, payload any, dest any) error {
	return rt.DoJSON(ctx, http.MethodDelete, path, payload, dest)
}

func (rt *Runtime) DoJSON(ctx context.Context, method, path string, payload any, dest any) error {
	var body io.Reader
	contentType := ""
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode runtime request body: %w", err)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	}
	raw, err := rt.DoRaw(ctx, method, path, body, contentType, 0)
	if err != nil {
		return err
	}
	if dest == nil || len(bytes.TrimSpace(raw.Body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Body, dest); err != nil {
		return fmt.Errorf("decode runtime response: %w", err)
	}
	return nil
}

func (rt *Runtime) PostMultipartFile(ctx context.Context, path, fieldName, filePath string, dest any) error {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return fmt.Errorf("file path is required")
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat file: %w", err)
	}
	if info.IsDir() {
		_ = file.Close()
		return fmt.Errorf("file path is a directory: %s", cleanPath)
	}

	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	contentType := multipartWriter.FormDataContentType()
	writeErr := make(chan error, 1)
	go func() {
		err := streamMultipartFile(multipartWriter, file, strings.TrimSpace(fieldName), filepath.Base(cleanPath))
		if err != nil {
			_ = writer.CloseWithError(err)
		} else {
			_ = writer.Close()
		}
		_ = file.Close()
		writeErr <- err
	}()

	raw, err := rt.DoRaw(ctx, http.MethodPost, path, reader, contentType, 0)
	_ = reader.CloseWithError(context.Canceled)
	streamErr := <-writeErr
	if err != nil {
		return err
	}
	if streamErr != nil && !errors.Is(streamErr, io.ErrClosedPipe) && !errors.Is(streamErr, context.Canceled) {
		return fmt.Errorf("stream multipart file: %w", streamErr)
	}
	if dest == nil || len(bytes.TrimSpace(raw.Body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Body, dest); err != nil {
		return fmt.Errorf("decode runtime response: %w", err)
	}
	return nil
}

func streamMultipartFile(writer *multipart.Writer, file *os.File, fieldName, filename string) error {
	if writer == nil {
		return fmt.Errorf("multipart writer is required")
	}
	if strings.TrimSpace(fieldName) == "" {
		return fmt.Errorf("multipart field name is required")
	}
	part, err := writer.CreateFormFile(strings.TrimSpace(fieldName), filename)
	if err != nil {
		_ = writer.Close()
		return fmt.Errorf("create multipart file part: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		_ = writer.Close()
		return fmt.Errorf("copy multipart file content: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close multipart body: %w", err)
	}
	return nil
}

func (rt *Runtime) DoMultipart(ctx context.Context, method, path string, parts []MultipartPart, maxBytes int64) (RawResponse, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for _, part := range parts {
		name := strings.TrimSpace(part.Name)
		if name == "" {
			_ = writer.Close()
			return RawResponse{}, fmt.Errorf("multipart part name is required")
		}
		if part.Data == nil {
			if err := writer.WriteField(name, part.Value); err != nil {
				_ = writer.Close()
				return RawResponse{}, fmt.Errorf("write multipart field %q: %w", name, err)
			}
			continue
		}
		header := make(textproto.MIMEHeader)
		disposition := fmt.Sprintf(`form-data; name="%s"`, escapeQuote(name))
		if filename := strings.TrimSpace(part.Filename); filename != "" {
			disposition += fmt.Sprintf(`; filename="%s"`, escapeQuote(filename))
		}
		header.Set("Content-Disposition", disposition)
		if contentType := strings.TrimSpace(part.ContentType); contentType != "" {
			header.Set("Content-Type", contentType)
		}
		w, err := writer.CreatePart(header)
		if err != nil {
			_ = writer.Close()
			return RawResponse{}, fmt.Errorf("create multipart part %q: %w", name, err)
		}
		if _, err := w.Write(part.Data); err != nil {
			_ = writer.Close()
			return RawResponse{}, fmt.Errorf("write multipart part %q: %w", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return RawResponse{}, fmt.Errorf("close multipart body: %w", err)
	}
	return rt.DoRaw(ctx, method, path, bytes.NewReader(buf.Bytes()), writer.FormDataContentType(), maxBytes)
}

func (rt *Runtime) DoRaw(ctx context.Context, method, path string, body io.Reader, contentType string, maxBytes int64) (RawResponse, error) {
	if rt == nil || rt.handler == nil {
		return RawResponse{}, fmt.Errorf("desktop runtime is not ready")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return RawResponse{}, fmt.Errorf("build runtime request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "meow-traffic-DesktopRuntime")
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", strings.TrimSpace(contentType))
	}

	rec := httptest.NewRecorder()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				done <- fmt.Errorf("desktop runtime handler panic: %v", recovered)
			}
		}()
		rt.handler.ServeHTTP(rec, req)
		done <- nil
	}()
	select {
	case <-ctx.Done():
		return RawResponse{}, fmt.Errorf("desktop runtime request canceled: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			return RawResponse{}, err
		}
	}
	res := rec.Result()
	defer res.Body.Close()

	reader := res.Body
	if maxBytes > 0 {
		reader = io.NopCloser(io.LimitReader(res.Body, maxBytes+1))
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return RawResponse{}, fmt.Errorf("read runtime response: %w", err)
	}
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return RawResponse{}, fmt.Errorf("desktop IPC blob response too large: %s exceeds 50MB; use native export or narrow the selection", path)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return RawResponse{}, normalizeError(res.StatusCode, raw)
	}
	return RawResponse{StatusCode: res.StatusCode, Header: res.Header.Clone(), Body: raw}, nil
}

func (rt *Runtime) publish(ev Event) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	for ch := range rt.subscribers {
		if ev.Type == "status" || ev.Type == "error" {
			rt.enqueuePriorityLocked(ch, ev)
			continue
		}
		rt.trySend(ch, ev)
	}
}

func (rt *Runtime) enqueuePriorityLocked(ch chan Event, ev Event) {
	if rt.trySend(ch, ev) {
		return
	}
	preserved := make([]Event, 0, cap(ch))
	for {
		select {
		case pending := <-ch:
			if pending.Type == "packet" {
				continue
			}
			preserved = append(preserved, pending)
		default:
			maxPreserved := cap(ch) - 1
			if maxPreserved < 0 {
				maxPreserved = 0
			}
			if len(preserved) > maxPreserved {
				preserved = preserved[len(preserved)-maxPreserved:]
			}
			for _, pending := range preserved {
				if !rt.trySend(ch, pending) {
					break
				}
			}
			_ = rt.trySend(ch, ev)
			return
		}
	}
}

func (rt *Runtime) trySend(ch chan Event, ev Event) bool {
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}

func normalizeError(statusCode int, raw []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		if msg := strings.TrimSpace(payload.Error); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	message := strings.TrimSpace(string(raw))
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return fmt.Errorf("desktop runtime request failed: %d %s", statusCode, message)
}

func escapeQuote(value string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, `\"`).Replace(value)
}

func ContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func BlobMaxBytes() int64 {
	return blobMaxBytes
}
