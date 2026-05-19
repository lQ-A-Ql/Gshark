package transport

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleCaptureUploadSmallFileSucceeds(t *testing.T) {
	server := &Server{uploadedFiles: map[string]struct{}{}}
	body, contentType := multipartUploadBody(t, "file", "sample.pcap", strings.NewReader("pcap"))
	req := httptest.NewRequest(http.MethodPost, "/api/capture/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()

	server.handleCaptureUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected upload to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}
	var result openCaptureResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if result.FileSize != 4 {
		t.Fatalf("expected file size 4, got %d", result.FileSize)
	}
	if _, err := os.Stat(result.FilePath); err != nil {
		t.Fatalf("expected uploaded file to exist: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(result.FilePath)
	})
}

func TestHandleCaptureUploadRejectsOversizeAndCleansTempFile(t *testing.T) {
	originalLimit := maxCaptureUploadBytes
	maxCaptureUploadBytes = 8 << 10
	t.Cleanup(func() {
		maxCaptureUploadBytes = originalLimit
	})

	before := listTempCaptureUploads(t)
	server := &Server{uploadedFiles: map[string]struct{}{}}
	body, contentType := multipartUploadBody(t, "file", "large.pcap", strings.NewReader(strings.Repeat("x", int(maxCaptureUploadBytes)+1)))
	req := httptest.NewRequest(http.MethodPost, "/api/capture/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()

	server.handleCaptureUpload(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized upload to fail with 413, got %d body=%s", rec.Code, rec.Body.String())
	}
	after := listTempCaptureUploads(t)
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Fatalf("expected oversized upload temp file to be cleaned up, found %s", path)
		}
	}
}

func multipartUploadBody(t *testing.T, fieldName, fileName string, content *strings.Reader) (*bytes.Buffer, string) {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := content.WriteTo(part); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return &body, writer.FormDataContentType()
}

func listTempCaptureUploads(t *testing.T) map[string]struct{} {
	t.Helper()

	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	paths := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "gshark-") && (strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") || strings.HasSuffix(name, ".cap")) {
			paths[filepath.Join(os.TempDir(), name)] = struct{}{}
		}
	}
	return paths
}
