package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

const maxCaptureUploadMemory = 64 << 20

var maxCaptureUploadBytes int64 = 2 << 30

type openCaptureResult struct {
	FilePath string `json:"filePath"`
	FileSize int64  `json:"fileSize"`
	FileName string `json:"fileName"`
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var options model.ParseOptions
	if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	options.FilePath = strings.TrimSpace(options.FilePath)
	if options.FilePath == "" {
		writeError(w, http.StatusBadRequest, "missing capture file path")
		return
	}
	info, err := os.Stat(options.FilePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("capture file is not accessible: %v", err))
		return
	}
	if info.IsDir() {
		writeError(w, http.StatusBadRequest, "capture file path points to a directory")
		return
	}
	log.Printf(
		"http: capture start requested file=%q size=%d filter=%q fast_list=%t tshark=%q custom=%t",
		options.FilePath,
		info.Size(),
		options.DisplayFilter,
		options.FastList,
		s.toolRuntime.TSharkStatusPath(),
		s.toolRuntime.TSharkUsingCustomPath(),
	)
	s.promoteUploadedFile(options.FilePath)
	loadRunID, loadCtx := s.capture.BeginCaptureLoad(context.WithoutCancel(r.Context()))
	go func() {
		if err := s.capture.LoadPCAPWithRun(loadCtx, options, loadRunID); err != nil {
			log.Printf("http: capture start failed file=%q err=%v", options.FilePath, err)
			if errors.Is(err, context.Canceled) {
				return
			}
			s.hub.EmitError(err.Error())
			return
		}
		log.Printf("http: capture start finished file=%q", options.FilePath)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "streaming"})
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.capture.StopStreaming()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleCapturePrepareReplacement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.capture.PrepareCaptureReplacement()
	writeJSON(w, http.StatusOK, map[string]string{"status": "prepared"})
}

func (s *Server) handleCaptureClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.capture.ClearCapture(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.capture.CaptureStatus())
}

func (s *Server) handleCaptureUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCaptureUploadBytes)
	if err := r.ParseMultipartForm(maxCaptureUploadMemory); err != nil {
		if isRequestBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "capture upload exceeds 2GB limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid multipart payload")
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	name := strings.TrimSpace(header.Filename)
	if name == "" {
		name = "capture.pcapng"
	}

	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		ext = ".pcapng"
	}

	targetPath := filepath.Join(os.TempDir(), fmt.Sprintf("gshark-%d%s", time.Now().UnixNano(), ext))
	target, err := os.Create(targetPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	defer target.Close()

	written, err := copyCaptureUpload(target, file, maxCaptureUploadBytes)
	if err != nil {
		_ = os.Remove(targetPath)
		if errors.Is(err, errCaptureUploadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "capture upload exceeds 2GB limit")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save upload")
		return
	}
	log.Printf("http: uploaded capture saved as %q (%d bytes)", targetPath, written)
	s.registerUploadedFile(targetPath)

	writeJSON(w, http.StatusOK, openCaptureResult{
		FilePath: targetPath,
		FileSize: written,
		FileName: name,
	})
}

var errCaptureUploadTooLarge = errors.New("capture upload exceeds size limit")

func copyCaptureUpload(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	written, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return written, err
	}
	if written > limit {
		return written, errCaptureUploadTooLarge
	}
	return written, nil
}

func isRequestBodyTooLarge(err error) bool {
	return strings.Contains(err.Error(), "http: request body too large")
}
