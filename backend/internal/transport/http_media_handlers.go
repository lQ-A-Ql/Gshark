package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) handleMediaArtifactDownload(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing media artifact token")
		return
	}

	path, name, err := s.media.MediaArtifact(token)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	header := make([]byte, 512)
	readBytes, _ := file.Read(header)
	_, _ = file.Seek(0, io.SeekStart)
	contentType := http.DetectContentType(header[:readBytes])
	if strings.HasSuffix(strings.ToLower(name), ".h264") || strings.HasSuffix(strings.ToLower(name), ".264") {
		contentType = "video/h264"
	}
	if strings.HasSuffix(strings.ToLower(name), ".h265") || strings.HasSuffix(strings.ToLower(name), ".hevc") {
		contentType = "video/h265"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) handleMediaArtifactPlayback(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing media artifact token")
		return
	}

	path, name, err := s.media.MediaPlaybackWithContext(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	contentType := "video/mp4"
	switch strings.ToLower(filepath.Ext(name)) {
	case ".m4a":
		contentType = "audio/mp4"
	case ".mp3":
		contentType = "audio/mpeg"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", name))
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) handleMediaArtifactTranscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Token string `json:"token"`
		Force bool   `json:"force"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.media.TranscribeMediaArtifactWithContext(r.Context(), payload.Token, payload.Force)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMediaBatchTranscription(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.media.MediaBatchTranscriptionStatus())
	case http.MethodPost:
		var payload struct {
			Force bool `json:"force"`
		}
		if r.Body != nil {
			if err := decodeJSONBody(w, r, &payload); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		status, err := s.media.StartMediaBatchTranscription(payload.Force)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, status)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMediaBatchTranscriptionCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.media.CancelMediaBatchTranscription())
}

func (s *Server) handleMediaBatchTranscriptionExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	export := s.media.ExportMediaBatchTranscription()
	if len(export.Items) == 0 {
		writeError(w, http.StatusBadRequest, "no batch transcription results available")
		return
	}

	switch format {
	case "txt":
		var b strings.Builder
		for idx, item := range export.Items {
			if idx > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString(item.Title)
			b.WriteString("\n")
			b.WriteString(item.Text)
		}
		filename := "media-transcription.txt"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		_, _ = w.Write([]byte(b.String()))
	case "json":
		filename := "media-transcription.json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		_ = json.NewEncoder(w).Encode(export)
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}
