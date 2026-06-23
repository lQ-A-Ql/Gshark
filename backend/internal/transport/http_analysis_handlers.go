package transport

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

func (s *Server) handleHunting(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	prefixes := r.URL.Query()["prefix"]
	writeJSON(w, http.StatusOK, s.detection.ThreatHuntWithContext(r.Context(), prefixes))
}

func (s *Server) handleHuntingConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.detection.GetHuntingRuntimeConfig())
		return
	case http.MethodPost:
		var cfg model.HuntingRuntimeConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		writeJSON(w, http.StatusOK, s.detection.SetHuntingRuntimeConfig(cfg))
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.detection.ObjectsWithContext(r.Context()))
}

func (s *Server) handleGlobalTrafficStats(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	stats, err := s.analysis.GlobalTrafficStatsWithContext(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleIndustrialAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.IndustrialAnalysisWithContext(analysisRequestContext(r, "industrial"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleVehicleAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.VehicleAnalysisWithContext(analysisRequestContext(r, "vehicle"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleMediaAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	refreshParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("refresh")))
	forceRefresh := refreshParam == "1" || refreshParam == "true" || refreshParam == "yes"

	var (
		analysis model.MediaAnalysis
		err      error
	)
	if forceRefresh {
		analysis, err = s.media.RefreshMediaAnalysisWithContext(r.Context())
	} else {
		analysis, err = s.media.MediaAnalysisWithContext(r.Context())
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleUSBAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	hidSource := strings.TrimSpace(r.URL.Query().Get("hid_source"))
	mode, ok := model.NormalizeUSBHIDSourceMode(hidSource)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid hid_source; expected auto, usbhid, capdata, btatt, or raw")
		return
	}
	hidEventLimit, ok := parseUSBHIDEventLimit(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid hid_event_limit; expected integer")
		return
	}
	analysis, err := s.analysis.USBAnalysisWithOptions(analysisRequestContext(r, "usb"), model.USBAnalysisOptions{HIDSourceMode: mode, HIDEventLimit: hidEventLimit})
	if err != nil {
		if strings.Contains(err.Error(), "no capture loaded") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func parseUSBHIDEventLimit(r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("hid_event_limit"))
	if raw == "" {
		return model.DefaultUSBHIDEventLimit, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return model.NormalizeUSBHIDEventLimit(limit), true
}

func (s *Server) handleC2Analysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.C2SampleAnalysis(analysisRequestContext(r, "c2"))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func analysisRequestContext(r *http.Request, target string) context.Context {
	ctx := r.Context()
	warmup := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("warmup")))
	if warmup != "1" && warmup != "true" && warmup != "yes" {
		return servicecontract.WithAnalysisRequestMeta(ctx, servicecontract.AnalysisRequestMeta{
			Source:   servicecontract.AnalysisRequestSourceUser,
			Priority: servicecontract.AnalysisRequestPriorityNormal,
			Target:   target,
		})
	}
	return servicecontract.WithAnalysisRequestMeta(ctx, servicecontract.AnalysisRequestMeta{
		Source:   servicecontract.AnalysisRequestSourceWarmup,
		Priority: servicecontract.AnalysisRequestPriorityBackground,
		Target:   target,
	})
}

func (s *Server) handleC2Decrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload model.C2DecryptRequest
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.analysis.C2Decrypt(r.Context(), payload)
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

func (s *Server) handleAPTAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.APTAnalysis(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	var filter model.EvidenceFilter
	if modulesParam := r.URL.Query().Get("modules"); modulesParam != "" {
		for _, m := range strings.Split(modulesParam, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				filter.Modules = append(filter.Modules, m)
			}
		}
	}
	result, err := s.analysis.GatherEvidence(r.Context(), filter)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		if strings.Contains(err.Error(), "no capture loaded") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleVehicleDBC(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.analysis.VehicleDBCProfiles())
	case http.MethodPost:
		var payload struct {
			Path string `json:"path"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		payload.Path = strings.TrimSpace(payload.Path)
		if !IsSafeFilePath(payload.Path) {
			writeError(w, http.StatusBadRequest, "path traversal not allowed")
			return
		}
		profiles, err := s.analysis.AddVehicleDBC(payload.Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, sanitizeErrorMessage(err))
			return
		}
		writeJSON(w, http.StatusOK, profiles)
	case http.MethodDelete:
		path := strings.TrimSpace(r.URL.Query().Get("path"))
		if path == "" {
			writeError(w, http.StatusBadRequest, "missing dbc path")
			return
		}
		if !IsSafeFilePath(path) {
			writeError(w, http.StatusBadRequest, "path traversal not allowed")
			return
		}
		writeJSON(w, http.StatusOK, s.analysis.RemoveVehicleDBC(path))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleObjectsDownload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
		// allowed
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var reqIds []int64
	if r.Method == http.MethodPost {
		var payload struct {
			IDs []int64 `json:"ids"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		reqIds = payload.IDs
	} else if r.Method == http.MethodGet {
		q := r.URL.Query().Get("ids")
		if q != "" {
			parts := strings.Split(q, ",")
			for _, part := range parts {
				if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil {
					reqIds = append(reqIds, id)
				}
			}
		}
	}

	allObjects := s.detection.ObjectsWithContext(r.Context())
	var toDownload []model.ObjectFile

	const maxObjectsPerDownload = 100

	if len(reqIds) == 0 {
		if len(allObjects) > maxObjectsPerDownload {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many objects (%d); specify ids to download", len(allObjects)))
			return
		}
		toDownload = allObjects
	} else {
		idMap := make(map[int64]bool)
		for _, id := range reqIds {
			idMap[id] = true
		}
		for _, obj := range allObjects {
			if idMap[obj.ID] {
				toDownload = append(toDownload, obj)
			}
		}
	}

	if len(toDownload) == 0 {
		writeError(w, http.StatusNotFound, "no objects to download")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="exported_objects.zip"`)

	zw := zip.NewWriter(w)
	for _, obj := range toDownload {
		if r.Context().Err() != nil {
			break
		}
		f, err := os.Open(obj.Path)
		if err != nil {
			continue
		}
		zf, err := zw.Create(obj.Name)
		if err == nil {
			const maxObjectFileSize = 256 << 20 // 256MB per file
			_, _ = io.Copy(zf, io.LimitReader(f, maxObjectFileSize))
		}
		f.Close()
	}
	zw.Close()
}
