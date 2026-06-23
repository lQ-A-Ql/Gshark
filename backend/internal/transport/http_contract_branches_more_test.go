package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestPlaybookAndWorkspaceHandlersCoverFailureBranches(t *testing.T) {
	playbook := newAPIContractPlaybookService()
	server := &Server{playbook: playbook}

	for _, tt := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		method string
		path   string
		body   string
		want   int
	}{
		{name: "playbook empty id", handle: server.handlePlaybookRoute, method: http.MethodGet, path: "/api/playbooks/", want: http.StatusBadRequest},
		{name: "playbook update missing", handle: server.handlePlaybookRoute, method: http.MethodPut, path: "/api/playbooks/missing", body: `{"name":"Missing","steps":[{"name":"Hunt","type":"threat_hunt","enabled":true}]}`, want: http.StatusBadRequest},
		{name: "playbook update bad json", handle: server.handlePlaybookRoute, method: http.MethodPut, path: "/api/playbooks/missing", body: `{bad`, want: http.StatusBadRequest},
		{name: "playbook delete missing", handle: server.handlePlaybookRoute, method: http.MethodDelete, path: "/api/playbooks/missing", want: http.StatusNotFound},
		{name: "playbook run missing", handle: server.handlePlaybookRoute, method: http.MethodPost, path: "/api/playbooks/missing/run", want: http.StatusBadRequest},
		{name: "playbook run wrong method", handle: server.handlePlaybookRoute, method: http.MethodGet, path: "/api/playbooks/missing/run", want: http.StatusMethodNotAllowed},
		{name: "playbook last run missing", handle: server.handlePlaybookRoute, method: http.MethodGet, path: "/api/playbooks/missing/last-run", want: http.StatusNotFound},
		{name: "playbook last run wrong method", handle: server.handlePlaybookRoute, method: http.MethodPost, path: "/api/playbooks/missing/last-run", want: http.StatusMethodNotAllowed},
		{name: "saved search create invalid model", handle: server.handleSavedSearches, method: http.MethodPost, path: "/api/hunting/saved-searches", body: `{"name":""}`, want: http.StatusBadRequest},
		{name: "saved search list wrong method", handle: server.handleSavedSearches, method: http.MethodDelete, path: "/api/hunting/saved-searches", want: http.StatusMethodNotAllowed},
		{name: "saved search empty id", handle: server.handleSavedSearchRoute, method: http.MethodGet, path: "/api/hunting/saved-searches/", want: http.StatusBadRequest},
		{name: "saved search get missing", handle: server.handleSavedSearchRoute, method: http.MethodGet, path: "/api/hunting/saved-searches/missing", want: http.StatusNotFound},
		{name: "saved search update bad json", handle: server.handleSavedSearchRoute, method: http.MethodPut, path: "/api/hunting/saved-searches/missing", body: `{bad`, want: http.StatusBadRequest},
		{name: "saved search update missing", handle: server.handleSavedSearchRoute, method: http.MethodPut, path: "/api/hunting/saved-searches/missing", body: `{"name":"Missing","query":"x"}`, want: http.StatusBadRequest},
		{name: "saved search delete missing", handle: server.handleSavedSearchRoute, method: http.MethodDelete, path: "/api/hunting/saved-searches/missing", want: http.StatusNotFound},
		{name: "saved search execute missing", handle: server.handleSavedSearchRoute, method: http.MethodPost, path: "/api/hunting/saved-searches/missing/execute", want: http.StatusBadRequest},
		{name: "saved search execute wrong method", handle: server.handleSavedSearchRoute, method: http.MethodGet, path: "/api/hunting/saved-searches/missing/execute", want: http.StatusMethodNotAllowed},
		{name: "hypothesis create invalid model", handle: server.handleHypotheses, method: http.MethodPost, path: "/api/hunting/hypotheses", body: `{"title":""}`, want: http.StatusBadRequest},
		{name: "hypothesis list wrong method", handle: server.handleHypotheses, method: http.MethodDelete, path: "/api/hunting/hypotheses", want: http.StatusMethodNotAllowed},
		{name: "hypothesis empty id", handle: server.handleHypothesisRoute, method: http.MethodGet, path: "/api/hunting/hypotheses/", want: http.StatusBadRequest},
		{name: "hypothesis get missing", handle: server.handleHypothesisRoute, method: http.MethodGet, path: "/api/hunting/hypotheses/missing", want: http.StatusNotFound},
		{name: "hypothesis update bad json", handle: server.handleHypothesisRoute, method: http.MethodPut, path: "/api/hunting/hypotheses/missing", body: `{bad`, want: http.StatusBadRequest},
		{name: "hypothesis update missing", handle: server.handleHypothesisRoute, method: http.MethodPut, path: "/api/hunting/hypotheses/missing", body: `{"title":"Missing"}`, want: http.StatusBadRequest},
		{name: "hypothesis delete missing", handle: server.handleHypothesisRoute, method: http.MethodDelete, path: "/api/hunting/hypotheses/missing", want: http.StatusNotFound},
		{name: "hypothesis evidence missing", handle: server.handleHypothesisRoute, method: http.MethodPost, path: "/api/hunting/hypotheses/missing/evidence", body: `{"description":"x"}`, want: http.StatusBadRequest},
		{name: "hypothesis evidence wrong method", handle: server.handleHypothesisRoute, method: http.MethodGet, path: "/api/hunting/hypotheses/missing/evidence", want: http.StatusMethodNotAllowed},
		{name: "hypothesis status missing", handle: server.handleHypothesisRoute, method: http.MethodPost, path: "/api/hunting/hypotheses/missing/status", body: `{"status":"confirmed"}`, want: http.StatusBadRequest},
		{name: "hypothesis status wrong method", handle: server.handleHypothesisRoute, method: http.MethodGet, path: "/api/hunting/hypotheses/missing/status", want: http.StatusMethodNotAllowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			tt.handle(rec, req)
			requireStatus(t, rec, tt.want)
		})
	}

	var payload struct {
		Name string `json:"name"`
	}
	rec := httptest.NewRecorder()
	if err := decodeJSONBodyTo(rec, httptest.NewRequest(http.MethodPost, "/decode", strings.NewReader(`{"name":"ok"}`)), &payload); err != nil || payload.Name != "ok" {
		t.Fatalf("decodeJSONBodyTo() payload=%+v err=%v", payload, err)
	}
}

func TestAnalysisHandlersCoverErrorBranches(t *testing.T) {
	analysis := &erroringAnalysisService{}
	media := &erroringMediaService{}
	server := &Server{analysis: analysis, media: media}

	for _, tt := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		path   string
		want   int
	}{
		{name: "global stats error", handle: server.handleGlobalTrafficStats, path: "/api/stats/traffic/global", want: http.StatusBadRequest},
		{name: "industrial error", handle: server.handleIndustrialAnalysis, path: "/api/analysis/industrial", want: http.StatusBadRequest},
		{name: "vehicle error", handle: server.handleVehicleAnalysis, path: "/api/analysis/vehicle", want: http.StatusBadRequest},
		{name: "c2 canceled", handle: server.handleC2Analysis, path: "/api/c2-analysis", want: http.StatusRequestTimeout},
		{name: "apt canceled", handle: server.handleAPTAnalysis, path: "/api/apt-analysis", want: http.StatusRequestTimeout},
		{name: "evidence canceled", handle: server.handleEvidence, path: "/api/evidence?modules=c2,usb", want: http.StatusRequestTimeout},
		{name: "usb generic error", handle: server.handleUSBAnalysis, path: "/api/analysis/usb?hid_source=auto&hid_event_limit=600", want: http.StatusInternalServerError},
		{name: "media refresh error", handle: server.handleMediaAnalysis, path: "/api/analysis/media?refresh=true", want: http.StatusBadRequest},
		{name: "media normal error", handle: server.handleMediaAnalysis, path: "/api/analysis/media", want: http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handle(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			requireStatus(t, rec, tt.want)
		})
	}

	rec := httptest.NewRecorder()
	server.handleObjects(rec, httptest.NewRequest(http.MethodPost, "/api/objects", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestObjectsDownloadCoversSelectionAndPayloadErrors(t *testing.T) {
	tooMany := make([]model.ObjectFile, 101)
	for i := range tooMany {
		tooMany[i] = model.ObjectFile{ID: int64(i + 1), Name: "obj.bin", Path: "missing.bin"}
	}
	server := &Server{detection: &apiContractDetectionService{objects: tooMany}}

	rec := httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodGet, "/api/objects/download", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodPost, "/api/objects/download", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodGet, "/api/objects/download?ids=999,abc", nil))
	requireStatus(t, rec, http.StatusNotFound)

	server = &Server{detection: &apiContractDetectionService{objects: []model.ObjectFile{{ID: 1, Name: "missing.bin", Path: "missing.bin"}}}}
	rec = httptest.NewRecorder()
	server.handleObjectsDownload(rec, httptest.NewRequest(http.MethodPost, "/api/objects/download", strings.NewReader(`{"ids":[1]}`)))
	requireStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("zip content-type = %q", got)
	}
}

func (erroringMediaService) MediaAnalysisWithContext(context.Context) (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, errors.New("media failed")
}

func (erroringMediaService) RefreshMediaAnalysisWithContext(context.Context) (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, errors.New("refresh failed")
}

type erroringAnalysisService struct{ contractAnalysisService }

func (erroringAnalysisService) GlobalTrafficStatsWithContext(context.Context) (model.GlobalTrafficStats, error) {
	return model.GlobalTrafficStats{}, errors.New("stats failed")
}

func (erroringAnalysisService) IndustrialAnalysisWithContext(context.Context) (model.IndustrialAnalysis, error) {
	return model.IndustrialAnalysis{}, errors.New("industrial failed")
}

func (erroringAnalysisService) VehicleAnalysisWithContext(context.Context) (model.VehicleAnalysis, error) {
	return model.VehicleAnalysis{}, errors.New("vehicle failed")
}

func (erroringAnalysisService) USBAnalysisWithOptions(context.Context, model.USBAnalysisOptions) (model.USBAnalysis, error) {
	return model.USBAnalysis{}, errors.New("usb exploded")
}

func (erroringAnalysisService) C2SampleAnalysis(context.Context) (model.C2SampleAnalysis, error) {
	return model.C2SampleAnalysis{}, context.Canceled
}

func (erroringAnalysisService) APTAnalysis(context.Context) (model.APTAnalysis, error) {
	return model.APTAnalysis{}, context.Canceled
}

func (erroringAnalysisService) GatherEvidence(context.Context, model.EvidenceFilter) (model.EvidenceResponse, error) {
	return model.EvidenceResponse{}, context.Canceled
}

type erroringMediaService struct{ contractMediaService }

func (erroringMediaService) MediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, errors.New("media failed")
}

func (erroringMediaService) RefreshMediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, errors.New("refresh failed")
}
