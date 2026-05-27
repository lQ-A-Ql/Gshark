package model

type CaptureStatus struct {
	FilePath    string             `json:"file_path"`
	HasCapture  bool               `json:"has_capture"`
	PacketCount int                `json:"packet_count"`
	Load        *CaptureLoadStatus `json:"load,omitempty"`
}

type CaptureLoadPhase string

const (
	CaptureLoadIdle       CaptureLoadPhase = "idle"
	CaptureLoadStarting   CaptureLoadPhase = "starting"
	CaptureLoadCounting   CaptureLoadPhase = "counting"
	CaptureLoadParsing    CaptureLoadPhase = "parsing"
	CaptureLoadCommitting CaptureLoadPhase = "committing"
	CaptureLoadReady      CaptureLoadPhase = "ready"
	CaptureLoadFailed     CaptureLoadPhase = "failed"
	CaptureLoadCanceled   CaptureLoadPhase = "canceled"
)

type CaptureEnrichmentStatus struct {
	Phase     string `json:"phase"`
	Processed int    `json:"processed"`
	Updated   int    `json:"updated"`
	LastError string `json:"last_error,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type CaptureLoadStatus struct {
	RunID          int64                    `json:"run_id"`
	FilePath       string                   `json:"file_path"`
	Phase          string                   `json:"phase"`
	ParserProfile  string                   `json:"parser_profile"`
	EstimatedTotal int                      `json:"estimated_total,omitempty"`
	Processed      int                      `json:"processed"`
	Accepted       int                      `json:"accepted"`
	StagedCount    int                      `json:"staged_count"`
	LastError      string                   `json:"last_error,omitempty"`
	StartedAt      string                   `json:"started_at,omitempty"`
	UpdatedAt      string                   `json:"updated_at,omitempty"`
	CompletedAt    string                   `json:"completed_at,omitempty"`
	Enrichment     *CaptureEnrichmentStatus `json:"enrichment,omitempty"`
}
