package model

type InvestigationReport struct {
	Summary         []InvestigationReportItem `json:"summary,omitempty"`
	Evidence        []InvestigationReportItem `json:"evidence,omitempty"`
	Details         []InvestigationReportItem `json:"details,omitempty"`
	Recommendations []string                  `json:"recommendations,omitempty"`
}

type InvestigationReportItem struct {
	Title    string   `json:"title"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	PacketID int64    `json:"packet_id,omitempty"`
	StreamID int64    `json:"stream_id,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}
