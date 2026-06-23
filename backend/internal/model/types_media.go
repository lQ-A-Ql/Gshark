package model

type MediaArtifact struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	Codec     string `json:"codec,omitempty"`
	Format    string `json:"format,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
}

type MediaSession struct {
	ID              string         `json:"id"`
	MediaType       string         `json:"media_type"`
	Family          string         `json:"family"`
	Application     string         `json:"application"`
	Source          string         `json:"source"`
	SourcePort      int            `json:"source_port"`
	Destination     string         `json:"destination"`
	DestinationPort int            `json:"destination_port"`
	Transport       string         `json:"transport"`
	SSRC            string         `json:"ssrc,omitempty"`
	PayloadType     string         `json:"payload_type,omitempty"`
	Codec           string         `json:"codec,omitempty"`
	ClockRate       int            `json:"clock_rate,omitempty"`
	StartTime       string         `json:"start_time,omitempty"`
	EndTime         string         `json:"end_time,omitempty"`
	PacketCount     int            `json:"packet_count"`
	GapCount        int            `json:"gap_count"`
	ControlSummary  string         `json:"control_summary,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Artifact        *MediaArtifact `json:"artifact,omitempty"`
}

type MediaAnalysis struct {
	TotalMediaPackets int             `json:"total_media_packets"`
	Protocols         []TrafficBucket `json:"protocols"`
	Applications      []TrafficBucket `json:"applications"`
	Sessions          []MediaSession  `json:"sessions"`
	Notes             []string        `json:"notes"`
}

type SpeechToTextStatus struct {
	Available             bool   `json:"available"`
	Engine                string `json:"engine"`
	Language              string `json:"language"`
	PythonAvailable       bool   `json:"python_available"`
	PythonCommand         string `json:"python_command,omitempty"`
	PythonPathWarning     string `json:"python_path_warning,omitempty"`
	PythonExtraAllowedDir string `json:"python_extra_allowed_dir,omitempty"`
	FFmpegAvailable       bool   `json:"ffmpeg_available"`
	VoskAvailable         bool   `json:"vosk_available"`
	ModelAvailable        bool   `json:"model_available"`
	ModelPath             string `json:"model_path,omitempty"`
	Message               string `json:"message"`
}

type MediaTranscriptionSegment struct {
	StartSeconds float64 `json:"start_seconds"`
	EndSeconds   float64 `json:"end_seconds"`
	Text         string  `json:"text"`
}

type MediaTranscription struct {
	Token           string                      `json:"token"`
	SessionID       string                      `json:"session_id"`
	Title           string                      `json:"title"`
	Text            string                      `json:"text"`
	Language        string                      `json:"language"`
	Engine          string                      `json:"engine"`
	Status          string                      `json:"status"`
	Error           string                      `json:"error,omitempty"`
	Cached          bool                        `json:"cached"`
	DurationSeconds float64                     `json:"duration_seconds"`
	Segments        []MediaTranscriptionSegment `json:"segments,omitempty"`
}

type SpeechBatchTaskItem struct {
	Token      string `json:"token"`
	SessionID  string `json:"session_id"`
	MediaLabel string `json:"media_label"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Cached     bool   `json:"cached"`
	Text       string `json:"text,omitempty"`
}

type SpeechBatchTaskStatus struct {
	TaskID       string                `json:"task_id"`
	Total        int                   `json:"total"`
	Queued       int                   `json:"queued"`
	Running      int                   `json:"running"`
	Completed    int                   `json:"completed"`
	Failed       int                   `json:"failed"`
	Skipped      int                   `json:"skipped"`
	CurrentToken string                `json:"current_token,omitempty"`
	CurrentLabel string                `json:"current_label,omitempty"`
	Done         bool                  `json:"done"`
	Cancelled    bool                  `json:"cancelled"`
	Items        []SpeechBatchTaskItem `json:"items"`
}

type MediaTranscriptionBatchItem struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Title     string `json:"title"`
	Text      string `json:"text"`
	Status    string `json:"status"`
	Cached    bool   `json:"cached"`
}

type MediaTranscriptionBatchExport struct {
	TaskID   string                        `json:"task_id"`
	Engine   string                        `json:"engine"`
	Language string                        `json:"language"`
	Items    []MediaTranscriptionBatchItem `json:"items"`
}
