package transport

import (
	"context"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/servicecontract"
)

// CaptureService covers capture lifecycle together with packet/stream lookups
// consumed by the HTTP transport layer. It embeds the shared read-only
// contract and adds transport-only lifecycle methods.
type CaptureService interface {
	servicecontract.CaptureReadService

	// Transport-only lifecycle methods:
	BeginCaptureLoad(ctx context.Context) (int64, context.Context)
	LoadPCAPWithRun(runCtx context.Context, opts model.ParseOptions, currentRunID int64) error
	PrepareCaptureReplacement()
	StopStreaming() bool
	ClearCapture() error
	CurrentCapturePath() string
	Packets() []model.Packet
	PacketPageCursorWithError(packetID int64, limit int, filter string) (int, int, bool, error)
	UpdateStreamPayloads(ctx context.Context, protocol string, streamID int64, patches []model.StreamChunkPatch) (model.ReassembledStream, error)
}

// DetectionService groups threat hunting, YARA configuration and object export
// functionality consumed by the transport layer. It embeds the shared
// read-only contract and adds transport-only setters.
type DetectionService interface {
	servicecontract.DetectionReadService

	// Transport-only setter:
	SetHuntingRuntimeConfig(cfg model.HuntingRuntimeConfig) model.HuntingRuntimeConfig
}

// AnalysisService groups the industrial / vehicle / USB / C2 / APT / traffic /
// evidence analysis methods consumed by the transport layer. It embeds the
// shared read-only contract and adds transport-only convenience methods.
type AnalysisService interface {
	servicecontract.AnalysisReadService

	// Transport-only convenience methods (non-context variants + DBC + evidence):
	GlobalTrafficStats() (model.GlobalTrafficStats, error)
	IndustrialAnalysis() (model.IndustrialAnalysis, error)
	VehicleAnalysis() (model.VehicleAnalysis, error)
	VehicleDBCProfiles() []model.DBCProfile
	AddVehicleDBC(path string) ([]model.DBCProfile, error)
	RemoveVehicleDBC(path string) []model.DBCProfile
	USBAnalysis() (model.USBAnalysis, error)
	USBAnalysisWithContext(ctx context.Context) (model.USBAnalysis, error)
	GatherEvidence(ctx context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error)
}

// MediaService groups media playback, media artifact export and speech
// transcription methods consumed by the transport layer. It embeds the shared
// read-only contract and adds transport-only media pipeline methods.
type MediaService interface {
	servicecontract.MediaReadService

	// Transport-only media pipeline methods:
	RefreshMediaAnalysis() (model.MediaAnalysis, error)
	RefreshMediaAnalysisWithContext(ctx context.Context) (model.MediaAnalysis, error)
	MediaArtifact(token string) (string, string, error)
	MediaPlaybackWithContext(ctx context.Context, token string) (string, string, error)
	TranscribeMediaArtifact(token string, force bool) (model.MediaTranscription, error)
	TranscribeMediaArtifactWithContext(ctx context.Context, token string, force bool) (model.MediaTranscription, error)
	MediaBatchTranscriptionStatus() model.SpeechBatchTaskStatus
	StartMediaBatchTranscription(force bool) (model.SpeechBatchTaskStatus, error)
	CancelMediaBatchTranscription() model.SpeechBatchTaskStatus
	ExportMediaBatchTranscription() model.MediaTranscriptionBatchExport
	SpeechToTextStatus() model.SpeechToTextStatus
}

// ToolRuntimeService groups tool runtime configuration (tshark / ffmpeg / TLS)
// methods consumed by the transport layer. It embeds the shared read-only
// contract and adds transport-only configuration methods.
type ToolRuntimeService interface {
	servicecontract.ToolRuntimeReadService

	// Transport-only configuration methods:
	TSharkStatus() model.TSharkToolStatus
	TSharkStatusWithContext(ctx context.Context) model.TSharkToolStatus
	SetTSharkPath(path string) model.TSharkToolStatus
	SetTSharkPathWithContext(ctx context.Context, path string) model.TSharkToolStatus
	AllowTSharkDirWithContext(ctx context.Context, dir string) model.TSharkToolStatus
	TSharkAllowedDirs() []string
	RemoveTSharkAllowedDirWithContext(ctx context.Context, dir string) model.TSharkToolStatus
	AllowToolDirWithContext(ctx context.Context, toolName string, dir string) model.ToolRuntimeSnapshot
	ToolAllowedDirs(toolName string) []string
	RemoveToolAllowedDirWithContext(ctx context.Context, toolName string, dir string) model.ToolRuntimeSnapshot
	TSharkStatusPath() string
	TSharkUsingCustomPath() bool
	ToolRuntimeSnapshot() model.ToolRuntimeSnapshot
	ToolRuntimeSnapshotWithContext(ctx context.Context) model.ToolRuntimeSnapshot
	ToolRuntimeSnapshotWithOptions(ctx context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot
	SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig
	FFmpegStatus() model.FFmpegToolStatus
	TLSConfig() model.TLSConfig
	SetTLSConfig(cfg model.TLSConfig)
	MCPConfig() model.MCPConfig
	SetMCPConfig(cfg model.MCPConfig) model.MCPConfig
	MCPStatus(authRequired bool) model.MCPStatus
}

// ToolRuntimeReadService defines the tool-runtime snapshot read methods
// shared across consumers.
type ToolRuntimeReadService interface {
	ToolRuntimeSnapshotWithOptions(ctx context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot
}

// ToolAnalysisService groups per-tool analysis methods (NTLM / HTTP-login /
// SMTP / MySQL / Shiro / SMB3 / WinRM / UDP-tunnel / bruteforce) consumed by
// the transport layer. It embeds the shared read-only contract and adds
// transport-only convenience methods.
type ToolAnalysisService interface {
	servicecontract.ToolAnalysisReadService

	// Transport-only convenience methods (non-context variants + export):
	ListNTLMSessionMaterials() ([]model.NTLMSessionMaterial, error)
	ListSMB3SessionCandidates() ([]model.SMB3SessionCandidate, error)
	GenerateSMB3RandomSessionKey(req model.SMB3RandomSessionKeyRequest) (model.SMB3RandomSessionKeyResult, error)
	RunWinRMDecrypt(req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error)
	WinRMExportFile(resultID string) (string, string, error)
}

// PlaybookService groups hunting playbook, saved search and hypothesis
// management methods consumed by the transport layer.
type PlaybookService interface {
	// Playbook CRUD:
	ListPlaybooks() []model.HuntingPlaybook
	GetPlaybook(id string) (*model.HuntingPlaybook, bool)
	CreatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error)
	UpdatePlaybook(pb model.HuntingPlaybook) (*model.HuntingPlaybook, error)
	DeletePlaybook(id string) bool
	RunPlaybook(ctx context.Context, playbookID string) (*model.PlaybookRunResult, error)
	GetPlaybookLastRun(playbookID string) (*model.PlaybookRunResult, bool)

	// Saved search CRUD:
	ListSavedSearches() []model.SavedSearch
	GetSavedSearch(id string) (*model.SavedSearch, bool)
	CreateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error)
	UpdateSavedSearch(ss model.SavedSearch) (*model.SavedSearch, error)
	DeleteSavedSearch(id string) bool
	ExecuteSavedSearch(id string) (*model.SavedSearch, []model.ThreatHit, error)

	// Hypothesis CRUD:
	ListHypotheses(statusFilter string) []model.Hypothesis
	GetHypothesis(id string) (*model.Hypothesis, bool)
	CreateHypothesis(h model.Hypothesis) (*model.Hypothesis, error)
	UpdateHypothesis(h model.Hypothesis) (*model.Hypothesis, error)
	DeleteHypothesis(id string) bool
	AddHypothesisEvidence(hypothesisID string, evidence model.HypothesisEvidence) (*model.Hypothesis, error)
	UpdateHypothesisStatus(id string, status model.HypothesisStatus, conclusion string) (*model.Hypothesis, error)
}
