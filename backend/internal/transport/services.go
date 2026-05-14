package transport

import (
	"context"

	"github.com/gshark/sentinel/backend/internal/model"
)

// CaptureService covers capture lifecycle together with packet/stream lookups
// consumed by the HTTP transport layer. It is intentionally narrow: only the
// methods actually invoked by the transport layer are declared.
type CaptureService interface {
	BeginCaptureLoad(ctx context.Context) (int64, context.Context)
	LoadPCAPWithRun(runCtx context.Context, opts model.ParseOptions, currentRunID int64) error
	PrepareCaptureReplacement()
	StopStreaming() bool
	ClearCapture() error
	CaptureStatus() model.CaptureStatus
	CurrentCapturePath() string

	Packets() []model.Packet
	PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error)
	PacketPageCursorWithError(packetID int64, limit int, filter string) (int, int, bool, error)
	Packet(packetID int64) (model.Packet, error)
	PacketRawHex(packetID int64) (string, error)
	PacketLayers(packetID int64) (map[string]any, error)

	StreamIDs(protocol string) []int64
	HTTPStream(ctx context.Context, streamID int64) model.ReassembledStream
	RawStream(ctx context.Context, protocol string, streamID int64) model.ReassembledStream
	RawStreamPage(ctx context.Context, protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int)
	UpdateStreamPayloads(ctx context.Context, protocol string, streamID int64, patches []model.StreamChunkPatch) (model.ReassembledStream, error)
	ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error)
}

// DetectionService groups threat hunting, YARA configuration and object export
// functionality consumed by the transport layer.
type DetectionService interface {
	ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit
	GetHuntingRuntimeConfig() model.HuntingRuntimeConfig
	SetHuntingRuntimeConfig(cfg model.HuntingRuntimeConfig) model.HuntingRuntimeConfig
	ObjectsWithContext(ctx context.Context) []model.ObjectFile
}

// AnalysisService groups the industrial / vehicle / USB / C2 / APT / traffic /
// evidence analysis methods consumed by the transport layer.
type AnalysisService interface {
	GlobalTrafficStats() (model.GlobalTrafficStats, error)
	GlobalTrafficStatsWithContext(ctx context.Context) (model.GlobalTrafficStats, error)
	IndustrialAnalysis() (model.IndustrialAnalysis, error)
	IndustrialAnalysisWithContext(ctx context.Context) (model.IndustrialAnalysis, error)
	VehicleAnalysis() (model.VehicleAnalysis, error)
	VehicleAnalysisWithContext(ctx context.Context) (model.VehicleAnalysis, error)
	VehicleDBCProfiles() []model.DBCProfile
	AddVehicleDBC(path string) ([]model.DBCProfile, error)
	RemoveVehicleDBC(path string) []model.DBCProfile
	USBAnalysis() (model.USBAnalysis, error)
	USBAnalysisWithContext(ctx context.Context) (model.USBAnalysis, error)
	C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error)
	C2Decrypt(ctx context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error)
	APTAnalysis(ctx context.Context) (model.APTAnalysis, error)
	GatherEvidence(ctx context.Context, filter model.EvidenceFilter) (model.EvidenceResponse, error)
}

// MediaService groups media playback, media artifact export and speech
// transcription methods consumed by the transport layer.
type MediaService interface {
	MediaAnalysis() (model.MediaAnalysis, error)
	RefreshMediaAnalysis() (model.MediaAnalysis, error)
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
// methods consumed by the transport layer.
type ToolRuntimeService interface {
	TSharkStatus() model.TSharkToolStatus
	SetTSharkPath(path string) model.TSharkToolStatus
	TSharkStatusPath() string
	TSharkUsingCustomPath() bool
	ToolRuntimeSnapshot() model.ToolRuntimeSnapshot
	SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig
	FFmpegStatus() model.FFmpegToolStatus
	TLSConfig() model.TLSConfig
	SetTLSConfig(cfg model.TLSConfig)
}

// ToolAnalysisService groups per-tool analysis methods (NTLM / HTTP-login /
// SMTP / MySQL / Shiro / SMB3 / WinRM) consumed by the transport layer.
type ToolAnalysisService interface {
	ListNTLMSessionMaterials() ([]model.NTLMSessionMaterial, error)
	ListNTLMSessionMaterialsWithContext(ctx context.Context) ([]model.NTLMSessionMaterial, error)
	HTTPLoginAnalysis(ctx context.Context) (model.HTTPLoginAnalysis, error)
	SMTPAnalysis(ctx context.Context) (model.SMTPAnalysis, error)
	MySQLAnalysis(ctx context.Context) (model.MySQLAnalysis, error)
	ShiroRememberMeAnalysis(ctx context.Context, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error)
	ListSMB3SessionCandidates() ([]model.SMB3SessionCandidate, error)
	ListSMB3SessionCandidatesWithContext(ctx context.Context) ([]model.SMB3SessionCandidate, error)
	GenerateSMB3RandomSessionKey(req model.SMB3RandomSessionKeyRequest) (model.SMB3RandomSessionKeyResult, error)
	RunWinRMDecrypt(req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error)
	RunWinRMDecryptWithContext(ctx context.Context, req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error)
	WinRMExportFile(resultID string) (string, string, error)
}

// PluginService groups the plugin registry methods consumed by the transport
// layer.
type PluginService interface {
	ListPlugins() []model.Plugin
	AddPlugin(p model.Plugin) (model.Plugin, error)
	DeletePlugin(id string) error
	PluginSource(id string) (model.PluginSource, error)
	UpdatePluginSource(source model.PluginSource) (model.PluginSource, error)
	TogglePlugin(id string) (model.Plugin, error)
	SetPluginsEnabled(ids []string, enabled bool) ([]model.Plugin, error)
}
