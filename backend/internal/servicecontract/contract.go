// Package servicecontract defines shared read-only service interfaces used by
// multiple consumers (transport, MCP, future gRPC, etc.). This follows the
// "ports" pattern from hexagonal architecture: the interfaces live in a
// neutral leaf package so that no transport package imports another.
package servicecontract

import (
	"context"

	"github.com/gshark/sentinel/backend/internal/model"
)

type AnalysisRequestSource string

const (
	AnalysisRequestSourceUser   AnalysisRequestSource = "user"
	AnalysisRequestSourceWarmup AnalysisRequestSource = "warmup"
)

type AnalysisRequestPriority string

const (
	AnalysisRequestPriorityNormal     AnalysisRequestPriority = "normal"
	AnalysisRequestPriorityBackground AnalysisRequestPriority = "background"
)

type AnalysisRequestMeta struct {
	Source      AnalysisRequestSource
	Priority    AnalysisRequestPriority
	Target      string
	CapturePath string
	TimeoutMS   int
}

type analysisRequestMetaKey struct{}

func WithAnalysisRequestMeta(ctx context.Context, meta AnalysisRequestMeta) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if meta.Source == "" {
		meta.Source = AnalysisRequestSourceUser
	}
	if meta.Priority == "" {
		meta.Priority = AnalysisRequestPriorityNormal
	}
	return context.WithValue(ctx, analysisRequestMetaKey{}, meta)
}

func AnalysisRequestMetaFromContext(ctx context.Context) AnalysisRequestMeta {
	if ctx == nil {
		return AnalysisRequestMeta{Source: AnalysisRequestSourceUser, Priority: AnalysisRequestPriorityNormal}
	}
	if meta, ok := ctx.Value(analysisRequestMetaKey{}).(AnalysisRequestMeta); ok {
		if meta.Source == "" {
			meta.Source = AnalysisRequestSourceUser
		}
		if meta.Priority == "" {
			meta.Priority = AnalysisRequestPriorityNormal
		}
		return meta
	}
	return AnalysisRequestMeta{Source: AnalysisRequestSourceUser, Priority: AnalysisRequestPriorityNormal}
}

func IsAnalysisWarmup(ctx context.Context) bool {
	return AnalysisRequestMetaFromContext(ctx).Source == AnalysisRequestSourceWarmup
}

// CaptureReadService defines the read-only capture and packet/stream query
// methods shared across consumers.
type CaptureReadService interface {
	CaptureStatus() model.CaptureStatus
	PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error)
	Packet(packetID int64) (model.Packet, error)
	PacketRawHex(packetID int64) (string, error)
	PacketLayers(packetID int64) (map[string]any, error)
	StreamIDs(protocol string) []int64
	HTTPStream(ctx context.Context, streamID int64) model.ReassembledStream
	RawStream(ctx context.Context, protocol string, streamID int64) model.ReassembledStream
	RawStreamPage(ctx context.Context, protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int)
	ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error)
}

// DetectionReadService defines the read-only detection methods shared across
// consumers (threat hunting, object listing, hunting config).
type DetectionReadService interface {
	ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit
	ObjectsWithContext(ctx context.Context) []model.ObjectFile
	GetHuntingRuntimeConfig() model.HuntingRuntimeConfig
}

// AnalysisReadService defines the read-only analysis methods shared across
// consumers (traffic stats, industrial, vehicle, USB, C2, APT).
type AnalysisReadService interface {
	GlobalTrafficStatsWithContext(ctx context.Context) (model.GlobalTrafficStats, error)
	IndustrialAnalysisWithContext(ctx context.Context) (model.IndustrialAnalysis, error)
	VehicleAnalysisWithContext(ctx context.Context) (model.VehicleAnalysis, error)
	USBAnalysisWithOptions(ctx context.Context, opts model.USBAnalysisOptions) (model.USBAnalysis, error)
	C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error)
	C2Decrypt(ctx context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error)
	APTAnalysis(ctx context.Context) (model.APTAnalysis, error)
}

// MediaReadService defines the media analysis read methods shared across
// consumers.
type MediaReadService interface {
	MediaAnalysis() (model.MediaAnalysis, error)
}

// ToolRuntimeReadService defines the tool-runtime snapshot read methods
// shared across consumers.
type ToolRuntimeReadService interface {
	ToolRuntimeSnapshotWithOptions(ctx context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot
}

// ToolAnalysisReadService defines the per-tool analysis methods shared across
// consumers (NTLM, HTTP-login, SMTP, MySQL, Shiro, SMB3, WinRM, UDP-tunnel,
// bruteforce).
type ToolAnalysisReadService interface {
	ListNTLMSessionMaterialsWithContext(ctx context.Context) ([]model.NTLMSessionMaterial, error)
	HTTPLoginAnalysis(ctx context.Context) (model.HTTPLoginAnalysis, error)
	SMTPAnalysis(ctx context.Context) (model.SMTPAnalysis, error)
	MySQLAnalysis(ctx context.Context) (model.MySQLAnalysis, error)
	ShiroRememberMeAnalysis(ctx context.Context, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error)
	ListSMB3SessionCandidatesWithContext(ctx context.Context) ([]model.SMB3SessionCandidate, error)
	RunWinRMDecryptWithContext(ctx context.Context, req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error)
	UDPTunnelAnalysis(ctx context.Context) (model.UDPTunnelAnalysis, error)
	BruteforceAnalysis(ctx context.Context) (model.BruteforceAnalysis, error)
}
