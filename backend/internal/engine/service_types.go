package engine

import (
	"context"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

// captureState groups fields related to the capture lifecycle:
// loading PCAPs, tracking active loads, and managing capture tasks.
type captureState struct {
	mu               sync.RWMutex
	loadMu           sync.Mutex
	activeLoadMu     sync.Mutex
	activeLoadID     int64
	activeLoadCancel context.CancelFunc
	activeLoadStatus *model.CaptureLoadStatus
	captureTaskMu    sync.Mutex
	captureTaskSeq   int64
	captureTasks     map[int64]captureTaskCancel
	packetStore      *packetStore
	runID            int64
	pcap             string
	cancel           context.CancelFunc
}

// displayFilterState groups the tshark display-filter result cache.
type displayFilterState struct {
	displayFilterCache      map[string]*filteredPacketIndex
	displayFilterCacheOrder []string
}

// streamState groups the reassembled-stream cache and overrides.
type streamState struct {
	streamCache      map[string]model.ReassembledStream
	streamCacheOrder []string
	rawStreamIndex   map[string]model.ReassembledStream
	streamOverrides  map[string]map[int]string
}

// analysisCache holds cached analysis results for traffic, protocols,
// C2, APT, USB, industrial, vehicle, and media analysis.
type analysisCache struct {
	globalTrafficStats  *model.GlobalTrafficStats
	industrialAnalysis  *model.IndustrialAnalysis
	vehicleAnalysis     *model.VehicleAnalysis
	mediaAnalysis       *model.MediaAnalysis
	usbAnalysis         *model.USBAnalysis
	usbAnalysisBySource map[string]*model.USBAnalysis
	c2Analysis          *model.C2SampleAnalysis
	aptAnalysis         *model.APTAnalysis
	vehicleDBCDefs      []*tshark.DBCDatabase
}

// objectState groups exported object metadata and directory.
type objectState struct {
	exportDir     string
	objectsLoaded bool
	objects       []model.ObjectFile
	objMu         sync.Mutex
}

// mediaState groups media playback, speech-to-text, and media artifacts.
type mediaState struct {
	mediaExportDir string
	mediaArtifacts map[string]string
	mediaPlayback  map[string]string
	mediaSpeech    map[string]model.MediaTranscription
	speechBatch    *model.SpeechBatchTaskStatus
	speechCancel   context.CancelFunc
}

// yaraHuntingState groups YARA scanning state and threat-hunting prefixes.
type yaraHuntingState struct {
	yaraLoaded      bool
	yaraScanning    bool
	yaraHits        []model.ThreatHit
	yaraLastError   string
	yaraMu          sync.Mutex
	huntMu          sync.RWMutex
	huntingPrefixes []string
	yaraConf        model.YaraConfig
}

// toolRuntimeState groups the tool runtime configuration surface
// (tshark path, ffmpeg/python/vosk env vars, TLS config).
type toolRuntimeState struct {
	toolRuntimeMu          sync.RWMutex
	toolRuntimeFullProbeMu sync.Mutex
	tlsConf                model.TLSConfig
}

// mcpState groups the MCP server configuration.
type mcpState struct {
	mcpMu     sync.RWMutex
	mcpConfig model.MCPConfig
}

// playbookState groups hunting playbook storage and execution results.
type playbookStatePB struct {
	playbookMu sync.RWMutex
	playbooks  map[string]*model.HuntingPlaybook
	lastRun    map[string]*model.PlaybookRunResult
}

// savedSearchState groups saved search storage.
type savedSearchStateSS struct {
	searchMu      sync.RWMutex
	savedSearches map[string]*model.SavedSearch
}

// hypothesisState groups hypothesis tracking storage.
type hypothesisStateHT struct {
	hypothesisMu sync.RWMutex
	hypotheses   map[string]*model.Hypothesis
}
