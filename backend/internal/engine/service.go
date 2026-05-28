package engine

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"os"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type Service struct {
	emitter EventEmitter

	mu                      sync.RWMutex
	loadMu                  sync.Mutex
	activeLoadMu            sync.Mutex
	activeLoadID            int64
	activeLoadCancel        context.CancelFunc
	activeLoadStatus        *model.CaptureLoadStatus
	captureTaskMu           sync.Mutex
	captureTaskSeq          int64
	captureTasks            map[int64]captureTaskCancel
	packetStore             *packetStore
	tlsConf                 model.TLSConfig
	runID                   int64
	pcap                    string
	displayFilterCache      map[string]*filteredPacketIndex
	displayFilterCacheOrder []string
	globalTrafficStats      *model.GlobalTrafficStats
	industrialAnalysis      *model.IndustrialAnalysis
	vehicleAnalysis         *model.VehicleAnalysis
	mediaAnalysis           *model.MediaAnalysis
	usbAnalysis             *model.USBAnalysis
	usbAnalysisBySource     map[string]*model.USBAnalysis
	c2Analysis              *model.C2SampleAnalysis
	aptAnalysis             *model.APTAnalysis
	vehicleDBCDefs          []*tshark.DBCDatabase
	streamCache             map[string]model.ReassembledStream
	streamCacheOrder        []string
	rawStreamIndex          map[string]model.ReassembledStream
	streamOverrides         map[string]map[int]string

	exportDir      string
	mediaExportDir string
	objectsLoaded  bool
	objects        []model.ObjectFile
	mediaArtifacts map[string]string
	mediaPlayback  map[string]string
	mediaSpeech    map[string]model.MediaTranscription
	speechBatch    *model.SpeechBatchTaskStatus
	speechCancel   context.CancelFunc
	objMu          sync.Mutex
	yaraLoaded     bool
	yaraScanning   bool
	yaraHits       []model.ThreatHit
	yaraLastError  string
	yaraMu         sync.Mutex

	// toolRuntimeMu serializes reads and writes of the tool runtime
	// configuration surface (tshark path, ffmpeg/python/vosk env vars and
	// the yaraConf slice below). It wraps the composite ToolRuntimeConfig
	// read so callers always observe a consistent snapshot.
	toolRuntimeMu sync.RWMutex
	// toolRuntimeFullProbeMu prevents repeated full runtime probes from
	// launching duplicate tshark/Python capability processes concurrently.
	toolRuntimeFullProbeMu sync.Mutex

	huntMu          sync.RWMutex
	huntingPrefixes []string
	yaraConf        model.YaraConfig

	cancel context.CancelFunc

	mcpMu     sync.RWMutex
	mcpConfig model.MCPConfig
}

const defaultStreamCacheLimit = 256
const displayFilterCacheLimit = 16
const skipEstimateFileSizeThreshold int64 = 256 << 20

type filteredPacketIndex struct {
	mu        sync.Mutex
	cond      *sync.Cond
	ids       []int64
	positions map[int64]int
	complete  bool
	err       error
	cancel    context.CancelFunc
}

type captureTaskCancel struct {
	name   string
	cancel context.CancelFunc
}

type DisplayFilterError struct {
	Filter string
	Err    error
}

func (e *DisplayFilterError) Error() string {
	if e == nil || e.Err == nil {
		return "display filter execution failed"
	}
	return e.Err.Error()
}

func (e *DisplayFilterError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func IsDisplayFilterError(err error) bool {
	var target *DisplayFilterError
	return errors.As(err, &target)
}

var (
	estimatePacketsFn     = tshark.EstimatePackets
	filterFrameIDsFn      = tshark.FilterFrameIDs
	scanFrameIDsFn        = tshark.ScanFrameIDs
	streamPacketsFn       = tshark.StreamPackets
	streamPacketsFirstFn  = tshark.StreamPacketsFirstScreen
	streamPacketsFastFn   = tshark.StreamPacketsFast
	streamPacketsCompatFn = tshark.StreamPacketsCompat
	httpStreamFromFileFn  = tshark.ReassembleHTTPStreamFromFileContext
	rawStreamFromFileFn   = tshark.ReassembleRawStreamFromFileContext
)

func NewService(emitter EventEmitter) *Service {
	if emitter == nil {
		emitter = NopEmitter{}
	}
	store, err := newPacketStore()
	if err != nil {
		log.Fatalf("engine: init packet store: %v", err)
	}
	return &Service{
		emitter:            emitter,
		packetStore:        store,
		captureTasks:       map[int64]captureTaskCancel{},
		displayFilterCache: map[string]*filteredPacketIndex{},
		streamCache:        map[string]model.ReassembledStream{},
		rawStreamIndex:     map[string]model.ReassembledStream{},
		streamOverrides:    map[string]map[int]string{},
		mediaArtifacts:     map[string]string{},
		mediaPlayback:      map[string]string{},
		mediaSpeech:        map[string]model.MediaTranscription{},
		huntingPrefixes: []string{
			"flag{",
			"ctf{",
		},
		yaraConf: model.YaraConfig{
			Enabled:   true,
			TimeoutMS: 25000,
		},
	}
}

func (s *Service) emitStatus(status string) {
	if s == nil || s.emitter == nil {
		return
	}
	s.emitter.EmitStatus(status)
}

func streamFollowTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GSHARK_STREAM_FOLLOW_TIMEOUT_MS"))
	if raw == "" {
		return 20 * time.Second
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 20 * time.Second
	}
	if parsed > 60000 {
		parsed = 60000
	}
	return time.Duration(parsed) * time.Millisecond
}
