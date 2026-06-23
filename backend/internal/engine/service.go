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
	"github.com/gshark/sentinel/backend/internal/tool"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type Service struct {
	emitter        EventEmitter
	captureCtl     captureController
	filterCtl      displayFilterController
	streamCtl      streamController
	analysisCtl    analysisController
	objectCtl      objectController
	mediaCtl       mediaController
	huntingCtl     yaraHuntingController
	runtimeCtl     toolRuntimeController
	mcpCtl         mcpController
	playbookCtl    playbookController
	savedSearchCtl savedSearchController
	hypothesisCtl  hypothesisController
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
		emitter: emitter,
		captureCtl: captureController{captureState: captureState{
			packetStore:  store,
			captureTasks: map[int64]captureTaskCancel{},
		}},
		filterCtl: displayFilterController{displayFilterState: displayFilterState{
			displayFilterCache: map[string]*filteredPacketIndex{},
		}},
		streamCtl: streamController{streamState: streamState{
			streamCache:     map[string]model.ReassembledStream{},
			rawStreamIndex:  map[string]model.ReassembledStream{},
			streamOverrides: map[string]map[int]string{},
		}},
		objectCtl: objectController{},
		mediaCtl: mediaController{mediaState: mediaState{
			mediaArtifacts: map[string]string{},
			mediaPlayback:  map[string]string{},
			mediaSpeech:    map[string]model.MediaTranscription{},
		}},
		huntingCtl: yaraHuntingController{yaraHuntingState: yaraHuntingState{
			huntingPrefixes: []string{
				"flag{",
				"ctf{",
			},
			yaraConf: model.YaraConfig{
				Enabled:   true,
				TimeoutMS: 25000,
			},
		}},
		analysisCtl: analysisController{analysisCache: analysisCache{
			analysisLimiter: newAnalysisLimiter(1),
			analysisMetrics: newAnalysisMetrics(),
		}},
		runtimeCtl: toolRuntimeController{toolRuntimeState: toolRuntimeState{
			tsharkRuntime: tool.NewRuntime("tshark", []string{"tshark"}, nil),
			ffmpegRuntime: tool.NewRuntime("ffmpeg", []string{"ffmpeg"}, nil),
			pythonRuntime: tool.NewRuntime("python", []string{"python", "python3"}, nil),
			yaraRuntime:   tool.NewRuntime("yara", []string{"yara", "yara64"}, nil),
		}},
		playbookCtl: playbookController{playbookStatePB: playbookStatePB{
			playbooks: map[string]*model.HuntingPlaybook{},
			lastRun:   map[string]*model.PlaybookRunResult{},
		}},
		savedSearchCtl: savedSearchController{savedSearchStateSS: savedSearchStateSS{
			savedSearches: map[string]*model.SavedSearch{},
		}},
		hypothesisCtl: hypothesisController{hypothesisStateHT: hypothesisStateHT{
			hypotheses: map[string]*model.Hypothesis{},
		}},
	}
}

func (s *Service) emitStatus(status string) {
	if s == nil || s.emitter == nil {
		return
	}
	s.emitter.EmitStatus(status)
}

func streamFollowTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_STREAM_FOLLOW_TIMEOUT_MS"))
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
