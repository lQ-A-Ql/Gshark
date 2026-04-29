package engine

import (
	"context"
	"errors"
	"fmt"
	"log"

	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/plugin"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type Service struct {
	emitter      EventEmitter
	pluginManger *plugin.Manager

	mu                      sync.RWMutex
	loadMu                  sync.Mutex
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
	yaraHits       []model.ThreatHit
	yaraLastError  string
	yaraMu         sync.Mutex

	huntMu          sync.RWMutex
	huntingPrefixes []string
	yaraConf        model.YaraConfig

	cancel context.CancelFunc
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
	streamPacketsFastFn   = tshark.StreamPacketsFast
	streamPacketsCompatFn = tshark.StreamPacketsCompat
	httpStreamFromFileFn  = tshark.ReassembleHTTPStreamFromFileContext
	rawStreamFromFileFn   = tshark.ReassembleRawStreamFromFileContext
)

func NewService(emitter EventEmitter, pm *plugin.Manager) *Service {
	if emitter == nil {
		emitter = NopEmitter{}
	}
	store, err := newPacketStore()
	if err != nil {
		panic(err)
	}
	return &Service{
		emitter:            emitter,
		pluginManger:       pm,
		packetStore:        store,
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

func (s *Service) LoadPCAP(ctx context.Context, opts model.ParseOptions) error {
	if opts.FilePath == "" {
		return errors.New("empty file path")
	}

	requestRunID := atomic.AddInt64(&s.runID, 1)
	s.StopStreaming()
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if atomic.LoadInt64(&s.runID) != requestRunID {
		return context.Canceled
	}

	currentRunID := requestRunID
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	s.mu.RLock()
	oldPCAP := s.pcap
	s.mu.RUnlock()
	if oldPCAP != "" {
		tshark.ClearFieldScanCache(oldPCAP)
	}
	tshark.ClearFieldScanCache(opts.FilePath)

	s.objMu.Lock()
	if s.exportDir != "" {
		os.RemoveAll(s.exportDir)
		s.exportDir = ""
	}
	s.objectsLoaded = false
	s.objects = nil
	s.objMu.Unlock()

	s.yaraMu.Lock()
	s.yaraLoaded = false
	s.yaraHits = nil
	s.yaraLastError = ""
	s.yaraMu.Unlock()

	if s.packetStore != nil {
		if err := s.packetStore.Reset(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.mediaExportDir != "" {
		_ = os.RemoveAll(s.mediaExportDir)
		s.mediaExportDir = ""
	}
	s.cancelDisplayFilterCacheLocked()
	s.pcap = opts.FilePath
	s.displayFilterCache = map[string]*filteredPacketIndex{}
	s.displayFilterCacheOrder = s.displayFilterCacheOrder[:0]
	s.globalTrafficStats = nil
	s.industrialAnalysis = nil
	s.vehicleAnalysis = nil
	s.mediaAnalysis = nil
	s.usbAnalysis = nil
	s.c2Analysis = nil
	s.aptAnalysis = nil
	s.mediaArtifacts = map[string]string{}
	s.mediaPlayback = map[string]string{}
	s.mediaSpeech = map[string]model.MediaTranscription{}
	s.cancelSpeechBatchLocked()
	s.speechBatch = nil
	s.streamCache = map[string]model.ReassembledStream{}
	s.streamCacheOrder = s.streamCacheOrder[:0]
	s.rawStreamIndex = map[string]model.ReassembledStream{}
	s.streamOverrides = map[string]map[int]string{}
	// Inject current TLS config into parse options
	opts.TLS = s.tlsConf
	s.mu.Unlock()

	tsharkStatus := tshark.CurrentStatus()
	log.Printf(
		"engine: load capture file=%q filter=%q fast_list=%t tshark=%q custom=%t",
		opts.FilePath,
		opts.DisplayFilter,
		opts.FastList,
		tsharkStatus.Path,
		tsharkStatus.UsingCustomPath,
	)

	s.emitStatus("开始解析 PCAP")
	total := 0
	if shouldSkipPacketEstimate(opts) {
		s.emitStatus("大流量包已跳过总包数预估，直接开始入库解析。")
		log.Printf("engine: skipping packet estimate for %q due to large file fast_list path", opts.FilePath)
	} else {
		estimatedTotal, countErr := estimatePacketsFn(runCtx, opts)
		if countErr == nil && estimatedTotal > 0 {
			total = estimatedTotal
			s.emitStatus(fmt.Sprintf("__progress__:counting:%d:%d", total, total))
			s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", 0, total))
			log.Printf("engine: tshark estimated %d packets for %q", total, opts.FilePath)
		} else if countErr != nil {
			log.Printf("engine: tshark packet estimate failed for %q: %v", opts.FilePath, countErr)
		}
	}

	processed := 0
	accepted := 0
	rawStreamIndex := make(map[string]*model.ReassembledStream)
	streamFn := streamPacketsFn
	if opts.FastList {
		streamFn = streamPacketsFastFn
	}

	pending := make([]model.Packet, 0, 1024)
	flushPending := func() {
		if len(pending) == 0 {
			return
		}
		if s.packetStore != nil {
			if err := s.packetStore.Append(pending); err != nil {
				s.emitStatus("写入数据包存储失败: " + err.Error())
			}
		}
		pending = pending[:0]
	}

	err := streamFn(runCtx, opts, func(packet model.Packet) error {
		if atomic.LoadInt64(&s.runID) != currentRunID {
			return nil
		}
		accepted++
		appendPacketToRawStreamIndex(rawStreamIndex, packet)
		pending = append(pending, packet)
		if len(pending) >= 1024 {
			flushPending()
		}
		if opts.EmitPackets {
			s.emitter.EmitPacket(packet)
		}
		return nil
	}, func(frameProcessed int) {
		processed = frameProcessed
		if total > 0 {
			s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
		}
	})
	flushPending()
	log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", func() string {
		if opts.FastList {
			return "fast_list"
		}
		return "ek"
	}(), processed, accepted, err)
	if opts.FastList && !errors.Is(err, context.Canceled) {
		needsFallback := err != nil
		if !needsFallback && total > 0 && accepted == 0 {
			needsFallback = true
		}
		if needsFallback {
			s.emitStatus("fast_list compatibility fallback: retrying parse with EK mode")
			if s.packetStore != nil {
				if resetErr := s.packetStore.Reset(); resetErr != nil {
					return resetErr
				}
			}
			processed = 0
			accepted = 0
			rawStreamIndex = make(map[string]*model.ReassembledStream)
			streamFn = streamPacketsFn
			pending = make([]model.Packet, 0, 1024)
			err = streamFn(runCtx, opts, func(packet model.Packet) error {
				if atomic.LoadInt64(&s.runID) != currentRunID {
					return nil
				}
				accepted++
				appendPacketToRawStreamIndex(rawStreamIndex, packet)
				pending = append(pending, packet)
				if len(pending) >= 1024 {
					flushPending()
				}
				if opts.EmitPackets {
					s.emitter.EmitPacket(packet)
				}
				return nil
			}, func(frameProcessed int) {
				processed = frameProcessed
				if total > 0 {
					s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
				}
			})
			flushPending()
			log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", "ek_fallback", processed, accepted, err)
		}
	}
	if !errors.Is(err, context.Canceled) {
		needsCompatFallback := err != nil
		if !needsCompatFallback && total > 0 && accepted == 0 {
			needsCompatFallback = true
		}
		if needsCompatFallback {
			s.emitStatus("compatibility fallback: retrying parse with minimal field mode")
			log.Printf("engine: switching parser to compat_fields fallback for %q", opts.FilePath)
			if s.packetStore != nil {
				if resetErr := s.packetStore.Reset(); resetErr != nil {
					return resetErr
				}
			}
			processed = 0
			accepted = 0
			rawStreamIndex = make(map[string]*model.ReassembledStream)
			pending = make([]model.Packet, 0, 1024)
			err = streamPacketsCompatFn(runCtx, opts, func(packet model.Packet) error {
				if atomic.LoadInt64(&s.runID) != currentRunID {
					return nil
				}
				accepted++
				appendPacketToRawStreamIndex(rawStreamIndex, packet)
				pending = append(pending, packet)
				if len(pending) >= 1024 {
					flushPending()
				}
				if opts.EmitPackets {
					s.emitter.EmitPacket(packet)
				}
				return nil
			}, func(frameProcessed int) {
				processed = frameProcessed
				if total > 0 {
					s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
				}
			})
			flushPending()
			log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", "compat_fields_fallback", processed, accepted, err)
		}
	}
	if total > 0 {
		s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", processed, total))
	}

	dropped := processed - accepted
	if dropped < 0 {
		dropped = 0
	}
	if processed > 0 {
		s.emitStatus(fmt.Sprintf("解析统计: 已处理=%d, 入库=%d, 跳过=%d", processed, accepted, dropped))
	}
	if s.packetStore != nil {
		log.Printf("engine: packet store path=%q rows=%d", s.packetStore.Path(), s.packetStore.Count())
		s.emitStatus(fmt.Sprintf("临时数据库已缓存 %d 条数据包", s.packetStore.Count()))
	}
	if opts.FastList && dropped > 0 {
		s.emitStatus(fmt.Sprintf("fast_list 告警: 有 %d 条记录未入库，请检查字段映射/解析规则", dropped))
	}

	if err == nil {
		log.Printf("engine: capture parse completed file=%q accepted=%d processed=%d", opts.FilePath, accepted, processed)
	} else if errors.Is(err, context.Canceled) {
		log.Printf("engine: capture parse canceled file=%q", opts.FilePath)
	} else {
		log.Printf("engine: capture parse failed file=%q err=%v", opts.FilePath, err)
	}

	switch err {
	case nil:
		s.mu.Lock()
		s.rawStreamIndex = make(map[string]model.ReassembledStream, len(rawStreamIndex))
		for key, stream := range rawStreamIndex {
			if stream == nil {
				continue
			}
			s.rawStreamIndex[key] = cloneReassembledStream(*stream)
		}
		s.mu.Unlock()
		s.emitStatus("解析完成")
	case context.Canceled:
		s.emitStatus("解析被取消")
	default:
		s.emitStatus("解析失败: " + err.Error())
	}
	return err
}

func shouldSkipPacketEstimate(opts model.ParseOptions) bool {
	if !opts.FastList {
		return false
	}
	filePath := strings.TrimSpace(opts.FilePath)
	if filePath == "" {
		return false
	}
	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() >= skipEstimateFileSizeThreshold
}

func (s *Service) cancelSpeechBatchLocked() {
	if s.speechCancel != nil {
		s.speechCancel()
		s.speechCancel = nil
	}
}

func (s *Service) StopStreaming() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) ClearCapture() error {
	atomic.AddInt64(&s.runID, 1)
	s.StopStreaming()

	s.mu.Lock()
	s.cancelDisplayFilterCacheLocked()
	s.mu.Unlock()

	s.loadMu.Lock()
	defer s.loadMu.Unlock()

	if s.packetStore != nil {
		if err := s.packetStore.Reset(); err != nil {
			return err
		}
		s.emitStatus("临时数据库已重置")
	}

	s.objMu.Lock()
	if s.exportDir != "" {
		_ = os.RemoveAll(s.exportDir)
		s.exportDir = ""
	}
	s.objectsLoaded = false
	s.objects = nil
	s.objMu.Unlock()

	s.mu.Lock()
	if s.mediaExportDir != "" {
		_ = os.RemoveAll(s.mediaExportDir)
		s.mediaExportDir = ""
	}
	if s.pcap != "" {
		tshark.ClearFieldScanCache(s.pcap)
	}
	s.pcap = ""
	s.displayFilterCache = map[string]*filteredPacketIndex{}
	s.displayFilterCacheOrder = s.displayFilterCacheOrder[:0]
	s.globalTrafficStats = nil
	s.industrialAnalysis = nil
	s.vehicleAnalysis = nil
	s.mediaAnalysis = nil
	s.usbAnalysis = nil
	s.c2Analysis = nil
	s.aptAnalysis = nil
	s.mediaArtifacts = map[string]string{}
	s.mediaPlayback = map[string]string{}
	s.mediaSpeech = map[string]model.MediaTranscription{}
	s.cancelSpeechBatchLocked()
	s.speechBatch = nil
	s.streamCache = map[string]model.ReassembledStream{}
	s.streamCacheOrder = s.streamCacheOrder[:0]
	s.rawStreamIndex = map[string]model.ReassembledStream{}
	s.streamOverrides = map[string]map[int]string{}
	s.mu.Unlock()

	s.yaraMu.Lock()
	s.yaraLoaded = false
	s.yaraHits = nil
	s.yaraLastError = ""
	s.yaraMu.Unlock()
	return nil
}

func (s *Service) Packets() []model.Packet {
	if s.packetStore == nil {
		return nil
	}
	out, err := s.packetStore.All(nil)
	if err != nil {
		return nil
	}
	return out
}

func (s *Service) PacketsPageWithError(cursor, limit int, filter string) ([]model.Packet, int, int, error) {
	items, next, total, _, err := s.PacketsPageWithState(cursor, limit, filter)
	return items, next, total, err
}

func (s *Service) PacketsPageWithState(cursor, limit int, filter string) ([]model.Packet, int, int, bool, error) {
	if s.packetStore == nil {
		return nil, 0, 0, false, nil
	}
	filtered, filterErr := s.filteredPacketIndex(filter)
	if filterErr == nil && filtered != nil {
		ids, next, total, pending, err := filtered.pageWindowState(cursor, limit)
		if err != nil {
			return []model.Packet{}, 0, 0, false, err
		}
		out, err := s.packetStore.PacketsByIDsSummary(ids)
		if err != nil {
			s.emitStatus("数据包分页查询失败: " + err.Error())
			return []model.Packet{}, 0, 0, false, err
		}
		return out, next, total, pending, nil
	}
	if filterErr != nil {
		return []model.Packet{}, 0, 0, false, filterErr
	}
	if strings.TrimSpace(filter) != "" && s.hasCapturePath() {
		return []model.Packet{}, 0, 0, false, nil
	}

	predicate := compilePacketFilter(filter)
	out, next, total, err := s.packetStore.PageSummaries(cursor, limit, predicate)
	if err != nil {
		s.emitStatus("数据包分页查询失败: " + err.Error())
		return []model.Packet{}, 0, 0, false, err
	}
	return out, next, total, false, nil
}

func (s *Service) PacketsPage(cursor, limit int, filter string) ([]model.Packet, int, int) {
	items, next, total, _ := s.PacketsPageWithError(cursor, limit, filter)
	return items, next, total
}

func (s *Service) PacketPageCursorWithError(packetID int64, limit int, filter string) (int, int, bool, error) {
	if packetID <= 0 || s.packetStore == nil {
		return 0, 0, false, nil
	}
	if limit <= 0 {
		limit = 1000
	}
	filtered, err := s.filteredPacketIndex(filter)
	if err == nil && filtered != nil {
		return filtered.pageCursor(packetID, limit)
	}
	if err != nil {
		return 0, 0, false, err
	}
	if strings.TrimSpace(filter) != "" && s.hasCapturePath() {
		return 0, 0, false, nil
	}

	predicate := compilePacketFilter(filter)
	matchIndex := -1
	total := 0
	_ = s.packetStore.Iterate(predicate, func(packet model.Packet) error {
		if packet.ID == packetID && matchIndex < 0 {
			matchIndex = total
		}
		total++
		return nil
	})
	if matchIndex < 0 {
		return 0, total, false, nil
	}
	cursor := (matchIndex / limit) * limit
	return cursor, total, true, nil
}

func (s *Service) PacketPageCursor(packetID int64, limit int, filter string) (int, int, bool) {
	cursor, total, found, _ := s.PacketPageCursorWithError(packetID, limit, filter)
	return cursor, total, found
}

func (s *Service) Packet(packetID int64) (model.Packet, error) {
	if packetID <= 0 || s.packetStore == nil {
		return model.Packet{}, errors.New("invalid packet id")
	}
	packet, ok, err := s.packetStore.PacketByID(packetID)
	if err != nil {
		return model.Packet{}, err
	}
	if !ok {
		return model.Packet{}, errors.New("packet not found")
	}
	return packet, nil
}

func (s *Service) ThreatHunt(prefixes []string) []model.ThreatHit {
	return s.ThreatHuntWithContext(context.Background(), prefixes)
}

func (s *Service) ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(prefixes) == 0 {
		prefixes = s.getHuntingPrefixes()
	}
	s.emitStatus("__progress__:threat:0:5:准备威胁分析")
	hunter := newThreatHunter(prefixes, 1)
	var pluginRunner *plugin.PacketPluginRunner
	if s.pluginManger != nil {
		pluginRunner = s.pluginManger.NewPacketPluginRunner()
	}

	const pluginBatchSize = 1024
	batch := make([]model.Packet, 0, pluginBatchSize)
	flushPluginBatch := func() {
		if len(batch) == 0 || pluginRunner == nil {
			batch = batch[:0]
			return
		}
		pluginRunner.ProcessBatch(batch)
		batch = batch[:0]
	}

	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			hunter.Observe(packet)
			if pluginRunner != nil {
				batch = append(batch, packet)
				if len(batch) >= pluginBatchSize {
					flushPluginBatch()
				}
			}
			return nil
		})
		flushPluginBatch()
	}
	if ctx.Err() != nil {
		s.emitStatus("威胁分析已取消")
		return nil
	}
	s.emitStatus("__progress__:threat:1:5:扫描数据包基础特征")

	hits := hunter.Results()
	if pluginRunner != nil {
		hits = append(hits, pluginRunner.Close(int64(len(hits)+1))...)
		for _, warning := range pluginRunner.Warnings() {
			s.emitStatus("plugin warning: " + warning)
		}
	}
	if ctx.Err() != nil {
		s.emitStatus("威胁分析已取消")
		return nil
	}
	s.emitStatus("__progress__:threat:2:5:导出可疑对象")
	objects := s.ObjectsWithContext(ctx)
	if ctx.Err() != nil {
		s.emitStatus("威胁分析已取消")
		return nil
	}
	s.emitStatus("__progress__:threat:3:5:整理重组流与扫描目标")
	hits = append(hits, s.cachedYaraHitsWithContext(ctx, objects)...)
	if ctx.Err() != nil {
		s.emitStatus("威胁分析已取消")
		return nil
	}
	s.emitStatus("__progress__:threat:4:5:执行 YARA 扫描")
	hits = append(hits, StegoPrecheck(objects)...)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].ID == hits[j].ID {
			return hits[i].PacketID < hits[j].PacketID
		}
		return hits[i].ID < hits[j].ID
	})
	s.emitStatus("__progress__:threat:5:5:威胁分析完成")
	s.emitStatus("威胁分析完成")
	return hits
}

func (s *Service) getHuntingPrefixes() []string {
	s.huntMu.RLock()
	defer s.huntMu.RUnlock()
	out := make([]string, len(s.huntingPrefixes))
	copy(out, s.huntingPrefixes)
	return out
}

func (s *Service) GetHuntingRuntimeConfig() model.HuntingRuntimeConfig {
	prefixes := s.getHuntingPrefixes()
	if len(prefixes) == 0 {
		prefixes = []string{"flag{", "ctf{"}
	}

	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()

	yaraTimeoutMS := yc.TimeoutMS
	if yaraTimeoutMS <= 0 {
		yaraTimeoutMS = 25000
	}

	return model.HuntingRuntimeConfig{
		Prefixes:      prefixes,
		YaraEnabled:   yc.Enabled,
		YaraBin:       yc.Bin,
		YaraRules:     yc.Rules,
		YaraTimeoutMS: yaraTimeoutMS,
	}
}

func (s *Service) SetHuntingRuntimeConfig(cfg model.HuntingRuntimeConfig) model.HuntingRuntimeConfig {
	if len(cfg.Prefixes) > 0 {
		normalized := make([]string, 0, len(cfg.Prefixes))
		seen := map[string]struct{}{}
		for _, p := range cfg.Prefixes {
			v := strings.TrimSpace(p)
			if v == "" {
				continue
			}
			key := strings.ToLower(v)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			normalized = append(normalized, v)
		}
		if len(normalized) > 0 {
			s.huntMu.Lock()
			s.huntingPrefixes = normalized
			s.huntMu.Unlock()
		}
	}

	s.huntMu.Lock()
	s.yaraConf = model.YaraConfig{
		Enabled:   cfg.YaraEnabled,
		Bin:       strings.TrimSpace(cfg.YaraBin),
		Rules:     strings.TrimSpace(cfg.YaraRules),
		TimeoutMS: cfg.YaraTimeoutMS,
	}
	s.huntMu.Unlock()

	s.yaraMu.Lock()
	s.yaraLoaded = false
	s.yaraHits = nil
	s.yaraLastError = ""
	s.yaraMu.Unlock()

	return s.GetHuntingRuntimeConfig()
}

func (s *Service) cachedYaraHits(objects []model.ObjectFile) []model.ThreatHit {
	return s.cachedYaraHitsWithContext(context.Background(), objects)
}

func (s *Service) cachedYaraHitsWithContext(ctx context.Context, objects []model.ObjectFile) []model.ThreatHit {
	if ctx == nil {
		ctx = context.Background()
	}
	s.yaraMu.Lock()
	defer s.yaraMu.Unlock()

	if s.yaraLoaded {
		out := make([]model.ThreatHit, len(s.yaraHits))
		copy(out, s.yaraHits)
		return out
	}

	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()

	targets, cleanup, err := s.buildYaraScanTargets(objects)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		log.Printf("engine: build yara scan targets failed: %v", err)
		s.emitStatus("YARA 扫描目标构建失败: " + err.Error())
		hits := []model.ThreatHit{newYaraWarningHit("YARA 扫描目标构建失败: " + err.Error())}
		s.yaraHits = make([]model.ThreatHit, len(hits))
		copy(s.yaraHits, hits)
		s.yaraLastError = err.Error()
		s.yaraLoaded = true
		out := make([]model.ThreatHit, len(s.yaraHits))
		copy(out, s.yaraHits)
		return out
	}

	hits, scanErr := BatchScanTargetsWithYaraConfigContext(ctx, targets, yc)
	if scanErr != nil {
		if errors.Is(scanErr, context.Canceled) {
			return nil
		}
		log.Printf("engine: yara scan failed: %v", scanErr)
		s.emitStatus("YARA 扫描异常: " + scanErr.Error())
		hits = append(hits, newYaraWarningHit(scanErr.Error()))
		s.yaraLastError = scanErr.Error()
	} else {
		s.yaraLastError = ""
	}
	s.yaraHits = make([]model.ThreatHit, len(hits))
	copy(s.yaraHits, hits)
	s.yaraLoaded = true

	out := make([]model.ThreatHit, len(s.yaraHits))
	copy(out, s.yaraHits)
	return out
}

func (s *Service) Objects() []model.ObjectFile {
	return s.ObjectsWithContext(context.Background())
}

func (s *Service) ObjectsWithContext(ctx context.Context) []model.ObjectFile {
	if ctx == nil {
		ctx = context.Background()
	}
	s.objMu.Lock()
	if s.objectsLoaded {
		objects := s.objects
		s.objMu.Unlock()
		return objects
	}
	s.objMu.Unlock()

	s.mu.RLock()
	pcapPath := s.pcap
	s.mu.RUnlock()

	if pcapPath == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	tempDir, err := os.MkdirTemp("", "gshark-export-")
	if err != nil {
		return nil
	}

	keepTempDir := false
	defer func() {
		if keepTempDir {
			return
		}
		_ = os.RemoveAll(tempDir)
	}()

	if err := tshark.ExportObjectsContext(ctx, pcapPath, tempDir); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		s.objMu.Lock()
		s.mu.RLock()
		currentPCAP := s.pcap
		s.mu.RUnlock()
		if currentPCAP == pcapPath && !s.objectsLoaded {
			s.objectsLoaded = true
			s.objects = nil
		}
		s.objMu.Unlock()
		return nil
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		s.objMu.Lock()
		s.mu.RLock()
		currentPCAP := s.pcap
		s.mu.RUnlock()
		if currentPCAP == pcapPath && !s.objectsLoaded {
			s.objectsLoaded = true
			s.objects = nil
		}
		s.objMu.Unlock()
		return nil
	}

	packetByObjectName := s.packetObjectNameIndex()

	var objects []model.ObjectFile
	var id int64 = 1
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil
		}
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(tempDir, entry.Name())

		f, err := os.Open(path)
		mimeType := "application/octet-stream"
		if err == nil {
			buf := make([]byte, 512)
			n, _ := f.Read(buf)
			if n > 0 {
				mimeType = http.DetectContentType(buf[:n])
			}
			f.Close()
		}

		objects = append(objects, model.ObjectFile{
			ID:        id,
			PacketID:  packetByObjectName[normalizeObjectLookupKey(entry.Name())],
			Name:      entry.Name(),
			SizeBytes: info.Size(),
			MIME:      mimeType,
			Source:    "Extracted",
			Path:      path,
		})
		id++
	}

	s.objMu.Lock()
	defer s.objMu.Unlock()
	if s.objectsLoaded {
		return s.objects
	}

	s.mu.RLock()
	currentPCAP := s.pcap
	s.mu.RUnlock()
	if currentPCAP != pcapPath {
		return nil
	}

	s.exportDir = tempDir
	s.objects = objects
	s.objectsLoaded = true
	keepTempDir = true
	return s.objects
}

func (s *Service) packetObjectNameIndex() map[string]int64 {
	if s.packetStore == nil {
		return map[string]int64{}
	}
	return buildPacketIDByObjectNameFromIterate(func(fn func(model.Packet) error) error {
		return s.packetStore.Iterate(nil, fn)
	})
}

func (s *Service) HTTPStream(ctx context.Context, streamID int64) model.ReassembledStream {
	if ctx == nil {
		ctx = context.Background()
	}
	key := streamCacheKey("HTTP", streamID)
	log.Printf("engine: http stream request stream=%d", streamID)
	s.mu.RLock()
	pcap := s.pcap
	if cached, ok := s.streamCache[key]; ok {
		s.mu.RUnlock()
		stream := s.streamWithOverrides(key, cached)
		stream.LoadMeta = newStreamLoadMeta("cache", true, false, false, 0)
		s.applyOverrideCountToMeta(key, stream.LoadMeta)
		log.Printf("engine: http stream stream=%d source=cache chunks=%d", streamID, len(stream.Chunks))
		return stream
	}
	s.mu.RUnlock()

	if s.packetStore != nil {
		stream := ReassembleHTTPStreamFromIterate(func(fn func(model.Packet) error) error {
			return s.packetStore.Iterate(nil, fn)
		}, streamID)
		if len(stream.Chunks) > 0 || strings.TrimSpace(stream.Request) != "" || strings.TrimSpace(stream.Response) != "" {
			stream = s.streamWithOverrides(key, stream)
			stream.LoadMeta = newStreamLoadMeta("memory", false, false, false, 0)
			s.applyOverrideCountToMeta(key, stream.LoadMeta)
			s.cacheStream(key, stream)
			log.Printf("engine: http stream stream=%d source=memory chunks=%d request_bytes=%d response_bytes=%d", streamID, len(stream.Chunks), len(stream.Request), len(stream.Response))
			return stream
		}
	}

	if pcap != "" {
		log.Printf("engine: http stream stream=%d source=file-fallback start", streamID)
		ctx, cancel := context.WithTimeout(ctx, streamFollowTimeout())
		startedAt := time.Now()
		stream, err := httpStreamFromFileFn(ctx, pcap, streamID)
		cancel()
		if err == nil && (stream.Request != "" || stream.Response != "") {
			stream = s.streamWithOverrides(key, stream)
			stream.LoadMeta = newStreamLoadMeta("file", false, false, true, time.Since(startedAt))
			s.applyOverrideCountToMeta(key, stream.LoadMeta)
			s.cacheStream(key, stream)
			log.Printf("engine: http stream stream=%d source=file-fallback chunks=%d tshark_ms=%d", streamID, len(stream.Chunks), stream.LoadMeta.TSharkMS)
			return stream
		}
		if err != nil {
			log.Printf("engine: http stream stream=%d source=file-fallback failed err=%v", streamID, err)
		}
	}

	log.Printf("engine: http stream stream=%d source=empty", streamID)
	return model.ReassembledStream{StreamID: streamID, Protocol: "HTTP"}
}

func (s *Service) RawStream(ctx context.Context, protocol string, streamID int64) model.ReassembledStream {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	key := streamCacheKey(normalized, streamID)
	log.Printf("engine: raw stream request protocol=%s stream=%d", normalized, streamID)

	s.mu.RLock()
	pcap := s.pcap
	if cached, ok := s.streamCache[key]; ok {
		s.mu.RUnlock()
		stream := s.streamWithOverrides(key, cached)
		stream.LoadMeta = newStreamLoadMeta("cache", true, false, false, 0)
		s.applyOverrideCountToMeta(key, stream.LoadMeta)
		log.Printf("engine: raw stream protocol=%s stream=%d source=cache chunks=%d", normalized, streamID, len(stream.Chunks))
		return stream
	}
	if indexed, ok := s.rawStreamIndex[key]; ok {
		stream := s.streamWithOverrides(key, indexed)
		stream.LoadMeta = newStreamLoadMeta("index", false, true, false, 0)
		s.mu.RUnlock()
		s.applyOverrideCountToMeta(key, stream.LoadMeta)
		s.cacheStream(key, stream)
		log.Printf("engine: raw stream protocol=%s stream=%d source=index chunks=%d", normalized, streamID, len(stream.Chunks))
		return stream
	}
	s.mu.RUnlock()

	if pcap != "" {
		log.Printf("engine: raw stream protocol=%s stream=%d source=file-fallback start", normalized, streamID)
		ctx, cancel := context.WithTimeout(ctx, streamFollowTimeout())
		startedAt := time.Now()
		stream, err := rawStreamFromFileFn(ctx, pcap, normalized, streamID)
		cancel()
		if err == nil && len(stream.Chunks) > 0 {
			stream = s.streamWithOverrides(key, stream)
			stream.LoadMeta = newStreamLoadMeta("file", false, false, true, time.Since(startedAt))
			s.applyOverrideCountToMeta(key, stream.LoadMeta)
			s.cacheStream(key, stream)
			log.Printf("engine: raw stream protocol=%s stream=%d source=file-fallback chunks=%d tshark_ms=%d", normalized, streamID, len(stream.Chunks), stream.LoadMeta.TSharkMS)
			return stream
		}
		if err != nil {
			log.Printf("engine: raw stream protocol=%s stream=%d source=file-fallback failed err=%v", normalized, streamID, err)
		}
	}

	log.Printf("engine: raw stream protocol=%s stream=%d source=empty", normalized, streamID)
	return model.ReassembledStream{StreamID: streamID, Protocol: normalized}
}

func (s *Service) RawStreamPage(ctx context.Context, protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	key := streamCacheKey(normalized, streamID)
	log.Printf("engine: raw stream page request protocol=%s stream=%d cursor=%d limit=%d", normalized, streamID, cursor, limit)

	s.mu.RLock()
	if indexed, ok := s.rawStreamIndex[key]; ok {
		stream, next, total := cloneRawStreamWindow(s.streamWithOverrides(key, indexed), cursor, limit)
		stream.LoadMeta = newStreamLoadMeta("index", false, true, false, 0)
		s.mu.RUnlock()
		s.applyOverrideCountToMeta(key, stream.LoadMeta)
		log.Printf("engine: raw stream page protocol=%s stream=%d source=index returned=%d total=%d next=%d", normalized, streamID, len(stream.Chunks), total, next)
		return stream, next, total
	}
	s.mu.RUnlock()

	stream := s.RawStream(ctx, normalized, streamID)
	window, next, total := cloneRawStreamWindow(stream, cursor, limit)
	source := "unknown"
	if window.LoadMeta != nil && window.LoadMeta.Source != "" {
		source = window.LoadMeta.Source
	}
	log.Printf("engine: raw stream page protocol=%s stream=%d source=%s returned=%d total=%d next=%d", normalized, streamID, source, len(window.Chunks), total, next)
	return window, next, total
}

func (s *Service) UpdateStreamPayloads(ctx context.Context, protocol string, streamID int64, patches []model.StreamChunkPatch) (model.ReassembledStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	if normalized != "HTTP" && normalized != "TCP" && normalized != "UDP" {
		return model.ReassembledStream{}, fmt.Errorf("unsupported protocol: %s", protocol)
	}
	if streamID < 0 {
		return model.ReassembledStream{}, fmt.Errorf("invalid stream id")
	}
	if len(patches) == 0 {
		if normalized == "HTTP" {
			return s.HTTPStream(ctx, streamID), nil
		}
		return s.RawStream(ctx, normalized, streamID), nil
	}

	key := streamCacheKey(normalized, streamID)
	normalizedPatches := make(map[int]string, len(patches))
	for _, patch := range patches {
		if patch.Index < 0 {
			continue
		}
		normalizedPatches[patch.Index] = patch.Body
	}
	if len(normalizedPatches) == 0 {
		return model.ReassembledStream{}, fmt.Errorf("no valid patches")
	}

	s.mu.Lock()
	if s.streamOverrides == nil {
		s.streamOverrides = map[string]map[int]string{}
	}
	existing := s.streamOverrides[key]
	if existing == nil {
		existing = map[int]string{}
		s.streamOverrides[key] = existing
	}
	for index, body := range normalizedPatches {
		existing[index] = body
	}

	if cached, ok := s.streamCache[key]; ok {
		updated := applyChunkOverrides(cloneReassembledStream(cached), existing)
		s.streamCache[key] = cloneReassembledStream(updated)
	}
	if indexed, ok := s.rawStreamIndex[key]; ok {
		updated := applyChunkOverrides(cloneReassembledStream(indexed), existing)
		s.rawStreamIndex[key] = cloneReassembledStream(updated)
	}
	s.mu.Unlock()

	if normalized == "HTTP" {
		return s.HTTPStream(ctx, streamID), nil
	}
	return s.RawStream(ctx, normalized, streamID), nil
}

func (s *Service) cacheStream(key string, stream model.ReassembledStream) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.streamCache == nil {
		s.streamCache = map[string]model.ReassembledStream{}
	}
	if _, exists := s.streamCache[key]; exists {
		s.removeStreamCacheOrderLocked(key)
	}
	s.streamCache[key] = cloneReassembledStream(stream)
	s.streamCacheOrder = append(s.streamCacheOrder, key)

	limit := streamCacheLimitValue()
	for len(s.streamCacheOrder) > limit {
		oldest := s.streamCacheOrder[0]
		s.streamCacheOrder = s.streamCacheOrder[1:]
		delete(s.streamCache, oldest)
	}
}

func (s *Service) removeStreamCacheOrderLocked(key string) {
	for i, v := range s.streamCacheOrder {
		if v == key {
			s.streamCacheOrder = append(s.streamCacheOrder[:i], s.streamCacheOrder[i+1:]...)
			return
		}
	}
}

func streamCacheKey(protocol string, streamID int64) string {
	return protocol + ":" + fmt.Sprintf("%d", streamID)
}

func cloneReassembledStream(in model.ReassembledStream) model.ReassembledStream {
	out := in
	if len(in.Chunks) > 0 {
		out.Chunks = make([]model.StreamChunk, len(in.Chunks))
		copy(out.Chunks, in.Chunks)
	}
	if in.LoadMeta != nil {
		meta := *in.LoadMeta
		out.LoadMeta = &meta
	}
	return out
}

func (s *Service) streamWithOverrides(key string, in model.ReassembledStream) model.ReassembledStream {
	s.mu.RLock()
	overrides := cloneChunkOverrideMap(s.streamOverrides[key])
	s.mu.RUnlock()
	return applyChunkOverrides(cloneReassembledStream(in), overrides)
}

func cloneChunkOverrideMap(in map[int]string) map[int]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int]string, len(in))
	for index, body := range in {
		out[index] = body
	}
	return out
}

func (s *Service) countStreamOverrides(key string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streamOverrides[key])
}

func (s *Service) applyOverrideCountToMeta(key string, meta *model.StreamLoadMeta) {
	if meta == nil {
		return
	}
	if count := s.countStreamOverrides(key); count > 0 {
		meta.OverrideCount = count
	}
}

func applyChunkOverrides(stream model.ReassembledStream, overrides map[int]string) model.ReassembledStream {
	if len(overrides) == 0 || len(stream.Chunks) == 0 {
		return stream
	}
	for index, body := range overrides {
		if index < 0 || index >= len(stream.Chunks) {
			continue
		}
		stream.Chunks[index].Body = body
	}
	if strings.EqualFold(stream.Protocol, "HTTP") {
		rebuildHTTPStreamBodies(&stream)
	}
	return stream
}

func rebuildHTTPStreamBodies(stream *model.ReassembledStream) {
	if stream == nil {
		return
	}
	if len(stream.Chunks) == 0 {
		return
	}
	var request strings.Builder
	var response strings.Builder
	for _, chunk := range stream.Chunks {
		if strings.EqualFold(chunk.Direction, "server") {
			response.WriteString(chunk.Body)
			continue
		}
		request.WriteString(chunk.Body)
	}
	stream.Request = request.String()
	stream.Response = response.String()
}

func newStreamLoadMeta(source string, cacheHit, indexHit, fileFallback bool, elapsed time.Duration) *model.StreamLoadMeta {
	meta := &model.StreamLoadMeta{
		Source:       source,
		CacheHit:     cacheHit,
		IndexHit:     indexHit,
		FileFallback: fileFallback,
	}
	if elapsed > 0 {
		meta.TSharkMS = elapsed.Milliseconds()
	}
	return meta
}

func (s *Service) SetTLSConfig(cfg model.TLSConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsConf = cfg
}

func (s *Service) TLSConfig() model.TLSConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsConf
}

func (s *Service) PacketRawHex(packetID int64) (string, error) {
	s.mu.RLock()
	pcap := s.pcap
	s.mu.RUnlock()

	if pcap == "" {
		return "", errors.New("no capture loaded")
	}
	return tshark.ReadPacketRawHexFromFile(pcap, packetID)
}

func (s *Service) PacketLayers(packetID int64) (map[string]any, error) {
	s.mu.RLock()
	pcap := s.pcap
	s.mu.RUnlock()

	if pcap == "" {
		return nil, errors.New("no capture loaded")
	}
	return tshark.ReadPacketLayersFromFile(pcap, packetID)
}

func (s *Service) ListPlugins() []model.Plugin {
	if s.pluginManger == nil {
		return nil
	}
	return s.pluginManger.List()
}

func (s *Service) TogglePlugin(id string) (model.Plugin, error) {
	if s.pluginManger == nil {
		return model.Plugin{}, errors.New("plugin manager is nil")
	}
	return s.pluginManger.Toggle(id)
}

func (s *Service) SetPluginsEnabled(ids []string, enabled bool) ([]model.Plugin, error) {
	if s.pluginManger == nil {
		return nil, errors.New("plugin manager is nil")
	}
	return s.pluginManger.SetEnabled(ids, enabled)
}

func (s *Service) AddPlugin(p model.Plugin) (model.Plugin, error) {
	if s.pluginManger == nil {
		return model.Plugin{}, errors.New("plugin manager is nil")
	}
	return s.pluginManger.Add(plugin.RulePlugin{
		ID:           p.ID,
		Name:         p.Name,
		Version:      p.Version,
		Tag:          p.Tag,
		Author:       p.Author,
		Enabled:      p.Enabled,
		Entry:        p.Entry,
		Capabilities: p.Capabilities,
	})
}

func (s *Service) DeletePlugin(id string) error {
	if s.pluginManger == nil {
		return errors.New("plugin manager is nil")
	}
	return s.pluginManger.Delete(id)
}

func (s *Service) PluginSource(id string) (model.PluginSource, error) {
	if s.pluginManger == nil {
		return model.PluginSource{}, errors.New("plugin manager is nil")
	}
	return s.pluginManger.Source(id)
}

func (s *Service) UpdatePluginSource(source model.PluginSource) (model.PluginSource, error) {
	if s.pluginManger == nil {
		return model.PluginSource{}, errors.New("plugin manager is nil")
	}
	return s.pluginManger.UpdateSource(source)
}

func (s *Service) StreamIDs(protocol string) []int64 {
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	ids := make(map[int64]struct{})

	s.mu.RLock()
	if len(s.rawStreamIndex) > 0 {
		for _, stream := range s.rawStreamIndex {
			if strings.EqualFold(stream.Protocol, normalized) && stream.StreamID >= 0 {
				ids[stream.StreamID] = struct{}{}
			}
		}
	}
	s.mu.RUnlock()

	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(p model.Packet) error {
			if p.StreamID < 0 {
				return nil
			}
			proto := strings.ToUpper(strings.TrimSpace(p.Protocol))
			if matchStreamProtocol(normalized, proto) {
				ids[p.StreamID] = struct{}{}
			}
			return nil
		})
	}

	out := make([]int64, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Service) GlobalTrafficStats() (model.GlobalTrafficStats, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.globalTrafficStats
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.GlobalTrafficStats{}, errors.New("no capture loaded")
	}

	stats, err := tshark.BuildGlobalTrafficStatsFromFile(pcap)
	if err != nil {
		return model.GlobalTrafficStats{}, err
	}

	s.mu.Lock()
	if s.globalTrafficStats == nil {
		s.globalTrafficStats = &stats
	}
	out := *s.globalTrafficStats
	s.mu.Unlock()
	return out, nil
}

func (s *Service) IndustrialAnalysis() (model.IndustrialAnalysis, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.industrialAnalysis
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.IndustrialAnalysis{}, errors.New("no capture loaded")
	}
	if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
		log.Printf("engine: specialized field cache warm failed for industrial analysis: %v", err)
	}

	analysis, err := tshark.BuildIndustrialAnalysisFromFile(pcap)
	if err != nil {
		return model.IndustrialAnalysis{}, err
	}

	s.mu.Lock()
	if s.industrialAnalysis == nil {
		s.industrialAnalysis = &analysis
	}
	out := *s.industrialAnalysis
	s.mu.Unlock()
	return out, nil
}

func (s *Service) VehicleAnalysis() (model.VehicleAnalysis, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.vehicleAnalysis
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.VehicleAnalysis{}, errors.New("no capture loaded")
	}
	if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
		log.Printf("engine: specialized field cache warm failed for vehicle analysis: %v", err)
	}

	s.mu.RLock()
	dbcDefs := append([]*tshark.DBCDatabase(nil), s.vehicleDBCDefs...)
	s.mu.RUnlock()

	analysis, err := tshark.BuildVehicleAnalysisFromFile(pcap, dbcDefs...)
	if err != nil {
		return model.VehicleAnalysis{}, err
	}

	s.mu.Lock()
	if s.vehicleAnalysis == nil {
		s.vehicleAnalysis = &analysis
	}
	out := *s.vehicleAnalysis
	s.mu.Unlock()
	return out, nil
}

func (s *Service) MediaAnalysis() (model.MediaAnalysis, error) {
	return s.mediaAnalysisWithForce(false)
}

func (s *Service) RefreshMediaAnalysis() (model.MediaAnalysis, error) {
	return s.mediaAnalysisWithForce(true)
}

func (s *Service) mediaAnalysisWithForce(force bool) (model.MediaAnalysis, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.mediaAnalysis
	s.mu.RUnlock()

	if !force && cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.MediaAnalysis{}, errors.New("no capture loaded")
	}
	s.emitStatus("__progress__:media:0:3:准备媒体流分析")
	cfg := s.buildMediaScanConfig(pcap)

	tempDir, err := os.MkdirTemp("", "gshark-media-")
	if err != nil {
		s.emitStatus("媒体流分析失败: " + err.Error())
		return model.MediaAnalysis{}, err
	}

	progressFn := func(current, total int, label string) {
		s.emitStatus(fmt.Sprintf("__progress__:media:%d:%d:%s", current, total, label))
	}

	var (
		analysis  model.MediaAnalysis
		artifacts map[string]string
	)

	if s.packetStore != nil && s.packetStore.Count() > 0 {
		packetCount := s.packetStore.Count()
		analysis, artifacts, err = tshark.BuildMediaAnalysisFromPacketStream(tempDir, packetCount, cfg, progressFn, func(onPacket func(model.Packet) error) error {
			return s.packetStore.Iterate(nil, onPacket)
		})
		if err != nil {
			log.Printf("engine: media analysis packet-store fast path failed, falling back to tshark file scan: %v", err)
		} else if analysis.TotalMediaPackets > 0 || len(analysis.Sessions) > 0 {
			log.Printf("engine: media analysis completed via packet-store fast path packets=%d sessions=%d", analysis.TotalMediaPackets, len(analysis.Sessions))
		} else {
			log.Printf("engine: media analysis packet-store fast path found no sessions, falling back to tshark file scan")
			err = nil
		}
	}

	if err == nil && analysis.TotalMediaPackets == 0 && len(analysis.Sessions) == 0 {
		analysis, artifacts, err = tshark.BuildMediaAnalysisFromFileWithConfig(pcap, tempDir, cfg, progressFn)
	}
	if err != nil {
		_ = os.RemoveAll(tempDir)
		s.emitStatus("媒体流分析失败: " + err.Error())
		return model.MediaAnalysis{}, err
	}

	s.mu.Lock()
	if force {
		if s.mediaExportDir != "" && s.mediaExportDir != tempDir {
			_ = os.RemoveAll(s.mediaExportDir)
		}
		s.mediaAnalysis = &analysis
		s.mediaExportDir = tempDir
		s.mediaArtifacts = artifacts
		s.mediaPlayback = map[string]string{}
		s.mediaSpeech = map[string]model.MediaTranscription{}
		s.cancelSpeechBatchLocked()
		s.speechBatch = nil
	} else if s.mediaAnalysis == nil {
		if s.mediaExportDir != "" && s.mediaExportDir != tempDir {
			_ = os.RemoveAll(s.mediaExportDir)
		}
		s.mediaAnalysis = &analysis
		s.mediaExportDir = tempDir
		s.mediaArtifacts = artifacts
		s.mediaPlayback = map[string]string{}
		s.mediaSpeech = map[string]model.MediaTranscription{}
		s.cancelSpeechBatchLocked()
		s.speechBatch = nil
	} else {
		_ = os.RemoveAll(tempDir)
	}
	out := *s.mediaAnalysis
	s.mu.Unlock()
	s.emitStatus("媒体流分析完成")
	return out, nil
}

func (s *Service) buildMediaScanConfig(pcap string) tshark.MediaScanConfig {
	cfg := tshark.MediaScanConfig{}
	if s.packetStore == nil || strings.TrimSpace(pcap) == "" {
		return cfg
	}

	candidatePorts, err := s.packetStore.TopUDPDestinationPorts(10, 32)
	if err != nil {
		log.Printf("engine: media preflight failed to query udp ports: %v", err)
		return cfg
	}
	if len(candidatePorts) == 0 {
		return cfg
	}

	decodeAsPorts, err := tshark.DetectLikelyRTPPorts(pcap, candidatePorts, 24)
	if err != nil {
		log.Printf("engine: media preflight failed to detect rtp-like ports: %v", err)
		return cfg
	}
	if len(decodeAsPorts) == 0 {
		return cfg
	}

	cfg.RTPDecodeAsPorts = decodeAsPorts
	cfg.PreflightNotes = append(cfg.PreflightNotes, fmt.Sprintf("预探测发现 RTP-like UDP 端口：%s。", formatPortList(decodeAsPorts)))
	if onlyNonStandardRTPPorts(decodeAsPorts) {
		cfg.SkipControlHints = true
		cfg.PreflightNotes = append(cfg.PreflightNotes, "检测到媒体流位于非标准 RTP 端口，已跳过全量 RTSP/SDP 控制信令扫描以避免大包阻塞。")
	}
	log.Printf("engine: media preflight config skip_control=%t decode_as_ports=%v", cfg.SkipControlHints, cfg.RTPDecodeAsPorts)
	return cfg
}

func onlyNonStandardRTPPorts(ports []int) bool {
	if len(ports) == 0 {
		return false
	}

	known := map[int]struct{}{
		554:   {},
		8554:  {},
		5004:  {},
		5005:  {},
		6970:  {},
		7070:  {},
		47984: {},
		47989: {},
		47990: {},
		47998: {},
		47999: {},
		48000: {},
		48002: {},
		48010: {},
	}

	for _, port := range ports {
		if _, ok := known[port]; ok {
			return false
		}
	}
	return true
}

func formatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ", ")
}

func (s *Service) USBAnalysis() (model.USBAnalysis, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.usbAnalysis
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.USBAnalysis{}, errors.New("no capture loaded")
	}
	if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
		log.Printf("engine: specialized field cache warm failed for usb analysis: %v", err)
	}

	analysis, err := tshark.BuildUSBAnalysisFromFile(pcap)
	if err != nil {
		return model.USBAnalysis{}, err
	}

	s.mu.Lock()
	if s.usbAnalysis == nil {
		s.usbAnalysis = &analysis
	}
	out := *s.usbAnalysis
	s.mu.Unlock()
	return out, nil
}

func (s *Service) C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error) {
	if err := ctx.Err(); err != nil {
		return model.C2SampleAnalysis{}, err
	}

	s.mu.RLock()
	cached := s.c2Analysis
	pcap := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}

	var analysis model.C2SampleAnalysis
	if pcap == "" {
		analysis = emptyC2SampleAnalysis()
		analysis.Notes = append(analysis.Notes, "当前未加载抓包，C2 骨架页仅显示空结构。")
	} else {
		if s.packetStore == nil {
			return model.C2SampleAnalysis{}, errors.New("当前抓包尚未建立本地数据包索引")
		}
		packets, err := s.packetStore.All(nil)
		if err != nil {
			return model.C2SampleAnalysis{}, err
		}
		analysis, err = buildC2SampleAnalysisFromPackets(ctx, packets)
		if err != nil {
			return model.C2SampleAnalysis{}, err
		}
		analysis.Notes = append(analysis.Notes,
			"当前版本已接入 CS / VShell 第一版可观测流量规则；结果仍按“候选证据”处理，静态端口/路径不会单独定性。",
			"Silver Fox / 银狐相关字段已预埋为归因扩展口，后续独立 APT 页面可复用这里的技术证据。",
		)
	}

	if err := ctx.Err(); err != nil {
		return model.C2SampleAnalysis{}, err
	}

	s.mu.Lock()
	if s.c2Analysis == nil {
		s.c2Analysis = &analysis
	}
	out := *s.c2Analysis
	s.mu.Unlock()
	return out, nil
}

func emptyC2SampleAnalysis() model.C2SampleAnalysis {
	return model.C2SampleAnalysis{
		TotalMatchedPackets: 0,
		Families:            []model.TrafficBucket{},
		Conversations:       []model.AnalysisConversation{},
		CS: model.C2FamilyAnalysis{
			CandidateCount:   0,
			MatchedRuleCount: 0,
			Channels:         []model.TrafficBucket{},
			Indicators:       []model.TrafficBucket{},
			Conversations:    []model.AnalysisConversation{},
			BeaconPatterns:   []model.C2BeaconPattern{},
			Candidates:       []model.C2IndicatorRecord{},
			Notes:            []string{},
			RelatedActors:    []model.TrafficBucket{},
			DeliveryChains:   []model.TrafficBucket{},
		},
		VShell: model.C2FamilyAnalysis{
			CandidateCount:   0,
			MatchedRuleCount: 0,
			Channels:         []model.TrafficBucket{},
			Indicators:       []model.TrafficBucket{},
			Conversations:    []model.AnalysisConversation{},
			BeaconPatterns:   []model.C2BeaconPattern{},
			Candidates:       []model.C2IndicatorRecord{},
			Notes:            []string{},
			RelatedActors:    []model.TrafficBucket{},
			DeliveryChains:   []model.TrafficBucket{},
		},
		Notes: []string{},
	}
}

func (s *Service) APTAnalysis(ctx context.Context) (model.APTAnalysis, error) {
	if err := ctx.Err(); err != nil {
		return model.APTAnalysis{}, err
	}

	s.mu.RLock()
	cached := s.aptAnalysis
	pcap := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}

	analysis := emptyAPTAnalysis()
	if pcap == "" {
		analysis.Notes = append(analysis.Notes, "当前未加载抓包，APT 组织画像页仅显示独立骨架与 Silver Fox 预留模型。")
	} else {
		c2, err := s.C2SampleAnalysis(ctx)
		if err != nil {
			return model.APTAnalysis{}, err
		}
		analysis = buildAPTAnalysisFromC2(c2)
		threatHits := s.ThreatHuntWithContext(ctx, nil)
		if len(threatHits) > 0 {
			analysis = buildAPTAnalysisFromThreatHits(threatHits, analysis)
		}
		objects := s.ObjectsWithContext(ctx)
		if len(objects) > 0 {
			analysis = buildAPTAnalysisFromObjects(objects, analysis)
		}
		analysis.Notes = append(analysis.Notes,
			"APT 页消费 C2、Threat Hunting 与 Object Export 三个模块的证据。",
			"Silver Fox / 银狐作为首个预置 actor profile；ValleyRAT、Winos 4.0、Gh0st 系、HFS 下载链与 fallback C2 作为后续规则接入口。",
		)
	}
	analysis = finalizeAPTAnalysis(analysis)

	if err := ctx.Err(); err != nil {
		return model.APTAnalysis{}, err
	}

	s.mu.Lock()
	if s.aptAnalysis == nil {
		s.aptAnalysis = &analysis
	}
	out := *s.aptAnalysis
	s.mu.Unlock()
	return out, nil
}

func emptyAPTAnalysis() model.APTAnalysis {
	return model.APTAnalysis{
		TotalEvidence:       0,
		Actors:              []model.TrafficBucket{},
		SampleFamilies:      []model.TrafficBucket{},
		CampaignStages:      []model.TrafficBucket{},
		TransportTraits:     []model.TrafficBucket{},
		InfrastructureHints: []model.TrafficBucket{},
		RelatedC2Families:   []model.TrafficBucket{},
		Profiles: []model.APTActorProfile{
			emptySilverFoxProfile(),
		},
		Evidence: []model.APTEvidenceRecord{},
		Notes:    []string{},
	}
}

func emptySilverFoxProfile() model.APTActorProfile {
	return model.APTActorProfile{
		ID:            "silver-fox",
		Name:          "Silver Fox / 银狐",
		Aliases:       []string{"Swimming Snake", "银狐", "Silver Fox"},
		Summary:       "预置 APT 画像骨架：用于承载 ValleyRAT / Winos 4.0 / Gh0st 系、HFS 下载链、HTTPS/TCP C2、fallback C2 与周期回连等后续证据。",
		Confidence:    0,
		EvidenceCount: 0,
		SampleFamilies: []model.TrafficBucket{
			{Label: "ValleyRAT", Count: 0},
			{Label: "Winos 4.0", Count: 0},
			{Label: "Gh0st variant", Count: 0},
		},
		CampaignStages: []model.TrafficBucket{
			{Label: "delivery", Count: 0},
			{Label: "downloader", Count: 0},
			{Label: "rat-c2", Count: 0},
		},
		TransportTraits: []model.TrafficBucket{
			{Label: "https-c2", Count: 0},
			{Label: "tcp-long-connection", Count: 0},
			{Label: "periodic-callback", Count: 0},
		},
		InfrastructureHints: []model.TrafficBucket{
			{Label: "hfs-download-chain", Count: 0},
			{Label: "fallback-c2", Count: 0},
			{Label: "custom-high-port", Count: 0},
		},
		RelatedC2Families: []model.TrafficBucket{},
		TTPTags: []model.TrafficBucket{
			{Label: "multi-stage-delivery", Count: 0},
			{Label: "encrypted-c2", Count: 0},
			{Label: "rat-family", Count: 0},
		},
		Notes: []string{
			"组织画像默认不直接等同于样本家族；只有流量侧证据、样本解析证据与投递链证据交叉后才应提升归因置信度。",
			"端口、路径、单个 IOC 仅作为弱观察位，不能单独作为 Silver Fox 归因结论。",
		},
	}
}

func buildAPTAnalysisFromC2(c2 model.C2SampleAnalysis) model.APTAnalysis {
	analysis := emptyAPTAnalysis()
	actorCounts := map[string]int{}
	sampleFamilies := map[string]int{}
	campaignStages := map[string]int{}
	transportTraits := map[string]int{}
	infrastructureHints := map[string]int{}
	relatedC2Families := map[string]int{}
	ttpTags := map[string]int{}
	profiles := map[string]*model.APTActorProfile{
		"silver-fox": cloneAPTActorProfile(emptySilverFoxProfile()),
	}

	consume := func(records []model.C2IndicatorRecord) {
		for _, item := range records {
			actors := normalizeActorHints(item.ActorHints, item.SampleFamily)
			if len(actors) == 0 {
				continue
			}
			for _, actorName := range actors {
				actorID := aptActorID(actorName)
				profile := profiles[actorID]
				if profile == nil {
					profile = &model.APTActorProfile{
						ID:                  actorID,
						Name:                actorName,
						Aliases:             []string{},
						Summary:             "由 C2 技术证据临时聚合出的 APT 候选画像，仍需人工复核。",
						SampleFamilies:      []model.TrafficBucket{},
						CampaignStages:      []model.TrafficBucket{},
						TransportTraits:     []model.TrafficBucket{},
						InfrastructureHints: []model.TrafficBucket{},
						RelatedC2Families:   []model.TrafficBucket{},
						TTPTags:             []model.TrafficBucket{},
						Notes:               []string{"临时 actor hint：尚未接入正式组织画像基线。"},
					}
					profiles[actorID] = profile
				}
				actorCounts[profile.Name]++
				profile.EvidenceCount++
				if item.Confidence > profile.Confidence {
					profile.Confidence = item.Confidence
				}
				if item.SampleFamily != "" {
					sampleFamilies[item.SampleFamily]++
				}
				if item.CampaignStage != "" {
					campaignStages[item.CampaignStage]++
				}
				for _, value := range item.TransportTraits {
					if strings.TrimSpace(value) != "" {
						transportTraits[value]++
					}
				}
				for _, value := range item.InfrastructureHints {
					if strings.TrimSpace(value) != "" {
						infrastructureHints[value]++
					}
				}
				if item.Family != "" {
					relatedC2Families[item.Family]++
				}
				for _, value := range item.TTPTags {
					if strings.TrimSpace(value) != "" {
						ttpTags[value]++
					}
				}
				record := model.APTEvidenceRecord{
					PacketID:            item.PacketID,
					StreamID:            item.StreamID,
					Time:                item.Time,
					ActorID:             profile.ID,
					ActorName:           profile.Name,
					SourceModule:        "c2-analysis",
					Family:              item.Family,
					EvidenceType:        c2FirstNonEmpty(item.IndicatorType, "c2-indicator"),
					EvidenceValue:       item.IndicatorValue,
					Confidence:          item.Confidence,
					Source:              item.Source,
					Destination:         item.Destination,
					Host:                item.Host,
					URI:                 item.URI,
					SampleFamily:        item.SampleFamily,
					CampaignStage:       item.CampaignStage,
					TransportTraits:     item.TransportTraits,
					InfrastructureHints: item.InfrastructureHints,
					TTPTags:             item.TTPTags,
					Tags:                item.Tags,
					Summary:             item.Summary,
					Evidence:            item.Evidence,
				}
				record.ScoreFactors = aptScoreFactorsForRecord(record)
				analysis.Evidence = append(analysis.Evidence, record)
			}
		}
	}
	consume(c2.CS.Candidates)
	consume(c2.VShell.Candidates)

	for _, profile := range profiles {
		profile.SampleFamilies = mergeAPTProfileBuckets(profile.SampleFamilies, sampleFamilies)
		profile.CampaignStages = mergeAPTProfileBuckets(profile.CampaignStages, campaignStages)
		profile.TransportTraits = mergeAPTProfileBuckets(profile.TransportTraits, transportTraits)
		profile.InfrastructureHints = mergeAPTProfileBuckets(profile.InfrastructureHints, infrastructureHints)
		profile.RelatedC2Families = mergeAPTProfileBuckets(profile.RelatedC2Families, relatedC2Families)
		profile.TTPTags = mergeAPTProfileBuckets(profile.TTPTags, ttpTags)
		analysis.Profiles = appendOrReplaceAPTProfile(analysis.Profiles, *profile)
	}
	sort.SliceStable(analysis.Profiles, func(i, j int) bool {
		if analysis.Profiles[i].EvidenceCount == analysis.Profiles[j].EvidenceCount {
			return analysis.Profiles[i].Name < analysis.Profiles[j].Name
		}
		return analysis.Profiles[i].EvidenceCount > analysis.Profiles[j].EvidenceCount
	})

	analysis.TotalEvidence = len(analysis.Evidence)
	analysis.Actors = bucketsFromMap(actorCounts, 16)
	analysis.SampleFamilies = bucketsFromMap(sampleFamilies, 24)
	analysis.CampaignStages = bucketsFromMap(campaignStages, 24)
	analysis.TransportTraits = bucketsFromMap(transportTraits, 24)
	analysis.InfrastructureHints = bucketsFromMap(infrastructureHints, 24)
	analysis.RelatedC2Families = bucketsFromMap(relatedC2Families, 12)
	return analysis
}

func cloneAPTActorProfile(profile model.APTActorProfile) *model.APTActorProfile {
	out := profile
	return &out
}

func normalizeActorHints(hints []string, sampleFamily string) []string {
	values := make([]string, 0, len(hints)+1)
	for _, hint := range hints {
		if trimmed := strings.TrimSpace(hint); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	family := strings.ToLower(strings.TrimSpace(sampleFamily))
	if family == "valleyrat" || strings.Contains(family, "winos") || strings.Contains(family, "gh0st") {
		values = append(values, "Silver Fox / 银狐")
	}
	return uniqueStrings(values)
}

func aptActorID(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(lower, "silver") || strings.Contains(name, "银狐") || strings.Contains(lower, "swimming snake") {
		return "silver-fox"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", "_", "-", "：", "-", ":", "-", "(", "", ")", "")
	id := strings.Trim(replacer.Replace(lower), "-")
	if id == "" {
		return "unknown-actor"
	}
	return id
}

func mergeAPTProfileBuckets(base []model.TrafficBucket, counts map[string]int) []model.TrafficBucket {
	merged := map[string]int{}
	for _, item := range base {
		if strings.TrimSpace(item.Label) != "" {
			merged[item.Label] += item.Count
		}
	}
	for label, count := range counts {
		if strings.TrimSpace(label) != "" {
			merged[label] += count
		}
	}
	return bucketsFromMap(merged, 24)
}

func appendOrReplaceAPTProfile(items []model.APTActorProfile, next model.APTActorProfile) []model.APTActorProfile {
	for i := range items {
		if items[i].ID == next.ID {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func (s *Service) MediaArtifact(token string) (string, string, error) {
	s.mu.RLock()
	path := s.mediaArtifacts[token]
	analysis := s.mediaAnalysis
	s.mu.RUnlock()

	if strings.TrimSpace(path) == "" {
		return "", "", errors.New("media artifact not found")
	}

	name := filepath.Base(path)
	if analysis != nil {
		for _, session := range analysis.Sessions {
			if session.Artifact != nil && session.Artifact.Token == token && strings.TrimSpace(session.Artifact.Name) != "" {
				name = session.Artifact.Name
				break
			}
		}
	}

	return path, name, nil
}

func (s *Service) VehicleDBCProfiles() []model.DBCProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return buildDBCProfilesForService(s.vehicleDBCDefs)
}

func (s *Service) AddVehicleDBC(path string) ([]model.DBCProfile, error) {
	db, err := tshark.LoadDBCDatabase(path)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cleanPath := filepath.Clean(strings.TrimSpace(path))
	for _, existing := range s.vehicleDBCDefs {
		if existing != nil && strings.EqualFold(existing.Path, cleanPath) {
			return buildDBCProfilesForService(s.vehicleDBCDefs), nil
		}
	}

	s.vehicleDBCDefs = append(s.vehicleDBCDefs, db)
	s.vehicleAnalysis = nil
	return buildDBCProfilesForService(s.vehicleDBCDefs), nil
}

func (s *Service) RemoveVehicleDBC(path string) []model.DBCProfile {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := s.vehicleDBCDefs[:0]
	for _, db := range s.vehicleDBCDefs {
		if db == nil || strings.EqualFold(db.Path, cleanPath) {
			continue
		}
		filtered = append(filtered, db)
	}
	s.vehicleDBCDefs = filtered
	s.vehicleAnalysis = nil
	return buildDBCProfilesForService(s.vehicleDBCDefs)
}

func matchStreamProtocol(target, proto string) bool {
	switch target {
	case "HTTP":
		return proto == "HTTP"
	case "UDP":
		return proto == "UDP" || proto == "DNS"
	case "TCP":
		return proto == "TCP" || proto == "HTTP" || proto == "HTTPS" || proto == "TLS" || proto == "SSHV2"
	default:
		return false
	}
}

func buildDBCProfilesForService(databases []*tshark.DBCDatabase) []model.DBCProfile {
	if len(databases) == 0 {
		return nil
	}
	out := make([]model.DBCProfile, 0, len(databases))
	for _, db := range databases {
		if db == nil {
			continue
		}
		out = append(out, db.Profile())
	}
	return out
}

func (s *Service) filteredPacketIndex(filter string) (*filteredPacketIndex, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil, nil
	}

	s.mu.Lock()
	if cached, ok := s.displayFilterCache[filter]; ok {
		s.touchDisplayFilterCacheLocked(filter)
		s.mu.Unlock()
		return cached, nil
	}
	pcap := s.pcap
	tlsConf := s.tlsConf
	if strings.TrimSpace(pcap) == "" || s.packetStore == nil {
		s.mu.Unlock()
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	index := newFilteredPacketIndex(cancel)
	s.displayFilterCache[filter] = index
	s.touchDisplayFilterCacheLocked(filter)
	s.evictDisplayFilterCacheLocked()
	s.mu.Unlock()
	go s.scanDisplayFilterIndex(ctx, filter, pcap, tlsConf, index)
	return index, nil
}

func (s *Service) touchDisplayFilterCacheLocked(filter string) {
	for i, existing := range s.displayFilterCacheOrder {
		if existing != filter {
			continue
		}
		copy(s.displayFilterCacheOrder[i:], s.displayFilterCacheOrder[i+1:])
		s.displayFilterCacheOrder = s.displayFilterCacheOrder[:len(s.displayFilterCacheOrder)-1]
		break
	}
	s.displayFilterCacheOrder = append(s.displayFilterCacheOrder, filter)
}

func (s *Service) evictDisplayFilterCacheLocked() {
	for len(s.displayFilterCacheOrder) > displayFilterCacheLimit {
		oldest := s.displayFilterCacheOrder[0]
		s.displayFilterCacheOrder = s.displayFilterCacheOrder[1:]
		if cached, ok := s.displayFilterCache[oldest]; ok {
			cached.stop()
		}
		delete(s.displayFilterCache, oldest)
	}
}

func (s *Service) cancelDisplayFilterCacheLocked() {
	for filter, cached := range s.displayFilterCache {
		if cached != nil {
			cached.stop()
		}
		delete(s.displayFilterCache, filter)
	}
}

func (s *Service) hasCapturePath() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.pcap) != ""
}

func streamCacheLimitValue() int {
	raw := strings.TrimSpace(os.Getenv("GSHARK_STREAM_CACHE_LIMIT"))
	if raw == "" {
		return defaultStreamCacheLimit
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 64 {
		return defaultStreamCacheLimit
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
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
