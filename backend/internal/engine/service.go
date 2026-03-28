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

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/plugin"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type Service struct {
	emitter      EventEmitter
	pluginManger *plugin.Manager

	mu                 sync.RWMutex
	packetStore        *packetStore
	tlsConf            model.TLSConfig
	runID              int64
	pcap               string
	displayFilterCache map[string]*filteredPacketIndex
	globalTrafficStats *model.GlobalTrafficStats
	industrialAnalysis *model.IndustrialAnalysis
	vehicleAnalysis    *model.VehicleAnalysis
	mediaAnalysis      *model.MediaAnalysis
	vehicleDBCDefs     []*tshark.DBCDatabase
	streamCache        map[string]model.ReassembledStream
	streamCacheOrder   []string
	rawStreamIndex     map[string]model.ReassembledStream

	exportDir      string
	mediaExportDir string
	objectsLoaded  bool
	objects        []model.ObjectFile
	mediaArtifacts map[string]string
	objMu          sync.Mutex
	yaraLoaded     bool
	yaraHits       []model.ThreatHit
	yaraMu         sync.Mutex

	huntMu          sync.RWMutex
	huntingPrefixes []string

	cancel context.CancelFunc
}

const streamCacheLimit = 256

type filteredPacketIndex struct {
	ids       []int64
	positions map[int64]int
}

var (
	estimatePacketsFn     = tshark.EstimatePackets
	filterFrameIDsFn      = tshark.FilterFrameIDs
	streamPacketsFn       = tshark.StreamPackets
	streamPacketsFastFn   = tshark.StreamPacketsFast
	streamPacketsCompatFn = tshark.StreamPacketsCompat
	httpStreamFromFileFn  = tshark.ReassembleHTTPStreamFromFile
	rawStreamFromFileFn   = tshark.ReassembleRawStreamFromFile
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
		mediaArtifacts:     map[string]string{},
		huntingPrefixes: []string{
			"flag{",
			"ctf{",
		},
	}
}

func (s *Service) LoadPCAP(ctx context.Context, opts model.ParseOptions) error {
	if opts.FilePath == "" {
		return errors.New("empty file path")
	}

	s.StopStreaming()
	currentRunID := atomic.AddInt64(&s.runID, 1)
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

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
	s.pcap = opts.FilePath
	s.displayFilterCache = map[string]*filteredPacketIndex{}
	s.globalTrafficStats = nil
	s.industrialAnalysis = nil
	s.vehicleAnalysis = nil
	s.mediaAnalysis = nil
	s.mediaArtifacts = map[string]string{}
	s.streamCache = map[string]model.ReassembledStream{}
	s.streamCacheOrder = s.streamCacheOrder[:0]
	s.rawStreamIndex = map[string]model.ReassembledStream{}
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

	s.emitter.EmitStatus("开始解析 PCAP")
	total, countErr := estimatePacketsFn(runCtx, opts)
	if countErr == nil && total > 0 {
		s.emitter.EmitStatus(fmt.Sprintf("__progress__:counting:%d:%d", total, total))
		s.emitter.EmitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", 0, total))
		log.Printf("engine: tshark estimated %d packets for %q", total, opts.FilePath)
	} else if countErr != nil {
		log.Printf("engine: tshark packet estimate failed for %q: %v", opts.FilePath, countErr)
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
				s.emitter.EmitStatus("写入数据包存储失败: " + err.Error())
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
			s.emitter.EmitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
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
			s.emitter.EmitStatus("fast_list compatibility fallback: retrying parse with EK mode")
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
					s.emitter.EmitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
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
			s.emitter.EmitStatus("compatibility fallback: retrying parse with minimal field mode")
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
					s.emitter.EmitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
				}
			})
			flushPending()
			log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", "compat_fields_fallback", processed, accepted, err)
		}
	}
	if total > 0 {
		s.emitter.EmitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", processed, total))
	}

	dropped := processed - accepted
	if dropped < 0 {
		dropped = 0
	}
	if processed > 0 {
		s.emitter.EmitStatus(fmt.Sprintf("解析统计: 已处理=%d, 入库=%d, 跳过=%d", processed, accepted, dropped))
	}
	if opts.FastList && dropped > 0 {
		s.emitter.EmitStatus(fmt.Sprintf("fast_list 告警: 有 %d 条记录未入库，请检查字段映射/解析规则", dropped))
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
		s.emitter.EmitStatus("解析完成")
	case context.Canceled:
		s.emitter.EmitStatus("解析被取消")
	default:
		s.emitter.EmitStatus("解析失败: " + err.Error())
	}
	return err
}

func (s *Service) StopStreaming() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
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

func (s *Service) PacketsPage(cursor, limit int, filter string) ([]model.Packet, int, int) {
	if s.packetStore == nil {
		return nil, 0, 0
	}
	filtered, filterErr := s.filteredPacketIndex(filter)
	if filterErr == nil && filtered != nil {
		out, next, total, err := s.packetStore.PageByIDs(filtered.ids, cursor, limit)
		if err != nil {
			s.emitter.EmitStatus("数据包分页查询失败: " + err.Error())
			return []model.Packet{}, 0, 0
		}
		return out, next, total
	}
	if strings.TrimSpace(filter) != "" && s.hasCapturePath() {
		return []model.Packet{}, 0, 0
	}

	predicate := compilePacketFilter(filter)
	out, next, total, err := s.packetStore.Page(cursor, limit, predicate)
	if err != nil {
		s.emitter.EmitStatus("数据包分页查询失败: " + err.Error())
		return []model.Packet{}, 0, 0
	}
	return out, next, total
}

func (s *Service) PacketPageCursor(packetID int64, limit int, filter string) (int, int, bool) {
	if packetID <= 0 || s.packetStore == nil {
		return 0, 0, false
	}
	if limit <= 0 {
		limit = 1000
	}
	filtered, err := s.filteredPacketIndex(filter)
	if err == nil && filtered != nil {
		matchIndex, ok := filtered.positions[packetID]
		if !ok {
			return 0, len(filtered.ids), false
		}
		cursor := (matchIndex / limit) * limit
		return cursor, len(filtered.ids), true
	}
	if strings.TrimSpace(filter) != "" && s.hasCapturePath() {
		return 0, 0, false
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
		return 0, total, false
	}
	cursor := (matchIndex / limit) * limit
	return cursor, total, true
}

func (s *Service) ThreatHunt(prefixes []string) []model.ThreatHit {
	if len(prefixes) == 0 {
		prefixes = s.getHuntingPrefixes()
	}
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

	hits := hunter.Results()
	if pluginRunner != nil {
		hits = append(hits, pluginRunner.Close(int64(len(hits)+1))...)
		for _, warning := range pluginRunner.Warnings() {
			s.emitter.EmitStatus("plugin warning: " + warning)
		}
	}
	objects := s.Objects()
	hits = append(hits, s.cachedYaraHits(objects)...)
	hits = append(hits, StegoPrecheck(objects)...)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].ID == hits[j].ID {
			return hits[i].PacketID < hits[j].PacketID
		}
		return hits[i].ID < hits[j].ID
	})
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

	yaraEnabled := !strings.EqualFold(strings.TrimSpace(os.Getenv("GSHARK_YARA_ENABLED")), "false")
	yaraBin := strings.TrimSpace(os.Getenv("GSHARK_YARA_BIN"))
	yaraRules := strings.TrimSpace(os.Getenv("GSHARK_YARA_RULES"))
	yaraTimeoutMS := 25000
	if raw := strings.TrimSpace(os.Getenv("GSHARK_YARA_TIMEOUT_MS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			yaraTimeoutMS = parsed
		}
	}

	return model.HuntingRuntimeConfig{
		Prefixes:      prefixes,
		YaraEnabled:   yaraEnabled,
		YaraBin:       yaraBin,
		YaraRules:     yaraRules,
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

	if cfg.YaraEnabled {
		_ = os.Unsetenv("GSHARK_YARA_ENABLED")
	} else {
		_ = os.Setenv("GSHARK_YARA_ENABLED", "false")
	}

	if strings.TrimSpace(cfg.YaraBin) == "" {
		_ = os.Unsetenv("GSHARK_YARA_BIN")
	} else {
		_ = os.Setenv("GSHARK_YARA_BIN", strings.TrimSpace(cfg.YaraBin))
	}

	if strings.TrimSpace(cfg.YaraRules) == "" {
		_ = os.Unsetenv("GSHARK_YARA_RULES")
	} else {
		_ = os.Setenv("GSHARK_YARA_RULES", strings.TrimSpace(cfg.YaraRules))
	}

	if cfg.YaraTimeoutMS <= 0 {
		_ = os.Unsetenv("GSHARK_YARA_TIMEOUT_MS")
	} else {
		_ = os.Setenv("GSHARK_YARA_TIMEOUT_MS", strconv.Itoa(cfg.YaraTimeoutMS))
	}

	s.yaraMu.Lock()
	s.yaraLoaded = false
	s.yaraHits = nil
	s.yaraMu.Unlock()

	return s.GetHuntingRuntimeConfig()
}

func (s *Service) cachedYaraHits(objects []model.ObjectFile) []model.ThreatHit {
	s.yaraMu.Lock()
	defer s.yaraMu.Unlock()

	if s.yaraLoaded {
		out := make([]model.ThreatHit, len(s.yaraHits))
		copy(out, s.yaraHits)
		return out
	}

	hits := BatchScanObjectsWithYaraIndex(objects, s.packetObjectNameIndex())
	s.yaraHits = make([]model.ThreatHit, len(hits))
	copy(s.yaraHits, hits)
	s.yaraLoaded = true

	out := make([]model.ThreatHit, len(s.yaraHits))
	copy(out, s.yaraHits)
	return out
}

func (s *Service) Objects() []model.ObjectFile {
	s.objMu.Lock()
	defer s.objMu.Unlock()

	if s.objectsLoaded {
		return s.objects
	}

	s.mu.RLock()
	pcapPath := s.pcap
	s.mu.RUnlock()

	if pcapPath == "" {
		return nil
	}

	tempDir, err := os.MkdirTemp("", "gshark-export-")
	if err != nil {
		return nil
	}
	s.exportDir = tempDir

	if err := tshark.ExportObjects(pcapPath, tempDir); err != nil {
		s.objectsLoaded = true
		return nil
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		s.objectsLoaded = true
		return nil
	}

	packetByObjectName := s.packetObjectNameIndex()

	var objects []model.ObjectFile
	var id int64 = 1
	for _, entry := range entries {
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

	s.objects = objects
	s.objectsLoaded = true
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

func (s *Service) HTTPStream(streamID int64) model.ReassembledStream {
	key := streamCacheKey("HTTP", streamID)
	s.mu.RLock()
	pcap := s.pcap
	if cached, ok := s.streamCache[key]; ok {
		s.mu.RUnlock()
		return cloneReassembledStream(cached)
	}
	s.mu.RUnlock()

	if s.packetStore != nil {
		stream := ReassembleHTTPStreamFromIterate(func(fn func(model.Packet) error) error {
			return s.packetStore.Iterate(nil, fn)
		}, streamID)
		if len(stream.Chunks) > 0 || stream.Request != "" || stream.Response != "" {
			s.cacheStream(key, stream)
			return stream
		}
	}

	if pcap != "" {
		stream, err := httpStreamFromFileFn(pcap, streamID)
		if err == nil && (stream.Request != "" || stream.Response != "") {
			s.cacheStream(key, stream)
			return stream
		}
	}

	return model.ReassembledStream{StreamID: streamID, Protocol: "HTTP"}
}

func (s *Service) RawStream(protocol string, streamID int64) model.ReassembledStream {
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	key := streamCacheKey(normalized, streamID)

	s.mu.RLock()
	pcap := s.pcap
	if cached, ok := s.streamCache[key]; ok {
		s.mu.RUnlock()
		return cloneReassembledStream(cached)
	}
	if indexed, ok := s.rawStreamIndex[key]; ok {
		s.mu.RUnlock()
		s.cacheStream(key, indexed)
		return cloneReassembledStream(indexed)
	}
	s.mu.RUnlock()

	if pcap != "" {
		stream, err := rawStreamFromFileFn(pcap, normalized, streamID)
		if err == nil && len(stream.Chunks) > 0 {
			s.cacheStream(key, stream)
			return stream
		}
	}

	return model.ReassembledStream{StreamID: streamID, Protocol: normalized}
}

func (s *Service) RawStreamPage(protocol string, streamID int64, cursor, limit int) (model.ReassembledStream, int, int) {
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	key := streamCacheKey(normalized, streamID)

	s.mu.RLock()
	if indexed, ok := s.rawStreamIndex[key]; ok {
		s.mu.RUnlock()
		return cloneRawStreamWindow(indexed, cursor, limit)
	}
	s.mu.RUnlock()

	stream := s.RawStream(normalized, streamID)
	return cloneRawStreamWindow(stream, cursor, limit)
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

	for len(s.streamCacheOrder) > streamCacheLimit {
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
	return out
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
	if s.packetStore != nil {
		_ = s.packetStore.Iterate(nil, func(p model.Packet) error {
			if p.StreamID <= 0 {
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
	s.mu.RLock()
	pcap := s.pcap
	cached := s.mediaAnalysis
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.MediaAnalysis{}, errors.New("no capture loaded")
	}
	if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
		log.Printf("engine: specialized field cache warm failed for media analysis: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "gshark-media-")
	if err != nil {
		return model.MediaAnalysis{}, err
	}

	analysis, artifacts, err := tshark.BuildMediaAnalysisFromFile(pcap, tempDir)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return model.MediaAnalysis{}, err
	}

	s.mu.Lock()
	if s.mediaAnalysis == nil {
		if s.mediaExportDir != "" && s.mediaExportDir != tempDir {
			_ = os.RemoveAll(s.mediaExportDir)
		}
		s.mediaAnalysis = &analysis
		s.mediaExportDir = tempDir
		s.mediaArtifacts = artifacts
	} else {
		_ = os.RemoveAll(tempDir)
	}
	out := *s.mediaAnalysis
	s.mu.Unlock()
	return out, nil
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

	s.mu.RLock()
	if cached, ok := s.displayFilterCache[filter]; ok {
		s.mu.RUnlock()
		return cached, nil
	}
	pcap := s.pcap
	tlsConf := s.tlsConf
	s.mu.RUnlock()
	if strings.TrimSpace(pcap) == "" || s.packetStore == nil {
		return nil, nil
	}

	ids, err := filterFrameIDsFn(context.Background(), model.ParseOptions{
		FilePath:      pcap,
		DisplayFilter: filter,
		TLS:           tlsConf,
	})
	if err != nil {
		s.emitter.EmitStatus("显示过滤器执行失败: " + err.Error())
		return nil, err
	}

	ids = s.packetStore.ExistingIDs(ids)
	index := &filteredPacketIndex{
		ids:       ids,
		positions: make(map[int64]int, len(ids)),
	}
	for i, id := range ids {
		index.positions[id] = i
	}

	s.mu.Lock()
	if existing, ok := s.displayFilterCache[filter]; ok {
		s.mu.Unlock()
		return existing, nil
	}
	s.displayFilterCache[filter] = index
	s.mu.Unlock()
	return index, nil
}

func (s *Service) hasCapturePath() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.pcap) != ""
}
