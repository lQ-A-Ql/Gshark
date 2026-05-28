package engine

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/plugin"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func (s *Service) ThreatHunt(prefixes []string) []model.ThreatHit {
	return s.ThreatHuntWithContext(context.Background(), prefixes)
}

func (s *Service) ThreatHuntWithContext(ctx context.Context, prefixes []string) []model.ThreatHit {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, finishTask := s.TrackCaptureTask(ctx, "threat-hunting")
	defer finishTask()
	if len(prefixes) == 0 {
		prefixes = s.getHuntingPrefixes()
	}
	s.emitStatus("__progress__:threat:0:5:准备威胁分析")
	hunter := newThreatHunter(prefixes, 1)
	var pluginRunner *plugin.PacketPluginRunner
	if s.pluginManager != nil {
		pluginRunner = s.pluginManager.NewPacketPluginRunner(ctx)
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
	s.yaraScanning = false
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
	ctx, finishTask := s.TrackCaptureTask(ctx, "yara-scan")
	defer finishTask()
	if ctx.Err() != nil {
		return nil
	}

	// Fast path: return cached results under short lock.
	s.yaraMu.Lock()
	if s.yaraLoaded {
		out := make([]model.ThreatHit, len(s.yaraHits))
		copy(out, s.yaraHits)
		s.yaraMu.Unlock()
		return out
	}
	if s.yaraScanning {
		// Another goroutine is already scanning; wait for it.
		s.yaraMu.Unlock()
		<-ctx.Done()
		s.yaraMu.Lock()
		out := make([]model.ThreatHit, len(s.yaraHits))
		copy(out, s.yaraHits)
		s.yaraMu.Unlock()
		return out
	}
	s.yaraScanning = true
	s.yaraMu.Unlock()

	// Scan runs outside the lock.
	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()

	if !yc.Enabled {
		s.setYaraResult(nil, nil, true)
		return nil
	}

	hits, scanErr := s.executeYaraScan(ctx, yc, objects)

	s.setYaraResult(hits, scanErr, true)

	s.yaraMu.Lock()
	out := make([]model.ThreatHit, len(s.yaraHits))
	copy(out, s.yaraHits)
	s.yaraMu.Unlock()
	return out
}

func (s *Service) setYaraResult(hits []model.ThreatHit, scanErr error, loaded bool) {
	s.yaraMu.Lock()
	s.yaraHits = hits
	s.yaraLoaded = loaded
	s.yaraScanning = false
	if scanErr != nil {
		s.yaraLastError = scanErr.Error()
	} else {
		s.yaraLastError = ""
	}
	s.yaraMu.Unlock()
}

func (s *Service) executeYaraScan(ctx context.Context, yc model.YaraConfig, objects []model.ObjectFile) ([]model.ThreatHit, error) {
	if err := preflightYaraScanConfig(yc); err != nil {
		log.Printf("engine: yara scan unavailable: %v", err)
		s.emitStatus("YARA 扫描异常: " + err.Error())
		return []model.ThreatHit{newYaraWarningHit(err.Error())}, err
	}

	targets, cleanup, err := s.buildYaraScanTargetsWithContext(ctx, objects)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		log.Printf("engine: build yara scan targets failed: %v", err)
		s.emitStatus("YARA 扫描目标构建失败: " + err.Error())
		return []model.ThreatHit{newYaraWarningHit("YARA 扫描目标构建失败: " + err.Error())}, err
	}

	hits, scanErr := BatchScanTargetsWithYaraConfigContext(ctx, targets, yc)
	if scanErr != nil {
		if errors.Is(scanErr, context.Canceled) {
			return nil, scanErr
		}
		log.Printf("engine: yara scan failed: %v", scanErr)
		s.emitStatus("YARA 扫描异常: " + scanErr.Error())
		hits = append(hits, newYaraWarningHit(scanErr.Error()))
		return hits, scanErr
	}
	return hits, nil
}

func (s *Service) Objects() []model.ObjectFile {
	return s.ObjectsWithContext(context.Background())
}

func (s *Service) ObjectsWithContext(ctx context.Context) []model.ObjectFile {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, finishTask := s.TrackCaptureTask(ctx, "object-export")
	defer finishTask()
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
	if s.pluginManager == nil {
		return nil
	}
	return s.pluginManager.List()
}

func (s *Service) TogglePlugin(id string) (model.Plugin, error) {
	if s.pluginManager == nil {
		return model.Plugin{}, errors.New("plugin manager is nil")
	}
	return s.pluginManager.Toggle(id)
}

func (s *Service) SetPluginsEnabled(ids []string, enabled bool) ([]model.Plugin, error) {
	if s.pluginManager == nil {
		return nil, errors.New("plugin manager is nil")
	}
	return s.pluginManager.SetEnabled(ids, enabled)
}

func (s *Service) AddPlugin(p model.Plugin) (model.Plugin, error) {
	if s.pluginManager == nil {
		return model.Plugin{}, errors.New("plugin manager is nil")
	}
	return s.pluginManager.Add(plugin.RulePlugin{
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
	if s.pluginManager == nil {
		return errors.New("plugin manager is nil")
	}
	return s.pluginManager.Delete(id)
}

func (s *Service) PluginSource(id string) (model.PluginSource, error) {
	if s.pluginManager == nil {
		return model.PluginSource{}, errors.New("plugin manager is nil")
	}
	return s.pluginManager.Source(id)
}

func (s *Service) UpdatePluginSource(source model.PluginSource) (model.PluginSource, error) {
	if s.pluginManager == nil {
		return model.PluginSource{}, errors.New("plugin manager is nil")
	}
	return s.pluginManager.UpdateSource(source)
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
