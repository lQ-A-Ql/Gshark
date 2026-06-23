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
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var exportObjectsContextFn = tshark.ExportObjectsContext

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

	if s.captureCtl.packetStore != nil {
		_ = s.captureCtl.packetStore.Iterate(nil, func(packet model.Packet) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			hunter.Observe(packet)
			return nil
		})
	}
	if ctx.Err() != nil {
		s.emitStatus("威胁分析已取消")
		return nil
	}
	s.emitStatus("__progress__:threat:1:5:扫描数据包基础特征")

	hits := hunter.Results()
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
	s.huntingCtl.huntMu.RLock()
	defer s.huntingCtl.huntMu.RUnlock()
	out := make([]string, len(s.huntingCtl.huntingPrefixes))
	copy(out, s.huntingCtl.huntingPrefixes)
	return out
}

func (s *Service) GetHuntingRuntimeConfig() model.HuntingRuntimeConfig {
	prefixes := s.getHuntingPrefixes()
	if len(prefixes) == 0 {
		prefixes = []string{"flag{", "ctf{"}
	}
	s.huntingCtl.huntMu.RLock()
	yc := s.huntingCtl.yaraConf
	s.huntingCtl.huntMu.RUnlock()

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
			s.huntingCtl.huntMu.Lock()
			s.huntingCtl.huntingPrefixes = normalized
			s.huntingCtl.huntMu.Unlock()
		}
	}
	yaraBin, yaraAllowedDirs := s.runtimeCtl.setYaraRuntimePath(cfg.YaraBin)
	s.huntingCtl.huntMu.Lock()
	s.huntingCtl.yaraConf = model.YaraConfig{
		Enabled:     cfg.YaraEnabled,
		Bin:         yaraBin,
		AllowedDirs: yaraAllowedDirs,
		Rules:       strings.TrimSpace(cfg.YaraRules),
		TimeoutMS:   cfg.YaraTimeoutMS,
	}
	s.huntingCtl.huntMu.Unlock()
	s.resetYaraScanState()

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
	s.huntingCtl.yaraMu.Lock()
	if s.huntingCtl.yaraLoaded {
		out := make([]model.ThreatHit, len(s.huntingCtl.yaraHits))
		copy(out, s.huntingCtl.yaraHits)
		s.huntingCtl.yaraMu.Unlock()
		return out
	}
	if s.huntingCtl.yaraScanning {
		// Another goroutine is already scanning; wait for it.
		done := s.huntingCtl.yaraScanDone
		s.huntingCtl.yaraMu.Unlock()
		if done == nil {
			<-ctx.Done()
		} else {
			select {
			case <-done:
			case <-ctx.Done():
			}
		}
		s.huntingCtl.yaraMu.Lock()
		out := make([]model.ThreatHit, len(s.huntingCtl.yaraHits))
		copy(out, s.huntingCtl.yaraHits)
		s.huntingCtl.yaraMu.Unlock()
		return out
	}
	s.huntingCtl.yaraScanning = true
	s.huntingCtl.yaraScanDone = make(chan struct{})
	s.huntingCtl.yaraMu.Unlock()
	// Scan runs outside the lock.
	s.huntingCtl.huntMu.RLock()
	yc := s.huntingCtl.yaraConf
	s.huntingCtl.huntMu.RUnlock()

	if !yc.Enabled {
		s.setYaraResult(nil, nil, true)
		return nil
	}

	hits, scanErr := s.executeYaraScan(ctx, yc, objects)

	s.setYaraResult(hits, scanErr, true)
	s.huntingCtl.yaraMu.Lock()
	out := make([]model.ThreatHit, len(s.huntingCtl.yaraHits))
	copy(out, s.huntingCtl.yaraHits)
	s.huntingCtl.yaraMu.Unlock()
	return out
}

func (s *Service) setYaraResult(hits []model.ThreatHit, scanErr error, loaded bool) {
	s.huntingCtl.yaraMu.Lock()
	done := s.huntingCtl.yaraScanDone
	s.huntingCtl.yaraHits = hits
	s.huntingCtl.yaraLoaded = loaded
	s.huntingCtl.yaraScanning = false
	s.huntingCtl.yaraScanDone = nil
	if scanErr != nil {
		s.huntingCtl.yaraLastError = scanErr.Error()
	} else {
		s.huntingCtl.yaraLastError = ""
	}
	s.huntingCtl.yaraMu.Unlock()
	if done != nil {
		close(done)
	}
}

func closeYaraScanDoneLocked(state *yaraHuntingState) {
	if state == nil || state.yaraScanDone == nil {
		return
	}
	close(state.yaraScanDone)
	state.yaraScanDone = nil
}

func (s *Service) resetYaraScanState() {
	s.huntingCtl.yaraMu.Lock()
	closeYaraScanDoneLocked(&s.huntingCtl.yaraHuntingState)
	s.huntingCtl.yaraLoaded = false
	s.huntingCtl.yaraScanning = false
	s.huntingCtl.yaraHits = nil
	s.huntingCtl.yaraLastError = ""
	s.huntingCtl.yaraMu.Unlock()
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
	s.objectCtl.objMu.Lock()
	if s.objectCtl.objectsLoaded {
		objects := s.objectCtl.objects
		s.objectCtl.objMu.Unlock()
		return objects
	}
	s.objectCtl.objMu.Unlock()
	s.captureCtl.mu.RLock()
	pcapPath := s.captureCtl.pcap
	s.captureCtl.mu.RUnlock()

	if pcapPath == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	tempDir, err := os.MkdirTemp("", "meow-traffic-export-")
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

	if err := exportObjectsContextFn(ctx, pcapPath, tempDir); err != nil {
		return nil
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
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
	s.objectCtl.objMu.Lock()
	defer s.objectCtl.objMu.Unlock()
	if s.objectCtl.objectsLoaded {
		return s.objectCtl.objects
	}
	s.captureCtl.mu.RLock()
	currentPCAP := s.captureCtl.pcap
	s.captureCtl.mu.RUnlock()
	if currentPCAP != pcapPath {
		return nil
	}
	s.objectCtl.exportDir = tempDir
	s.objectCtl.objects = objects
	s.objectCtl.objectsLoaded = true
	keepTempDir = true
	return s.objectCtl.objects
}

func (s *Service) packetObjectNameIndex() map[string]int64 {
	if s.captureCtl.packetStore == nil {
		return map[string]int64{}
	}
	return buildPacketIDByObjectNameFromIterate(func(fn func(model.Packet) error) error {
		return s.captureCtl.packetStore.Iterate(nil, fn)
	})
}

func (s *Service) SetTLSConfig(cfg model.TLSConfig) {
	s.runtimeCtl.setTLSConfig(cfg)
}

func (s *Service) TLSConfig() model.TLSConfig {
	return s.runtimeCtl.tlsConfig()
}

func (ctl *toolRuntimeController) setTLSConfig(cfg model.TLSConfig) {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.tlsConf = cfg
}

func (ctl *toolRuntimeController) tlsConfig() model.TLSConfig {
	ctl.toolRuntimeMu.RLock()
	defer ctl.toolRuntimeMu.RUnlock()
	return ctl.tlsConf
}

func (s *Service) PacketRawHex(packetID int64) (string, error) {
	s.captureCtl.mu.RLock()
	pcap := s.captureCtl.pcap
	s.captureCtl.mu.RUnlock()

	if pcap == "" {
		return "", errors.New("no capture loaded")
	}
	return tshark.ReadPacketRawHexFromFile(pcap, packetID)
}

func (s *Service) PacketLayers(packetID int64) (map[string]any, error) {
	s.captureCtl.mu.RLock()
	pcap := s.captureCtl.pcap
	s.captureCtl.mu.RUnlock()

	if pcap == "" {
		return nil, errors.New("no capture loaded")
	}
	return tshark.ReadPacketLayersFromFile(pcap, packetID)
}

func (s *Service) StreamIDs(protocol string) []int64 {
	normalized := strings.ToUpper(strings.TrimSpace(protocol))
	ids := make(map[int64]struct{})
	s.captureCtl.mu.RLock()
	if len(s.streamCtl.rawStreamIndex) > 0 {
		for _, stream := range s.streamCtl.rawStreamIndex {
			if strings.EqualFold(stream.Protocol, normalized) && stream.StreamID >= 0 {
				ids[stream.StreamID] = struct{}{}
			}
		}
	}
	s.captureCtl.mu.RUnlock()

	if s.captureCtl.packetStore != nil {
		_ = s.captureCtl.packetStore.Iterate(nil, func(p model.Packet) error {
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
	s.captureCtl.mu.Lock()
	if cached, ok := s.filterCtl.displayFilterCache[filter]; ok {
		s.touchDisplayFilterCacheLocked(filter)
		s.captureCtl.mu.Unlock()
		return cached, nil
	}
	pcap := s.captureCtl.pcap
	tlsConf := s.runtimeCtl.tlsConfig()
	if strings.TrimSpace(pcap) == "" || s.captureCtl.packetStore == nil {
		s.captureCtl.mu.Unlock()
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	index := newFilteredPacketIndex(cancel)
	s.filterCtl.displayFilterCache[filter] = index
	s.touchDisplayFilterCacheLocked(filter)
	s.evictDisplayFilterCacheLocked()
	s.captureCtl.mu.Unlock()
	go s.scanDisplayFilterIndex(ctx, filter, pcap, tlsConf, index)
	return index, nil
}

func (s *Service) touchDisplayFilterCacheLocked(filter string) {
	for i, existing := range s.filterCtl.displayFilterCacheOrder {
		if existing != filter {
			continue
		}
		copy(s.filterCtl.displayFilterCacheOrder[i:], s.filterCtl.displayFilterCacheOrder[i+1:])
		s.filterCtl.displayFilterCacheOrder = s.filterCtl.displayFilterCacheOrder[:len(s.filterCtl.displayFilterCacheOrder)-1]
		break
	}
	s.filterCtl.displayFilterCacheOrder = append(s.filterCtl.displayFilterCacheOrder, filter)
}

func (s *Service) evictDisplayFilterCacheLocked() {
	for len(s.filterCtl.displayFilterCacheOrder) > displayFilterCacheLimit {
		oldest := s.filterCtl.displayFilterCacheOrder[0]
		s.filterCtl.displayFilterCacheOrder = s.filterCtl.displayFilterCacheOrder[1:]
		if cached, ok := s.filterCtl.displayFilterCache[oldest]; ok {
			cached.stop()
		}
		delete(s.filterCtl.displayFilterCache, oldest)
	}
}

func (s *Service) cancelDisplayFilterCacheLocked() {
	for filter, cached := range s.filterCtl.displayFilterCache {
		if cached != nil {
			cached.stop()
		}
		delete(s.filterCtl.displayFilterCache, filter)
	}
}

func (s *Service) hasCapturePath() bool {
	s.captureCtl.mu.RLock()
	defer s.captureCtl.mu.RUnlock()
	return strings.TrimSpace(s.captureCtl.pcap) != ""
}

func streamCacheLimitValue() int {
	raw := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_STREAM_CACHE_LIMIT"))
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
