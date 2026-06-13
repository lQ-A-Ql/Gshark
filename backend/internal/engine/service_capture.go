package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func (s *Service) LoadPCAP(ctx context.Context, opts model.ParseOptions) error {
	if opts.FilePath == "" {
		return errors.New("empty file path")
	}

	currentRunID, runCtx := s.BeginCaptureLoad(ctx)
	return s.LoadPCAPWithRun(runCtx, opts, currentRunID)
}

func (s *Service) LoadPCAPWithRun(runCtx context.Context, opts model.ParseOptions, currentRunID int64) error {
	if opts.FilePath == "" {
		s.finishActiveCaptureLoad(currentRunID)
		return errors.New("empty file path")
	}
	s.startCaptureLoadStatus(currentRunID, opts)
	defer s.finishActiveCaptureLoad(currentRunID)

	if err := s.lockLoad(runCtx); err != nil {
		log.Printf("engine: capture parse canceled before acquiring load lock file=%q err=%v", opts.FilePath, err)
		s.setCaptureLoadPhase(currentRunID, model.CaptureLoadCanceled, err.Error())
		s.emitStatus("解析被取消")
		return err
	}
	defer s.captureCtl.loadMu.Unlock()
	if atomic.LoadInt64(&s.captureCtl.runID) != currentRunID {
		return context.Canceled
	}

	return s.loadPCAPLocked(runCtx, opts, currentRunID)
}

type streamParseState struct {
	processed      int
	accepted       int
	pending        []model.Packet
	rawStreamIndex map[string]*model.ReassembledStream
}

func (s *Service) makeStreamCallbacks(
	currentRunID int64,
	total int,
	nextStore *packetStore,
	opts model.ParseOptions,
	state *streamParseState,
	flushPending func(),
) (func(model.Packet) error, func(int)) {
	onPacket := func(packet model.Packet) error {
		if atomic.LoadInt64(&s.captureCtl.runID) != currentRunID {
			return nil
		}
		state.accepted++
		appendPacketToRawStreamIndex(state.rawStreamIndex, packet)
		state.pending = append(state.pending, packet)
		if len(state.pending) >= 1024 {
			flushPending()
		}
		if opts.EmitPackets {
			s.emitter.EmitPacket(packet)
		}
		return nil
	}
	onProgress := func(frameProcessed int) {
		state.processed = frameProcessed
		s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
			status.Processed = frameProcessed
			status.Accepted = state.accepted
			status.StagedCount = nextStore.Count()
		})
		if total > 0 {
			s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", frameProcessed, total))
		}
	}
	return onPacket, onProgress
}

func (s *Service) loadPCAPLocked(runCtx context.Context, opts model.ParseOptions, currentRunID int64) error {
	s.captureCtl.mu.RLock()
	oldPCAP := s.captureCtl.pcap
	currentTLS := s.runtimeCtl.tlsConfig()
	s.captureCtl.mu.RUnlock()
	if oldPCAP != "" {
		tshark.ClearFieldScanCache(oldPCAP)
	}
	tshark.ClearFieldScanCache(opts.FilePath)

	nextStore, err := newPacketStore()
	if err != nil {
		return err
	}
	commitPending := false
	defer func() {
		if !commitPending {
			_ = nextStore.Close()
		}
	}()

	// Inject current TLS config into parse options
	opts.TLS = currentTLS

	tsharkStatus := tshark.CurrentStatus()
	log.Printf(
		"engine: load capture file=%q filter=%q fast_list=%t list_profile=%q tshark=%q custom=%t",
		opts.FilePath,
		opts.DisplayFilter,
		opts.FastList,
		normalizeCaptureListProfile(opts),
		tsharkStatus.Path,
		tsharkStatus.UsingCustomPath,
	)

	s.emitStatus("开始解析 PCAP")
	total := 0
	if shouldSkipPacketEstimate(opts) {
		s.emitStatus("大流量包已跳过总包数预估，直接开始入库解析。")
		log.Printf("engine: skipping packet estimate for %q due to large file fast_list path", opts.FilePath)
	} else {
		s.setCaptureLoadPhase(currentRunID, model.CaptureLoadCounting, "")
		estimatedTotal, countErr := estimatePacketsFn(runCtx, opts)
		if countErr == nil && estimatedTotal > 0 {
			total = estimatedTotal
			s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
				status.EstimatedTotal = total
			})
			s.emitStatus(fmt.Sprintf("__progress__:counting:%d:%d", total, total))
			s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", 0, total))
			log.Printf("engine: tshark estimated %d packets for %q", total, opts.FilePath)
		} else if countErr != nil {
			log.Printf("engine: tshark packet estimate failed for %q: %v", opts.FilePath, countErr)
		}
	}
	s.setCaptureLoadPhase(currentRunID, model.CaptureLoadParsing, "")

	profile := normalizeCaptureListProfile(opts)
	streamFn := streamPacketsFn
	switch profile {
	case "first_screen":
		streamFn = streamPacketsFirstFn
	case "full_fast":
		streamFn = streamPacketsFastFn
	case "compat":
		streamFn = streamPacketsCompatFn
	case "ek":
		streamFn = streamPacketsFn
	}

	state := &streamParseState{
		pending:        make([]model.Packet, 0, 1024),
		rawStreamIndex: make(map[string]*model.ReassembledStream),
	}
	flushPending := func() {
		if len(state.pending) == 0 {
			return
		}
		if appendErr := nextStore.Append(state.pending); appendErr != nil {
			s.emitStatus("写入数据包存储失败: " + appendErr.Error())
			if err == nil {
				err = appendErr
			}
		}
		state.pending = state.pending[:0]
		s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
			status.Processed = state.processed
			status.Accepted = state.accepted
			status.StagedCount = nextStore.Count()
		})
	}

	onPacket, onProgress := s.makeStreamCallbacks(currentRunID, total, nextStore, opts, state, flushPending)
	err = streamFn(runCtx, opts, onPacket, onProgress)
	flushPending()
	log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", func() string {
		return profile
	}(), state.processed, state.accepted, err)
	if profile == "full_fast" && !errors.Is(err, context.Canceled) {
		needsFallback := err != nil
		if !needsFallback && total > 0 && state.accepted == 0 {
			needsFallback = true
		}
		if needsFallback {
			s.emitStatus("fast_list compatibility fallback: retrying parse with EK mode")
			s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
				status.ParserProfile = "ek_fallback"
				status.Processed = 0
				status.Accepted = 0
				status.StagedCount = 0
			})
			if resetErr := nextStore.Reset(); resetErr != nil {
				return resetErr
			}
			state.processed = 0
			state.accepted = 0
			state.rawStreamIndex = make(map[string]*model.ReassembledStream)
			state.pending = make([]model.Packet, 0, 1024)
			streamFn = streamPacketsFn
			onPacket, onProgress = s.makeStreamCallbacks(currentRunID, total, nextStore, opts, state, flushPending)
			err = streamFn(runCtx, opts, onPacket, onProgress)
			flushPending()
			log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", "ek_fallback", state.processed, state.accepted, err)
		}
	}
	if !errors.Is(err, context.Canceled) {
		needsCompatFallback := err != nil
		if !needsCompatFallback && total > 0 && state.accepted == 0 {
			needsCompatFallback = true
		}
		if needsCompatFallback {
			s.emitStatus("compatibility fallback: retrying parse with minimal field mode")
			log.Printf("engine: switching parser to compat_fields fallback for %q", opts.FilePath)
			s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
				status.ParserProfile = "compat_fields_fallback"
				status.Processed = 0
				status.Accepted = 0
				status.StagedCount = 0
			})
			if resetErr := nextStore.Reset(); resetErr != nil {
				return resetErr
			}
			state.processed = 0
			state.accepted = 0
			state.rawStreamIndex = make(map[string]*model.ReassembledStream)
			state.pending = make([]model.Packet, 0, 1024)
			onPacket, onProgress = s.makeStreamCallbacks(currentRunID, total, nextStore, opts, state, flushPending)
			err = streamPacketsCompatFn(runCtx, opts, onPacket, onProgress)
			flushPending()
			log.Printf("engine: parse mode=%s processed=%d accepted=%d err=%v", "compat_fields_fallback", state.processed, state.accepted, err)
		}
	}
	if total > 0 {
		s.emitStatus(fmt.Sprintf("__progress__:parsing:%d:%d", state.processed, total))
	}
	if err == nil && atomic.LoadInt64(&s.captureCtl.runID) != currentRunID {
		err = context.Canceled
	}

	dropped := state.processed - state.accepted
	if dropped < 0 {
		dropped = 0
	}
	if state.processed > 0 {
		s.emitStatus(fmt.Sprintf("解析统计: 已处理=%d, 入库=%d, 跳过=%d", state.processed, state.accepted, dropped))
	}
	log.Printf("engine: packet store path=%q rows=%d", nextStore.Path(), nextStore.Count())
	s.emitStatus(fmt.Sprintf("临时数据库已缓存 %d 条数据包", nextStore.Count()))
	if profile == "full_fast" && dropped > 0 {
		s.emitStatus(fmt.Sprintf("fast_list 告警: 有 %d 条记录未入库，请检查字段映射/解析规则", dropped))
	}

	if err == nil {
		log.Printf("engine: capture parse completed file=%q accepted=%d processed=%d", opts.FilePath, state.accepted, state.processed)
	} else if errors.Is(err, context.Canceled) {
		log.Printf("engine: capture parse canceled file=%q", opts.FilePath)
	} else {
		log.Printf("engine: capture parse failed file=%q err=%v", opts.FilePath, err)
	}

	switch err {
	case nil:
		if state.accepted == 0 {
			s.emitStatus("解析失败: 未读取到有效数据包")
			s.setCaptureLoadPhase(currentRunID, model.CaptureLoadFailed, "capture parse completed but produced no packets")
			return errors.New("capture parse completed but produced no packets")
		}
		if atomic.LoadInt64(&s.captureCtl.runID) != currentRunID {
			s.emitStatus("解析被取消")
			s.setCaptureLoadPhase(currentRunID, model.CaptureLoadCanceled, context.Canceled.Error())
			return context.Canceled
		}
		s.setCaptureLoadPhase(currentRunID, model.CaptureLoadCommitting, "")
		if err := s.commitLoadedCapture(opts.FilePath, nextStore, state.rawStreamIndex); err != nil {
			s.emitStatus("解析失败: " + err.Error())
			s.setCaptureLoadPhase(currentRunID, model.CaptureLoadFailed, err.Error())
			return err
		}
		commitPending = true
		s.captureCtl.mu.Lock()
		s.streamCtl.rawStreamIndex = make(map[string]model.ReassembledStream, len(state.rawStreamIndex))
		for key, stream := range state.rawStreamIndex {
			if stream == nil {
				continue
			}
			s.streamCtl.rawStreamIndex[key] = cloneReassembledStream(*stream)
		}
		s.captureCtl.mu.Unlock()
		s.emitStatus("解析完成")
		s.updateCaptureLoadStatus(currentRunID, func(status *model.CaptureLoadStatus) {
			status.Phase = string(model.CaptureLoadReady)
			status.Processed = state.processed
			status.Accepted = state.accepted
			if s.captureCtl.packetStore != nil {
				status.StagedCount = s.captureCtl.packetStore.Count()
			}
			status.CompletedAt = nowCaptureLoadTimestamp()
		})
		if opts.EnableEnrichment && profile == "first_screen" {
			s.startCaptureEnrichment(opts, currentRunID)
		}
	case context.Canceled:
		s.emitStatus("解析被取消")
		s.setCaptureLoadPhase(currentRunID, model.CaptureLoadCanceled, context.Canceled.Error())
	default:
		s.emitStatus("解析失败: " + err.Error())
		s.setCaptureLoadPhase(currentRunID, model.CaptureLoadFailed, err.Error())
	}
	return err
}

func (s *Service) commitLoadedCapture(filePath string, nextStore *packetStore, nextRawStreamIndex map[string]*model.ReassembledStream) error {
	if nextStore == nil {
		return errors.New("replacement packet store is nil")
	}
	s.objectCtl.objMu.Lock()
	if s.objectCtl.exportDir != "" {
		_ = os.RemoveAll(s.objectCtl.exportDir)
		s.objectCtl.exportDir = ""
	}
	s.objectCtl.objectsLoaded = false
	s.objectCtl.objects = nil
	s.objectCtl.objMu.Unlock()
	s.resetYaraScanState()
	s.captureCtl.mu.Lock()
	defer s.captureCtl.mu.Unlock()

	if s.mediaCtl.mediaExportDir != "" {
		_ = os.RemoveAll(s.mediaCtl.mediaExportDir)
		s.mediaCtl.mediaExportDir = ""
	}
	if s.captureCtl.packetStore == nil {
		return errors.New("active packet store is not initialized")
	}
	if err := s.captureCtl.packetStore.ReplaceWith(nextStore); err != nil {
		return err
	}
	tshark.ClearUSBAnalysisRawScanCache()
	s.cancelDisplayFilterCacheLocked()
	s.captureCtl.pcap = filePath
	s.filterCtl.displayFilterCache = map[string]*filteredPacketIndex{}
	s.filterCtl.displayFilterCacheOrder = s.filterCtl.displayFilterCacheOrder[:0]
	s.resetAnalysisCachesLocked()
	s.mediaCtl.cancelBatchLocked()
	s.streamCtl.rawStreamIndex = make(map[string]model.ReassembledStream, len(nextRawStreamIndex))
	for key, stream := range nextRawStreamIndex {
		if stream == nil {
			continue
		}
		s.streamCtl.rawStreamIndex[key] = cloneReassembledStream(*stream)
	}
	s.streamCtl.streamOverrides = map[string]map[int]string{}
	return nil
}

func (s *Service) startCaptureEnrichment(opts model.ParseOptions, runID int64) {
	if strings.TrimSpace(opts.FilePath) == "" {
		return
	}
	s.setCaptureEnrichmentStatus(runID, "pending", 0, 0, "")
	enrichOpts := opts
	enrichOpts.ListProfile = "full_fast"
	enrichOpts.FastList = true
	enrichOpts.EnableEnrichment = false
	taskCtx, finish := s.TrackCaptureTask(context.Background(), "capture-enrichment")
	go func() {
		defer finish()
		s.setCaptureEnrichmentStatus(runID, "running", 0, 0, "")
		processed := 0
		updated := 0
		enrichedRawStreamIndex := make(map[string]*model.ReassembledStream)
		err := streamPacketsFastFn(taskCtx, enrichOpts, func(packet model.Packet) error {
			if atomic.LoadInt64(&s.captureCtl.runID) != runID {
				return context.Canceled
			}
			appendPacketToRawStreamIndex(enrichedRawStreamIndex, packet)
			changed, updateErr := s.captureCtl.packetStore.UpdatePacketEnrichment(packet)
			if updateErr != nil {
				return updateErr
			}
			if changed {
				updated++
			}
			if updated == 1 || updated%2000 == 0 {
				s.setCaptureEnrichmentStatus(runID, "running", processed, updated, "")
			}
			return nil
		}, func(frameProcessed int) {
			processed = frameProcessed
			if frameProcessed == 1 || frameProcessed%2000 == 0 {
				s.setCaptureEnrichmentStatus(runID, "running", processed, updated, "")
			}
		})
		if errors.Is(err, context.Canceled) {
			s.setCaptureEnrichmentStatus(runID, "canceled", processed, updated, context.Canceled.Error())
			return
		}
		if err != nil {
			log.Printf("engine: capture enrichment failed file=%q err=%v", opts.FilePath, err)
			s.setCaptureEnrichmentStatus(runID, "failed", processed, updated, err.Error())
			return
		}
		if atomic.LoadInt64(&s.captureCtl.runID) != runID {
			s.setCaptureEnrichmentStatus(runID, "canceled", processed, updated, context.Canceled.Error())
			return
		}
		s.captureCtl.mu.Lock()
		if s.captureCtl.pcap == opts.FilePath {
			s.streamCtl.rawStreamIndex = make(map[string]model.ReassembledStream, len(enrichedRawStreamIndex))
			for key, stream := range enrichedRawStreamIndex {
				if stream == nil {
					continue
				}
				s.streamCtl.rawStreamIndex[key] = cloneReassembledStream(*stream)
			}
		}
		s.captureCtl.mu.Unlock()
		s.setCaptureEnrichmentStatus(runID, "ready", processed, updated, "")
		log.Printf("engine: capture enrichment completed file=%q processed=%d updated=%d", opts.FilePath, processed, updated)
	}()
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

func (s *Service) lockLoad(ctx context.Context) error {
	for {
		if s.captureCtl.loadMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (s *Service) registerActiveCaptureLoad(runID int64, cancel context.CancelFunc) {
	s.captureCtl.activeLoadMu.Lock()
	previous := s.captureCtl.activeLoadCancel
	s.captureCtl.activeLoadID = runID
	s.captureCtl.activeLoadCancel = cancel
	s.captureCtl.activeLoadMu.Unlock()
	if previous != nil {
		previous()
	}
}

func (s *Service) TrackCaptureTask(ctx context.Context, name string) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	taskCtx, cancel := context.WithCancel(ctx)
	s.captureCtl.captureTaskMu.Lock()
	if s.captureCtl.captureTasks == nil {
		s.captureCtl.captureTasks = map[int64]captureTaskCancel{}
	}
	s.captureCtl.captureTaskSeq++
	id := s.captureCtl.captureTaskSeq
	s.captureCtl.captureTasks[id] = captureTaskCancel{name: strings.TrimSpace(name), cancel: cancel}
	s.captureCtl.captureTaskMu.Unlock()

	var done atomic.Bool
	finish := func() {
		if !done.CompareAndSwap(false, true) {
			return
		}
		s.captureCtl.captureTaskMu.Lock()
		delete(s.captureCtl.captureTasks, id)
		s.captureCtl.captureTaskMu.Unlock()
		cancel()
	}
	return taskCtx, finish
}

func (s *Service) CancelCaptureTasks() int {
	s.captureCtl.captureTaskMu.Lock()
	tasks := make([]captureTaskCancel, 0, len(s.captureCtl.captureTasks))
	for id, task := range s.captureCtl.captureTasks {
		tasks = append(tasks, task)
		delete(s.captureCtl.captureTasks, id)
	}
	s.captureCtl.captureTaskMu.Unlock()
	for _, task := range tasks {
		if task.cancel != nil {
			task.cancel()
		}
	}
	return len(tasks)
}

func (s *Service) ActiveCaptureTaskCount() int {
	s.captureCtl.captureTaskMu.Lock()
	defer s.captureCtl.captureTaskMu.Unlock()
	return len(s.captureCtl.captureTasks)
}

func nowCaptureLoadTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func cloneCaptureLoadStatus(status *model.CaptureLoadStatus) *model.CaptureLoadStatus {
	if status == nil {
		return nil
	}
	clone := *status
	if status.Enrichment != nil {
		enrichment := *status.Enrichment
		clone.Enrichment = &enrichment
	}
	return &clone
}

func normalizeCaptureListProfile(opts model.ParseOptions) string {
	switch strings.ToLower(strings.TrimSpace(opts.ListProfile)) {
	case "first_screen":
		return "first_screen"
	case "full_fast":
		return "full_fast"
	case "compat":
		return "compat"
	case "ek":
		return "ek"
	}
	if opts.FastList {
		return "full_fast"
	}
	return "ek"
}

func (s *Service) startCaptureLoadStatus(runID int64, opts model.ParseOptions) {
	now := nowCaptureLoadTimestamp()
	s.captureCtl.activeLoadMu.Lock()
	s.captureCtl.activeLoadStatus = &model.CaptureLoadStatus{
		RunID:         runID,
		FilePath:      opts.FilePath,
		Phase:         string(model.CaptureLoadStarting),
		ParserProfile: normalizeCaptureListProfile(opts),
		StartedAt:     now,
		UpdatedAt:     now,
	}
	s.captureCtl.activeLoadMu.Unlock()
}

func (s *Service) updateCaptureLoadStatus(runID int64, fn func(*model.CaptureLoadStatus)) {
	s.captureCtl.activeLoadMu.Lock()
	defer s.captureCtl.activeLoadMu.Unlock()
	if s.captureCtl.activeLoadStatus == nil || s.captureCtl.activeLoadStatus.RunID != runID {
		return
	}
	fn(s.captureCtl.activeLoadStatus)
	s.captureCtl.activeLoadStatus.UpdatedAt = nowCaptureLoadTimestamp()
}

func (s *Service) setCaptureLoadPhase(runID int64, phase model.CaptureLoadPhase, lastError string) {
	s.updateCaptureLoadStatus(runID, func(status *model.CaptureLoadStatus) {
		status.Phase = string(phase)
		status.LastError = strings.TrimSpace(lastError)
		switch phase {
		case model.CaptureLoadReady, model.CaptureLoadFailed, model.CaptureLoadCanceled:
			status.CompletedAt = nowCaptureLoadTimestamp()
		}
	})
}

func (s *Service) setCaptureEnrichmentStatus(runID int64, phase string, processed, updated int, lastError string) {
	s.updateCaptureLoadStatus(runID, func(status *model.CaptureLoadStatus) {
		if status.Enrichment == nil {
			status.Enrichment = &model.CaptureEnrichmentStatus{}
		}
		status.Enrichment.Phase = strings.TrimSpace(phase)
		status.Enrichment.Processed = processed
		status.Enrichment.Updated = updated
		status.Enrichment.LastError = strings.TrimSpace(lastError)
		status.Enrichment.UpdatedAt = nowCaptureLoadTimestamp()
	})
}

func (s *Service) BeginCaptureLoad(ctx context.Context) (int64, context.Context) {
	currentRunID := atomic.AddInt64(&s.captureCtl.runID, 1)
	s.CancelActiveCaptureLoad()
	s.cancelLegacyStreaming()
	if canceled := s.CancelCaptureTasks(); canceled > 0 {
		s.emitStatus(fmt.Sprintf("正在终止后台分析任务: %d", canceled))
	}
	s.captureCtl.mu.Lock()
	s.cancelDisplayFilterCacheLocked()
	s.captureCtl.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	s.registerActiveCaptureLoad(currentRunID, cancel)
	return currentRunID, runCtx
}

func (s *Service) finishActiveCaptureLoad(runID int64) {
	s.captureCtl.activeLoadMu.Lock()
	if s.captureCtl.activeLoadID == runID {
		s.captureCtl.activeLoadID = 0
		s.captureCtl.activeLoadCancel = nil
	}
	if s.captureCtl.activeLoadStatus != nil && s.captureCtl.activeLoadStatus.RunID == runID {
		switch s.captureCtl.activeLoadStatus.Phase {
		case string(model.CaptureLoadReady), string(model.CaptureLoadFailed), string(model.CaptureLoadCanceled):
		default:
			s.captureCtl.activeLoadStatus.Phase = string(model.CaptureLoadCanceled)
			s.captureCtl.activeLoadStatus.CompletedAt = nowCaptureLoadTimestamp()
			s.captureCtl.activeLoadStatus.UpdatedAt = s.captureCtl.activeLoadStatus.CompletedAt
		}
	}
	s.captureCtl.activeLoadMu.Unlock()
}

func (s *Service) CancelActiveCaptureLoad() bool {
	s.captureCtl.activeLoadMu.Lock()
	cancel := s.captureCtl.activeLoadCancel
	canceledRunID := s.captureCtl.activeLoadID
	s.captureCtl.activeLoadCancel = nil
	s.captureCtl.activeLoadID = 0
	if s.captureCtl.activeLoadStatus != nil && s.captureCtl.activeLoadStatus.RunID == canceledRunID && canceledRunID != 0 {
		now := nowCaptureLoadTimestamp()
		s.captureCtl.activeLoadStatus.Phase = string(model.CaptureLoadCanceled)
		s.captureCtl.activeLoadStatus.CompletedAt = now
		s.captureCtl.activeLoadStatus.UpdatedAt = now
	}
	s.captureCtl.activeLoadMu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

func (s *Service) cancelLegacyStreaming() bool {
	s.captureCtl.mu.Lock()
	cancel := s.captureCtl.cancel
	s.captureCtl.cancel = nil
	s.captureCtl.mu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

func (s *Service) StopStreaming() bool {
	activeCanceled := s.CancelActiveCaptureLoad()
	legacyCanceled := s.cancelLegacyStreaming()
	return activeCanceled || legacyCanceled
}

func (s *Service) PrepareCaptureReplacement() {
	atomic.AddInt64(&s.captureCtl.runID, 1)
	if s.StopStreaming() {
		s.emitStatus("正在终止旧抓包解析")
	}
	if canceled := s.CancelCaptureTasks(); canceled > 0 {
		s.emitStatus(fmt.Sprintf("正在终止后台分析任务: %d", canceled))
	}
	s.captureCtl.mu.Lock()
	s.cancelDisplayFilterCacheLocked()
	s.clearUSBAnalysisCacheLocked()
	s.captureCtl.mu.Unlock()
	tshark.ClearUSBAnalysisRawScanCache()
}

func (s *Service) ClearCapture() error {
	atomic.AddInt64(&s.captureCtl.runID, 1)
	if s.StopStreaming() {
		s.emitStatus("正在终止当前抓包解析")
	}
	if canceled := s.CancelCaptureTasks(); canceled > 0 {
		s.emitStatus(fmt.Sprintf("正在终止后台分析任务: %d", canceled))
	}
	s.captureCtl.mu.Lock()
	s.cancelDisplayFilterCacheLocked()
	s.captureCtl.mu.Unlock()
	tshark.ClearUSBAnalysisRawScanCache()

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.lockLoad(waitCtx); err != nil {
		s.emitStatus("正在终止旧解析，请稍后重试关闭抓包。")
		return err
	}
	defer s.captureCtl.loadMu.Unlock()

	if s.captureCtl.packetStore != nil {
		if err := s.captureCtl.packetStore.Reset(); err != nil {
			return err
		}
		s.emitStatus("临时数据库已重置")
	}
	s.objectCtl.objMu.Lock()
	if s.objectCtl.exportDir != "" {
		_ = os.RemoveAll(s.objectCtl.exportDir)
		s.objectCtl.exportDir = ""
	}
	s.objectCtl.objectsLoaded = false
	s.objectCtl.objects = nil
	s.objectCtl.objMu.Unlock()
	s.captureCtl.mu.Lock()
	if s.mediaCtl.mediaExportDir != "" {
		_ = os.RemoveAll(s.mediaCtl.mediaExportDir)
		s.mediaCtl.mediaExportDir = ""
	}
	if s.captureCtl.pcap != "" {
		tshark.ClearFieldScanCache(s.captureCtl.pcap)
	}
	s.resetCaptureAnalysisStateLocked()
	s.mediaCtl.cancelBatchLocked()
	s.captureCtl.mu.Unlock()
	tshark.ClearUSBAnalysisRawScanCache()
	s.resetYaraScanState()
	s.captureCtl.activeLoadMu.Lock()
	s.captureCtl.activeLoadStatus = nil
	s.captureCtl.activeLoadMu.Unlock()
	return nil
}

func (s *Service) resetCaptureAnalysisStateLocked() {
	s.captureCtl.pcap = ""
	s.filterCtl.displayFilterCache = map[string]*filteredPacketIndex{}
	s.filterCtl.displayFilterCacheOrder = s.filterCtl.displayFilterCacheOrder[:0]
	s.resetAnalysisCachesLocked()
	s.mediaCtl.cancelBatchLocked()
	s.streamCtl.rawStreamIndex = map[string]model.ReassembledStream{}
	s.streamCtl.streamOverrides = map[string]map[int]string{}
}

func (s *Service) resetAnalysisCachesLocked() {
	s.analysisCtl.globalTrafficStats = nil
	s.analysisCtl.industrialAnalysis = nil
	s.analysisCtl.vehicleAnalysis = nil
	s.analysisCtl.mediaAnalysis = nil
	s.analysisCtl.usbAnalysis = nil
	s.analysisCtl.usbAnalysisBySource = nil
	s.analysisCtl.c2Analysis = nil
	s.analysisCtl.aptAnalysis = nil
	s.analysisCtl.inFlightAnalysis = analysisInFlightGroup{}
	s.mediaCtl.mediaArtifacts = map[string]string{}
	s.mediaCtl.mediaPlayback = map[string]string{}
	s.mediaCtl.mediaSpeech = map[string]model.MediaTranscription{}
	s.mediaCtl.speechBatch = nil
	s.streamCtl.streamCache = map[string]model.ReassembledStream{}
	s.streamCtl.streamCacheOrder = s.streamCtl.streamCacheOrder[:0]
}

func (s *Service) clearUSBAnalysisCacheLocked() {
	s.analysisCtl.usbAnalysis = nil
	s.analysisCtl.usbAnalysisBySource = nil
}
