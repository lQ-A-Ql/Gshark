package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Service) CaptureStatus() model.CaptureStatus {
	s.mu.RLock()
	filePath := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()

	packetCount := 0
	if s.packetStore != nil {
		packetCount = s.packetStore.Count()
	}
	s.activeLoadMu.Lock()
	loadStatus := cloneCaptureLoadStatus(s.activeLoadStatus)
	s.activeLoadMu.Unlock()
	return model.CaptureStatus{
		FilePath:    filePath,
		HasCapture:  filePath != "" && packetCount > 0,
		PacketCount: packetCount,
		Load:        loadStatus,
	}
}

func (s *Service) Packets() []model.Packet {
	if s.packetStore == nil {
		return nil
	}
	out, err := s.packetStore.All(nil)
	if err != nil {
		log.Printf("engine: packetStore.All failed: %v", err)
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

func (s *Service) HTTPStream(ctx context.Context, streamID int64) model.ReassembledStream {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return model.ReassembledStream{StreamID: streamID, Protocol: "HTTP"}
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
	if ctx.Err() != nil {
		return model.ReassembledStream{StreamID: streamID, Protocol: normalized}
	}
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
		s.mu.RUnlock()
		stream := s.streamWithOverrides(key, indexed)
		stream.LoadMeta = newStreamLoadMeta("index", false, true, false, 0)
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
		s.mu.RUnlock()
		stream, next, total := cloneRawStreamWindow(s.streamWithOverrides(key, indexed), cursor, limit)
		stream.LoadMeta = newStreamLoadMeta("index", false, true, false, 0)
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
	s.streamCache[key] = cloneReassembledStream(stream)
	s.markStreamCacheKeyNewestLocked(key)
	for len(s.streamCacheOrder) > streamCacheLimitValue() {
		oldest := s.streamCacheOrder[0]
		s.streamCacheOrder = s.streamCacheOrder[1:]
		delete(s.streamCache, oldest)
	}
}

func (s *Service) markStreamCacheKeyNewestLocked(key string) {
	s.removeStreamCacheOrderLocked(key)
	s.streamCacheOrder = append(s.streamCacheOrder, key)
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
