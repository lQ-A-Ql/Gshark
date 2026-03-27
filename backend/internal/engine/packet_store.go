package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
)

type packetStore struct {
	mu      sync.RWMutex
	path    string
	offsets []int64
	byID    map[int64]int64
	size    int64
}

func newPacketStore() (*packetStore, error) {
	store := &packetStore{}
	if err := store.Reset(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *packetStore) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldPath := s.path
	s.path = ""
	s.offsets = nil
	s.byID = make(map[int64]int64)
	s.size = 0

	tmp, err := os.CreateTemp("", "gshark-packets-*.jsonl")
	if err != nil {
		return fmt.Errorf("create packet store: %w", err)
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close packet store: %w", err)
	}

	s.path = path
	if oldPath != "" && oldPath != path {
		_ = os.Remove(oldPath)
	}
	return nil
}

func (s *packetStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path
	s.path = ""
	s.offsets = nil
	s.byID = nil
	s.size = 0
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *packetStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.offsets)
}

func (s *packetStore) Append(packets []model.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return fmt.Errorf("packet store not initialized")
	}

	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open packet store: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriterSize(f, 256*1024)
	pos := s.size

	for _, packet := range packets {
		row, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("marshal packet: %w", err)
		}
		s.offsets = append(s.offsets, pos)
		s.byID[packet.ID] = pos

		n, err := writer.Write(row)
		if err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("write packet newline: %w", err)
		}
		pos += int64(n + 1)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush packet store: %w", err)
	}
	s.size = pos
	return nil
}

func (s *packetStore) All(predicate packetPredicate) ([]model.Packet, error) {
	items := make([]model.Packet, 0, s.Count())
	err := s.Iterate(predicate, func(packet model.Packet) error {
		items = append(items, packet)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *packetStore) Iterate(predicate packetPredicate, fn func(model.Packet) error) error {
	path, offsets := s.snapshot()
	if path == "" || len(offsets) == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open packet store reader: %w", err)
	}
	defer f.Close()

	for _, offset := range offsets {
		packet, err := readStoredPacket(f, offset)
		if err != nil {
			return err
		}
		if predicate != nil && !predicate(packet) {
			continue
		}
		if err := fn(packet); err != nil {
			return err
		}
	}

	return nil
}

func (s *packetStore) Page(cursor, limit int, predicate packetPredicate) ([]model.Packet, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	if predicate == nil {
		return s.directPage(cursor, limit)
	}

	total := 0
	items := make([]model.Packet, 0, limit)
	err := s.Iterate(predicate, func(packet model.Packet) error {
		if total >= cursor && len(items) < limit {
			items = append(items, packet)
		}
		total++
		return nil
	})
	if err != nil {
		return nil, 0, 0, err
	}

	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}
	next := cursor + len(items)
	if next > total {
		next = total
	}
	return items, next, total, nil
}

func (s *packetStore) directPage(cursor, limit int) ([]model.Packet, int, int, error) {
	path, offsets := s.snapshot()
	total := len(offsets)
	if path == "" || total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open packet store reader: %w", err)
	}
	defer f.Close()

	items := make([]model.Packet, 0, end-cursor)
	for _, offset := range offsets[cursor:end] {
		packet, err := readStoredPacket(f, offset)
		if err != nil {
			return nil, 0, 0, err
		}
		items = append(items, packet)
	}
	return items, end, total, nil
}

func (s *packetStore) PageByIDs(ids []int64, cursor, limit int) ([]model.Packet, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	path, byID := s.snapshotByID()
	total := len(ids)
	if path == "" || total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open packet store reader: %w", err)
	}
	defer f.Close()

	items := make([]model.Packet, 0, end-cursor)
	for _, id := range ids[cursor:end] {
		offset, ok := byID[id]
		if !ok {
			continue
		}
		packet, err := readStoredPacket(f, offset)
		if err != nil {
			return nil, 0, 0, err
		}
		items = append(items, packet)
	}
	return items, end, total, nil
}

func (s *packetStore) ExistingIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	_, byID := s.snapshotByID()
	if len(byID) == 0 {
		return nil
	}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, ok := byID[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func (s *packetStore) snapshot() (string, []int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	offsets := make([]int64, len(s.offsets))
	copy(offsets, s.offsets)
	return s.path, offsets
}

func (s *packetStore) snapshotByID() (string, map[int64]int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byID := make(map[int64]int64, len(s.byID))
	for id, offset := range s.byID {
		byID[id] = offset
	}
	return s.path, byID
}

func readStoredPacket(file *os.File, offset int64) (model.Packet, error) {
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return model.Packet{}, fmt.Errorf("seek packet store: %w", err)
	}

	reader := bufio.NewReader(file)
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return model.Packet{}, fmt.Errorf("read packet store: %w", err)
	}

	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return model.Packet{}, nil
	}

	var packet model.Packet
	if err := json.Unmarshal(line, &packet); err != nil {
		return model.Packet{}, fmt.Errorf("decode packet store row: %w", err)
	}
	return packet, nil
}
