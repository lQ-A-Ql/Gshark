package engine

import (
	"context"
	"errors"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
)

func newFilteredPacketIndex(cancel context.CancelFunc) *filteredPacketIndex {
	index := &filteredPacketIndex{
		positions: make(map[int64]int),
		cancel:    cancel,
	}
	index.cond = sync.NewCond(&index.mu)
	return index
}

func (f *filteredPacketIndex) appendID(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.positions[id]; exists {
		return
	}
	f.positions[id] = len(f.ids)
	f.ids = append(f.ids, id)
	f.cond.Broadcast()
}

func (f *filteredPacketIndex) finish(err error) {
	f.mu.Lock()
	if !errors.Is(err, context.Canceled) {
		f.err = err
	}
	f.complete = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *filteredPacketIndex) stop() {
	f.mu.Lock()
	cancel := f.cancel
	f.cancel = nil
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (f *filteredPacketIndex) pageWindow(cursor, limit int) ([]int64, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	target := cursor + limit + 1

	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if f.err != nil {
			return nil, 0, 0, f.err
		}
		if f.complete || len(f.ids) >= target {
			break
		}
		f.cond.Wait()
	}

	if f.err != nil {
		return nil, 0, 0, f.err
	}

	knownTotal := len(f.ids)
	if cursor >= knownTotal {
		if f.complete {
			return []int64{}, knownTotal, knownTotal, nil
		}
		return []int64{}, cursor, cursor + 1, nil
	}

	end := cursor + limit
	if end > knownTotal {
		end = knownTotal
	}
	window := append([]int64(nil), f.ids[cursor:end]...)
	next := end
	total := knownTotal
	if !f.complete && knownTotal > end && total <= next {
		total = next + 1
	}
	return window, next, total, nil
}

func (f *filteredPacketIndex) pageCursor(packetID int64, limit int) (int, int, bool, error) {
	if limit <= 0 {
		limit = 1000
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if f.err != nil {
			return 0, 0, false, f.err
		}
		if matchIndex, ok := f.positions[packetID]; ok {
			cursor := (matchIndex / limit) * limit
			total := len(f.ids)
			if !f.complete && total <= cursor {
				total = cursor + 1
			}
			return cursor, total, true, nil
		}
		if f.complete {
			return 0, len(f.ids), false, nil
		}
		f.cond.Wait()
	}
}

func (s *Service) scanDisplayFilterIndex(
	ctx context.Context,
	filter string,
	pcap string,
	tlsConf model.TLSConfig,
	index *filteredPacketIndex,
) {
	err := scanFrameIDsFn(ctx, model.ParseOptions{
		FilePath:      pcap,
		DisplayFilter: filter,
		TLS:           tlsConf,
	}, func(id int64) {
		if s.packetStore != nil && !s.packetStore.HasID(id) {
			return
		}
		index.appendID(id)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.emitter.EmitStatus("显示过滤器执行失败: " + err.Error())
		index.finish(&DisplayFilterError{
			Filter: filter,
			Err:    err,
		})
		return
	}
	index.finish(nil)
}
