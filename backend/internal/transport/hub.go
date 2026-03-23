package transport

import (
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
)

type PacketListener func(packet model.Packet)
type StatusListener func(status string)
type ErrorListener func(message string)

type Hub struct {
	mu              sync.RWMutex
	packetListeners []PacketListener
	statusListeners []StatusListener
	errorListeners  []ErrorListener
}

func NewHub() *Hub {
	return &Hub{}
}

func (h *Hub) OnPacket(fn PacketListener) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.packetListeners = append(h.packetListeners, fn)
}

func (h *Hub) OnStatus(fn StatusListener) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statusListeners = append(h.statusListeners, fn)
}

func (h *Hub) OnError(fn ErrorListener) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errorListeners = append(h.errorListeners, fn)
}

func (h *Hub) EmitPacket(packet model.Packet) {
	h.mu.RLock()
	listeners := append([]PacketListener(nil), h.packetListeners...)
	h.mu.RUnlock()
	for _, listener := range listeners {
		listener(packet)
	}
}

func (h *Hub) EmitStatus(status string) {
	h.mu.RLock()
	listeners := append([]StatusListener(nil), h.statusListeners...)
	h.mu.RUnlock()
	for _, listener := range listeners {
		listener(status)
	}
}

func (h *Hub) EmitError(message string) {
	h.mu.RLock()
	listeners := append([]ErrorListener(nil), h.errorListeners...)
	h.mu.RUnlock()
	for _, listener := range listeners {
		listener(message)
	}
}
