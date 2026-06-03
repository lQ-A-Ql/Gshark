package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const clientEventBufferSize = 1024

type event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan event, clientEventBufferSize)
	s.addClient(ch)
	defer s.removeClient(ch)

	_, _ = fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			payload, _ := json.Marshal(ev.Data)
			safeType := strings.ReplaceAll(strings.ReplaceAll(ev.Type, "\n", ""), "\r", "")
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", safeType, string(payload))
			flusher.Flush()
		}
	}
}

func (s *Server) addClient(ch chan event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[ch] = struct{}{}
}

func (s *Server) removeClient(ch chan event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, ch)
	close(ch)
}

func (s *Server) broadcast(ev event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		if ev.Type == "status" || ev.Type == "error" {
			s.enqueuePriorityEventLocked(ch, ev)
			continue
		}
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) enqueuePriorityEventLocked(ch chan event, ev event) {
	if trySendEvent(ch, ev) {
		return
	}

	preserved := make([]event, 0, cap(ch))
	for {
		select {
		case pending := <-ch:
			if pending.Type == "packet" {
				continue
			}
			preserved = append(preserved, pending)
		default:
			maxPreserved := cap(ch) - 1
			if maxPreserved < 0 {
				maxPreserved = 0
			}
			if len(preserved) > maxPreserved {
				preserved = preserved[len(preserved)-maxPreserved:]
			}
			for _, pending := range preserved {
				if !trySendEvent(ch, pending) {
					break
				}
			}
			_ = trySendEvent(ch, ev)
			return
		}
	}
}

func trySendEvent(ch chan event, ev event) bool {
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}
