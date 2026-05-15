package transport

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Server) handlePackets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.capture.Packets())
}

type packetsPageResponse struct {
	Items      []model.Packet `json:"items"`
	NextCursor int            `json:"next_cursor"`
	Total      int            `json:"total"`
	HasMore    bool           `json:"has_more"`
	Filtering  bool           `json:"filtering"`
}

func (s *Server) handlePacketsPage(w http.ResponseWriter, r *http.Request) {
	cursor, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("cursor")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	items, next, total, filtering, err := s.capture.PacketsPageWithState(cursor, limit, filter)
	if err != nil {
		if engine.IsDisplayFilterError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packetsPageResponse{
		Items:      items,
		NextCursor: next,
		Total:      total,
		HasMore:    next < total,
		Filtering:  filtering,
	})
}

func (s *Server) handlePacketLocate(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	cursor, total, found, err := s.capture.PacketPageCursorWithError(packetID, limit, filter)
	if err != nil {
		if engine.IsDisplayFilterError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"cursor":    cursor,
		"total":     total,
		"found":     found,
	})
}

func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	packet, err := s.capture.Packet(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packet)
}

func (s *Server) handlePacketRaw(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	rawHex, err := s.capture.PacketRawHex(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"raw_hex":   rawHex,
	})
}

func (s *Server) handlePacketLayers(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	layers, err := s.capture.PacketLayers(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"layers":    layers,
	})
}

func (s *Server) handleStreamIndex(w http.ResponseWriter, r *http.Request) {
	protocol := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("protocol")))
	if protocol != "HTTP" && protocol != "TCP" && protocol != "UDP" {
		writeError(w, http.StatusBadRequest, "invalid protocol")
		return
	}

	ids := s.capture.StreamIDs(protocol)
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": protocol,
		"total":    len(ids),
		"ids":      ids,
	})
}

func (s *Server) handleHTTPStream(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	writeJSON(w, http.StatusOK, s.capture.HTTPStream(r.Context(), streamID))
}

func (s *Server) handleRawStream(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	writeJSON(w, http.StatusOK, s.capture.RawStream(r.Context(), protocol, streamID))
}

type streamPageResponse struct {
	StreamID   int64                 `json:"stream_id"`
	Protocol   string                `json:"protocol"`
	From       string                `json:"from"`
	To         string                `json:"to"`
	Chunks     []model.StreamChunk   `json:"chunks"`
	LoadMeta   *model.StreamLoadMeta `json:"load_meta,omitempty"`
	NextCursor int                   `json:"next_cursor"`
	Total      int                   `json:"total"`
	HasMore    bool                  `json:"has_more"`
}

func (s *Server) handleRawStreamPage(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	cursor, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("cursor")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))

	stream, next, total := s.capture.RawStreamPage(r.Context(), protocol, streamID, cursor, limit)
	writeJSON(w, http.StatusOK, streamPageResponse{
		StreamID:   stream.StreamID,
		Protocol:   stream.Protocol,
		From:       stream.From,
		To:         stream.To,
		Chunks:     stream.Chunks,
		LoadMeta:   stream.LoadMeta,
		NextCursor: next,
		Total:      total,
		HasMore:    next < total,
	})
}

func (s *Server) handleStreamPayloadSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = parsed
	}
	rows, err := s.capture.ListStreamPayloadSources(limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
