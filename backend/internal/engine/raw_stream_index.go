package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"regexp"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var colonHexPayloadPattern = regexp.MustCompile(`^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$`)

func appendPacketToRawStreamIndex(index map[string]*model.ReassembledStream, packet model.Packet) {
	if packet.StreamID < 0 {
		return
	}

	protocol := rawStreamProtocol(packet)
	if protocol == "" {
		return
	}

	body := extractPacketTransportPayload(packet)
	if body == "" {
		return
	}

	key := streamCacheKey(protocol, packet.StreamID)
	stream := index[key]
	if stream == nil {
		from, to := tshark.SelectClientServerHosts(packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort)
		stream = &model.ReassembledStream{
			StreamID: packet.StreamID,
			Protocol: protocol,
			From:     from,
			To:       to,
		}
		index[key] = stream
	}

	direction := "server"
	if packet.SourceIP == stream.From {
		direction = "client"
	}

	appendMergedRawStreamChunk(stream, packet.ID, direction, body)
}

func rawStreamProtocol(packet model.Packet) string {
	proto := strings.ToUpper(strings.TrimSpace(packet.Protocol))
	switch {
	case matchStreamProtocol("UDP", proto):
		return "UDP"
	case matchStreamProtocol("TCP", proto):
		return "TCP"
	default:
		return ""
	}
}

func extractPacketTransportPayload(packet model.Packet) string {
	if body := extractPacketTransportPayloadFromRaw(packet); body != "" {
		return body
	}
	return normalizePacketPayloadHex(packet.Payload)
}

func extractPacketTransportPayloadFromRaw(packet model.Packet) string {
	raw := strings.TrimSpace(packet.RawHex)
	if raw == "" || packet.IPHeaderLen <= 0 || packet.L4HeaderLen <= 0 {
		return ""
	}

	frame := decodeLooseHex(raw)
	if len(frame) == 0 {
		return ""
	}

	ipOffset, ipTotalLen := locateIPPayload(frame, packet)
	if ipOffset < 0 {
		return ""
	}

	payloadStart := ipOffset + packet.IPHeaderLen + packet.L4HeaderLen
	payloadEnd := len(frame)
	if ipTotalLen > 0 && ipOffset+ipTotalLen < payloadEnd {
		payloadEnd = ipOffset + ipTotalLen
	}
	if payloadStart >= payloadEnd || payloadStart < 0 || payloadEnd > len(frame) {
		return ""
	}

	return bytesToColonHex(frame[payloadStart:payloadEnd])
}

func locateIPPayload(frame []byte, packet model.Packet) (int, int) {
	src := net.ParseIP(strings.TrimSpace(packet.SourceIP))
	dst := net.ParseIP(strings.TrimSpace(packet.DestIP))
	if src == nil || dst == nil {
		return -1, 0
	}

	if src4, dst4 := src.To4(), dst.To4(); src4 != nil && dst4 != nil {
		return findIPv4Payload(frame, src4, dst4, packet.IPHeaderLen)
	}

	if src16, dst16 := src.To16(), dst.To16(); src16 != nil && dst16 != nil {
		return findIPv6Payload(frame, src16, dst16)
	}

	return -1, 0
}

func findIPv4Payload(frame []byte, src, dst net.IP, expectedHeaderLen int) (int, int) {
	minHeaderLen := expectedHeaderLen
	if minHeaderLen < 20 {
		minHeaderLen = 20
	}

	for offset := 0; offset+minHeaderLen <= len(frame); offset++ {
		if frame[offset]>>4 != 4 {
			continue
		}

		headerLen := int(frame[offset]&0x0F) * 4
		if headerLen < 20 {
			continue
		}
		if expectedHeaderLen > 0 && headerLen != expectedHeaderLen {
			continue
		}
		if offset+20 > len(frame) {
			break
		}
		if !bytes.Equal(frame[offset+12:offset+16], src) || !bytes.Equal(frame[offset+16:offset+20], dst) {
			continue
		}

		totalLen := int(binary.BigEndian.Uint16(frame[offset+2 : offset+4]))
		if totalLen < headerLen {
			continue
		}
		if offset+totalLen > len(frame) {
			totalLen = len(frame) - offset
		}
		return offset, totalLen
	}

	return -1, 0
}

func findIPv6Payload(frame []byte, src, dst net.IP) (int, int) {
	for offset := 0; offset+40 <= len(frame); offset++ {
		if frame[offset]>>4 != 6 {
			continue
		}
		if !bytes.Equal(frame[offset+8:offset+24], src) || !bytes.Equal(frame[offset+24:offset+40], dst) {
			continue
		}

		payloadLen := int(binary.BigEndian.Uint16(frame[offset+4 : offset+6]))
		totalLen := 40 + payloadLen
		if offset+totalLen > len(frame) {
			totalLen = len(frame) - offset
		}
		return offset, totalLen
	}

	return -1, 0
}

func decodeLooseHex(raw string) []byte {
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(strings.TrimSpace(raw))
	if len(cleaned) == 0 || len(cleaned)%2 != 0 {
		return nil
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil
	}
	return decoded
}

func bytesToColonHex(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	out := make([]string, len(payload))
	for i, b := range payload {
		out[i] = strings.ToLower(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(out, ":")
}

func normalizePacketPayloadHex(payload string) string {
	raw := strings.TrimSpace(payload)
	if raw == "" {
		return ""
	}
	if decoded := decodeLooseHex(raw); len(decoded) > 0 {
		return bytesToColonHex(decoded)
	}
	return bytesToColonHex([]byte(raw))
}

func cloneRawStreamWindow(in model.ReassembledStream, cursor, limit int) (model.ReassembledStream, int, int) {
	total := len(in.Chunks)
	if limit <= 0 {
		limit = 128
	}
	if limit > 2048 {
		limit = 2048
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor > total {
		cursor = total
	}

	end := cursor + limit
	if end > total {
		end = total
	}

	out := in
	if end > cursor {
		out.Chunks = make([]model.StreamChunk, end-cursor)
		copy(out.Chunks, in.Chunks[cursor:end])
	} else {
		out.Chunks = nil
	}
	if in.LoadMeta != nil {
		meta := *in.LoadMeta
		out.LoadMeta = &meta
	}
	return out, end, total
}

func appendMergedRawStreamChunk(stream *model.ReassembledStream, packetID int64, direction, body string) {
	if stream == nil || strings.TrimSpace(body) == "" {
		return
	}
	if n := len(stream.Chunks); n > 0 && stream.Chunks[n-1].Direction == direction {
		stream.Chunks[n-1].Body = joinStreamChunkBodies(stream.Chunks[n-1].Body, body)
		return
	}
	stream.Chunks = append(stream.Chunks, model.StreamChunk{
		PacketID:  packetID,
		Direction: direction,
		Body:      body,
	})
}

func joinStreamChunkBodies(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	if isColonHexPayload(left) && isColonHexPayload(right) {
		return left + ":" + right
	}
	return left + right
}

func isColonHexPayload(raw string) bool {
	return colonHexPayloadPattern.MatchString(strings.TrimSpace(raw))
}
