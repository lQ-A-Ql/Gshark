package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func HuntThreats(packets []model.Packet, customPrefixes []string) []model.ThreatHit {
	hits := make([]model.ThreatHit, 0, 64)
	var seq int64 = 1

	for _, packet := range packets {
		text := packet.Info + "\n" + packet.Payload

		for _, prefix := range customPrefixes {
			if strings.Contains(strings.ToLower(text), strings.ToLower(prefix)) {
				hits = append(hits, model.ThreatHit{
					ID:       seq,
					PacketID: packet.ID,
					Category: "CTF",
					Rule:     "Flag 嗅探",
					Level:    "high",
					Preview:  previewText(text),
					Match:    prefix,
				})
				seq++
			}

			encoded := base64.StdEncoding.EncodeToString([]byte(prefix))
			if strings.Contains(text, encoded) {
				hits = append(hits, model.ThreatHit{
					ID:       seq,
					PacketID: packet.ID,
					Category: "CTF",
					Rule:     "Flag Base64 变体",
					Level:    "medium",
					Preview:  previewText(text),
					Match:    encoded,
				})
				seq++
			}

			hexText := hex.EncodeToString([]byte(prefix))
			if strings.Contains(strings.ToLower(text), strings.ToLower(hexText)) {
				hits = append(hits, model.ThreatHit{
					ID:       seq,
					PacketID: packet.ID,
					Category: "CTF",
					Rule:     "Flag Hex 变体",
					Level:    "medium",
					Preview:  previewText(text),
					Match:    hexText,
				})
				seq++
			}
		}
	}

	hits = append(hits, findAnomaly404403(packets, seq)...)
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].ID < hits[j].ID
	})
	return hits
}

func findAnomaly404403(packets []model.Packet, startID int64) []model.ThreatHit {
	counter := map[string]int{}
	for _, packet := range packets {
		info := strings.ToLower(packet.Info)
		if strings.Contains(info, " 404") || strings.Contains(info, " 403") {
			counter[packet.SourceIP]++
		}
	}

	result := make([]model.ThreatHit, 0)
	seq := startID
	for ip, c := range counter {
		if c < 8 {
			continue
		}
		result = append(result, model.ThreatHit{
			ID:       seq,
			PacketID: 0,
			Category: "Anomaly",
			Rule:     "异常扫描行为",
			Level:    "medium",
			Preview:  "短时间 403/404 激增",
			Match:    ip,
		})
		seq++
	}
	return result
}

func ExtractObjects(packets []model.Packet) []model.ObjectFile {
	objects := make([]model.ObjectFile, 0, 64)
	var seq int64 = 1

	for _, packet := range packets {
		if packet.Protocol != "HTTP" && packet.Protocol != "FTP" {
			continue
		}
		payloadLower := strings.ToLower(packet.Payload)
		if !strings.Contains(payloadLower, "filename=") && !strings.Contains(payloadLower, "content-type") {
			continue
		}
		name := guessObjectName(packet)
		mime := guessMIME(name)
		objects = append(objects, model.ObjectFile{
			ID:        seq,
			PacketID:  packet.ID,
			Name:      name,
			SizeBytes: int64(packet.Length * 12),
			MIME:      mime,
			Source:    packet.Protocol,
		})
		seq++
	}
	return objects
}

func DetectNonStandardPortFlows(packets []model.Packet) []model.ThreatHit {
	var seq int64 = 100000
	result := make([]model.ThreatHit, 0, 16)
	for _, packet := range packets {
		info := strings.ToLower(packet.Info)
		if strings.Contains(info, "http") && packet.DestPort != 80 && packet.DestPort != 8080 && packet.DestPort != 443 {
			result = append(result, model.ThreatHit{
				ID:       seq,
				PacketID: packet.ID,
				Category: "Anomaly",
				Rule:     "非标准协议端口画像",
				Level:    "medium",
				Preview:  previewText(packet.Info),
				Match:    packet.DestIP,
			})
			seq++
		}
	}
	return result
}

func StegoPrecheck(objects []model.ObjectFile) []model.ThreatHit {
	result := make([]model.ThreatHit, 0, 8)
	var seq int64 = 200000
	for _, object := range objects {
		nameLower := strings.ToLower(object.Name)
		if !strings.HasSuffix(nameLower, ".png") {
			continue
		}
		if object.Path != "" {
			isThreat, reason := checkPNG(object.Path)
			if isThreat {
				result = append(result, model.ThreatHit{
					ID:       seq,
					PacketID: object.PacketID,
					Category: "CTF",
					Rule:     "隐写术初筛异常",
					Level:    "medium",
					Preview:  reason,
					Match:    object.Name,
				})
				seq++
			}
		}
	}
	return result
}

func checkPNG(path string) (bool, string) {
	f, err := os.Open(path)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.Size() < 33 {
		return false, ""
	}

	buf := make([]byte, 33)
	if _, err := io.ReadFull(f, buf); err != nil {
		return false, ""
	}

	if !bytes.Equal(buf[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return false, ""
	}

	if string(buf[12:16]) == "IHDR" {
		expectedCRC := binary.BigEndian.Uint32(buf[29:33])
		actualCRC := crc32.ChecksumIEEE(buf[12:29])
		if expectedCRC != actualCRC {
			return true, "PNG IHDR CRC 校验失败（宽高可能被篡改）"
		}
	}

	_, err = f.Seek(-12, io.SeekEnd)
	if err == nil {
		endBuf := make([]byte, 12)
		if _, err := io.ReadFull(f, endBuf); err == nil {
			if string(endBuf[4:8]) != "IEND" {
				return true, "PNG 包含可疑的 EOF 附加数据"
			}
		}
	}

	return false, ""
}

func previewText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

func guessObjectName(packet model.Packet) string {
	payload := strings.ToLower(packet.Payload)
	if strings.Contains(payload, ".png") {
		return "capture.png"
	}
	if strings.Contains(payload, ".jpg") || strings.Contains(payload, ".jpeg") {
		return "capture.jpg"
	}
	if strings.Contains(payload, ".zip") {
		return "archive.zip"
	}
	if strings.Contains(payload, ".txt") {
		return "dump.txt"
	}
	return "object.bin"
}

func guessMIME(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".png"):
		return "image/png"
	case strings.HasSuffix(n, ".jpg") || strings.HasSuffix(n, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(n, ".zip"):
		return "application/zip"
	case strings.HasSuffix(n, ".txt"):
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

func ReassembleHTTPStream(packets []model.Packet, streamID int64) model.ReassembledStream {
	return ReassembleHTTPStreamFromIterate(func(fn func(model.Packet) error) error {
		for _, packet := range packets {
			if err := fn(packet); err != nil {
				return err
			}
		}
		return nil
	}, streamID)
}

func ReassembleHTTPStreamFromIterate(iterate func(func(model.Packet) error) error, streamID int64) model.ReassembledStream {
	stream := model.ReassembledStream{StreamID: streamID, Protocol: "HTTP"}
	clientIP := ""
	clientPort := 0

	_ = iterate(func(packet model.Packet) error {
		if packet.StreamID != streamID || !isHTTPLikePacket(packet) {
			return nil
		}
		body := decodeHTTPPayloadText(packet.Payload)
		if body == "" {
			return nil
		}
		if stream.From == "" {
			stream.From = packet.SourceIP
			stream.To = packet.DestIP
			clientIP = packet.SourceIP
			clientPort = packet.SourcePort
		}

		if isHTTPRequestPacket(packet, clientIP, clientPort) {
			appendHTTPChunk(&stream, packet.ID, "client", body)
			stream.Request += body
		} else {
			appendHTTPChunk(&stream, packet.ID, "server", body)
			stream.Response += body
		}
		return nil
	})
	return stream
}

func appendHTTPChunk(stream *model.ReassembledStream, packetID int64, direction, body string) {
	if body == "" {
		return
	}
	if n := len(stream.Chunks); n > 0 && stream.Chunks[n-1].Direction == direction {
		stream.Chunks[n-1].Body += body
		return
	}
	stream.Chunks = append(stream.Chunks, model.StreamChunk{PacketID: packetID, Direction: direction, Body: body})
}

func decodeHTTPPayloadText(payload string) string {
	raw := strings.TrimSpace(payload)
	if raw == "" {
		return ""
	}
	if decoded := decodeLooseHex(raw); len(decoded) > 0 {
		return string(bytes.Trim(decoded, "\x00"))
	}
	return payload
}

func isHTTPLikePacket(packet model.Packet) bool {
	if packet.Protocol == "HTTP" {
		return true
	}
	infoUpper := strings.ToUpper(packet.Info)
	if strings.Contains(infoUpper, "HTTP") || strings.Contains(infoUpper, "GET ") || strings.Contains(infoUpper, "POST ") {
		return true
	}
	payloadUpper := strings.ToUpper(packet.Payload)
	if strings.Contains(payloadUpper, "47:45:54:20") || strings.Contains(payloadUpper, "50:4f:53:54:20") || strings.Contains(payloadUpper, "48:54:54:50:2f:31") {
		return true
	}
	return false
}

func isHTTPRequestPacket(packet model.Packet, clientIP string, clientPort int) bool {
	infoUpper := strings.ToUpper(packet.Info)
	if strings.HasPrefix(infoUpper, "GET ") || strings.HasPrefix(infoUpper, "POST ") || strings.HasPrefix(infoUpper, "PUT ") || strings.HasPrefix(infoUpper, "DELETE ") || strings.HasPrefix(infoUpper, "HEAD ") || strings.HasPrefix(infoUpper, "OPTIONS ") || strings.HasPrefix(infoUpper, "PATCH ") {
		return true
	}

	if strings.HasPrefix(infoUpper, "HTTP/") || strings.HasPrefix(infoUpper, "1") || strings.HasPrefix(infoUpper, "2") || strings.HasPrefix(infoUpper, "3") || strings.HasPrefix(infoUpper, "4") || strings.HasPrefix(infoUpper, "5") {
		if strings.Contains(infoUpper, " OK") || strings.Contains(infoUpper, " NOT") || strings.Contains(infoUpper, " FOUND") || strings.Contains(infoUpper, " ERROR") {
			return false
		}
	}

	payloadUpper := strings.ToUpper(packet.Payload)
	if strings.HasPrefix(payloadUpper, "47:45:54:20") || strings.HasPrefix(payloadUpper, "50:4F:53:54:20") || strings.HasPrefix(payloadUpper, "50:55:54:20") || strings.HasPrefix(payloadUpper, "48:45:41:44:20") || strings.HasPrefix(payloadUpper, "44:45:4C:45:54:45:20") || strings.HasPrefix(payloadUpper, "4F:50:54:49:4F:4E:53:20") || strings.HasPrefix(payloadUpper, "50:41:54:43:48:20") {
		return true
	}

	if strings.HasPrefix(payloadUpper, "48:54:54:50:2F:31") {
		return false
	}

	if clientIP != "" && packet.SourceIP == clientIP {
		if clientPort == 0 || packet.SourcePort == clientPort {
			return true
		}
	}

	return false
}

func ReassembleRawStream(packets []model.Packet, protocol string, streamID int64) model.ReassembledStream {
	return ReassembleRawStreamFromIterate(func(fn func(model.Packet) error) error {
		for _, packet := range packets {
			if err := fn(packet); err != nil {
				return err
			}
		}
		return nil
	}, protocol, streamID)
}

func ReassembleRawStreamFromIterate(iterate func(func(model.Packet) error) error, protocol string, streamID int64) model.ReassembledStream {
	stream := model.ReassembledStream{StreamID: streamID, Protocol: protocol}
	clientIP := ""
	clientPort := 0

	_ = iterate(func(packet model.Packet) error {
		if packet.StreamID != streamID || !matchesRawProtocol(packet, protocol) {
			return nil
		}
		if stream.From == "" {
			stream.From = packet.SourceIP
			stream.To = packet.DestIP
			clientIP = packet.SourceIP
			clientPort = packet.SourcePort
		}
		direction := "server"
		if clientIP != "" && packet.SourceIP == clientIP && (clientPort == 0 || packet.SourcePort == clientPort) {
			direction = "client"
		}
		appendMergedRawStreamChunk(&stream, packet.ID, direction, packet.Payload)
		return nil
	})
	return stream
}

func matchesRawProtocol(packet model.Packet, protocol string) bool {
	if strings.EqualFold(packet.Protocol, protocol) {
		return true
	}

	if strings.EqualFold(protocol, "TCP") {
		// HTTP rides on TCP; include it so "Follow TCP Stream" from HTTP packets is not empty.
		if strings.EqualFold(packet.Protocol, "HTTP") {
			return true
		}
	}

	return false
}
