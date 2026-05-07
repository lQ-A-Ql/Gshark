package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var httpStatusLineRE = regexp.MustCompile(`^\d{3}\s`)

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
		magic := detectMagic(packet.RawHex)
		if magic == "" {
			magic = detectMagicFromPayload(packet.Payload)
		}
		if magic != "" && mime == "application/octet-stream" {
			if inferred := magicToMIME(magic); inferred != "" {
				mime = inferred
			}
		}
		objects = append(objects, model.ObjectFile{
			ID:        seq,
			PacketID:  packet.ID,
			Name:      name,
			SizeBytes: int64(packet.Length * 12),
			MIME:      mime,
			Magic:     magic,
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
	case strings.HasSuffix(n, ".gif"):
		return "image/gif"
	case strings.HasSuffix(n, ".webp"):
		return "image/webp"
	case strings.HasSuffix(n, ".bmp"):
		return "image/bmp"
	case strings.HasSuffix(n, ".zip"):
		return "application/zip"
	case strings.HasSuffix(n, ".pdf"):
		return "application/pdf"
	case strings.HasSuffix(n, ".txt"):
		return "text/plain"
	case strings.HasSuffix(n, ".html") || strings.HasSuffix(n, ".htm"):
		return "text/html"
	default:
		return "application/octet-stream"
	}
}

var magicSigs = []struct {
	sig  []byte
	mime string
	name string
}{
	{[]byte{0x89, 0x50, 0x4E, 0x47}, "image/png", "PNG"},
	{[]byte{0xFF, 0xD8, 0xFF}, "image/jpeg", "JPEG"},
	{[]byte("GIF87a"), "image/gif", "GIF87a"},
	{[]byte("GIF89a"), "image/gif", "GIF89a"},
	{[]byte("RIFF"), "image/webp", "RIFF"},
	{[]byte{0x42, 0x4D}, "image/bmp", "BMP"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "application/zip", "ZIP"},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "application/zip", "ZIP (empty)"},
	{[]byte{0x1F, 0x8B}, "application/gzip", "GZIP"},
	{[]byte("BZh"), "application/x-bzip2", "BZIP2"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "application/x-xz", "XZ"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "application/x-rar", "RAR"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "application/x-7z-compressed", "7z"},
	{[]byte("%PDF"), "application/pdf", "PDF"},
	{[]byte{0x25, 0x21}, "application/postscript", "PS"},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "image/x-icon", "ICO"},
	{[]byte{0x4F, 0x67, 0x67, 0x53}, "application/ogg", "OGG"},
	{[]byte{0x1A, 0x45, 0xDF, 0xA3}, "video/webm", "MKV/WebM"},
	{[]byte{0x00, 0x00, 0x00}, "video/mp4", "MP4 (ftyp)"},
	{[]byte("FLV"), "video/x-flv", "FLV"},
	{[]byte{0x49, 0x44, 0x33}, "audio/mpeg", "MP3 (ID3)"},
	{[]byte{0xFF, 0xFB}, "audio/mpeg", "MP3 (sync)"},
	{[]byte("fLaC"), "audio/flac", "FLAC"},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "application/java-archive", "Java class/Mach-O"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "application/x-elf", "ELF"},
	{[]byte{0x4D, 0x5A}, "application/x-dosexec", "PE/DOS MZ"},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "application/msword", "OLE2 (doc/xls)"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "application/zip", "ZIP/DOCX/XLSX"},
}

func detectMagic(rawHex string) string {
	if len(rawHex) < 2 {
		return ""
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil || len(raw) < 4 {
		return ""
	}
	for _, sig := range magicSigs {
		if len(raw) >= len(sig.sig) && bytes.Equal(raw[:len(sig.sig)], sig.sig) {
			return sig.name
		}
	}
	return ""
}

func detectMagicFromPayload(payload string) string {
	payload = strings.TrimSpace(payload)
	if len(payload) < 8 {
		return ""
	}
	raw, err := hex.DecodeString(payload)
	if err != nil {
		return ""
	}
	if len(raw) < 4 {
		return ""
	}
	for _, sig := range magicSigs {
		if len(raw) >= len(sig.sig) && bytes.Equal(raw[:len(sig.sig)], sig.sig) {
			return sig.name
		}
	}
	return ""
}

func magicToMIME(magic string) string {
	m := strings.ToLower(magic)
	switch {
	case strings.Contains(m, "png"):
		return "image/png"
	case strings.Contains(m, "jpeg"):
		return "image/jpeg"
	case strings.Contains(m, "gif"):
		return "image/gif"
	case strings.Contains(m, "webp") || strings.Contains(m, "riff"):
		return "image/webp"
	case strings.Contains(m, "bmp"):
		return "image/bmp"
	case strings.Contains(m, "zip") || strings.Contains(m, "docx") || strings.Contains(m, "xlsx"):
		return "application/zip"
	case strings.Contains(m, "pdf"):
		return "application/pdf"
	case strings.Contains(m, "gzip"):
		return "application/gzip"
	case strings.Contains(m, "rar"):
		return "application/x-rar"
	case strings.Contains(m, "7z"):
		return "application/x-7z-compressed"
	case strings.Contains(m, "elf"):
		return "application/x-elf"
	case strings.Contains(m, "pe") || strings.Contains(m, "dos") || strings.Contains(m, "mz"):
		return "application/x-dosexec"
	case strings.Contains(m, "ole") || strings.Contains(m, "doc"):
		return "application/msword"
	case strings.Contains(m, "mp3"):
		return "audio/mpeg"
	case strings.Contains(m, "flac"):
		return "audio/flac"
	case strings.Contains(m, "mp4"):
		return "video/mp4"
	case strings.Contains(m, "mkv") || strings.Contains(m, "webm"):
		return "video/webm"
	case strings.Contains(m, "flv"):
		return "video/x-flv"
	case strings.Contains(m, "ogg"):
		return "application/ogg"
	default:
		return ""
	}
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
			tshark.AppendStreamChunk(&stream, packet.ID, "client", body)
			stream.Request += body
		} else {
			tshark.AppendStreamChunk(&stream, packet.ID, "server", body)
			stream.Response += body
		}
		return nil
	})
	return stream
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

	if strings.HasPrefix(infoUpper, "HTTP/") || httpStatusLineRE.MatchString(strings.TrimSpace(packet.Info)) {
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
