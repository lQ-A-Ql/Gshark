package tshark

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ReassembleHTTPStreamFromFile rebuilds HTTP request/response bodies from the raw
// TCP payload of a stream, independent from current display filter.
func ReassembleHTTPStreamFromFile(filePath string, streamID int64) (model.ReassembledStream, error) {
	return ReassembleHTTPStreamFromFileContext(context.Background(), filePath, streamID)
}

func ReassembleHTTPStreamFromFileContext(ctx context.Context, filePath string, streamID int64) (model.ReassembledStream, error) {
	stream := model.ReassembledStream{StreamID: streamID, Protocol: "HTTP"}
	log.Printf("tshark: follow http stream start file=%q stream=%d", filePath, streamID)

	filter := fmt.Sprintf("tcp.stream==%d && tcp.payload", streamID)
	args := []string{
		"-n",
		"-r", filePath,
		"-Y", filter,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "ip.src",
		"-e", "tcp.srcport",
		"-e", "ip.dst",
		"-e", "tcp.dstport",
		"-e", "tcp.payload",
	}

	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return stream, fmt.Errorf("resolve tshark: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stream, fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return stream, fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	clientIP := ""
	clientPort := 0
	loggedChunks := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}

		packetID, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		srcIP := strings.TrimSpace(parts[1])
		srcPort, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
		dstIP := strings.TrimSpace(parts[3])
		dstPort, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
		payloadHex := strings.TrimSpace(parts[5])

		if payloadHex == "" {
			continue
		}

		payloadText := decodeHexPayloadToText(payloadHex)
		if payloadText == "" {
			continue
		}

		if clientIP == "" {
			clientIP, stream.To = selectClientServerHosts(srcIP, srcPort, dstIP, dstPort)
			if clientIP == srcIP {
				clientPort = srcPort
				stream.From = srcIP
			} else {
				clientPort = dstPort
				stream.From = dstIP
			}
		}

		if packetID <= 0 {
			packetID = int64(len(stream.Chunks) + 1)
		}
		if srcIP == clientIP && (clientPort == 0 || srcPort == clientPort) {
			appendStreamChunk(&stream, packetID, "client", payloadText)
			stream.Request += payloadText
			if loggedChunks < 8 {
				log.Printf("tshark: follow http stream=%d packet=%d dir=client bytes=%d", streamID, packetID, len(payloadText))
				loggedChunks++
			}
		} else {
			appendStreamChunk(&stream, packetID, "server", payloadText)
			stream.Response += payloadText
			if loggedChunks < 8 {
				log.Printf("tshark: follow http stream=%d packet=%d dir=server bytes=%d", streamID, packetID, len(payloadText))
				loggedChunks++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return stream, fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return stream, fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return stream, fmt.Errorf("wait tshark: %w", err)
	}
	log.Printf("tshark: follow http stream done stream=%d chunks=%d request_bytes=%d response_bytes=%d", streamID, len(stream.Chunks), len(stream.Request), len(stream.Response))

	return stream, nil
}

func appendStreamChunk(stream *model.ReassembledStream, packetID int64, direction, body string) {
	if body == "" {
		return
	}
	if n := len(stream.Chunks); n > 0 && stream.Chunks[n-1].Direction == direction {
		stream.Chunks[n-1].Body += body
		return
	}
	stream.Chunks = append(stream.Chunks, model.StreamChunk{PacketID: packetID, Direction: direction, Body: body})
}

func decodeHexPayloadToText(payloadHex string) string {
	segments := strings.Split(payloadHex, ",")
	var out strings.Builder

	for _, seg := range segments {
		hexPart := strings.ReplaceAll(strings.TrimSpace(seg), ":", "")
		if hexPart == "" || len(hexPart)%2 != 0 {
			continue
		}

		buf, err := hex.DecodeString(hexPart)
		if err != nil {
			continue
		}
		out.Write(buf)
	}

	return out.String()
}

func ReassembleRawStreamFromFile(filePath, protocol string, streamID int64) (model.ReassembledStream, error) {
	return ReassembleRawStreamFromFileContext(context.Background(), filePath, protocol, streamID)
}

func ReassembleRawStreamFromFileContext(ctx context.Context, filePath, protocol string, streamID int64) (model.ReassembledStream, error) {
	stream := model.ReassembledStream{StreamID: streamID, Protocol: strings.ToUpper(strings.TrimSpace(protocol))}
	log.Printf("tshark: follow raw stream start file=%q protocol=%s stream=%d", filePath, stream.Protocol, streamID)

	upperProto := strings.ToUpper(strings.TrimSpace(protocol))
	streamField := ""
	payloadField := ""
	srcPortField := ""
	dstPortField := ""

	switch upperProto {
	case "TCP":
		streamField = "tcp.stream"
		payloadField = "tcp.payload"
		srcPortField = "tcp.srcport"
		dstPortField = "tcp.dstport"
	case "UDP":
		streamField = "udp.stream"
		payloadField = "udp.payload"
		srcPortField = "udp.srcport"
		dstPortField = "udp.dstport"
	default:
		return stream, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	filter := fmt.Sprintf("%s==%d && %s", streamField, streamID, payloadField)
	args := []string{
		"-n",
		"-r", filePath,
		"-Y", filter,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "ip.src",
		"-e", srcPortField,
		"-e", "ip.dst",
		"-e", dstPortField,
		"-e", payloadField,
	}

	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return stream, fmt.Errorf("resolve tshark: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stream, fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return stream, fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	clientIP := ""
	clientPort := 0
	loggedChunks := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}

		packetID, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		srcIP := strings.TrimSpace(parts[1])
		srcPort, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
		dstIP := strings.TrimSpace(parts[3])
		dstPort, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
		payloadHex := normalizePayloadHex(parts[5])
		if payloadHex == "" {
			continue
		}

		if clientIP == "" {
			clientIP, stream.To = selectClientServerHosts(srcIP, srcPort, dstIP, dstPort)
			if clientIP == srcIP {
				clientPort = srcPort
				stream.From = srcIP
			} else {
				clientPort = dstPort
				stream.From = dstIP
			}
		}

		direction := "server"
		if srcIP == clientIP && (clientPort == 0 || srcPort == clientPort) {
			direction = "client"
		}
		if packetID <= 0 {
			packetID = int64(len(stream.Chunks) + 1)
		}
		stream.Chunks = append(stream.Chunks, model.StreamChunk{PacketID: packetID, Direction: direction, Body: payloadHex})
		if loggedChunks < 8 {
			byteCount := 0
			if payloadHex != "" {
				byteCount = len(strings.Split(payloadHex, ":"))
			}
			log.Printf("tshark: follow raw stream=%d protocol=%s packet=%d dir=%s payload_bytes=%d", streamID, stream.Protocol, packetID, direction, byteCount)
			loggedChunks++
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return stream, fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return stream, fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return stream, fmt.Errorf("wait tshark: %w", err)
	}
	log.Printf("tshark: follow raw stream done protocol=%s stream=%d chunks=%d", stream.Protocol, streamID, len(stream.Chunks))

	return stream, nil
}

func normalizePayloadHex(payloadHex string) string {
	segments := strings.Split(strings.TrimSpace(payloadHex), ",")
	bytesOut := make([]string, 0, 32)
	for _, seg := range segments {
		hexPart := strings.ReplaceAll(strings.TrimSpace(seg), ":", "")
		if hexPart == "" || len(hexPart)%2 != 0 {
			continue
		}
		decoded, err := hex.DecodeString(hexPart)
		if err != nil {
			continue
		}
		for _, b := range decoded {
			bytesOut = append(bytesOut, fmt.Sprintf("%02x", b))
		}
	}
	return strings.Join(bytesOut, ":")
}

func selectClientServerHosts(srcIP string, srcPort int, dstIP string, dstPort int) (string, string) {
	if isLikelyClientPort(srcPort, dstPort) {
		return srcIP, dstIP
	}
	if isLikelyClientPort(dstPort, srcPort) {
		return dstIP, srcIP
	}
	return srcIP, dstIP
}

func isLikelyClientPort(candidate int, peer int) bool {
	if candidate <= 0 {
		return false
	}
	if peer <= 0 {
		return candidate >= 49152
	}
	if candidate >= 49152 && peer < 49152 {
		return true
	}
	if candidate > 1024 && peer <= 1024 {
		return true
	}
	return false
}
