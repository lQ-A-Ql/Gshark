package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/gshark/sentinel/backend/internal/model"
)

const maxStreamContentBytes = 1 << 20 // 1 MB

func (s *Service) buildYaraScanTargets(objects []model.ObjectFile) ([]yaraScanTarget, func(), error) {
	targets := make([]yaraScanTarget, 0, len(objects)+64)
	for _, object := range objects {
		if strings.TrimSpace(object.Path) == "" {
			continue
		}
		targets = append(targets, yaraScanTarget{
			name:     object.Name,
			path:     object.Path,
			packetID: object.PacketID,
			source:   object.Source,
		})
	}

	if s.packetStore == nil {
		return targets, func() {}, nil
	}

	tempDir, err := os.MkdirTemp("", "gshark-yara-streams-")
	if err != nil {
		return targets, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }

	ctx := context.Background()
	for _, protocol := range []string{"HTTP", "TCP", "UDP"} {
		ids := s.StreamIDs(protocol)
		for _, streamID := range ids {
			content, packetID := s.yaraStreamContent(ctx, protocol, streamID)
			if strings.TrimSpace(content) == "" {
				continue
			}
			if len(content) > maxStreamContentBytes {
				content = content[:maxStreamContentBytes]
			}
			name := fmt.Sprintf("%s-stream-%d.txt", strings.ToLower(protocol), streamID)
			path := filepath.Join(tempDir, name)
			if writeErr := os.WriteFile(path, []byte(content), 0o644); writeErr != nil {
				cleanup()
				return nil, func() {}, writeErr
			}
			targets = append(targets, yaraScanTarget{
				name:     name,
				path:     path,
				packetID: packetID,
				source:   strings.ToLower(protocol) + "-stream",
			})
		}
	}

	return targets, cleanup, nil
}

func (s *Service) yaraStreamContent(ctx context.Context, protocol string, streamID int64) (string, int64) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTP":
		stream := s.HTTPStream(ctx, streamID)
		return buildYaraHTTPStreamContent(stream)
	case "TCP", "UDP":
		stream := s.RawStream(ctx, protocol, streamID)
		return buildYaraRawStreamContent(stream)
	default:
		return "", 0
	}
}

func buildYaraHTTPStreamContent(stream model.ReassembledStream) (string, int64) {
	if strings.TrimSpace(stream.Request) == "" && strings.TrimSpace(stream.Response) == "" && len(stream.Chunks) == 0 {
		return "", 0
	}
	var builder strings.Builder
	packetID := firstStreamPacketID(stream.Chunks)

	if strings.TrimSpace(stream.Request) != "" {
		builder.WriteString("=== HTTP REQUEST ===\n")
		builder.WriteString(stream.Request)
		if !strings.HasSuffix(stream.Request, "\n") {
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}
	if strings.TrimSpace(stream.Response) != "" {
		builder.WriteString("=== HTTP RESPONSE ===\n")
		builder.WriteString(stream.Response)
		if !strings.HasSuffix(stream.Response, "\n") {
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}
	if builder.Len() == 0 {
		for _, chunk := range stream.Chunks {
			body := decodeYaraChunkBody(chunk.Body)
			if strings.TrimSpace(body) == "" {
				continue
			}
			builder.WriteString("=== ")
			builder.WriteString(strings.ToUpper(chunk.Direction))
			builder.WriteString(" ===\n")
			builder.WriteString(body)
			if !strings.HasSuffix(body, "\n") {
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
	}
	return strings.TrimSpace(builder.String()), packetID
}

func buildYaraRawStreamContent(stream model.ReassembledStream) (string, int64) {
	if len(stream.Chunks) == 0 {
		return "", 0
	}
	var builder strings.Builder
	packetID := firstStreamPacketID(stream.Chunks)

	for _, chunk := range stream.Chunks {
		body := decodeYaraChunkBody(chunk.Body)
		if strings.TrimSpace(body) == "" {
			continue
		}
		builder.WriteString("=== ")
		builder.WriteString(strings.ToUpper(chunk.Direction))
		builder.WriteString(" ===\n")
		builder.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}

	return strings.TrimSpace(builder.String()), packetID
}

func decodeYaraChunkBody(body string) string {
	raw := strings.TrimSpace(body)
	if raw == "" {
		return ""
	}
	if decoded := decodeLooseHex(raw); len(decoded) > 0 {
		text := strings.Trim(string(decoded), "\x00")
		if looksReadableForYara(text) {
			return text
		}
	}
	if looksReadableForYara(raw) {
		return raw
	}
	return ""
}

func looksReadableForYara(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return false
	}
	runes := []rune(trimmed)
	if len(runes) == 0 {
		return false
	}
	readable := 0
	letters := 0
	for _, r := range runes {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			readable++
		case unicode.IsPrint(r):
			readable++
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				letters++
			}
		}
	}
	if readable == 0 {
		return false
	}
	return letters >= 4 || float64(readable)/float64(len(runes)) >= 0.80
}

func firstStreamPacketID(chunks []model.StreamChunk) int64 {
	ids := make([]int64, 0, len(chunks))
	for _, chunk := range chunks {
		if chunk.PacketID > 0 {
			ids = append(ids, chunk.PacketID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids[0]
}
