package tshark

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type conversationCount struct {
	Label    string
	Protocol string
	Count    int
}

func scanFieldRows(filePath string, fields []string, onRow func([]string)) error {
	args := []string{
		"-n",
		"-r", filePath,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-E", "quote=n",
	}
	for _, field := range fields {
		args = append(args, "-e", field)
	}

	cmd, err := Command(args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		onRow(strings.Split(line, "\t"))
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("wait tshark: %w", err)
	}
	return nil
}

func sortConversationBuckets(input map[string]conversationCount) []model.AnalysisConversation {
	items := make([]model.AnalysisConversation, 0, len(input))
	for _, item := range input {
		items = append(items, model.AnalysisConversation{
			Label:    item.Label,
			Protocol: item.Protocol,
			Count:    item.Count,
		})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Count > items[i].Count || (items[j].Count == items[i].Count && items[j].Label < items[i].Label) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	return items
}

func formatHex(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		return strings.ToUpper(raw)
	}
	value := parseInt(raw)
	if value <= 0 {
		return raw
	}
	return fmt.Sprintf("0x%X", value)
}

func parseFlexibleInt(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if value, err := strconv.Atoi(raw); err == nil {
		return value
	}
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		if value, err := strconv.ParseInt(raw, 0, 64); err == nil {
			return int(value)
		}
	}
	return 0
}

func splitHexBytes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer(":", " ", "-", " ", ",", " ", "\t", " ")
	raw = replacer.Replace(raw)
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(part), "0X"))
		if part == "" {
			continue
		}
		if len(part) == 1 {
			part = "0" + part
		}
		out = append(out, part)
	}
	return out
}

func normalizeHexBytes(raw string) string {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func previewHexBytes(raw string, limit int) string {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return ""
	}
	if limit > 0 && len(parts) > limit {
		return strings.Join(parts[:limit], " ") + " ..."
	}
	return strings.Join(parts, " ")
}
