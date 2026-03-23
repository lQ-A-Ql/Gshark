package tshark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func ReadPacketLayersFromFile(pcapPath string, packetID int64) (map[string]any, error) {
	if strings.TrimSpace(pcapPath) == "" {
		return nil, fmt.Errorf("empty pcap path")
	}
	if packetID <= 0 {
		return nil, fmt.Errorf("invalid packet id")
	}

	cmd, err := Command(
		"-n",
		"-r", pcapPath,
		"-c", fmt.Sprintf("%d", packetID),
		"-T", "ek",
	)
	if err != nil {
		return nil, fmt.Errorf("resolve tshark: %w", err)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read packet layers: %w", err)
	}

	var found map[string]any
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var node map[string]any
		if err := json.Unmarshal([]byte(trimmed), &node); err != nil {
			continue
		}
		layers, ok := node["layers"].(map[string]any)
		if !ok {
			continue
		}
		found = layers
	}

	if found != nil {
		return found, nil
	}

	return nil, fmt.Errorf("packet layers not found")
}
