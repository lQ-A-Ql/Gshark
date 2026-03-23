//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func parseHexDump(dump string) string {
	var sb strings.Builder
	lines := strings.Split(dump, "\n")
	for _, line := range lines {
		if len(line) < 6 || line[4] != ' ' || line[5] != ' ' {
			continue
		}

		hexPart := line[6:]
		if len(hexPart) > 48 {
			hexPart = hexPart[:48]
		}

		hexPart = strings.ReplaceAll(hexPart, " ", "")
		sb.WriteString(strings.TrimSpace(hexPart))
	}
	return sb.String()
}

func main() {
	packetID := int64(1)
	pcapPath := "../http.pcap" // Adjusting for cwd
	filter := "frame.number==" + strconv.FormatInt(packetID, 10)
	cmd := exec.Command(
		"tshark",
		"-n",
		"-r", pcapPath,
		"-Y", filter,
		"-c", "1",
		"-x",
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		fmt.Println("Error running tshark:", err)
		return
	}

	dump := out.String()
	fmt.Printf("RAW DUMP (%d bytes):\n%s\n", len(dump), dump)
	parsed := parseHexDump(dump)
	fmt.Printf("PARSED HEX (%d length):\n%s\n", len(parsed), parsed)
}
