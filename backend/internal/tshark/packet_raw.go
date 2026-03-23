package tshark

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func ReadPacketRawHexFromFile(pcapPath string, packetID int64) (string, error) {
	if strings.TrimSpace(pcapPath) == "" {
		return "", fmt.Errorf("empty pcap path")
	}
	if packetID <= 0 {
		return "", fmt.Errorf("invalid packet id")
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		return "", fmt.Errorf("open capture: %w", err)
	}
	defer f.Close()

	reader, err := openPacketDataReader(f)
	if err != nil {
		return "", err
	}

	var current int64
	for {
		data, _, readErr := reader.ReadPacketData()
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", fmt.Errorf("read packet data: %w", readErr)
		}
		current++
		if current == packetID {
			if len(data) == 0 {
				return "", nil
			}
			return hex.EncodeToString(data), nil
		}
	}

	return "", nil
}

type packetDataReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func openPacketDataReader(file *os.File) (packetDataReader, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek capture start: %w", err)
	}

	ngReader, ngErr := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if ngErr == nil {
		return ngReader, nil
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek capture start: %w", err)
	}

	pcapReader, pcapErr := pcapgo.NewReader(file)
	if pcapErr == nil {
		return pcapReader, nil
	}

	return nil, fmt.Errorf("open capture reader failed: pcapng=%v; pcap=%v", ngErr, pcapErr)
}
