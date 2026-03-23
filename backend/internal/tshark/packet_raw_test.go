package tshark

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestReadPacketRawHexFromFile_Pcap(t *testing.T) {
	f, err := os.CreateTemp("", "gshark-raw-*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)

	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("open temp pcap: %v", err)
	}
	writer := pcapgo.NewWriter(out)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = out.Close()
		t.Fatalf("write file header: %v", err)
	}

	p1 := []byte{0x01, 0x02, 0x03, 0x04}
	p2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	ts := time.Unix(1700000000, 0)

	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(p1), Length: len(p1)}, p1); err != nil {
		_ = out.Close()
		t.Fatalf("write packet1: %v", err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: ts.Add(time.Millisecond), CaptureLength: len(p2), Length: len(p2)}, p2); err != nil {
		_ = out.Close()
		t.Fatalf("write packet2: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close temp pcap: %v", err)
	}

	rawHex, err := ReadPacketRawHexFromFile(path, 2)
	if err != nil {
		t.Fatalf("read packet raw: %v", err)
	}
	if rawHex != "aabbccddee" {
		t.Fatalf("unexpected raw hex: %q", rawHex)
	}
}
