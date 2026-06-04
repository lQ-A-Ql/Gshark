package engine

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

// RTP header field sizes.
const (
	rtpHeaderMinLen = 12
	rtpCSRCLen      = 4
	rtpExtHeaderLen = 4
)

// Well-known RTP payload type → codec mapping (static, non-dynamic).
var rtpStaticCodecMap = map[uint8]RTPCodecInfo{
	0:  {Name: "PCMU", ClockRate: 8000},
	3:  {Name: "GSM", ClockRate: 8000},
	4:  {Name: "G723", ClockRate: 8000},
	5:  {Name: "DVI4", ClockRate: 8000},
	6:  {Name: "DVI4", ClockRate: 16000},
	7:  {Name: "LPC", ClockRate: 8000},
	8:  {Name: "PCMA", ClockRate: 8000},
	9:  {Name: "G722", ClockRate: 8000},
	10: {Name: "L16", ClockRate: 44100},
	11: {Name: "L16", ClockRate: 44100},
	12: {Name: "QCELP", ClockRate: 8000},
	13: {Name: "CN", ClockRate: 8000},
	14: {Name: "MPA", ClockRate: 90000},
	15: {Name: "G728", ClockRate: 8000},
	16: {Name: "DVI4", ClockRate: 11025},
	17: {Name: "DVI4", ClockRate: 22050},
	18: {Name: "G729", ClockRate: 8000},
	25: {Name: "CelB", ClockRate: 90000},
	26: {Name: "JPEG", ClockRate: 90000},
	28: {Name: "nv", ClockRate: 90000},
	31: {Name: "H261", ClockRate: 90000},
	32: {Name: "MPV", ClockRate: 90000},
	33: {Name: "MP2T", ClockRate: 90000},
	34: {Name: "H263", ClockRate: 90000},
}

// RTPCodecInfo describes an RTP codec identified by payload type.
type RTPCodecInfo struct {
	Name      string `json:"name"`
	ClockRate int    `json:"clock_rate"`
}

// RTPHeader represents the parsed fixed header of an RTP packet.
type RTPHeader struct {
	Version     uint8  // 2 bits
	Padding     bool   // 1 bit
	Extension   bool   // 1 bit
	CSRCCount   uint8  // 4 bits
	Marker      bool   // 1 bit
	PayloadType uint8  // 7 bits
	SeqNum      uint16 // 16 bits
	Timestamp   uint32 // 32 bits
	SSRC        uint32 // 32 bits
	CSRC        []uint32
}

// RTPPacket represents a fully parsed RTP packet with its header and payload.
type RTPPacket struct {
	Header  RTPHeader
	Payload []byte
	// Raw is the original raw bytes (may be nil if not retained).
	Raw []byte
}

// RTPStreamStats contains quality-of-service statistics for an RTP stream.
type RTPStreamStats struct {
	PacketCount     int     `json:"packet_count"`
	ExpectedPackets int     `json:"expected_packets"`
	LostPackets     int     `json:"lost_packets"`
	LossRate        float64 `json:"loss_rate"`
	OutOfOrder      int     `json:"out_of_order"`
	Duplicates      int     `json:"duplicates"`
	Jitter          float64 `json:"jitter_ms"`
	MinSeq          uint16  `json:"min_seq"`
	MaxSeq          uint16  `json:"max_seq"`
	SeqCycles       int     `json:"seq_cycles"` // number of 16-bit wrap-arounds
}

// RTPStream represents a single RTP stream identified by SSRC.
type RTPStream struct {
	SSRC        uint32         `json:"ssrc"`
	SSRCHex     string         `json:"ssrc_hex"`
	Codec       RTPCodecInfo   `json:"codec"`
	PayloadType uint8          `json:"payload_type"`
	Packets     []*RTPPacket   `json:"-"`
	Stats       RTPStreamStats `json:"stats"`
	SrcIP       string         `json:"src_ip,omitempty"`
	DstIP       string         `json:"dst_ip,omitempty"`
	SrcPort     int            `json:"src_port,omitempty"`
	DstPort     int            `json:"dst_port,omitempty"`
}

// RTPExtractionResult holds the result of extracting RTP streams from raw packets.
type RTPExtractionResult struct {
	Streams       []*RTPStream `json:"streams"`
	TotalParsed   int          `json:"total_parsed"`
	TotalRejected int          `json:"total_rejected"`
	Notes         []string     `json:"notes,omitempty"`
}

// RTPPacketInfo is a lightweight per-packet descriptor for building streams
// from pre-extracted packet metadata (e.g., from tshark output).
type RTPPacketInfo struct {
	SSRC        uint32
	PayloadType uint8
	SeqNum      uint16
	Timestamp   uint32
	SrcIP       string
	DstIP       string
	SrcPort     int
	DstPort     int
	PayloadSize int
}

var (
	errRTPTooShort  = errors.New("rtp: packet too short")
	errRTPVersion   = errors.New("rtp: unsupported version")
	errRTPTruncated = errors.New("rtp: packet truncated (CSRC/extension)")
)

// ParseRTPHeader parses the fixed RTP header from raw bytes.
// Returns the header and the offset where payload begins.
func ParseRTPHeader(data []byte) (RTPHeader, int, error) {
	if len(data) < rtpHeaderMinLen {
		return RTPHeader{}, 0, errRTPTooShort
	}

	v := (data[0] >> 6) & 0x03
	if v != 2 {
		return RTPHeader{}, 0, errRTPVersion
	}

	h := RTPHeader{
		Version:     v,
		Padding:     data[0]&0x20 != 0,
		Extension:   data[0]&0x10 != 0,
		CSRCCount:   data[0] & 0x0F,
		Marker:      data[1]&0x80 != 0,
		PayloadType: data[1] & 0x7F,
		SeqNum:      binary.BigEndian.Uint16(data[2:4]),
		Timestamp:   binary.BigEndian.Uint32(data[4:8]),
		SSRC:        binary.BigEndian.Uint32(data[8:12]),
	}

	offset := rtpHeaderMinLen

	// Parse CSRC list.
	csrcBytes := int(h.CSRCCount) * rtpCSRCLen
	if len(data) < offset+csrcBytes {
		return RTPHeader{}, 0, errRTPTruncated
	}
	if h.CSRCCount > 0 {
		h.CSRC = make([]uint32, h.CSRCCount)
		for i := 0; i < int(h.CSRCCount); i++ {
			h.CSRC[i] = binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4
		}
	}

	// Parse extension header if present.
	if h.Extension {
		if len(data) < offset+rtpExtHeaderLen {
			return RTPHeader{}, 0, errRTPTruncated
		}
		// bytes 2-3 of extension header = length in 32-bit words.
		extWords := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extBytes := rtpExtHeaderLen + extWords*4
		if len(data) < offset+extBytes {
			return RTPHeader{}, 0, errRTPTruncated
		}
		offset += extBytes
	}

	return h, offset, nil
}

// ParseRTPPacket parses a complete RTP packet from raw bytes.
func ParseRTPPacket(data []byte) (*RTPPacket, error) {
	h, payloadOffset, err := ParseRTPHeader(data)
	if err != nil {
		return nil, err
	}

	payload := data[payloadOffset:]

	// Handle padding: if set, last byte of payload indicates padding length.
	if h.Padding && len(payload) > 0 {
		padLen := int(payload[len(payload)-1])
		if padLen > 0 && padLen <= len(payload) {
			payload = payload[:len(payload)-padLen]
		}
	}

	return &RTPPacket{
		Header:  h,
		Payload: payload,
		Raw:     data,
	}, nil
}

// IdentifyCodec returns codec info for a given payload type.
// Dynamic payload types (96-127) return a generic entry.
func IdentifyCodec(pt uint8) RTPCodecInfo {
	if info, ok := rtpStaticCodecMap[pt]; ok {
		return info
	}
	if pt >= 96 && pt <= 127 {
		return RTPCodecInfo{Name: "dynamic", ClockRate: 0}
	}
	return RTPCodecInfo{Name: "unknown", ClockRate: 0}
}

// ExtractRTPStreamsFromPackets extracts RTP streams from raw packet bytes,
// grouping by SSRC.
func ExtractRTPStreamsFromPackets(rawPackets [][]byte) *RTPExtractionResult {
	result := &RTPExtractionResult{}

	// Group packets by SSRC.
	streamMap := make(map[uint32]*RTPStream)

	for _, raw := range rawPackets {
		pkt, err := ParseRTPPacket(raw)
		if err != nil {
			result.TotalRejected++
			continue
		}
		result.TotalParsed++

		ssrc := pkt.Header.SSRC
		stream, exists := streamMap[ssrc]
		if !exists {
			codec := IdentifyCodec(pkt.Header.PayloadType)
			stream = &RTPStream{
				SSRC:        ssrc,
				SSRCHex:     formatSSRC(ssrc),
				Codec:       codec,
				PayloadType: pkt.Header.PayloadType,
				Packets:     make([]*RTPPacket, 0, 64),
			}
			streamMap[ssrc] = stream
		}
		stream.Packets = append(stream.Packets, pkt)
	}

	// Build sorted result.
	streams := make([]*RTPStream, 0, len(streamMap))
	for _, s := range streamMap {
		CalculateStreamStats(s)
		streams = append(streams, s)
	}
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].SSRC < streams[j].SSRC
	})

	result.Streams = streams
	return result
}

// ExtractRTPStreamsFromInfo extracts RTP streams from pre-extracted packet
// metadata (e.g., from tshark field output). This is the lightweight path
// when full packet payloads are not available.
func ExtractRTPStreamsFromInfo(packets []RTPPacketInfo) *RTPExtractionResult {
	result := &RTPExtractionResult{}
	streamMap := make(map[uint32]*RTPStream)

	for _, info := range packets {
		result.TotalParsed++
		ssrc := info.SSRC
		stream, exists := streamMap[ssrc]
		if !exists {
			codec := IdentifyCodec(info.PayloadType)
			stream = &RTPStream{
				SSRC:        ssrc,
				SSRCHex:     formatSSRC(ssrc),
				Codec:       codec,
				PayloadType: info.PayloadType,
				SrcIP:       info.SrcIP,
				DstIP:       info.DstIP,
				SrcPort:     info.SrcPort,
				DstPort:     info.DstPort,
			}
			streamMap[ssrc] = stream
		}
		// Store synthetic packets for stats computation.
		stream.Packets = append(stream.Packets, &RTPPacket{
			Header: RTPHeader{
				SeqNum:    info.SeqNum,
				Timestamp: info.Timestamp,
				SSRC:      info.SSRC,
			},
		})
	}

	streams := make([]*RTPStream, 0, len(streamMap))
	for _, s := range streamMap {
		CalculateStreamStats(s)
		streams = append(streams, s)
	}
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].SSRC < streams[j].SSRC
	})

	result.Streams = streams
	return result
}

// CalculateStreamStats computes QoS statistics for an RTP stream.
// Implements RFC 3550 loss and jitter calculations.
func CalculateStreamStats(s *RTPStream) {
	if s == nil || len(s.Packets) == 0 {
		return
	}

	n := len(s.Packets)
	seqs := make([]uint16, n)
	for i, pkt := range s.Packets {
		seqs[i] = pkt.Header.SeqNum
	}

	// Count out-of-order and duplicates using sequence number analysis.
	// We detect wrap-around and compute expected vs actual.
	reordered, duplicates := countReorderAndDups(seqs)

	// Compute loss using extended sequence numbers to handle wrap-around.
	minSeq, maxSeq, cycles := findSeqRange(seqs)
	extMin := uint32(minSeq) + uint32(cycles)*0x10000
	extMax := uint32(maxSeq) + uint32(cycles)*0x10000
	expected := int(extMax-extMin) + 1
	lost := expected - n
	if lost < 0 {
		lost = 0
	}

	lossRate := 0.0
	if expected > 0 {
		lossRate = float64(lost) / float64(expected)
	}

	// Jitter calculation: RFC 3550 A.8 — interarrival jitter estimate.
	// We approximate using sequence-ordered packets' timestamp differences.
	jitter := calculateJitter(s.Packets)

	s.Stats = RTPStreamStats{
		PacketCount:     n,
		ExpectedPackets: expected,
		LostPackets:     lost,
		LossRate:        lossRate,
		OutOfOrder:      reordered,
		Duplicates:      duplicates,
		Jitter:          jitter,
		MinSeq:          minSeq,
		MaxSeq:          maxSeq,
		SeqCycles:       cycles,
	}
}

// countReorderAndDups counts out-of-order packets and duplicates from
// a sequence of RTP sequence numbers. Handles 16-bit wrap-around.
func countReorderAndDups(seqs []uint16) (reordered, duplicates int) {
	if len(seqs) <= 1 {
		return 0, 0
	}

	seen := make(map[uint16]int, len(seqs))
	for _, s := range seqs {
		seen[s]++
	}
	for _, count := range seen {
		if count > 1 {
			duplicates += count - 1
		}
	}

	// Count reorder: a packet is out-of-order if its sequence number is
	// less than the previously seen maximum (with wrap-around awareness).
	var maxExt uint32
	var cycles int
	prevSeq := seqs[0]
	maxExt = uint32(prevSeq)

	for i := 1; i < len(seqs); i++ {
		cur := seqs[i]
		diff := int32(cur) - int32(prevSeq)
		if diff < -0x7FFF {
			// Forward wrap-around.
			cycles++
		}
		extCur := uint32(cur) + uint32(cycles)*0x10000
		if extCur < maxExt {
			reordered++
		} else {
			maxExt = extCur
		}
		prevSeq = cur
	}
	return
}

// findSeqRange returns the min, max sequence numbers and wrap-around cycles.
func findSeqRange(seqs []uint16) (min, max uint16, cycles int) {
	if len(seqs) == 0 {
		return 0, 0, 0
	}
	min = seqs[0]
	max = seqs[0]
	var prevSeq uint16
	for i, s := range seqs {
		if i == 0 {
			prevSeq = s
			continue
		}
		diff := int32(s) - int32(prevSeq)
		if diff < -0x7FFF {
			cycles++
		}
		if s < min && cycles == 0 {
			min = s
		}
		if s > max {
			max = s
		}
		prevSeq = s
	}
	return
}

// calculateJitter computes the interarrival jitter in milliseconds.
// Uses the RFC 3550 A.8 algorithm: J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16.
// D(i,j) = (Rj - Ri) - (Sj - Si) where R=arrival, S=RTP timestamp.
// Without wall-clock arrival times, we approximate D using the RTP timestamp
// delta deviation from the median inter-packet interval. This gives a
// conservative lower-bound jitter estimate.
func calculateJitter(packets []*RTPPacket) float64 {
	if len(packets) < 2 {
		return 0
	}

	// Sort by sequence number to process in transmission order.
	sorted := make([]*RTPPacket, len(packets))
	copy(sorted, packets)
	sort.Slice(sorted, func(i, j int) bool {
		return seqNumLess(sorted[i].Header.SeqNum, sorted[j].Header.SeqNum)
	})

	// Determine clock rate for converting timestamp units to ms.
	codec := IdentifyCodec(sorted[0].Header.PayloadType)
	clockRate := float64(codec.ClockRate)
	if clockRate <= 0 {
		clockRate = 90000 // default assumption for video/dynamic
	}

	// Compute median inter-packet timestamp delta as the "expected" interval.
	deltas := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		ts1 := float64(sorted[i-1].Header.Timestamp)
		ts2 := float64(sorted[i].Header.Timestamp)
		d := ts2 - ts1
		if d < 0 {
			d += 0x100000000 // handle 32-bit timestamp wrap
		}
		deltas = append(deltas, d)
	}

	medianDelta := medianFloat64(deltas)
	if medianDelta <= 0 {
		medianDelta = 160 // fallback: typical 20ms @ 8kHz
	}

	// RFC 3550 jitter estimate: running exponential mean.
	var jitter float64
	for _, d := range deltas {
		deviation := math.Abs(d - medianDelta)
		jitter += (deviation - jitter) / 16.0
	}

	// Convert from timestamp units to milliseconds.
	return jitter / clockRate * 1000
}

// medianFloat64 returns the median of a float64 slice.
func medianFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// seqNumLess compares two RTP sequence numbers with wrap-around awareness.
// Returns true if a comes before b in the circular sequence space.
func seqNumLess(a, b uint16) bool {
	diff := int16(b - a)
	return diff > 0
}

func formatSSRC(ssrc uint32) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 10)
	buf[0] = '0'
	buf[1] = 'x'
	for i := 7; i >= 0; i-- {
		buf[9-i] = hexDigits[(ssrc>>(uint(i)*4))&0x0F]
	}
	return string(buf)
}
