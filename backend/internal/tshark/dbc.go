package tshark

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type DBCSignalDef struct {
	Name         string
	StartBit     int
	Length       int
	LittleEndian bool
	Signed       bool
	Factor       float64
	Offset       float64
	Unit         string
}

type DBCMessageDef struct {
	ID      uint32
	Name    string
	Length  int
	Sender  string
	Signals []DBCSignalDef
}

type DBCDatabase struct {
	Path         string
	Name         string
	Messages     map[uint32][]DBCMessageDef
	MessageCount int
	SignalCount  int
}

var (
	dbcMessagePattern = regexp.MustCompile(`^BO_\s+(\d+)\s+(\S+)\s*:\s*(\d+)\s+(\S+)`)
	dbcSignalPattern  = regexp.MustCompile(`^SG_\s+(\S+)(?:\s+\S+)?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s+\(([^,]+),([^)]+)\)\s+\[([^\|]+)\|([^\]]+)\]\s+"([^"]*)"\s*(.*)$`)
)

func LoadDBCDatabase(path string) (*DBCDatabase, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return nil, fmt.Errorf("empty dbc path")
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open dbc: %w", err)
	}
	defer file.Close()

	db := &DBCDatabase{
		Path:     cleanPath,
		Name:     strings.TrimSuffix(filepath.Base(cleanPath), filepath.Ext(cleanPath)),
		Messages: make(map[uint32][]DBCMessageDef),
	}

	var current *DBCMessageDef
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "CM_") || strings.HasPrefix(line, "VAL_") || strings.HasPrefix(line, "BA_") || strings.HasPrefix(line, "NS_") || strings.HasPrefix(line, "BS_") || strings.HasPrefix(line, "BU_") || strings.HasPrefix(line, "VERSION") {
			continue
		}

		if matches := dbcMessagePattern.FindStringSubmatch(line); len(matches) == 5 {
			id, _ := strconv.ParseUint(matches[1], 10, 32)
			length, _ := strconv.Atoi(matches[3])
			msg := DBCMessageDef{
				ID:      uint32(id),
				Name:    matches[2],
				Length:  length,
				Sender:  matches[4],
				Signals: nil,
			}
			db.Messages[msg.ID] = append(db.Messages[msg.ID], msg)
			current = &db.Messages[msg.ID][len(db.Messages[msg.ID])-1]
			db.MessageCount++
			continue
		}

		if current == nil {
			continue
		}
		if matches := dbcSignalPattern.FindStringSubmatch(line); len(matches) == 12 {
			startBit, _ := strconv.Atoi(matches[2])
			length, _ := strconv.Atoi(matches[3])
			factor, _ := strconv.ParseFloat(strings.TrimSpace(matches[6]), 64)
			offset, _ := strconv.ParseFloat(strings.TrimSpace(matches[7]), 64)
			sig := DBCSignalDef{
				Name:         matches[1],
				StartBit:     startBit,
				Length:       length,
				LittleEndian: matches[4] == "1",
				Signed:       matches[5] == "-",
				Factor:       factor,
				Offset:       offset,
				Unit:         strings.TrimSpace(matches[10]),
			}
			current.Signals = append(current.Signals, sig)
			db.SignalCount++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan dbc: %w", err)
	}
	return db, nil
}

func (db *DBCDatabase) Profile() model.DBCProfile {
	if db == nil {
		return model.DBCProfile{}
	}
	return model.DBCProfile{
		Path:         db.Path,
		Name:         db.Name,
		MessageCount: db.MessageCount,
		SignalCount:  db.SignalCount,
	}
}

func parseCANIdentifier(raw string) uint32 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		if value, err := strconv.ParseUint(raw, 0, 32); err == nil {
			return uint32(value)
		}
	}
	if value, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return uint32(value)
	}
	return 0
}

func findDBCMessage(databases []*DBCDatabase, canID uint32, payloadLen int) (*DBCDatabase, *DBCMessageDef) {
	var bestDB *DBCDatabase
	var bestMsg *DBCMessageDef
	bestScore := -1
	for _, db := range databases {
		if db == nil {
			continue
		}
		for i := range db.Messages[canID] {
			msg := &db.Messages[canID][i]
			score := len(msg.Signals)
			if payloadLen > 0 && msg.Length == payloadLen {
				score += 1000
			}
			if score > bestScore {
				bestScore = score
				bestDB = db
				bestMsg = msg
			}
		}
	}
	return bestDB, bestMsg
}

func decodeDBCSignals(msg *DBCMessageDef, data []byte) []model.CANDBCSignal {
	if msg == nil || len(msg.Signals) == 0 || len(data) == 0 {
		return nil
	}
	results := make([]model.CANDBCSignal, 0, len(msg.Signals))
	for _, sig := range msg.Signals {
		if sig.Length <= 0 || sig.Length > 64 {
			continue
		}
		raw, ok := extractDBCSignalRaw(data, sig)
		if !ok {
			continue
		}
		valueText := formatDBCSignalValue(raw, sig)
		results = append(results, model.CANDBCSignal{
			Name:  sig.Name,
			Value: valueText,
			Unit:  sig.Unit,
		})
	}
	return results
}

func extractDBCSignalRaw(data []byte, sig DBCSignalDef) (uint64, bool) {
	if sig.LittleEndian {
		return extractLittleEndianSignal(data, sig.StartBit, sig.Length)
	}
	return extractBigEndianSignal(data, sig.StartBit, sig.Length)
}

func extractLittleEndianSignal(data []byte, startBit, length int) (uint64, bool) {
	if length <= 0 {
		return 0, false
	}
	var value uint64
	for i := 0; i < length; i++ {
		bitIndex := startBit + i
		bit, ok := readDBCBit(data, bitIndex)
		if !ok {
			return 0, false
		}
		if bit == 1 {
			value |= 1 << i
		}
	}
	return value, true
}

func extractBigEndianSignal(data []byte, startBit, length int) (uint64, bool) {
	if length <= 0 {
		return 0, false
	}
	var value uint64
	bitIndex := startBit
	for i := 0; i < length; i++ {
		bit, ok := readDBCBit(data, bitIndex)
		if !ok {
			return 0, false
		}
		value = (value << 1) | uint64(bit)
		if bitIndex%8 == 0 {
			bitIndex += 15
		} else {
			bitIndex--
		}
	}
	return value, true
}

func readDBCBit(data []byte, bitIndex int) (uint8, bool) {
	if bitIndex < 0 {
		return 0, false
	}
	byteIndex := bitIndex / 8
	if byteIndex < 0 || byteIndex >= len(data) {
		return 0, false
	}
	bitInByte := uint(bitIndex % 8)
	return uint8((data[byteIndex] >> bitInByte) & 0x1), true
}

func formatDBCSignalValue(raw uint64, sig DBCSignalDef) string {
	if sig.Signed {
		signed := signExtend(raw, sig.Length)
		scaled := float64(signed)*sig.Factor + sig.Offset
		return trimFloat(scaled)
	}
	scaled := float64(raw)*sig.Factor + sig.Offset
	return trimFloat(scaled)
}

func signExtend(raw uint64, length int) int64 {
	if length <= 0 || length >= 64 {
		return int64(raw)
	}
	signBit := uint64(1) << (length - 1)
	if raw&signBit == 0 {
		return int64(raw)
	}
	mask := ^uint64(0) << length
	return int64(raw | mask)
}

func trimFloat(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "0"
	}
	if math.Abs(value-math.Round(value)) < 0.000001 {
		return strconv.FormatInt(int64(math.Round(value)), 10)
	}
	return strconv.FormatFloat(value, 'f', 3, 64)
}
