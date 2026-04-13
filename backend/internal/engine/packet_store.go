package engine

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
	_ "modernc.org/sqlite"
)

type packetStore struct {
	mu        sync.RWMutex
	path      string
	db        *sql.DB
	ids       []int64
	positions map[int64]int
}

func newPacketStore() (*packetStore, error) {
	store := &packetStore{}
	if err := store.Reset(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *packetStore) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldPath := s.path
	oldDB := s.db

	s.path = ""
	s.db = nil
	s.ids = nil
	s.positions = make(map[int64]int)

	tmp, err := os.CreateTemp("", "gshark-packets-*.db")
	if err != nil {
		return fmt.Errorf("create packet db: %w", err)
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close packet db: %w", err)
	}

	db, err := openPacketStoreDB(path)
	if err != nil {
		_ = os.Remove(path)
		return err
	}

	s.path = path
	s.db = db

	if oldDB != nil {
		_ = oldDB.Close()
	}
	if oldPath != "" && oldPath != path {
		removePacketStoreFiles(oldPath)
	}
	return nil
}

func (s *packetStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path
	db := s.db

	s.path = ""
	s.db = nil
	s.ids = nil
	s.positions = nil

	if db != nil {
		if err := db.Close(); err != nil {
			return err
		}
	}
	if path == "" {
		return nil
	}
	if err := removePacketStoreFiles(path); err != nil {
		return err
	}
	return nil
}

func (s *packetStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ids)
}

func (s *packetStore) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

func (s *packetStore) Append(packets []model.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("packet store not initialized")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin packet insert: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO packets (
			seq,
			packet_id,
			timestamp,
			source_ip,
			source_port,
			dest_ip,
			dest_port,
			protocol,
			display_protocol,
			length,
			info,
			payload,
			raw_hex,
			udp_payload_hex,
			stream_id,
			ip_header_len,
			l4_header_len,
			color_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare packet insert: %w", err)
	}
	defer stmt.Close()

	nextSeq := len(s.ids) + 1
	for _, packet := range packets {
		colorJSON, marshalErr := marshalPacketColor(packet.Color)
		if marshalErr != nil {
			err = fmt.Errorf("marshal packet color: %w", marshalErr)
			return err
		}
		if _, execErr := stmt.Exec(
			nextSeq,
			packet.ID,
			packet.Timestamp,
			packet.SourceIP,
			packet.SourcePort,
			packet.DestIP,
			packet.DestPort,
			packet.Protocol,
			packet.DisplayProtocol,
			packet.Length,
			packet.Info,
			packet.Payload,
			packet.RawHex,
			packet.UDPPayloadHex,
			packet.StreamID,
			packet.IPHeaderLen,
			packet.L4HeaderLen,
			colorJSON,
		); execErr != nil {
			err = fmt.Errorf("insert packet: %w", execErr)
			return err
		}

		s.positions[packet.ID] = len(s.ids)
		s.ids = append(s.ids, packet.ID)
		nextSeq++
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit packet insert: %w", err)
	}
	return nil
}

func (s *packetStore) All(predicate packetPredicate) ([]model.Packet, error) {
	items := make([]model.Packet, 0, s.Count())
	err := s.Iterate(predicate, func(packet model.Packet) error {
		items = append(items, packet)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *packetStore) Iterate(predicate packetPredicate, fn func(model.Packet) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.ids) == 0 {
		return nil
	}

	rows, err := s.db.Query(`
		SELECT
			packet_id,
			timestamp,
			source_ip,
			source_port,
			dest_ip,
			dest_port,
			protocol,
			display_protocol,
			length,
			info,
			payload,
			raw_hex,
			udp_payload_hex,
			stream_id,
			ip_header_len,
			l4_header_len,
			color_json
		FROM packets
		ORDER BY seq
	`)
	if err != nil {
		return fmt.Errorf("query packet store: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		packet, scanErr := scanPacket(rows)
		if scanErr != nil {
			return scanErr
		}
		if predicate != nil && !predicate(packet) {
			continue
		}
		if err := fn(packet); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate packet store: %w", err)
	}
	return nil
}

func (s *packetStore) Page(cursor, limit int, predicate packetPredicate) ([]model.Packet, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	if predicate == nil {
		return s.directPage(cursor, limit)
	}

	total := 0
	items := make([]model.Packet, 0, limit)
	err := s.Iterate(predicate, func(packet model.Packet) error {
		if total >= cursor && len(items) < limit {
			items = append(items, packet)
		}
		total++
		return nil
	})
	if err != nil {
		return nil, 0, 0, err
	}

	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}
	next := cursor + len(items)
	if next > total {
		next = total
	}
	return items, next, total, nil
}

func (s *packetStore) PageSummaries(cursor, limit int, predicate packetPredicate) ([]model.Packet, int, int, error) {
	if predicate == nil {
		return s.directPageSummaries(cursor, limit)
	}
	items, next, total, err := s.Page(cursor, limit, predicate)
	if err != nil {
		return nil, 0, 0, err
	}
	return stripPacketPayloads(items), next, total, nil
}

func (s *packetStore) TopUDPDestinationPorts(limit, minCount int) ([]int, error) {
	if limit <= 0 {
		limit = 8
	}
	if minCount <= 0 {
		minCount = 1
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, nil
	}

	rows, err := s.db.Query(`
		SELECT dest_port
		FROM packets
		WHERE UPPER(protocol) = 'UDP'
			AND dest_port > 1024
		GROUP BY dest_port
		HAVING COUNT(*) >= ?
		ORDER BY COUNT(*) DESC, dest_port ASC
		LIMIT ?
	`, minCount, limit)
	if err != nil {
		return nil, fmt.Errorf("query top udp destination ports: %w", err)
	}
	defer rows.Close()

	ports := make([]int, 0, limit)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, fmt.Errorf("scan top udp destination port: %w", err)
		}
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top udp destination ports: %w", err)
	}
	return ports, nil
}

func (s *packetStore) directPage(cursor, limit int) ([]model.Packet, int, int, error) {
	total := s.Count()
	if total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	window := s.idWindow(cursor, limit)
	items, err := s.PacketsByIDs(window)
	if err != nil {
		return nil, 0, 0, err
	}
	return items, end, total, nil
}

func (s *packetStore) directPageSummaries(cursor, limit int) ([]model.Packet, int, int, error) {
	total := s.Count()
	if total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	window := s.idWindow(cursor, limit)
	items, err := s.PacketsByIDsSummary(window)
	if err != nil {
		return nil, 0, 0, err
	}
	return items, end, total, nil
}

func (s *packetStore) PageByIDs(ids []int64, cursor, limit int) ([]model.Packet, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	total := len(ids)
	if total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	window := ids[cursor:end]
	items, err := s.PacketsByIDs(window)
	if err != nil {
		return nil, 0, 0, err
	}
	return items, end, total, nil
}

func (s *packetStore) PageByIDsSummary(ids []int64, cursor, limit int) ([]model.Packet, int, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}
	if cursor < 0 {
		cursor = 0
	}

	total := len(ids)
	if total == 0 {
		return []model.Packet{}, 0, 0, nil
	}
	if cursor >= total {
		return []model.Packet{}, total, total, nil
	}

	end := cursor + limit
	if end > total {
		end = total
	}
	window := ids[cursor:end]
	items, err := s.PacketsByIDsSummary(window)
	if err != nil {
		return nil, 0, 0, err
	}
	return items, end, total, nil
}

func (s *packetStore) PacketByID(id int64) (model.Packet, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || id <= 0 {
		return model.Packet{}, false, nil
	}

	row := s.db.QueryRow(`
		SELECT
			packet_id,
			timestamp,
			source_ip,
			source_port,
			dest_ip,
			dest_port,
			protocol,
			display_protocol,
			length,
			info,
			payload,
			raw_hex,
			udp_payload_hex,
			stream_id,
			ip_header_len,
			l4_header_len,
			color_json
		FROM packets
		WHERE packet_id = ?
	`, id)

	packet, err := scanPacket(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Packet{}, false, nil
		}
		return model.Packet{}, false, err
	}
	return packet, true, nil
}

func (s *packetStore) PacketsByIDs(ids []int64) ([]model.Packet, error) {
	if len(ids) == 0 {
		return []model.Packet{}, nil
	}
	return s.queryPacketsByIDs(ids, false)
}

func (s *packetStore) PacketsByIDsSummary(ids []int64) ([]model.Packet, error) {
	if len(ids) == 0 {
		return []model.Packet{}, nil
	}
	return s.queryPacketsByIDs(ids, true)
}

func (s *packetStore) queryPacketsByIDs(ids []int64, summaryOnly bool) ([]model.Packet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(ids) == 0 {
		return []model.Packet{}, nil
	}

	queryArgs := make([]any, 0, len(ids))
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		queryArgs = append(queryArgs, id)
	}

	var query string
	if summaryOnly {
		query = fmt.Sprintf(`
			SELECT
				packet_id,
				timestamp,
				source_ip,
				source_port,
				dest_ip,
				dest_port,
				protocol,
				display_protocol,
				length,
				info,
				stream_id,
				ip_header_len,
				l4_header_len,
				color_json
			FROM packets
			WHERE packet_id IN (%s)
		`, strings.Join(placeholders, ","))
	} else {
		query = fmt.Sprintf(`
			SELECT
				packet_id,
				timestamp,
				source_ip,
				source_port,
				dest_ip,
				dest_port,
				protocol,
				display_protocol,
				length,
				info,
				payload,
				raw_hex,
				udp_payload_hex,
				stream_id,
				ip_header_len,
				l4_header_len,
				color_json
			FROM packets
			WHERE packet_id IN (%s)
		`, strings.Join(placeholders, ","))
	}

	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query packets by ids: %w", err)
	}
	defer rows.Close()

	packetByID := make(map[int64]model.Packet, len(ids))
	for rows.Next() {
		var packet model.Packet
		if summaryOnly {
			packet, err = scanPacketSummary(rows)
		} else {
			packet, err = scanPacket(rows)
		}
		if err != nil {
			return nil, err
		}
		packetByID[packet.ID] = packet
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read packets by ids: %w", err)
	}

	items := make([]model.Packet, 0, len(ids))
	for _, id := range ids {
		packet, ok := packetByID[id]
		if !ok {
			continue
		}
		items = append(items, packet)
	}
	return items, nil
}

func (s *packetStore) ExistingIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, ok := s.positions[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func (s *packetStore) HasID(id int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.positions[id]
	return ok
}

func (s *packetStore) meta() (string, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path, len(s.ids)
}

func (s *packetStore) idWindow(cursor, limit int) []int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil || len(s.ids) == 0 || cursor >= len(s.ids) || limit <= 0 {
		return nil
	}
	end := cursor + limit
	if end > len(s.ids) {
		end = len(s.ids)
	}
	out := make([]int64, end-cursor)
	copy(out, s.ids[cursor:end])
	return out
}

func openPacketStoreDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open packet db: %w", err)
	}
	db.SetMaxOpenConns(1)

	schema := `
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA temp_store=MEMORY;
		CREATE TABLE IF NOT EXISTS packets (
			seq INTEGER PRIMARY KEY,
			packet_id INTEGER NOT NULL UNIQUE,
			timestamp TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',
			source_port INTEGER NOT NULL DEFAULT 0,
			dest_ip TEXT NOT NULL DEFAULT '',
			dest_port INTEGER NOT NULL DEFAULT 0,
			protocol TEXT NOT NULL DEFAULT '',
			display_protocol TEXT NOT NULL DEFAULT '',
			length INTEGER NOT NULL DEFAULT 0,
			info TEXT NOT NULL DEFAULT '',
			payload TEXT NOT NULL DEFAULT '',
			raw_hex TEXT NOT NULL DEFAULT '',
			udp_payload_hex TEXT NOT NULL DEFAULT '',
			stream_id INTEGER NOT NULL DEFAULT 0,
			ip_header_len INTEGER NOT NULL DEFAULT 0,
			l4_header_len INTEGER NOT NULL DEFAULT 0,
			color_json TEXT NOT NULL DEFAULT ''
		);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init packet db schema: %w", err)
	}
	return db, nil
}

func marshalPacketColor(color model.PacketColorFeatures) (string, error) {
	payload, err := json.Marshal(color)
	if err != nil {
		return "", err
	}
	if string(payload) == "{}" {
		return "", nil
	}
	return string(payload), nil
}

type packetScanner interface {
	Scan(dest ...any) error
}

func scanPacket(scanner packetScanner) (model.Packet, error) {
	var packet model.Packet
	var colorJSON string
	err := scanner.Scan(
		&packet.ID,
		&packet.Timestamp,
		&packet.SourceIP,
		&packet.SourcePort,
		&packet.DestIP,
		&packet.DestPort,
		&packet.Protocol,
		&packet.DisplayProtocol,
		&packet.Length,
		&packet.Info,
		&packet.Payload,
		&packet.RawHex,
		&packet.UDPPayloadHex,
		&packet.StreamID,
		&packet.IPHeaderLen,
		&packet.L4HeaderLen,
		&colorJSON,
	)
	if err != nil {
		return model.Packet{}, err
	}
	if colorJSON != "" {
		if unmarshalErr := json.Unmarshal([]byte(colorJSON), &packet.Color); unmarshalErr != nil {
			return model.Packet{}, fmt.Errorf("decode packet color: %w", unmarshalErr)
		}
	}
	return packet, nil
}

func scanPacketSummary(scanner packetScanner) (model.Packet, error) {
	var packet model.Packet
	var colorJSON string
	err := scanner.Scan(
		&packet.ID,
		&packet.Timestamp,
		&packet.SourceIP,
		&packet.SourcePort,
		&packet.DestIP,
		&packet.DestPort,
		&packet.Protocol,
		&packet.DisplayProtocol,
		&packet.Length,
		&packet.Info,
		&packet.StreamID,
		&packet.IPHeaderLen,
		&packet.L4HeaderLen,
		&colorJSON,
	)
	if err != nil {
		return model.Packet{}, err
	}
	if colorJSON != "" {
		if unmarshalErr := json.Unmarshal([]byte(colorJSON), &packet.Color); unmarshalErr != nil {
			return model.Packet{}, fmt.Errorf("decode packet color: %w", unmarshalErr)
		}
	}
	return stripPacketPayload(packet), nil
}

func stripPacketPayload(packet model.Packet) model.Packet {
	packet.Payload = ""
	packet.RawHex = ""
	packet.UDPPayloadHex = ""
	return packet
}

func stripPacketPayloads(items []model.Packet) []model.Packet {
	out := make([]model.Packet, len(items))
	for i, packet := range items {
		out[i] = stripPacketPayload(packet)
	}
	return out
}

func removePacketStoreFiles(path string) error {
	targets := []string{
		path,
		path + "-wal",
		path + "-shm",
	}
	for _, target := range targets {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
