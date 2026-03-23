package tshark

import "github.com/gshark/sentinel/backend/internal/model"

func scanDBCDecodedMessages(filePath string, databases []*DBCDatabase) ([]model.TrafficBucket, []model.TrafficBucket, []model.CANDBCMessage, error) {
	if len(databases) == 0 {
		return nil, nil, nil, nil
	}

	fields := []string{
		"frame.number",
		"frame.time_epoch",
		"_ws.col.Info",
		"can.bus_id",
		"can.id",
		"can.len",
		"data.data",
	}

	messageMap := make(map[string]int)
	signalMap := make(map[string]int)
	records := make([]model.CANDBCMessage, 0, 128)

	err := scanFieldRows(filePath, fields, func(parts []string) {
		canID := parseCANIdentifier(safeTrim(parts, 4))
		if canID == 0 {
			return
		}
		dataBytes := splitHexBytes(safeTrim(parts, 6))
		if len(dataBytes) == 0 {
			return
		}

		db, message := findDBCMessage(databases, canID, len(dataBytes))
		if db == nil || message == nil {
			return
		}

		payload := make([]byte, 0, len(dataBytes))
		for _, item := range dataBytes {
			value := parseHexByte(item)
			payload = append(payload, byte(value))
		}
		signals := decodeDBCSignals(message, payload)
		if len(signals) == 0 {
			return
		}

		messageLabel := db.Name + " · " + message.Name
		messageMap[messageLabel]++
		for _, signal := range signals {
			signalMap[signal.Name]++
		}

		records = append(records, model.CANDBCMessage{
			PacketID:    parseInt64(safeTrim(parts, 0)),
			Time:        normalizeTimestamp(safeTrim(parts, 1)),
			BusID:       formatHex(safeTrim(parts, 3)),
			Identifier:  formatHex(safeTrim(parts, 4)),
			Database:    db.Name,
			MessageName: message.Name,
			Sender:      message.Sender,
			Signals:     signals,
			Summary:     safeTrim(parts, 2),
		})
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return topBuckets(messageMap, 0), topBuckets(signalMap, 0), records, nil
}
