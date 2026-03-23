package tshark

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type udsEvent struct {
	model.UDSMessageSummary
	epoch float64
}

func buildUDSTransactions(events []udsEvent) []model.UDSTransaction {
	if len(events) == 0 {
		return nil
	}

	pending := make(map[string][]udsEvent)
	results := make([]model.UDSTransaction, 0, len(events))

	for _, event := range events {
		normalizedService := normalizeUDSRequestServiceID(event.ServiceID, event.IsReply, event.NegativeCode)
		key := buildUDSMatchKey(event.SourceAddress, event.TargetAddress, normalizedService, event.SubFunction, event.DataIdentifier, event.DTC)

		if !event.IsReply {
			pending[key] = append(pending[key], event)
			continue
		}

		replyKey := buildUDSMatchKey(event.TargetAddress, event.SourceAddress, normalizedService, event.SubFunction, event.DataIdentifier, event.DTC)
		queue := pending[replyKey]
		if len(queue) == 0 {
			results = append(results, buildUDSTransaction(udsEvent{}, event, normalizedService, "orphan-response"))
			continue
		}

		request := queue[0]
		if len(queue) == 1 {
			delete(pending, replyKey)
		} else {
			pending[replyKey] = queue[1:]
		}

		status := "positive"
		if strings.TrimSpace(event.NegativeCode) != "" {
			status = "negative"
		}
		results = append(results, buildUDSTransaction(request, event, normalizedService, status))
	}

	for _, queue := range pending {
		for _, request := range queue {
			results = append(results, buildUDSTransaction(request, udsEvent{}, normalizeUDSRequestServiceID(request.ServiceID, false, ""), "request-only"))
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].RequestPacketID == results[j].RequestPacketID {
			return results[i].ResponsePacketID < results[j].ResponsePacketID
		}
		return results[i].RequestPacketID < results[j].RequestPacketID
	})
	return results
}

func buildUDSTransaction(request, response udsEvent, normalizedService, status string) model.UDSTransaction {
	serviceID := normalizedService
	serviceName := udsServiceName(serviceID)
	if strings.TrimSpace(serviceID) == "" {
		serviceID = firstNonEmpty(request.ServiceID, response.ServiceID)
		serviceName = firstNonEmpty(request.ServiceName, response.ServiceName)
	}
	transaction := model.UDSTransaction{
		RequestPacketID: request.PacketID,
		RequestTime:     request.Time,
		SourceAddress:   request.SourceAddress,
		TargetAddress:   request.TargetAddress,
		ServiceID:       serviceID,
		ServiceName:     serviceName,
		SubFunction:     firstNonEmpty(request.SubFunction, response.SubFunction),
		DataIdentifier:  firstNonEmpty(request.DataIdentifier, response.DataIdentifier),
		DTC:             firstNonEmpty(request.DTC, response.DTC),
		Status:          status,
		RequestSummary:  request.Summary,
	}

	if transaction.RequestPacketID == 0 {
		transaction.RequestPacketID = response.PacketID
		transaction.RequestTime = response.Time
		transaction.SourceAddress = response.TargetAddress
		transaction.TargetAddress = response.SourceAddress
		transaction.RequestSummary = ""
	}

	if response.PacketID > 0 {
		transaction.ResponsePacketID = response.PacketID
		transaction.ResponseTime = response.Time
		transaction.ResponseSummary = response.Summary
		transaction.NegativeCode = response.NegativeCode
		if request.epoch > 0 && response.epoch > 0 && response.epoch >= request.epoch {
			transaction.LatencyMS = round1((response.epoch - request.epoch) * 1000)
		}
	}

	return transaction
}

func buildUDSMatchKey(src, dst, serviceID, subFunction, dataIdentifier, dtc string) string {
	return strings.Join([]string{
		strings.TrimSpace(src),
		strings.TrimSpace(dst),
		strings.ToUpper(strings.TrimSpace(serviceID)),
		strings.ToUpper(strings.TrimSpace(subFunction)),
		strings.ToUpper(strings.TrimSpace(dataIdentifier)),
		strings.ToUpper(strings.TrimSpace(dtc)),
	}, "|")
}

func normalizeUDSRequestServiceID(serviceID string, isReply bool, negativeCode string) string {
	sid := strings.ToUpper(strings.TrimSpace(serviceID))
	if sid == "" {
		return ""
	}
	if !isReply || strings.TrimSpace(negativeCode) != "" {
		return sid
	}
	value := parseFlexibleInt(sid)
	if value >= 0x40 {
		return fmt.Sprintf("0X%X", value-0x40)
	}
	return sid
}

func buildCANSignalTimelines(messages []model.CANDBCMessage) []model.CANSignalTimeline {
	if len(messages) == 0 {
		return nil
	}

	timelineMap := make(map[string][]model.CANSignalSample)
	for _, message := range messages {
		for _, signal := range message.Signals {
			value, err := strconv.ParseFloat(strings.TrimSpace(signal.Value), 64)
			if err != nil {
				continue
			}
			timelineMap[signal.Name] = append(timelineMap[signal.Name], model.CANSignalSample{
				PacketID:    message.PacketID,
				Time:        message.Time,
				Value:       value,
				Unit:        signal.Unit,
				MessageName: message.MessageName,
			})
		}
	}

	if len(timelineMap) == 0 {
		return nil
	}

	names := make([]string, 0, len(timelineMap))
	for name := range timelineMap {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]model.CANSignalTimeline, 0, len(names))
	for _, name := range names {
		out = append(out, model.CANSignalTimeline{
			Name:    name,
			Samples: timelineMap[name],
		})
	}
	return out
}

func parseEpochSeconds(raw string) float64 {
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return value
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

const (
	vehiclePreviewRowLimit       = 240
	vehiclePreviewTimelineLimit  = 24
	vehiclePreviewSamplesPerLine = 48
)

func trimVehicleAnalysisPreview(stats *model.VehicleAnalysis) {
	if stats == nil {
		return
	}
	stats.CAN.Frames = limitPreviewRows(stats.CAN.Frames, vehiclePreviewRowLimit)
	stats.CAN.PayloadRecords = limitPreviewRows(stats.CAN.PayloadRecords, vehiclePreviewRowLimit)
	stats.CAN.DecodedMessages = limitPreviewRows(stats.CAN.DecodedMessages, vehiclePreviewRowLimit)
	stats.J1939.Messages = limitPreviewRows(stats.J1939.Messages, vehiclePreviewRowLimit)
	stats.DoIP.Messages = limitPreviewRows(stats.DoIP.Messages, vehiclePreviewRowLimit)
	stats.UDS.Messages = limitPreviewRows(stats.UDS.Messages, vehiclePreviewRowLimit)
	stats.UDS.Transactions = limitPreviewRows(stats.UDS.Transactions, vehiclePreviewRowLimit)

	if len(stats.CAN.SignalTimelines) > vehiclePreviewTimelineLimit {
		stats.CAN.SignalTimelines = stats.CAN.SignalTimelines[:vehiclePreviewTimelineLimit]
	}
	for i := range stats.CAN.SignalTimelines {
		if len(stats.CAN.SignalTimelines[i].Samples) > vehiclePreviewSamplesPerLine {
			stats.CAN.SignalTimelines[i].Samples = stats.CAN.SignalTimelines[i].Samples[len(stats.CAN.SignalTimelines[i].Samples)-vehiclePreviewSamplesPerLine:]
		}
	}
}

func limitPreviewRows[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
