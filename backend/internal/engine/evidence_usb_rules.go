package engine

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildUSBEvidenceSummary(op model.USBMassStorageOperation) string {
	command := firstNonEmpty(op.Command, "WRITE")
	summary := fmt.Sprintf("USB 存储写入: %s", command)
	if device := strings.TrimSpace(op.Device); device != "" {
		summary += " / " + device
	}
	if lun := strings.TrimSpace(op.LUN); lun != "" {
		summary += " / " + lun
	}
	if status := strings.TrimSpace(op.Status); status != "" && !isBenignUSBMassStorageStatus(status) {
		summary += " / status=" + status
	}
	return summary
}

func buildUSBEvidenceValue(op model.USBMassStorageOperation) string {
	parts := []string{
		fmt.Sprintf("len=%d", op.TransferLength),
		joinNonEmpty(" → ", op.Device, op.Endpoint),
	}
	if op.RequestFrame > 0 || op.ResponseFrame > 0 {
		parts = append(parts, fmt.Sprintf("frames=%d/%d", op.RequestFrame, op.ResponseFrame))
	}
	if op.LatencyMs > 0 {
		parts = append(parts, fmt.Sprintf("latency=%.1fms", op.LatencyMs))
	}
	if op.DataResidue > 0 {
		parts = append(parts, fmt.Sprintf("residue=%d", op.DataResidue))
	}
	if status := strings.TrimSpace(op.Status); status != "" {
		parts = append(parts, "status="+status)
	}
	return strings.Join(compactStrings(parts), " / ")
}

func isBenignUSBMassStorageStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "ok", "good", "unknown":
		return true
	default:
		return false
	}
}
