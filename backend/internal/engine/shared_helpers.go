package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var webshellParamPattern = regexp.MustCompile(`(?i)^(pass|password|pwd|cmd|assert|data|payload|rebeyond|ant|shell|key)$`)

func previewPayload(raw string) string {
	text := strings.TrimSpace(raw)
	if len(text) <= 120 {
		return text
	}
	return text[:120] + "..."
}

func cloneDecoderOptionsHint(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]any, len(raw))
	for key, value := range raw {
		out[key] = value
	}
	return out
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

type toolAnalysisError struct {
	operation string
	message   string
	cause     error
}

func (e *toolAnalysisError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.message) != "" {
		return e.message
	}
	if e.cause != nil {
		return e.cause.Error()
	}
	return e.operation
}

func (e *toolAnalysisError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func wrapToolAnalysisError(operation, userMessage string, cause error) error {
	if cause == nil {
		return errors.New(userMessage)
	}
	return &toolAnalysisError{
		operation: strings.TrimSpace(operation),
		message:   strings.TrimSpace(userMessage),
		cause:     cause,
	}
}

func (s *Service) packetsForToolAnalysis() ([]model.Packet, error) {
	if _, err := s.requireCapturePathForToolAnalysis(); err != nil {
		return nil, err
	}
	if s.captureCtl.packetStore == nil {
		return nil, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.captureCtl.packetStore.All(nil)
	if err != nil {
		return nil, fmt.Errorf("读取本地数据包索引失败: %w", err)
	}
	return packets, nil
}

func (s *Service) requireCapturePathForToolAnalysis() (string, error) {
	capturePath := s.CurrentCapturePath()
	if capturePath == "" {
		return "", fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	return capturePath, nil
}
