package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	antSwordChrPattern   = regexp.MustCompile(`(?i)(chr\(\d+\)\s*\.?){3,}`)
	antSwordEvalPattern  = regexp.MustCompile(`(?i)(assert|eval)\s*\(|base64_decode\s*\(|system\s*\(|exec\s*\(`)
	webshellParamPattern = regexp.MustCompile(`(?i)^(pass|password|pwd|cmd|assert|data|payload|rebeyond|ant|shell|key)$`)
)

type payloadFingerprint struct {
	Family         string
	Confidence     int
	Suggested      string
	Reasons        []string
	Fingerprints   []string
	DecoderHints   []string
}

func InspectStreamPayload(raw string) model.StreamPayloadInspection {
	normalized := normalizeTransportPayload(raw)
	candidates := collectInspectionCandidates(raw, normalized)
	if len(candidates) == 0 && strings.TrimSpace(normalized) != "" {
		candidates = append(candidates, model.StreamPayloadCandidate{
			ID:      "payload-0",
			Label:   "当前 payload",
			Kind:    "payload",
			Value:   normalized,
			Preview: previewPayload(normalized),
		})
	}

	inspection := model.StreamPayloadInspection{
		NormalizedPayload: normalized,
		Candidates:        candidates,
	}

	bestScore := -1
	for idx := range inspection.Candidates {
		fp := fingerprintPayloadCandidate(inspection.Candidates[idx])
		inspection.Candidates[idx].Confidence = fp.Confidence
		inspection.Candidates[idx].Fingerprints = append([]string(nil), fp.Fingerprints...)
		inspection.Candidates[idx].DecoderHints = append([]string(nil), fp.DecoderHints...)
		if fp.Confidence > bestScore {
			bestScore = fp.Confidence
			inspection.SuggestedCandidateID = inspection.Candidates[idx].ID
			inspection.SuggestedDecoder = fp.Suggested
			inspection.SuggestedFamily = fp.Family
			inspection.Confidence = fp.Confidence
			inspection.Reasons = append([]string(nil), fp.Reasons...)
		}
	}
	return inspection
}

func collectInspectionCandidates(raw, normalized string) []model.StreamPayloadCandidate {
	type candidate struct {
		id        string
		label     string
		kind      string
		paramName string
		value     string
	}
	out := make([]candidate, 0, 12)
	seen := map[string]struct{}{}
	add := func(label, kind, paramName, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := kind + "|" + paramName + "|" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, candidate{
			id:        fmt.Sprintf("%s-%d", kind, len(out)),
			label:     label,
			kind:      kind,
			paramName: paramName,
			value:     value,
		})
	}

	if strings.TrimSpace(normalized) != "" {
		add("当前 payload", "payload", "", normalized)
	}

	for _, item := range collectHTTPParamCandidates(raw) {
		label := "参数"
		if item.paramName != "" {
			label = "参数 " + item.paramName
		}
		add(label, item.kind, item.paramName, item.value)
	}
	for _, item := range collectMultipartCandidates(normalized) {
		label := "分段字段"
		if item.paramName != "" {
			label = "分段字段 " + item.paramName
		}
		add(label, item.kind, item.paramName, item.value)
	}

	if token := extractBestBase64Candidate(normalized); strings.TrimSpace(token) != "" && token != strings.TrimSpace(normalized) {
		add("Base64 片段", "token", "", token)
	}
	if token := extractEmbeddedHexCandidate(normalized); token != "" && token != strings.TrimSpace(normalized) {
		add("Hex 片段", "token", "", token)
	}

	result := make([]model.StreamPayloadCandidate, 0, len(out))
	for _, item := range out {
		result = append(result, model.StreamPayloadCandidate{
			ID:        item.id,
			Label:     item.label,
			Kind:      item.kind,
			ParamName: item.paramName,
			Value:     item.value,
			Preview:   previewPayload(item.value),
		})
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Label < result[j].Label
	})
	return result
}

type inspectionParamCandidate struct {
	kind      string
	paramName string
	value     string
}

func collectHTTPParamCandidates(raw string) []inspectionParamCandidate {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	results := make([]inspectionParamCandidate, 0, 8)

	if looksLikeHTTPMessage(text) {
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) >= 2 {
				if idx := strings.Index(parts[1], "?"); idx >= 0 && idx+1 < len(parts[1]) {
					results = append(results, queryValuesToCandidates(parts[1][idx+1:], "query")...)
				}
			}
		}
		body := strings.TrimSpace(extractHTTPMessageBody(text))
		results = append(results, queryValuesToCandidates(body, "form")...)
		return results
	}

	results = append(results, queryValuesToCandidates(text, "form")...)
	return results
}

func queryValuesToCandidates(raw, kind string) []inspectionParamCandidate {
	values, err := url.ParseQuery(strings.TrimSpace(raw))
	if err != nil || len(values) == 0 {
		return nil
	}
	out := make([]inspectionParamCandidate, 0, len(values))
	for key, items := range values {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			out = append(out, inspectionParamCandidate{
				kind:      kind,
				paramName: key,
				value:     item,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].paramName != out[j].paramName {
			return out[i].paramName < out[j].paramName
		}
		return len(out[i].value) > len(out[j].value)
	})
	return out
}

func collectMultipartCandidates(candidate string) []inspectionParamCandidate {
	body := strings.ReplaceAll(strings.TrimSpace(candidate), "\r\n", "\n")
	lines := strings.Split(body, "\n")
	boundary := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") && len(trimmed) > 4 {
			boundary = trimmed
			break
		}
	}
	if boundary == "" {
		return nil
	}

	sections := strings.Split(body, boundary)
	out := make([]inspectionParamCandidate, 0, len(sections))
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" || section == "--" {
			continue
		}
		headerBody := strings.SplitN(section, "\n\n", 2)
		if len(headerBody) != 2 {
			continue
		}
		headers := headerBody[0]
		value := strings.TrimSpace(strings.TrimSuffix(headerBody[1], "--"))
		if value == "" {
			continue
		}
		matches := multipartNamePattern.FindStringSubmatch(headers)
		name := ""
		if len(matches) > 1 {
			name = strings.TrimSpace(matches[1])
		}
		out = append(out, inspectionParamCandidate{
			kind:      "multipart",
			paramName: name,
			value:     value,
		})
	}
	return out
}

func extractEmbeddedHexCandidate(raw string) string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '&' || r == '=' || r == ',' || r == ';' || r == '|' || r == '"' || r == '\''
	})
	best := ""
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if !isPureHexToken(field) {
			continue
		}
		if len(field) > len(best) {
			best = field
		}
	}
	return best
}

func previewPayload(raw string) string {
	text := strings.TrimSpace(raw)
	if len(text) <= 120 {
		return text
	}
	return text[:120] + "..."
}

func fingerprintPayloadCandidate(candidate model.StreamPayloadCandidate) payloadFingerprint {
	text := strings.TrimSpace(candidate.Value)
	fp := payloadFingerprint{
		Family:       "plain",
		Confidence:   15,
		Suggested:    "auto",
		Reasons:      []string{"已提取出可操作 payload 候选。"},
		Fingerprints: []string{},
	}

	if candidate.ParamName != "" && webshellParamPattern.MatchString(candidate.ParamName) {
		fp.Confidence += 20
		fp.Reasons = append(fp.Reasons, "参数名命中常见 WebShell/命令执行字段。")
		fp.Fingerprints = append(fp.Fingerprints, "suspicious-param")
	}

	if antSwordChrPattern.MatchString(text) {
		fp.Family = "antsword_like"
		fp.Suggested = "antsword"
		fp.Confidence = 92
		fp.Reasons = append(fp.Reasons, "存在连续 chr() 表达式，极像蚁剑 chr 编码载荷。")
		fp.DecoderHints = append(fp.DecoderHints, "antsword")
		fp.Fingerprints = append(fp.Fingerprints, "chr-chain")
		return fp
	}

	if decoded, err := decodeBase64Loose(extractBestBase64Candidate(text)); err == nil && len(decoded) > 0 {
		printable := looksMostlyPrintable(decoded)
		if printable && antSwordEvalPattern.MatchString(strings.ToLower(string(decoded))) {
			fp.Family = "antsword_like"
			fp.Suggested = "antsword"
			fp.Confidence = 88
			fp.Reasons = append(fp.Reasons, "Base64 解码后出现 assert/eval/base64_decode 等脚本特征。")
			fp.DecoderHints = append(fp.DecoderHints, "antsword", "base64")
			fp.Fingerprints = append(fp.Fingerprints, "script-after-base64")
			return fp
		}
		if len(decoded)%16 == 0 && !printable {
			fp.Family = "aes_webshell_like"
			fp.Suggested = "behinder"
			fp.Confidence = 78
			fp.Reasons = append(fp.Reasons, "候选值 Base64 解码后长度符合 AES 分组且可打印率低，疑似 Behinder/Godzilla 类密文。")
			fp.DecoderHints = append(fp.DecoderHints, "behinder", "godzilla", "auto")
			fp.Fingerprints = append(fp.Fingerprints, "base64-aes-block")
			if candidate.ParamName != "" {
				fp.Confidence += 6
			}
			return fp
		}
		if printable {
			fp.Family = "base64_payload"
			fp.Suggested = "base64"
			fp.Confidence = 68
			fp.Reasons = append(fp.Reasons, "候选值可直接做 Base64 明文还原。")
			fp.DecoderHints = append(fp.DecoderHints, "base64", "auto")
			fp.Fingerprints = append(fp.Fingerprints, "printable-base64")
			return fp
		}
	}

	if isPureHexToken(text) {
		decoded := decodeLooseHex(text)
		if len(decoded) > 0 && len(decoded)%16 == 0 && !looksMostlyPrintable(decoded) {
			fp.Family = "hex_cipher"
			fp.Suggested = "auto"
			fp.Confidence = 64
			fp.Reasons = append(fp.Reasons, "候选值是纯十六进制且符合分组密文长度。")
			fp.DecoderHints = append(fp.DecoderHints, "auto", "behinder", "godzilla")
			fp.Fingerprints = append(fp.Fingerprints, "hex-block-cipher")
			return fp
		}
		fp.Family = "hex_payload"
		fp.Suggested = "base64"
		fp.Confidence = 46
		fp.Reasons = append(fp.Reasons, "候选值是独立十六进制片段，建议先做解包/转码。")
		fp.DecoderHints = append(fp.DecoderHints, "auto")
		fp.Fingerprints = append(fp.Fingerprints, "hex-token")
		return fp
	}

	if candidate.Kind == "query" || candidate.Kind == "form" || candidate.Kind == "multipart" {
		fp.Family = "parameter_payload"
		fp.Suggested = "auto"
		fp.Confidence = maxInt(fp.Confidence, 40)
		fp.DecoderHints = append(fp.DecoderHints, "auto")
		fp.Fingerprints = append(fp.Fingerprints, "parameter-extracted")
	}

	return fp
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
