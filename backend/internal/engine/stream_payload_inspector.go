package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	antSwordChrPattern          = regexp.MustCompile(`(?i)(chr\(\d+\)\s*\.?){3,}`)
	antSwordEvalPattern         = regexp.MustCompile(`(?i)(assert|eval)\s*\(|base64_decode\s*\(|system\s*\(|exec\s*\(`)
	chinaChopperEvalPattern     = regexp.MustCompile(`(?i)@eval\s*\(\s*\$_(POST|REQUEST)\s*\[`)
	chinaChopperAssertPattern   = regexp.MustCompile(`(?i)@assert\s*\(\s*\$_(POST|REQUEST)\s*\[`)
	chinaChopperParamPattern    = regexp.MustCompile(`(?i)^(caidao|chopper|c)$`)
	webshellParamPattern        = regexp.MustCompile(`(?i)^(pass|password|pwd|cmd|assert|data|payload|rebeyond|ant|shell|key)$`)
	numericWebshellParamPattern = regexp.MustCompile(`^\d{1,3}$`)
	randomHexParamPattern       = regexp.MustCompile(`(?i)^[a-f0-9]{5,16}$`)
	reGeorgHeaderPattern        = regexp.MustCompile(`(?i)(X-CMD|X-TARGET|X-STATUS-CODE|X-ERROR)\s*:`)

	// Behinder v2.0 key negotiation patterns
	behinderV2PassDigitsPattern = regexp.MustCompile(`^\d{2,3}$`)
	behinderV2HexKeyPattern     = regexp.MustCompile(`(?i)^[a-f0-9]{16}$`)

	// Behinder HTTP header fingerprint patterns
	// Behinder v3.0 ships 25 built-in User-Agent strings; v4.0 ships ~10.
	// These are the most common ones seen in the wild.
	behinderUASet = map[string]struct{}{
		"Java/1.8.0_211": {},
		"Java/1.8.0_181": {},
		"Java/1.7.0_67":  {},
		"Java/1.8.0_121": {},
		"Java/1.8.0_144": {},
		"Java/1.8.0_162": {},
		"Java/1.8.0_191": {},
		"Java/1.8.0_201": {},
		"Java/1.8.0_221": {},
		"Java/1.8.0_231": {},
		"Java/1.8.0_241": {},
		"Java/1.8.0_251": {},
		"Java/1.8.0_261": {},
		"Java/1.8.0_271": {},
		"Java/1.8.0_281": {},
		"Java/1.8.0_291": {},
		"Java/1.7.0_80":  {},
		"Java/1.7.0_79":  {},
		"Java/1.7.0_75":  {},
		"Java/1.7.0_72":  {},
		"Java/1.7.0_71":  {},
		"Java/1.7.0_65":  {},
		"Java/1.7.0_60":  {},
		"Java/1.6.0_45":  {},
		"Java/1.6.0_43":  {},
		"Java/1.6.0_38":  {},
		"Java/1.6.0_37":  {},
		"Java/1.6.0_35":  {},
		"Java/1.6.0_33":  {},
		"Java/1.6.0_31":  {},
		"Java/1.6.0_29":  {},
		"Java/1.6.0_27":  {},
		"Java/1.6.0_26":  {},
		"Java/1.6.0_24":  {},
		"Java/1.6.0_23":  {},
		"Java/1.6.0_22":  {},
		"Java/1.6.0_21":  {},
		"Java/1.6.0_20":  {},
		"Java/1.6.0_19":  {},
		"Java/1.6.0_18":  {},
		"Java/1.6.0_17":  {},
		"Java/1.6.0_16":  {},
		"Java/1.6.0_15":  {},
		"Java/1.6.0_14":  {},
	}
	// Behinder v2.x Accept header — a distinctive, non-standard q-value format.
	behinderAcceptPattern = regexp.MustCompile(`(?i)^text/html,\s*image/gif,\s*image/jpeg,\s*\*;\s*q=\.2,\s*\*/\*;\s*q=\.2$`)
)

type payloadFingerprint struct {
	Family             string
	Confidence         int
	Suggested          string
	Reasons            []string
	Fingerprints       []string
	DecoderHints       []string
	FamilyHint         string
	DecoderOptionsHint map[string]any
	SourceRole         string
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
		inspection.Candidates[idx].FamilyHint = fp.FamilyHint
		inspection.Candidates[idx].DecoderOptionsHint = cloneDecoderOptionsHint(fp.DecoderOptionsHint)
		inspection.Candidates[idx].SourceRole = fp.SourceRole
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

type inspectionTextVariant struct {
	label string
	text  string
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

	variants := collectInspectionTextVariants(raw, normalized)
	if strings.TrimSpace(normalized) != "" {
		add("当前 payload", "payload", "", normalized)
	}

	for _, variant := range variants {
		for _, item := range collectHTTPParamCandidates(variant.text) {
			label := "参数"
			if item.paramName != "" {
				label = "参数 " + item.paramName
			}
			if variant.label != "" && variant.label != "当前 payload" {
				label += " (" + variant.label + ")"
			}
			add(label, item.kind, item.paramName, item.value)
		}
		for _, item := range collectMultipartCandidates(variant.text) {
			label := "分段字段"
			if item.paramName != "" {
				label = "分段字段 " + item.paramName
			}
			if variant.label != "" && variant.label != "当前 payload" {
				label += " (" + variant.label + ")"
			}
			add(label, item.kind, item.paramName, item.value)
		}
		for _, item := range collectJSONCandidates(variant.text) {
			label := "JSON 字段"
			if item.paramName != "" {
				label = "JSON 字段 " + item.paramName
			}
			if variant.label != "" && variant.label != "当前 payload" {
				label += " (" + variant.label + ")"
			}
			add(label, item.kind, item.paramName, item.value)
		}

		if token := extractBestBase64Candidate(variant.text); strings.TrimSpace(token) != "" && token != strings.TrimSpace(variant.text) {
			label := "Base64 片段"
			if variant.label != "" && variant.label != "当前 payload" {
				label += " (" + variant.label + ")"
			}
			add(label, "token", "", token)
		}
		if token := extractEmbeddedHexCandidate(variant.text); token != "" && token != strings.TrimSpace(variant.text) {
			label := "Hex 片段"
			if variant.label != "" && variant.label != "当前 payload" {
				label += " (" + variant.label + ")"
			}
			add(label, "token", "", token)
		}
	}

	// If raw text contains reGeorg tunnel headers, add it as a candidate
	// so the fingerprinter can detect them even when HTTP body extraction strips headers.
	if reGeorgHeaderPattern.MatchString(raw) && !reGeorgHeaderPattern.MatchString(normalized) {
		add("reGeorg 隧道头", "payload", "", raw)
	}

	// If raw text contains Behinder-specific HTTP headers (User-Agent / Accept),
	// add it as a candidate so the fingerprinter can detect them.
	if looksLikeHTTPMessage(raw) {
		ua := extractHTTPHeaderIgnoreCase(raw, "User-Agent")
		_, uaMatch := behinderUASet[ua]
		acceptVal := extractHTTPHeaderIgnoreCase(raw, "Accept")
		acceptMatch := acceptVal != "" && behinderAcceptPattern.MatchString(acceptVal)
		if (uaMatch || acceptMatch) && raw != normalized {
			add("冰蝎 HTTP 头指纹", "payload", "", raw)
		}
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

func collectInspectionTextVariants(raw, normalized string) []inspectionTextVariant {
	variants := make([]inspectionTextVariant, 0, 12)
	seen := map[string]struct{}{}
	add := func(label, text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		key := text
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		variants = append(variants, inspectionTextVariant{label: label, text: text})
	}

	add("当前 payload", normalized)
	add("原始 payload", raw)
	for _, item := range append([]inspectionTextVariant(nil), variants...) {
		if looksLikeHTTPMessage(item.text) {
			if body := strings.TrimSpace(extractHTTPMessageBody(item.text)); body != "" && body != item.text {
				add(item.label+" body", body)
			}
		}
	}

	baseCount := len(variants)
	for i := 0; i < baseCount; i++ {
		current := variants[i].text
		for round := 1; round <= 2; round++ {
			decoded, err := url.QueryUnescape(current)
			if err != nil || decoded == current {
				break
			}
			current = decoded
			add(fmt.Sprintf("%s URL 解码 %d 轮", variants[i].label, round), decoded)
		}
	}

	baseCount = len(variants)
	for i := 0; i < baseCount; i++ {
		if decoded, ok := unwrapHexEncodedText(variants[i].text); ok {
			add(variants[i].label+" Hex 解包", decoded)
			if looksLikeHTTPMessage(decoded) {
				if body := strings.TrimSpace(extractHTTPMessageBody(decoded)); body != "" && body != decoded {
					add(variants[i].label+" Hex 解包 body", body)
				}
			}
		}
	}
	return variants
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

func collectJSONCandidates(candidate string) []inspectionParamCandidate {
	text := strings.TrimSpace(candidate)
	if text == "" || !(strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[")) {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return nil
	}
	out := make([]inspectionParamCandidate, 0, 8)
	collectJSONCandidateValues(decoded, "", &out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].paramName != out[j].paramName {
			return out[i].paramName < out[j].paramName
		}
		return len(out[i].value) > len(out[j].value)
	})
	if len(out) > 12 {
		return out[:12]
	}
	return out
}

func collectJSONCandidateValues(value any, path string, out *[]inspectionParamCandidate) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			collectJSONCandidateValues(typed[key], nextPath, out)
		}
	case []any:
		for idx, item := range typed {
			if idx >= 8 {
				return
			}
			nextPath := fmt.Sprintf("%s[%d]", path, idx)
			collectJSONCandidateValues(item, nextPath, out)
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		if len(trimmed) >= 8 {
			*out = append(*out, inspectionParamCandidate{
				kind:      "json",
				paramName: path,
				value:     trimmed,
			})
		}
	}
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
	paramName := strings.TrimSpace(candidate.ParamName)
	fp := payloadFingerprint{
		Family:       "plain",
		Confidence:   15,
		Suggested:    "auto",
		Reasons:      []string{"已提取出可操作 payload 候选。"},
		Fingerprints: []string{},
	}

	if paramName != "" && webshellParamPattern.MatchString(paramName) {
		fp.Confidence += 20
		fp.Reasons = append(fp.Reasons, "参数名命中常见 WebShell/命令执行字段。")
		fp.Fingerprints = append(fp.Fingerprints, "suspicious-param")
	}
	if paramName != "" && numericWebshellParamPattern.MatchString(paramName) {
		fp.Confidence += 18
		fp.Reasons = append(fp.Reasons, "参数名是蚁剑常见数字密码字段。")
		fp.Fingerprints = append(fp.Fingerprints, "numeric-webshell-param")
	}

	if reGeorgHeaderPattern.MatchString(text) {
		fp.Family = "regeorg"
		fp.Suggested = "regeorg"
		fp.Confidence = 90
		if strings.Contains(strings.ToUpper(text), "X-CMD") && strings.Contains(strings.ToUpper(text), "X-TARGET") {
			fp.Confidence = 96
		}
		fp.Reasons = append(fp.Reasons, "存在 reGeorg / neo-reGeorg 隧道特征头 (X-CMD / X-TARGET / X-STATUS-CODE / X-ERROR)。")
		fp.DecoderHints = append(fp.DecoderHints, "regeorg")
		fp.Fingerprints = append(fp.Fingerprints, "regeorg-tunnel-headers")
		fp.FamilyHint = "regeorg"
		fp.SourceRole = "tunnel"
		fp.DecoderOptionsHint = map[string]any{"decoder": "regeorg"}
		return fp
	}

	// Behinder HTTP header fingerprint (User-Agent / Accept header)
	if detected, family, versionHint, conf, reasons, fps := behinderHTTPHeaderFingerprint(text); detected {
		fp.Family = family
		fp.Suggested = "behinder"
		fp.Confidence = conf
		fp.Reasons = append(fp.Reasons, reasons...)
		fp.Fingerprints = append(fp.Fingerprints, fps...)
		fp.FamilyHint = family
		fp.SourceRole = "http_header"
		fp.DecoderHints = append(fp.DecoderHints, "behinder")
		fp.DecoderOptionsHint = map[string]any{
			"decoder":     "behinder",
			"versionHint": versionHint,
		}
		return fp
	}

	// Behinder v2.0 key negotiation: 16-char hex key response from pass=<digits> query
	if isBehinderV2HexKey(text) && (candidate.Kind == "query" || candidate.Kind == "form") &&
		paramName != "" && webshellParamPattern.MatchString(paramName) &&
		behinderV2PassDigitsPattern.MatchString(text) {
		// Not likely: hex key won't be digits-only; skip this branch.
	}
	if isBehinderV2HexKey(text) && (candidate.Kind == "query" || candidate.Kind == "form" || candidate.Kind == "payload") {
		fp.Family = "behinder_v2"
		fp.Suggested = "behinder"
		fp.Confidence = 92
		fp.Reasons = append(fp.Reasons, "候选值是 16 位十六进制字符串，符合冰蝎 v2.0 动态密钥协商响应格式 ([a-f0-9]{16})。")
		fp.DecoderHints = append(fp.DecoderHints, "behinder")
		fp.Fingerprints = append(fp.Fingerprints, "behinder-v2-hex-key")
		fp.FamilyHint = "behinder_v2"
		fp.SourceRole = "key_negotiation"
		fp.DecoderOptionsHint = map[string]any{
			"decoder":        "behinder",
			"versionHint":    "v2.0",
			"keyNegotiation": true,
			"keyFormat":      "hex16",
		}
		if paramName != "" {
			fp.DecoderOptionsHint["pass"] = paramName
			fp.DecoderOptionsHint["extractParam"] = true
		}
		return fp
	}

	// Behinder v2.0 handshake initiation: pass=<digits> on a script URL
	if (candidate.Kind == "query" || candidate.Kind == "form") && paramName != "" &&
		strings.EqualFold(paramName, "pass") &&
		behinderV2PassDigitsPattern.MatchString(text) {
		fp.Family = "behinder_v2"
		fp.Suggested = "behinder"
		fp.Confidence = 75
		fp.Reasons = append(fp.Reasons, "参数名 'pass' 值为 2-3 位数字，符合冰蝎 v2.0 密钥协商 GET 请求格式。")
		fp.DecoderHints = append(fp.DecoderHints, "behinder")
		fp.Fingerprints = append(fp.Fingerprints, "behinder-v2-pass-param")
		fp.FamilyHint = "behinder_v2"
		fp.SourceRole = "key_negotiation"
		fp.DecoderOptionsHint = map[string]any{
			"decoder":        "behinder",
			"versionHint":    "v2.0",
			"keyNegotiation": true,
			"handshakePhase": "initiation",
		}
		return fp
	}

	if antSwordChrPattern.MatchString(text) {
		fp.Family = "antsword_like"
		fp.Suggested = "antsword"
		fp.Confidence = 92
		fp.Reasons = append(fp.Reasons, "存在连续 chr() 表达式，极像蚁剑 chr 编码载荷。")
		fp.DecoderHints = append(fp.DecoderHints, "antsword")
		fp.Fingerprints = append(fp.Fingerprints, "chr-chain")
		fp.FamilyHint = "antsword_like"
		fp.SourceRole = "script_or_command"
		fp.DecoderOptionsHint = antswordDecoderOptionsHint(paramName)
		return fp
	}

	// China Chopper detection: @eval($_POST[...]) or @assert($_POST[...])
	if chinaChopperEvalPattern.MatchString(text) || chinaChopperAssertPattern.MatchString(text) {
		fp.Family = "china_chopper"
		fp.Suggested = "china_chopper"
		fp.Confidence = 95
		fp.Reasons = append(fp.Reasons, "存在 @eval($_POST[...]) 或 @assert($_POST[...]) 菜刀一句话特征。")
		fp.DecoderHints = append(fp.DecoderHints, "china_chopper")
		fp.Fingerprints = append(fp.Fingerprints, "china-chopper-eval")
		fp.FamilyHint = "china_chopper"
		fp.SourceRole = "script_or_command"
		fp.DecoderOptionsHint = chinaChopperDecoderOptionsHint(paramName)
		return fp
	}

	// China Chopper parameter name detection: caidao, chopper, c
	if chinaChopperParamPattern.MatchString(paramName) {
		fp.Family = "china_chopper"
		fp.Suggested = "china_chopper"
		fp.Confidence = 88
		fp.Reasons = append(fp.Reasons, "参数名命中菜刀常见字段 (caidao/chopper/c)。")
		fp.DecoderHints = append(fp.DecoderHints, "china_chopper")
		fp.Fingerprints = append(fp.Fingerprints, "china-chopper-param")
		fp.FamilyHint = "china_chopper"
		fp.SourceRole = "script_or_command"
		fp.DecoderOptionsHint = chinaChopperDecoderOptionsHint(paramName)
		return fp
	}

	if antSwordEvalPattern.MatchString(text) {
		fp.Family = "antsword_like"
		fp.Suggested = "antsword"
		fp.Confidence = 86
		if numericWebshellParamPattern.MatchString(paramName) {
			fp.Confidence = 94
		}
		fp.Reasons = append(fp.Reasons, "候选值直接出现 assert/eval/system/exec 等脚本执行特征。")
		fp.DecoderHints = append(fp.DecoderHints, "antsword", "auto")
		fp.Fingerprints = append(fp.Fingerprints, "script-keyword")
		fp.FamilyHint = "antsword_like"
		fp.SourceRole = "script_or_command"
		fp.DecoderOptionsHint = antswordDecoderOptionsHint(paramName)
		return fp
	}

	if decoded, err := decodeBase64Loose(extractBestBase64Candidate(text)); err == nil && len(decoded) > 0 {
		printable := looksMostlyPrintable(decoded)
		if printable && antSwordEvalPattern.MatchString(strings.ToLower(string(decoded))) {
			fp.Family = "antsword_like"
			fp.Suggested = "antsword"
			fp.Confidence = 88
			if numericWebshellParamPattern.MatchString(paramName) {
				fp.Confidence = 96
			}
			fp.Reasons = append(fp.Reasons, "Base64 解码后出现 assert/eval/base64_decode 等脚本特征。")
			fp.DecoderHints = append(fp.DecoderHints, "antsword", "base64")
			fp.Fingerprints = append(fp.Fingerprints, "script-after-base64")
			fp.FamilyHint = "antsword_like"
			fp.SourceRole = "script_or_command"
			fp.DecoderOptionsHint = antswordDecoderOptionsHint(paramName)
			return fp
		}
		if len(decoded)%16 == 0 && !printable {
			fp.Family = "aes_webshell_like"
			fp.Suggested = "behinder"
			fp.Confidence = 78
			fp.Reasons = append(fp.Reasons, "候选值 Base64 解码后长度符合 AES 分组且可打印率低，疑似 Behinder/Godzilla 类密文。")
			fp.DecoderHints = append(fp.DecoderHints, "behinder", "godzilla", "auto")
			fp.Fingerprints = append(fp.Fingerprints, "base64-aes-block")
			fp.SourceRole = "encrypted_blob"
			fp.DecoderOptionsHint = map[string]any{
				"extractParam":      paramName != "",
				"urlDecodeRounds":   1,
				"inputEncoding":     "base64",
				"deriveKeyFromPass": true,
			}
			if paramName != "" {
				fp.Confidence += 6
				fp.DecoderOptionsHint["pass"] = paramName
			}
			if isLikelyGodzillaParam(paramName) {
				fp.Family = "godzilla_like"
				fp.Suggested = "godzilla"
				fp.Confidence = 90
				fp.Reasons = append(fp.Reasons, "参数名形态符合哥斯拉随机字段，候选值是 Base64 AES 分组密文。")
				fp.DecoderHints = append([]string{"godzilla", "auto"}, removeDecodeHint(fp.DecoderHints, "godzilla")...)
				fp.Fingerprints = append(fp.Fingerprints, "godzilla-random-param")
				fp.FamilyHint = "godzilla_like"
				fp.DecoderOptionsHint = godzillaDecoderOptionsHint(paramName)
			} else {
				fp.FamilyHint = "aes_webshell_like"
				fp.DecoderOptionsHint["decoder"] = "behinder"
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
			if paramName != "" {
				fp.DecoderOptionsHint = map[string]any{
					"pass":          paramName,
					"extractParam":  true,
					"inputEncoding": "base64",
				}
			}
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
			fp.SourceRole = "encrypted_blob"
			if isLikelyGodzillaParam(paramName) {
				fp.Family = "godzilla_like"
				fp.Suggested = "godzilla"
				fp.Confidence = 88
				fp.DecoderHints = append([]string{"godzilla", "auto"}, removeDecodeHint(fp.DecoderHints, "godzilla")...)
				fp.Fingerprints = append(fp.Fingerprints, "godzilla-random-param")
				fp.FamilyHint = "godzilla_like"
				fp.DecoderOptionsHint = godzillaDecoderOptionsHint(paramName)
				fp.DecoderOptionsHint["inputEncoding"] = "hex"
			} else {
				fp.FamilyHint = "hex_cipher"
				fp.DecoderOptionsHint = map[string]any{
					"decoder":       "auto",
					"extractParam":  paramName != "",
					"inputEncoding": "hex",
				}
				if paramName != "" {
					fp.DecoderOptionsHint["pass"] = paramName
				}
			}
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

// behinderHTTPHeaderFingerprint checks raw text for Behinder-specific HTTP
// header patterns (User-Agent from built-in UA library, Accept header from
// v2.x). Returns (detected, family, versionHint, confidence, reasons,
// fingerprints).
func behinderHTTPHeaderFingerprint(text string) (bool, string, string, int, []string, []string) {
	if !strings.Contains(text, "\n") {
		return false, "", "", 0, nil, nil
	}

	acceptValue := extractHTTPHeaderIgnoreCase(text, "Accept")
	acceptMatch := acceptValue != "" && behinderAcceptPattern.MatchString(acceptValue)
	uaValue := extractHTTPHeaderIgnoreCase(text, "User-Agent")
	uaMatch := uaValue != ""
	if uaMatch {
		if _, ok := behinderUASet[uaValue]; !ok {
			uaMatch = false
		}
	}

	if !acceptMatch && !uaMatch {
		return false, "", "", 0, nil, nil
	}

	var family, versionHint string
	var confidence int
	var reasons, fingerprints []string

	if uaMatch && acceptMatch {
		family = "behinder"
		versionHint = "v2.x-v3.x"
		confidence = 95
		reasons = []string{
			fmt.Sprintf("User-Agent '%s' 命中冰蝎内置 UA 库。", uaValue),
			"Accept 头命中冰蝎 v2.x 固定特征。",
		}
		fingerprints = []string{"behinder-ua", "behinder-accept"}
	} else if acceptMatch {
		family = "behinder"
		versionHint = "v2.x"
		confidence = 88
		reasons = []string{"Accept 头命中冰蝎 v2.x 固定特征。"}
		fingerprints = []string{"behinder-accept"}
	} else {
		family = "behinder"
		versionHint = "v3.x"
		confidence = 80
		reasons = []string{fmt.Sprintf("User-Agent '%s' 命中冰蝎内置 UA 库。", uaValue)}
		fingerprints = []string{"behinder-ua"}
	}

	return true, family, versionHint, confidence, reasons, fingerprints
}

func antswordDecoderOptionsHint(paramName string) map[string]any {
	hint := map[string]any{
		"decoder":         "antsword",
		"extractParam":    strings.TrimSpace(paramName) != "",
		"urlDecodeRounds": 2,
	}
	if strings.TrimSpace(paramName) != "" {
		hint["pass"] = strings.TrimSpace(paramName)
	}
	return hint
}

func chinaChopperDecoderOptionsHint(paramName string) map[string]any {
	hint := map[string]any{
		"decoder":         "china_chopper",
		"extractParam":    true,
		"urlDecodeRounds": 1,
	}
	if strings.TrimSpace(paramName) != "" {
		hint["pass"] = strings.TrimSpace(paramName)
	} else {
		hint["pass"] = "caidao"
	}
	return hint
}

func godzillaDecoderOptionsHint(paramName string) map[string]any {
	hint := map[string]any{
		"decoder":         "godzilla",
		"extractParam":    strings.TrimSpace(paramName) != "",
		"urlDecodeRounds": 1,
		"inputEncoding":   "base64",
		"cipher":          "aes_ecb",
		"stripMarkers":    true,
	}
	if strings.TrimSpace(paramName) != "" {
		hint["pass"] = strings.TrimSpace(paramName)
	}
	return hint
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

func isLikelyGodzillaParam(paramName string) bool {
	paramName = strings.TrimSpace(paramName)
	if paramName == "" || numericWebshellParamPattern.MatchString(paramName) {
		return false
	}
	if webshellParamPattern.MatchString(paramName) {
		return false
	}
	return randomHexParamPattern.MatchString(paramName)
}

func isBehinderV2HexKey(text string) bool {
	return len(text) == 16 && behinderV2HexKeyPattern.MatchString(text)
}

func removeDecodeHint(items []string, target string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
