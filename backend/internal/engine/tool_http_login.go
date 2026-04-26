package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	httpLoginMethodRE           = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	httpLoginStatusPrefixRE     = regexp.MustCompile(`^\s*(\d{3})\b`)
	httpLoginPathKeywordRE      = regexp.MustCompile(`(?i)(login|signin|sign-in|auth|oauth|session|token|passwd|password|sso|otp|mfa)`)
	httpLoginSuccessKeywordRE   = regexp.MustCompile(`(?i)(welcome|dashboard|profile|logout|success|access[_ -]?token|refresh[_ -]?token|jwt|bearer|signed in)`)
	httpLoginFailureKeywordRE   = regexp.MustCompile(`(?i)(invalid|incorrect|wrong|denied|forbidden|failed|failure|captcha|rate limit|too many|locked|unauthorized|mismatch)`)
	httpLoginChallengeKeywordRE = regexp.MustCompile(`(?i)(captcha|required|otp|required|mfa|required|two-factor|verification code)`)
	httpLoginHeaderValueRE      = regexp.MustCompile(`(?im)^([A-Za-z0-9\-]+):\s*(.+)$`)
)

var (
	httpLoginUsernameKeys = map[string]bool{
		"username": true, "user": true, "login": true, "email": true, "account": true,
	}
	httpLoginPasswordKeys = map[string]bool{
		"password": true, "passwd": true, "pwd": true, "pass": true,
	}
	httpLoginTokenKeys = map[string]bool{
		"token": true, "access_token": true, "refresh_token": true, "otp": true, "code": true, "authcode": true,
	}
	httpLoginCaptchaKeys = map[string]bool{
		"captcha": true, "verify": true, "verification_code": true,
	}
)

type httpLoginRequestCandidate struct {
	attempt model.HTTPLoginAttempt
	ok      bool
}

type httpLoginEndpointAgg struct {
	endpoint         model.HTTPLoginEndpoint
	statusCodes      map[string]int
	requestKeys      map[string]struct{}
	responseHints    map[string]struct{}
	usernameVariants map[string]struct{}
}

func (s *Service) HTTPLoginAnalysis(ctx context.Context) (model.HTTPLoginAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.HTTPLoginAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.HTTPLoginAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.HTTPLoginAnalysis{}, err
	}
	return buildHTTPLoginAnalysisFromPackets(ctx, packets)
}

func buildHTTPLoginAnalysisFromPackets(ctx context.Context, packets []model.Packet) (model.HTTPLoginAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := model.HTTPLoginAnalysis{
		Endpoints: []model.HTTPLoginEndpoint{},
		Attempts:  []model.HTTPLoginAttempt{},
		Notes:     []string{},
	}
	pending := make(map[int64][]int)

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.HTTPLoginAnalysis{}, err
		}
		if !isHTTPLikePacket(packet) {
			continue
		}

		method := httpLoginMethod(packet)
		if method != "" {
			candidate := buildHTTPLoginRequestCandidate(packet, method)
			if !candidate.ok {
				continue
			}
			result.Attempts = append(result.Attempts, candidate.attempt)
			index := len(result.Attempts) - 1
			pending[packet.StreamID] = append(pending[packet.StreamID], index)
			continue
		}

		statusCode := httpLoginStatusCode(packet)
		if statusCode == 0 {
			continue
		}
		queue := pending[packet.StreamID]
		if len(queue) == 0 {
			continue
		}
		index := queue[0]
		pending[packet.StreamID] = queue[1:]
		applyHTTPLoginResponse(&result.Attempts[index], packet, statusCode)
	}

	for streamID, queue := range pending {
		_ = streamID
		for _, index := range queue {
			if result.Attempts[index].Result == "" {
				result.Attempts[index].Result = "uncertain"
				result.Attempts[index].Reason = "请求未在当前抓包中匹配到明确 HTTP 响应"
			}
		}
	}

	aggregateHTTPLoginAnalysis(&result)
	return result, nil
}

func buildHTTPLoginRequestCandidate(packet model.Packet, method string) httpLoginRequestCandidate {
	payloadText := decodeHTTPPayloadText(packet.Payload)
	bodyText := strings.TrimSpace(payloadText)
	if looksLikeHTTPMessage(bodyText) {
		bodyText = strings.TrimSpace(extractHTTPMessageBody(bodyText))
	}
	path := httpRequestPath(packet, payloadText)
	headers := extractHTTPHeaders(payloadText)
	host := strings.TrimSpace(headers["Host"])
	contentType := strings.TrimSpace(headers["Content-Type"])
	params := parseHTTPLoginParams(path, bodyText, contentType)

	requestKeys := make([]string, 0, len(params))
	username := ""
	passwordPresent := false
	tokenPresent := false
	captchaPresent := false
	for key, value := range params {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		requestKeys = append(requestKeys, normalizedKey)
		if username == "" && httpLoginUsernameKeys[normalizedKey] {
			username = truncatePreview(strings.TrimSpace(value), 96)
		}
		if httpLoginPasswordKeys[normalizedKey] && strings.TrimSpace(value) != "" {
			passwordPresent = true
		}
		if httpLoginTokenKeys[normalizedKey] && strings.TrimSpace(value) != "" {
			tokenPresent = true
		}
		if httpLoginCaptchaKeys[normalizedKey] && strings.TrimSpace(value) != "" {
			captchaPresent = true
		}
	}
	sort.Strings(requestKeys)

	pathCandidate := httpLoginPathKeywordRE.MatchString(path)
	keyCandidate := passwordPresent || tokenPresent || captchaPresent || username != ""
	methodCandidate := method == "POST" || method == "PUT" || method == "PATCH"
	if !pathCandidate && !keyCandidate {
		return httpLoginRequestCandidate{}
	}
	if !methodCandidate && !(pathCandidate && keyCandidate) {
		return httpLoginRequestCandidate{}
	}

	attempt := model.HTTPLoginAttempt{
		PacketID:           packet.ID,
		StreamID:           packet.StreamID,
		Time:               packet.Timestamp,
		Src:                packet.SourceIP,
		Dst:                packet.DestIP,
		Method:             method,
		Host:               host,
		Path:               path,
		EndpointLabel:      httpLoginEndpointLabel(method, host, path),
		Username:           username,
		PasswordPresent:    passwordPresent,
		TokenPresent:       tokenPresent,
		CaptchaPresent:     captchaPresent,
		RequestKeys:        requestKeys,
		RequestContentType: contentType,
		RequestPreview:     requestPreview(packet.Info, bodyText),
	}
	return httpLoginRequestCandidate{attempt: attempt, ok: true}
}

func applyHTTPLoginResponse(attempt *model.HTTPLoginAttempt, packet model.Packet, statusCode int) {
	if attempt == nil {
		return
	}
	payloadText := decodeHTTPPayloadText(packet.Payload)
	headers := extractHTTPHeaders(payloadText)
	body := strings.TrimSpace(payloadText)
	if looksLikeHTTPMessage(body) {
		body = strings.TrimSpace(extractHTTPMessageBody(body))
	}
	responseLocation := strings.TrimSpace(headers["Location"])
	setCookie := strings.TrimSpace(headers["Set-Cookie"]) != ""
	tokenHint := strings.Contains(strings.ToLower(body), "token") || strings.Contains(strings.ToLower(strings.Join(headerValues(headers), " ")), "bearer")
	indicators := detectHTTPLoginResponseIndicators(statusCode, responseLocation, setCookie, tokenHint, body)

	attempt.ResponsePacketID = packet.ID
	attempt.ResponseTime = packet.Timestamp
	attempt.StatusCode = statusCode
	attempt.ResponseLocation = responseLocation
	attempt.ResponseSetCookie = setCookie
	attempt.ResponseTokenHint = tokenHint
	attempt.ResponseIndicators = indicators
	attempt.ResponsePreview = requestPreview(packet.Info, body)
	attempt.Result, attempt.Reason = classifyHTTPLoginAttempt(statusCode, attempt.Path, responseLocation, setCookie, tokenHint, body, indicators)
}

func aggregateHTTPLoginAnalysis(result *model.HTTPLoginAnalysis) {
	if result == nil {
		return
	}
	aggregates := make(map[string]*httpLoginEndpointAgg)

	for index := range result.Attempts {
		attempt := &result.Attempts[index]
		key := httpLoginEndpointKey(attempt.Method, attempt.Host, attempt.Path)
		agg := aggregates[key]
		if agg == nil {
			agg = &httpLoginEndpointAgg{
				endpoint: model.HTTPLoginEndpoint{
					Key:    key,
					Method: attempt.Method,
					Host:   attempt.Host,
					Path:   attempt.Path,
				},
				statusCodes:      map[string]int{},
				requestKeys:      map[string]struct{}{},
				responseHints:    map[string]struct{}{},
				usernameVariants: map[string]struct{}{},
			}
			aggregates[key] = agg
		}

		agg.endpoint.AttemptCount++
		agg.endpoint.SamplePacketIDs = appendUniqueInt64(agg.endpoint.SamplePacketIDs, attempt.PacketID, 6)
		if attempt.Username != "" {
			agg.usernameVariants[attempt.Username] = struct{}{}
		}
		if attempt.PasswordPresent {
			agg.endpoint.PasswordAttempts++
		}
		if attempt.CaptchaPresent {
			agg.endpoint.CaptchaCount++
		}
		if attempt.ResponseSetCookie {
			agg.endpoint.SetCookieCount++
		}
		if attempt.ResponseTokenHint {
			agg.endpoint.TokenHintCount++
		}
		for _, key := range attempt.RequestKeys {
			agg.requestKeys[key] = struct{}{}
		}
		for _, hint := range attempt.ResponseIndicators {
			agg.responseHints[hint] = struct{}{}
		}
		if attempt.StatusCode > 0 {
			agg.statusCodes[strconv.Itoa(attempt.StatusCode)]++
		}
		switch attempt.Result {
		case "success":
			result.SuccessCount++
			agg.endpoint.SuccessCount++
		case "failure":
			result.FailureCount++
			agg.endpoint.FailureCount++
		default:
			result.UncertainCount++
			agg.endpoint.UncertainCount++
		}
	}

	result.TotalAttempts = len(result.Attempts)
	for _, agg := range aggregates {
		agg.endpoint.UsernameVariants = len(agg.usernameVariants)
		agg.endpoint.RequestKeys = sortedStringSet(agg.requestKeys)
		agg.endpoint.ResponseIndicators = sortedStringSet(agg.responseHints)
		agg.endpoint.StatusCodes = sortedBucketMap(agg.statusCodes)
		if agg.endpoint.AttemptCount >= 3 && agg.endpoint.FailureCount >= 2 && (agg.endpoint.UsernameVariants >= 2 || agg.endpoint.PasswordAttempts >= 3) {
			agg.endpoint.PossibleBruteforce = true
			agg.endpoint.Notes = append(agg.endpoint.Notes, "同一认证端点存在多次失败尝试且用户名/口令变化明显，疑似爆破或批量验证")
			result.BruteforceCount++
			for idx := range result.Attempts {
				if httpLoginEndpointKey(result.Attempts[idx].Method, result.Attempts[idx].Host, result.Attempts[idx].Path) == agg.endpoint.Key {
					result.Attempts[idx].PossibleBruteforce = true
				}
			}
		}
		if agg.endpoint.SuccessCount > 0 && agg.endpoint.SetCookieCount > 0 {
			agg.endpoint.Notes = append(agg.endpoint.Notes, "成功响应伴随 Set-Cookie，可能发生了会话建立或登录态刷新")
		}
		result.Endpoints = append(result.Endpoints, agg.endpoint)
	}

	sort.SliceStable(result.Endpoints, func(i, j int) bool {
		if result.Endpoints[i].AttemptCount != result.Endpoints[j].AttemptCount {
			return result.Endpoints[i].AttemptCount > result.Endpoints[j].AttemptCount
		}
		return result.Endpoints[i].Key < result.Endpoints[j].Key
	})
	sort.SliceStable(result.Attempts, func(i, j int) bool { return result.Attempts[i].PacketID < result.Attempts[j].PacketID })
	result.CandidateEndpoints = len(result.Endpoints)
	result.Notes = buildHTTPLoginNotes(*result)
}

func httpLoginMethod(packet model.Packet) string {
	info := strings.TrimSpace(packet.Info)
	if info != "" {
		if match := httpLoginMethodRE.FindStringSubmatch(strings.ToUpper(info)); len(match) == 2 {
			return match[1]
		}
	}
	payload := strings.TrimSpace(decodeHTTPPayloadText(packet.Payload))
	if payload == "" {
		return ""
	}
	firstLine := strings.Split(strings.ReplaceAll(payload, "\r\n", "\n"), "\n")[0]
	if match := httpLoginMethodRE.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(firstLine))); len(match) == 2 {
		return match[1]
	}
	return ""
}

func httpLoginStatusCode(packet model.Packet) int {
	info := strings.TrimSpace(packet.Info)
	if info != "" {
		if strings.HasPrefix(strings.ToUpper(info), "HTTP/") {
			if code := extractHTTPStatusCodeFromLine(info); code > 0 {
				return code
			}
		}
		if code := extractHTTPStatusCodeFromLine(info); code > 0 {
			return code
		}
	}
	payload := strings.TrimSpace(decodeHTTPPayloadText(packet.Payload))
	if payload == "" {
		return 0
	}
	firstLine := strings.Split(strings.ReplaceAll(payload, "\r\n", "\n"), "\n")[0]
	return extractHTTPStatusCodeFromLine(firstLine)
}

func extractHTTPStatusCodeFromLine(line string) int {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(strings.ToUpper(line), "HTTP/") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if code, err := strconv.Atoi(fields[1]); err == nil {
				return code
			}
		}
		return 0
	}
	match := httpLoginStatusPrefixRE.FindStringSubmatch(line)
	if len(match) != 2 {
		return 0
	}
	code, _ := strconv.Atoi(match[1])
	return code
}

func httpRequestPath(packet model.Packet, payload string) string {
	info := strings.TrimSpace(packet.Info)
	if info != "" {
		fields := strings.Fields(info)
		if len(fields) >= 2 && httpLoginMethodRE.MatchString(strings.ToUpper(fields[0])) {
			return strings.TrimSpace(fields[1])
		}
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return ""
	}
	firstLine := strings.Split(strings.ReplaceAll(payload, "\r\n", "\n"), "\n")[0]
	fields := strings.Fields(firstLine)
	if len(fields) >= 2 && httpLoginMethodRE.MatchString(strings.ToUpper(fields[0])) {
		return strings.TrimSpace(fields[1])
	}
	return ""
}

func extractHTTPHeaders(payload string) map[string]string {
	payload = strings.ReplaceAll(payload, "\r\n", "\n")
	headers := make(map[string]string)
	if payload == "" {
		return headers
	}
	headerPart := payload
	if idx := strings.Index(payload, "\n\n"); idx >= 0 {
		headerPart = payload[:idx]
	}
	for _, match := range httpLoginHeaderValueRE.FindAllStringSubmatch(headerPart, -1) {
		if len(match) != 3 {
			continue
		}
		headers[strings.TrimSpace(match[1])] = strings.TrimSpace(match[2])
	}
	return headers
}

func headerValues(headers map[string]string) []string {
	values := make([]string, 0, len(headers))
	for _, value := range headers {
		values = append(values, value)
	}
	return values
}

func parseHTTPLoginParams(path, body, contentType string) map[string]string {
	params := make(map[string]string)
	if idx := strings.Index(path, "?"); idx >= 0 && idx+1 < len(path) {
		mergeStringMap(params, parseQueryLikeParams(path[idx+1:]))
	}

	body = strings.TrimSpace(body)
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.Contains(contentType, "application/json"):
		mergeStringMap(params, parseJSONParams(body))
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		mergeStringMap(params, parseQueryLikeParams(body))
	default:
		if looksLikeJSONObject(body) {
			mergeStringMap(params, parseJSONParams(body))
		} else if strings.Contains(body, "=") && (strings.Contains(body, "&") || strings.Contains(body, "%")) {
			mergeStringMap(params, parseQueryLikeParams(body))
		}
	}
	return params
}

func parseQueryLikeParams(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, items := range values {
		if len(items) == 0 {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(items[0])
	}
	return out
}

func parseJSONParams(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	out := make(map[string]string, len(payload))
	for key, value := range payload {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case float64, bool:
			out[key] = fmt.Sprintf("%v", typed)
		}
	}
	return out
}

func looksLikeJSONObject(raw string) bool {
	raw = strings.TrimSpace(raw)
	return strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}")
}

func detectHTTPLoginResponseIndicators(statusCode int, location string, setCookie, tokenHint bool, body string) []string {
	indicators := make([]string, 0, 8)
	bodyLower := strings.ToLower(body)
	if statusCode > 0 {
		indicators = append(indicators, fmt.Sprintf("status:%d", statusCode))
	}
	if responseLocation := strings.TrimSpace(location); responseLocation != "" {
		if httpLoginPathKeywordRE.MatchString(responseLocation) {
			indicators = append(indicators, "redirect:auth")
		} else {
			indicators = append(indicators, "redirect:post-auth")
		}
	}
	if setCookie {
		indicators = append(indicators, "set-cookie")
	}
	if tokenHint {
		indicators = append(indicators, "token")
	}
	if httpLoginFailureKeywordRE.MatchString(bodyLower) {
		indicators = append(indicators, "failure-keyword")
	}
	if httpLoginSuccessKeywordRE.MatchString(bodyLower) {
		indicators = append(indicators, "success-keyword")
	}
	if httpLoginChallengeKeywordRE.MatchString(bodyLower) {
		indicators = append(indicators, "challenge")
	}
	return dedupeStrings(indicators)
}

func classifyHTTPLoginAttempt(statusCode int, path, location string, setCookie, tokenHint bool, body string, indicators []string) (string, string) {
	bodyLower := strings.ToLower(body)
	if statusCode == 401 || statusCode == 403 {
		return "failure", fmt.Sprintf("响应码 %d 明确表示认证失败或被拒绝", statusCode)
	}
	if statusCode == 429 {
		return "failure", "响应码 429 表示认证接口发生限速/爆破拦截"
	}
	if httpLoginChallengeKeywordRE.MatchString(bodyLower) {
		return "uncertain", "响应提示验证码/二次验证，属于认证中间态"
	}
	if httpLoginFailureKeywordRE.MatchString(bodyLower) {
		return "failure", "响应正文出现失败关键字"
	}
	if statusCode >= 300 && statusCode < 400 && strings.TrimSpace(location) != "" {
		if httpLoginPathKeywordRE.MatchString(location) {
			return "failure", "认证后仍跳转回登录/认证路径"
		}
		return "success", "认证后跳转到非登录页面，疑似已建立登录态"
	}
	if setCookie && statusCode >= 200 && statusCode < 300 {
		return "success", "成功响应伴随 Set-Cookie，疑似已建立会话"
	}
	if tokenHint && statusCode >= 200 && statusCode < 300 {
		return "success", "成功响应中返回 token / bearer 线索"
	}
	if httpLoginSuccessKeywordRE.MatchString(bodyLower) && statusCode >= 200 && statusCode < 300 {
		return "success", "响应正文出现成功关键字"
	}
	if statusCode >= 500 {
		return "failure", fmt.Sprintf("响应码 %d 表示服务端异常，可能为认证处理失败", statusCode)
	}
	if statusCode >= 200 && statusCode < 300 {
		return "uncertain", "响应码正常，但缺少明确登录成功或失败信号"
	}
	if len(indicators) == 0 && path != "" {
		return "uncertain", "缺少足够的响应特征，保留为待人工确认"
	}
	return "uncertain", "响应信号不足，建议结合完整流量继续复核"
}

func httpLoginEndpointLabel(method, host, path string) string {
	base := strings.TrimSpace(path)
	if base == "" {
		base = "/"
	}
	if strings.TrimSpace(host) != "" {
		base = host + base
	}
	if strings.TrimSpace(method) != "" {
		return method + " " + base
	}
	return base
}

func httpLoginEndpointKey(method, host, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + "|" + strings.TrimSpace(host) + "|" + strings.TrimSpace(path)
}

func requestPreview(info, body string) string {
	candidate := strings.TrimSpace(body)
	if candidate == "" {
		candidate = strings.TrimSpace(info)
	}
	return truncatePreview(candidate, 240)
}

func truncatePreview(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || limit <= 0 {
		return raw
	}
	runes := []rune(raw)
	if len(runes) <= limit {
		return raw
	}
	return string(runes[:limit]) + "..."
}

func mergeStringMap(dst, src map[string]string) {
	for key, value := range src {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := dst[key]; exists {
			continue
		}
		dst[key] = strings.TrimSpace(value)
	}
}

func appendUniqueInt64(items []int64, value int64, limit int) []int64 {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	if limit > 0 && len(items) >= limit {
		return items
	}
	return append(items, value)
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func sortedStringSet(items map[string]struct{}) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func sortedBucketMap(items map[string]int) []model.TrafficBucket {
	if len(items) == 0 {
		return nil
	}
	out := make([]model.TrafficBucket, 0, len(items))
	for label, count := range items {
		out = append(out, model.TrafficBucket{Label: label, Count: count})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func buildHTTPLoginNotes(result model.HTTPLoginAnalysis) []string {
	notes := make([]string, 0, 4)
	if result.TotalAttempts == 0 {
		return []string{"当前抓包中未识别到明显的 HTTP 登录行为候选。"}
	}
	notes = append(notes, fmt.Sprintf("共识别 %d 次 HTTP 登录候选，覆盖 %d 个认证端点。", result.TotalAttempts, result.CandidateEndpoints))
	if result.BruteforceCount > 0 {
		notes = append(notes, fmt.Sprintf("其中 %d 个端点存在疑似爆破或批量验证行为，建议优先复核失败次数和用户名变化。", result.BruteforceCount))
	}
	if result.SuccessCount > 0 {
		notes = append(notes, fmt.Sprintf("有 %d 次尝试命中成功特征，可结合 Set-Cookie / token / redirect 进一步验证会话建立。", result.SuccessCount))
	}
	if result.UncertainCount > 0 {
		notes = append(notes, fmt.Sprintf("仍有 %d 次尝试为待确认状态，建议回到 HTTP 流追踪页查看完整请求响应对。", result.UncertainCount))
	}
	return notes
}
