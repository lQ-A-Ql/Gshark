package engine

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	shiroRememberMePrintableRE = regexp.MustCompile(`[A-Za-z0-9_$][A-Za-z0-9_.$-]{3,}`)
)

var shiroDefaultRememberMeKeys = []string{
	"shiro-default::kPH+bIxk5D2deZiIxcaaaA==",
}

type shiroRememberMeKeyCandidate struct {
	Label  string
	Base64 string
	Raw    []byte
}

type shiroRememberMeCookieOccurrence struct {
	SourceHeader string
	Name         string
	Value        string
}

func (s *Service) ShiroRememberMeAnalysis(ctx context.Context, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.ShiroRememberMeAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.ShiroRememberMeAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.ShiroRememberMeAnalysis{}, err
	}
	return buildShiroRememberMeAnalysisFromPackets(ctx, packets, req)
}

func buildShiroRememberMeAnalysisFromPackets(ctx context.Context, packets []model.Packet, req model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	keys := prepareShiroRememberMeKeys(req.CandidateKeys)
	analysis := model.ShiroRememberMeAnalysis{
		Candidates: []model.ShiroRememberMeCandidate{},
		Notes:      []string{},
	}

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.ShiroRememberMeAnalysis{}, err
		}
		if !isHTTPLikePacket(packet) {
			continue
		}
		payloadText := decodeHTTPPayloadText(packet.Payload)
		if !looksLikeHTTPMessage(payloadText) {
			continue
		}
		occurrences := extractShiroRememberMeCookies(payloadText)
		if len(occurrences) == 0 {
			continue
		}
		host := strings.TrimSpace(extractHTTPHeaders(payloadText)["Host"])
		path := strings.TrimSpace(httpRequestPath(packet, payloadText))
		for _, occurrence := range occurrences {
			if err := ctx.Err(); err != nil {
				return model.ShiroRememberMeAnalysis{}, err
			}
			candidate := analyzeShiroRememberMeCookie(packet, host, path, occurrence, keys)
			analysis.CandidateCount++
			analysis.HitCount += candidate.HitCount
			analysis.Candidates = append(analysis.Candidates, candidate)
		}
	}

	sort.SliceStable(analysis.Candidates, func(i, j int) bool {
		if analysis.Candidates[i].HitCount != analysis.Candidates[j].HitCount {
			return analysis.Candidates[i].HitCount > analysis.Candidates[j].HitCount
		}
		if analysis.Candidates[i].PacketID != analysis.Candidates[j].PacketID {
			return analysis.Candidates[i].PacketID < analysis.Candidates[j].PacketID
		}
		return analysis.Candidates[i].CookieName < analysis.Candidates[j].CookieName
	})
	analysis.Notes = buildShiroRememberMeNotes(analysis)
	return analysis, nil
}

func analyzeShiroRememberMeCookie(packet model.Packet, host, path string, occurrence shiroRememberMeCookieOccurrence, keys []shiroRememberMeKeyCandidate) model.ShiroRememberMeCandidate {
	candidate := model.ShiroRememberMeCandidate{
		PacketID:      packet.ID,
		StreamID:      packet.StreamID,
		Time:          packet.Timestamp,
		Src:           packet.SourceIP,
		Dst:           packet.DestIP,
		Host:          host,
		Path:          path,
		SourceHeader:  occurrence.SourceHeader,
		CookieName:    occurrence.Name,
		CookieValue:   occurrence.Value,
		CookiePreview: truncatePreview(strings.TrimSpace(occurrence.Value), 160),
		Notes:         []string{},
	}
	if occurrence.SourceHeader != "" {
		candidate.Notes = append(candidate.Notes, "来源: "+occurrence.SourceHeader)
	}
	normalizedValue := normalizeShiroCookieValue(occurrence.Value)
	if strings.EqualFold(normalizedValue, "deleteMe") {
		candidate.Notes = append(candidate.Notes, "值为 deleteMe，常见于 Shiro rememberMe 校验失败后由服务端回收 Cookie")
		return candidate
	}

	decoded, err := decodeShiroRememberMeCookieValue(occurrence.Value)
	if err != nil {
		candidate.Notes = append(candidate.Notes, "Base64 解码失败: "+err.Error())
		return candidate
	}

	candidate.DecodeOK = true
	candidate.EncryptedLength = len(decoded)
	candidate.AesBlockAligned = len(decoded) > 0 && len(decoded)%aes.BlockSize == 0
	candidate.PossibleCBC = len(decoded) >= aes.BlockSize*2 && len(decoded)%aes.BlockSize == 0
	candidate.PossibleGCM = len(decoded) >= 28
	candidate.KeyResults = testShiroRememberMeKeys(decoded, keys)
	for _, result := range candidate.KeyResults {
		if result.Hit {
			candidate.HitCount++
		}
	}
	if candidate.HitCount > 0 {
		candidate.Notes = append(candidate.Notes, fmt.Sprintf("命中 %d 个候选密钥，可继续回溯对应会话。", candidate.HitCount))
	} else {
		candidate.Notes = append(candidate.Notes, "已识别 rememberMe 样本，但当前候选密钥未命中有效明文。")
	}
	return candidate
}

func prepareShiroRememberMeKeys(custom []string) []shiroRememberMeKeyCandidate {
	seen := map[string]struct{}{}
	keys := make([]shiroRememberMeKeyCandidate, 0, len(shiroDefaultRememberMeKeys)+len(custom))
	for _, raw := range append(append([]string(nil), shiroDefaultRememberMeKeys...), custom...) {
		label, base64Value := parseShiroRememberMeKeyLine(raw)
		if base64Value == "" {
			continue
		}
		if _, ok := seen[base64Value]; ok {
			continue
		}
		decoded, err := decodeRememberMeKey(base64Value)
		if err != nil {
			continue
		}
		seen[base64Value] = struct{}{}
		keys = append(keys, shiroRememberMeKeyCandidate{
			Label:  label,
			Base64: base64Value,
			Raw:    decoded,
		})
	}
	return keys
}

func parseShiroRememberMeKeyLine(raw string) (string, string) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", ""
	}
	if left, right, ok := strings.Cut(line, "::"); ok {
		label := strings.TrimSpace(left)
		base64Value := strings.TrimSpace(right)
		if label == "" {
			label = "custom"
		}
		return label, base64Value
	}
	return "custom", line
}

func decodeRememberMeKey(raw string) ([]byte, error) {
	decoded, err := decodeShiroBase64(raw)
	if err != nil {
		return nil, err
	}
	switch len(decoded) {
	case 16, 24, 32:
		return decoded, nil
	default:
		return nil, fmt.Errorf("AES 密钥长度 %d 非法", len(decoded))
	}
}

func extractShiroRememberMeCookies(payload string) []shiroRememberMeCookieOccurrence {
	normalized := strings.ReplaceAll(payload, "\r\n", "\n")
	headerPart := normalized
	if idx := strings.Index(normalized, "\n\n"); idx >= 0 {
		headerPart = normalized[:idx]
	}
	lines := strings.Split(headerPart, "\n")
	if len(lines) == 0 {
		return nil
	}

	out := make([]shiroRememberMeCookieOccurrence, 0, 2)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "cookie":
			for _, part := range strings.Split(value, ";") {
				cookieName, cookieValue, ok := strings.Cut(strings.TrimSpace(part), "=")
				if !ok || !isRememberMeCookieName(cookieName) {
					continue
				}
				out = append(out, shiroRememberMeCookieOccurrence{
					SourceHeader: "Cookie",
					Name:         strings.TrimSpace(cookieName),
					Value:        strings.TrimSpace(cookieValue),
				})
			}
		case "set-cookie":
			pair := strings.TrimSpace(value)
			if idx := strings.Index(pair, ";"); idx >= 0 {
				pair = pair[:idx]
			}
			cookieName, cookieValue, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !isRememberMeCookieName(cookieName) {
				continue
			}
			out = append(out, shiroRememberMeCookieOccurrence{
				SourceHeader: "Set-Cookie",
				Name:         strings.TrimSpace(cookieName),
				Value:        strings.TrimSpace(cookieValue),
			})
		}
	}
	return out
}

func isRememberMeCookieName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", ""))
	return normalized == "rememberme"
}

func normalizeShiroCookieValue(raw string) string {
	value := strings.TrimSpace(strings.Trim(raw, `"'`))
	if value == "" {
		return ""
	}
	if unescaped, err := url.PathUnescape(value); err == nil && strings.TrimSpace(unescaped) != "" {
		return strings.TrimSpace(unescaped)
	}
	return value
}

func decodeShiroRememberMeCookieValue(raw string) ([]byte, error) {
	return decodeShiroBase64(normalizeShiroCookieValue(raw))
}

func decodeShiroBase64(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("空值")
	}
	var lastErr error
	candidates := []string{value}
	if padded := padBase64String(value); padded != value {
		candidates = append(candidates, padded)
	}
	for _, candidate := range candidates {
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			decoded, err := encoding.DecodeString(candidate)
			if err == nil {
				return decoded, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未知 base64 编码")
	}
	return nil, lastErr
}

func padBase64String(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return value
	}
	if rem := len(value) % 4; rem != 0 {
		value += strings.Repeat("=", 4-rem)
	}
	return value
}

func testShiroRememberMeKeys(blob []byte, keys []shiroRememberMeKeyCandidate) []model.ShiroRememberMeKeyResult {
	results := make([]model.ShiroRememberMeKeyResult, 0, len(keys))
	for _, key := range keys {
		result := model.ShiroRememberMeKeyResult{
			Label:  key.Label,
			Base64: key.Base64,
		}
		plaintext, algorithm, err := decryptShiroRememberMe(blob, key.Raw)
		if err != nil {
			result.Reason = err.Error()
			results = append(results, result)
			continue
		}
		result.Algorithm = algorithm
		result.Hit = hasJavaSerializedMagic(plaintext)
		result.PayloadClass = extractSerializedPayloadClass(plaintext)
		result.Preview = shiroPayloadPreview(plaintext)
		if !result.Hit {
			result.Reason = "解密已成功，但未匹配到 Java 序列化头"
		}
		results = append(results, result)
	}
	return results
}

func decryptShiroRememberMe(blob, key []byte) ([]byte, string, error) {
	var reasons []string

	if plaintext, err := decryptShiroRememberMeCBC(blob, key); err == nil {
		return plaintext, "AES-CBC", nil
	} else {
		reasons = append(reasons, "AES-CBC: "+err.Error())
	}

	for _, nonceSize := range []int{12, 16} {
		plaintext, err := decryptShiroRememberMeGCM(blob, key, nonceSize)
		if err == nil {
			return plaintext, fmt.Sprintf("AES-GCM/%d", nonceSize), nil
		}
		reasons = append(reasons, fmt.Sprintf("AES-GCM/%d: %s", nonceSize, err.Error()))
	}

	return nil, "", errors.New(strings.Join(reasons, "; "))
}

func decryptShiroRememberMeCBC(blob, key []byte) ([]byte, error) {
	if len(blob) < aes.BlockSize*2 {
		return nil, fmt.Errorf("密文长度不足以构成 IV + CBC 密文")
	}
	if len(blob)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("CBC 样本长度不是 16 字节对齐")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := blob[:aes.BlockSize]
	ciphertext := append([]byte(nil), blob[aes.BlockSize:]...)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("CBC 密文长度不是 16 字节对齐")
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
	return pkcs7Unpad(ciphertext, aes.BlockSize)
}

func decryptShiroRememberMeGCM(blob, key []byte, nonceSize int) ([]byte, error) {
	if len(blob) <= nonceSize {
		return nil, fmt.Errorf("长度不足以构成 nonce + GCM 密文")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var gcm cipher.AEAD
	if nonceSize == 12 {
		gcm, err = cipher.NewGCM(block)
	} else {
		gcm, err = cipher.NewGCMWithNonceSize(block, nonceSize)
	}
	if err != nil {
		return nil, err
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func hasJavaSerializedMagic(raw []byte) bool {
	return len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0xac, 0xed, 0x00, 0x05})
}

func extractSerializedPayloadClass(raw []byte) string {
	text := shiroPrintableProjection(raw)
	for _, match := range shiroRememberMePrintableRE.FindAllString(text, -1) {
		if strings.Count(match, ".") >= 2 {
			return match
		}
	}
	for _, match := range shiroRememberMePrintableRE.FindAllString(text, -1) {
		if strings.Contains(match, "Principal") || strings.Contains(match, "Collection") || strings.Contains(match, "Remember") {
			return match
		}
	}
	return ""
}

func shiroPayloadPreview(raw []byte) string {
	text := truncatePreview(strings.Join(strings.Fields(shiroPrintableProjection(raw)), " "), 180)
	if text != "" {
		return text
	}
	if len(raw) == 0 {
		return ""
	}
	preview := raw
	if len(preview) > 24 {
		preview = preview[:24]
	}
	return fmt.Sprintf("%x", preview)
}

func shiroPrintableProjection(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(raw))
	for _, value := range raw {
		switch {
		case value >= 32 && value <= 126:
			builder.WriteByte(value)
		case value == '\t' || value == '\r' || value == '\n':
			builder.WriteByte(' ')
		default:
			builder.WriteByte(' ')
		}
	}
	return builder.String()
}

func buildShiroRememberMeNotes(analysis model.ShiroRememberMeAnalysis) []string {
	if analysis.CandidateCount == 0 {
		return []string{"当前抓包中未发现 rememberMe Cookie 线索。"}
	}

	deleteMeCount := 0
	defaultHitCount := 0
	for _, candidate := range analysis.Candidates {
		for _, note := range candidate.Notes {
			if strings.Contains(note, "deleteMe") {
				deleteMeCount++
				break
			}
		}
		for _, keyResult := range candidate.KeyResults {
			if keyResult.Hit && keyResult.Label == "shiro-default" {
				defaultHitCount++
			}
		}
	}

	notes := []string{
		fmt.Sprintf("共发现 %d 处 rememberMe 线索，候选密钥共命中 %d 次。", analysis.CandidateCount, analysis.HitCount),
	}
	if defaultHitCount > 0 {
		notes = append(notes, fmt.Sprintf("其中 %d 处样本命中历史默认密钥 shiro-default，需优先复核相关认证流量与利用风险。", defaultHitCount))
	}
	if deleteMeCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 处 rememberMe=deleteMe 痕迹，常见于服务端校验 rememberMe 失败后的清理动作。", deleteMeCount))
	}
	return notes
}
