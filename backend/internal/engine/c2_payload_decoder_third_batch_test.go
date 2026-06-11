package engine

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestC2AggregationHelperBoundaries(t *testing.T) {
	if got := endpoint("", 0); got != "" {
		t.Fatalf("endpoint empty = %q", got)
	}
	if got := endpoint("", 443); got != ":443" {
		t.Fatalf("endpoint port only = %q", got)
	}
	if got := endpoint("10.0.0.1", 0); got != "10.0.0.1" {
		t.Fatalf("endpoint ip only = %q", got)
	}
	if got := endpoint("10.0.0.1", 443); got != "10.0.0.1:443" {
		t.Fatalf("endpoint ip port = %q", got)
	}

	if got, ok := parseC2ClockSeconds("12:34:56.5"); !ok || got != 45296.5 {
		t.Fatalf("parseC2ClockSeconds clock = %v %v", got, ok)
	}
	if got, ok := parseC2ClockSeconds("17.25"); !ok || got != 17.25 {
		t.Fatalf("parseC2ClockSeconds numeric = %v %v", got, ok)
	}
	for _, raw := range []string{"", "12:bad:56", "nope"} {
		if got, ok := parseC2ClockSeconds(raw); ok || got != 0 {
			t.Fatalf("parseC2ClockSeconds(%q) = %v %v, want false", raw, got, ok)
		}
	}

	if code := extractHTTPStatusCode("HTTP/1.1 204 No Content\r\nHeader: x"); code != 204 {
		t.Fatalf("extractHTTPStatusCode() = %d", code)
	}
	for _, raw := range []string{"GET / HTTP/1.1", "HTTP/1.1 nope", ""} {
		if code := extractHTTPStatusCode(raw); code != 0 {
			t.Fatalf("extractHTTPStatusCode(%q) = %d, want 0", raw, code)
		}
	}

	if got := limitStringList([]string{"a", "b", "c"}, 2); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("limitStringList() = %+v", got)
	}
	if got := limitFloat64List([]float64{1, 2, 3}, 0); !reflect.DeepEqual(got, []float64{1, 2, 3}) {
		t.Fatalf("limitFloat64List() = %+v", got)
	}

	direction, weight, summary := classifyScoreFactor("stable-interval-observed")
	if direction != "positive" || weight != 10 || strings.TrimSpace(summary) == "" {
		t.Fatalf("classify positive = %q %d %q", direction, weight, summary)
	}
	direction, weight, summary = classifyScoreFactor("browser-context")
	if direction != "negative" || weight != -4 || strings.TrimSpace(summary) == "" {
		t.Fatalf("classify negative = %q %d %q", direction, weight, summary)
	}
	direction, weight, summary = classifyScoreFactor("unknown")
	if direction != "" || weight != 0 || summary != "" {
		t.Fatalf("classify unknown = %q %d %q", direction, weight, summary)
	}

	factors := buildScoreFactorsFromMap(map[string]*c2ScoreFactorWork{
		"weak": {
			name:      "weak",
			weight:    -1,
			direction: "negative",
			summaries: map[string]struct{}{"b": {}, "a": {}},
		},
		"tls": {
			name:      "tls",
			weight:    12,
			direction: "positive",
			summaries: map[string]struct{}{"matched": {}},
		},
	})
	if len(factors) != 2 || factors[0].Name != "tls" || factors[1].Name != "weak" || factors[1].Summary != "a; b" {
		t.Fatalf("buildScoreFactorsFromMap() = %+v", factors)
	}
	if got := buildScoreFactorsFromMap(nil); got != nil {
		t.Fatalf("buildScoreFactorsFromMap(nil) = %+v", got)
	}
}

func TestC2DecryptPayloadValueAndKeyBoundaries(t *testing.T) {
	raw := "POST /submit?meta=query-value HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Cookie: sid=abc\r\n" +
		"Authorization: Bearer token\r\n\r\n" +
		"a=one&b=two"
	values := httpPayloadValues(raw)
	for _, want := range []string{"a=one&b=two", "one", "two", "query-value", "sid=abc", "Bearer token"} {
		if !thirdBatchStringSliceContains(values, want) {
			t.Fatalf("httpPayloadValues() missing %q in %+v", want, values)
		}
	}

	if !isTimestampOnlyC2Text("2026-06-11 10:20:30") {
		t.Fatal("full timestamp should be timestamp-only C2 text")
	}
	if !isTimestampOnlyC2Text("1700000000") || !isTimestampOnlyC2Text("1700000000000") {
		t.Fatal("epoch second/millisecond values should be timestamp-only C2 text")
	}
	for _, raw := range []string{"999", "4102444800001", "cmd=whoami", ""} {
		if isTimestampOnlyC2Text(raw) {
			t.Fatalf("isTimestampOnlyC2Text(%q) = true, want false", raw)
		}
	}

	if got := parseFlexibleKey("41:42:43:44:45:46:47:48"); string(got) != "ABCDEFGH" {
		t.Fatalf("parseFlexibleKey hex = %q", got)
	}
	if got := parseFlexibleKey(base64.StdEncoding.EncodeToString([]byte("secret"))); string(got) != "secret" {
		t.Fatalf("parseFlexibleKey base64 = %q", got)
	}
	if got := parseFlexibleKey("plain-key"); string(got) != "plain-key" {
		t.Fatalf("parseFlexibleKey plain = %q", got)
	}
}

func TestPayloadSourceVariantKeepAndDecoderBoundaries(t *testing.T) {
	base64Command := base64.StdEncoding.EncodeToString([]byte("system('whoami');"))
	variants := payloadTextVariants(base64Command)
	if !thirdBatchStringSliceContains(variants, "system('whoami');") {
		t.Fatalf("payloadTextVariants(base64) = %+v", variants)
	}
	if !payloadContainsCommandExecFunction(base64Command) {
		t.Fatal("base64 command payload should trigger command-exec detection")
	}
	if !payloadContainsCommandExecFunction("cmd%3Dwhoami") {
		t.Fatal("URL encoded command payload should trigger command-exec detection")
	}
	if !payloadContainsCommandExecFunction("657865632827696427293b") {
		t.Fatal("hex encoded exec payload should trigger command-exec detection")
	}
	if got := payloadTextVariants("   "); got != nil {
		t.Fatalf("payloadTextVariants(blank) = %+v, want nil", got)
	}

	keepCases := []model.StreamPayloadSource{
		{FamilyHint: "antsword_like"},
		{SourceRole: "script_or_command"},
		{Signals: []string{"command-exec-function"}},
		{Signals: []string{"script-keyword"}},
		{Confidence: 45, Signals: []string{"suspicious-param", "structured-http-field"}},
		{Confidence: 60, Signals: []string{"suspicious-uri", "script-keyword"}},
	}
	for _, source := range keepCases {
		if !shouldKeepPayloadSource(source) {
			t.Fatalf("shouldKeepPayloadSource(%+v) = false, want true", source)
		}
	}
	if shouldKeepPayloadSource(model.StreamPayloadSource{Confidence: 80, Signals: []string{"structured-http-field"}}) {
		t.Fatal("benign structured payload without suspicious signal should not be kept")
	}

	if command := extractChinaChopperCommand("x=1&caidao=whoami", ""); command != "whoami" {
		t.Fatalf("extractChinaChopperCommand common param = %q", command)
	}
	if command := extractChinaChopperCommand("pass=ignored&secret=cmd.exe", "secret"); command != "cmd.exe" {
		t.Fatalf("extractChinaChopperCommand pass = %q", command)
	}
	if command := extractChinaChopperCommand("a=1&b=longest-value", ""); command != "longest-value" {
		t.Fatalf("extractChinaChopperCommand longest = %q", command)
	}
	multipart := "--b\r\nContent-Disposition: form-data; name=\"caidao\"\r\n\r\nwhoami\r\n--b--"
	if command := extractChinaChopperCommand(multipart, ""); command != "whoami" {
		t.Fatalf("extractChinaChopperCommand multipart = %q", command)
	}
	if command := extractChinaChopperCommand("", "pass"); command != "" {
		t.Fatalf("extractChinaChopperCommand empty = %q", command)
	}

	if !isLikelyHexCipher("41:42:43:44:45:46:47:48") {
		t.Fatal("colon-separated hex should be likely hex cipher")
	}
	for _, raw := range []string{"4142434", "4142434g", "YWJjZGVmZ2g="} {
		if isLikelyHexCipher(raw) {
			t.Fatalf("isLikelyHexCipher(%q) = true, want false", raw)
		}
	}
	if got := optionsIntDefault(map[string]any{"n": float64(7)}, "n", 1); got != 7 {
		t.Fatalf("optionsIntDefault float64 = %d", got)
	}
	if got := optionsIntDefault(map[string]any{"n": "bad"}, "n", 9); got != 9 {
		t.Fatalf("optionsIntDefault bad string = %d", got)
	}
	if got := optionsIntDefault(nil, "n", 11); got != 11 {
		t.Fatalf("optionsIntDefault nil = %d", got)
	}
}

func thirdBatchStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
