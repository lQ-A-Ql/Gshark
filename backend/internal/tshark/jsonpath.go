package tshark

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
)

func findStringByPath(node map[string]any, key string) string {
	if value, ok := walk(node, strings.Split(key, ".")); ok {
		if s, ok := anyToString(value); ok {
			return s
		}
	}
	return ""
}

func findIntByPath(node map[string]any, key string) int {
	s := findStringByPath(node, key)
	if s == "" {
		return 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return 0
}

func findBySuffix(node any, suffix string) string {
	target := normalizeKey(suffix)
	if target == "" {
		return ""
	}

	var search func(current any) string
	search = func(current any) string {
		switch v := current.(type) {
		case map[string]any:
			for k, child := range v {
				norm := normalizeKey(k)
				if strings.HasSuffix(norm, target) {
					if str, ok := anyToString(child); ok && str != "" {
						return str
					}
				}
				if nested := search(child); nested != "" {
					return nested
				}
			}
		case []any:
			for _, child := range v {
				if nested := search(child); nested != "" {
					return nested
				}
			}
		}
		return ""
	}

	return search(node)
}

func findIntBySuffix(node any, suffix string) int {
	s := findBySuffix(node, suffix)
	if s == "" {
		return 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return 0
}

func pickFirstString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func pickFirstInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func anyToString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case json.Number:
		return v.String(), true
	case []any:
		if len(v) == 0 {
			return "", false
		}
		return anyToString(v[0])
	}
	return "", false
}

func normalizeKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func walk(current any, path []string) (any, bool) {
	if len(path) == 0 {
		return current, true
	}
	obj, ok := current.(map[string]any)
	if !ok {
		return nil, false
	}
	next, ok := obj[path[0]]
	if !ok {
		return nil, false
	}
	return walk(next, path[1:])
}
