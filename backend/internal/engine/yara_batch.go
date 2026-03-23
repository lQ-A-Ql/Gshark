package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

type yaraRuleMeta struct {
	category string
	ruleName string
	level    string
}

var defaultYaraRuleMeta = map[string]yaraRuleMeta{
	"OWASP_SQL_INJECTION":  {category: "OWASP", ruleName: "SQL 注入", level: "high"},
	"OWASP_XSS":            {category: "OWASP", ruleName: "XSS", level: "high"},
	"OWASP_RCE":            {category: "OWASP", ruleName: "命令执行 RCE", level: "critical"},
	"OWASP_WEBSHELL":       {category: "OWASP", ruleName: "WebShell 特征", level: "critical"},
	"SENSITIVE_CREDENTIAL": {category: "Sensitive", ruleName: "敏感凭证泄露", level: "medium"},
}

const defaultYaraRuleSource = `rule OWASP_SQL_INJECTION {
  strings:
    $s1 = "union select" nocase
    $s2 = "information_schema" nocase
    $s3 = "' or '" nocase
    $s4 = "sleep(" nocase
    $s5 = "extractvalue(" nocase
  condition:
    any of them
}

rule OWASP_XSS {
  strings:
    $x1 = "<script" nocase
    $x2 = "onerror=" nocase
    $x3 = "javascript:" nocase
  condition:
    any of them
}

rule OWASP_RCE {
  strings:
    $r1 = "whoami" nocase
    $r2 = "/etc/passwd" nocase
    $r3 = "cmd.exe" nocase
    $r4 = "powershell" nocase
  condition:
    any of them
}

rule OWASP_WEBSHELL {
  strings:
    $w1 = "eval(base64_decode" nocase
    $w2 = "@eval($_post" nocase
    $w3 = "assert($_post" nocase
    $w4 = "shell_exec(" nocase
    $w5 = "passthru(" nocase
    $w6 = "php://input" nocase
  condition:
    any of them
}

rule SENSITIVE_CREDENTIAL {
  strings:
    $c1 = /AKIA[0-9A-Z]{16}/ nocase
    $c2 = /eyJ[A-Za-z0-9_-]+\./ nocase
  condition:
    any of them
}
`

func BatchScanObjectsWithYara(objects []model.ObjectFile, packets []model.Packet) []model.ThreatHit {
	return BatchScanObjectsWithYaraIndex(objects, buildPacketIDByObjectName(packets))
}

func BatchScanObjectsWithYaraIndex(objects []model.ObjectFile, packetByName map[string]int64) []model.ThreatHit {
	if len(objects) == 0 {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GSHARK_YARA_ENABLED")), "false") {
		return nil
	}

	scanDir := findScanDir(objects)
	if scanDir == "" {
		return nil
	}

	yaraExe, err := resolveYaraExecutable()
	if err != nil {
		return nil
	}

	rulePath, cleanup, err := resolveYaraRuleFile()
	if err != nil {
		return nil
	}
	defer cleanup()

	timeout := resolveYaraTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, yaraExe, "-r", rulePath, scanDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil
		}
		// Exit code 1 means "no matches" in classic yara.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return nil
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return nil
	}

	byName := map[string]model.ObjectFile{}
	for _, obj := range objects {
		byName[normalizeObjectLookupKey(obj.Name)] = obj
	}
	if packetByName == nil {
		packetByName = map[string]int64{}
	}

	hits := make([]model.ThreatHit, 0, len(lines))
	var seq int64 = 300000
	for _, line := range lines {
		ruleID, matchedFile, ok := parseYaraOutputLine(line)
		if !ok {
			continue
		}

		base := normalizeObjectLookupKey(filepath.Base(matchedFile))
		obj, found := byName[base]
		if !found {
			continue
		}

		packetID := obj.PacketID
		if packetID <= 0 {
			packetID = packetByName[normalizeObjectLookupKey(obj.Name)]
		}

		meta, hasMeta := defaultYaraRuleMeta[ruleID]
		if !hasMeta {
			meta = yaraRuleMeta{category: "OWASP", ruleName: ruleID, level: "medium"}
		}

		hits = append(hits, model.ThreatHit{
			ID:       seq,
			PacketID: packetID,
			Category: meta.category,
			Rule:     meta.ruleName,
			Level:    meta.level,
			Preview:  previewText("YARA 命中文件: " + obj.Name),
			Match:    ruleID,
		})
		seq++
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].ID < hits[j].ID
	})

	return hits
}

func parseYaraOutputLine(line string) (ruleID, matchedFile string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}

	firstSpace := strings.IndexAny(trimmed, " \t")
	if firstSpace <= 0 {
		return "", "", false
	}

	ruleID = strings.TrimSpace(trimmed[:firstSpace])
	matchedFile = strings.TrimSpace(trimmed[firstSpace+1:])
	if ruleID == "" || matchedFile == "" {
		return "", "", false
	}
	return ruleID, matchedFile, true
}

func findScanDir(objects []model.ObjectFile) string {
	for _, obj := range objects {
		if obj.Path != "" {
			return filepath.Dir(obj.Path)
		}
	}
	return ""
}

func resolveYaraExecutable() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("GSHARK_YARA_BIN")); custom != "" {
		if st, err := os.Stat(custom); err == nil && !st.IsDir() {
			return custom, nil
		}
	}

	exeCandidates := []string{"yara", "yara64.exe", "yara.exe"}
	for _, bin := range exeCandidates {
		if path, err := exec.LookPath(bin); err == nil {
			return path, nil
		}
	}

	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		for _, bin := range exeCandidates {
			local := filepath.Join(exeDir, bin)
			if st, statErr := os.Stat(local); statErr == nil && !st.IsDir() {
				return local, nil
			}
		}
	}

	return "", fmt.Errorf("yara executable not found")
}

func resolveYaraRuleFile() (string, func(), error) {
	if custom := strings.TrimSpace(os.Getenv("GSHARK_YARA_RULES")); custom != "" {
		if st, err := os.Stat(custom); err == nil && !st.IsDir() {
			return custom, func() {}, nil
		}
	}

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	cwd, _ := os.Getwd()

	ruleCandidates := []string{
		filepath.Join(exeDir, "rules", "yara", "default.yar"),
		filepath.Join(exeDir, "..", "rules", "yara", "default.yar"),
		filepath.Join(cwd, "rules", "yara", "default.yar"),
		filepath.Join(cwd, "backend", "rules", "yara", "default.yar"),
	}
	for _, candidate := range ruleCandidates {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, func() {}, nil
		}
	}

	fileName := "gshark-default.yar"
	tempDir := filepath.Join(os.TempDir(), "gshark-sentinel", "yara")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return "", nil, err
	}

	rulePath := filepath.Join(tempDir, fileName)
	if err := os.WriteFile(rulePath, []byte(defaultYaraRuleSource), 0o644); err != nil {
		return "", nil, err
	}

	cleanup := func() {
		// Keep generated rule file for reuse between runs to reduce churn.
		if runtime.GOOS != "windows" {
			return
		}
	}
	return rulePath, cleanup, nil
}

func resolveYaraTimeout() time.Duration {
	const defaultTimeout = 25 * time.Second
	raw := strings.TrimSpace(os.Getenv("GSHARK_YARA_TIMEOUT_MS"))
	if raw == "" {
		return defaultTimeout
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return defaultTimeout
	}
	return time.Duration(ms) * time.Millisecond
}
