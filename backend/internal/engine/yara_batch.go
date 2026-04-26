package engine

import (
	"context"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	yararules "github.com/gshark/sentinel/backend/rules/yara"
)

type yaraRuleMeta struct {
	category string
	ruleName string
	level    string
	cveID    string
}

type yaraRuleBundle struct {
	path string
	meta map[string]yaraRuleMeta
}

type yaraScanTarget struct {
	name     string
	path     string
	packetID int64
	source   string
}

var defaultYaraRuleMeta = map[string]yaraRuleMeta{
	"OWASP_SQL_INJECTION":  {category: "OWASP", ruleName: "SQL 注入", level: "high"},
	"OWASP_XSS":            {category: "OWASP", ruleName: "XSS", level: "high"},
	"OWASP_RCE":            {category: "OWASP", ruleName: "命令执行 RCE", level: "critical"},
	"OWASP_WEBSHELL":       {category: "OWASP", ruleName: "WebShell 特征", level: "critical"},
	"SENSITIVE_CREDENTIAL": {category: "Sensitive", ruleName: "敏感凭证泄露", level: "medium"},
}

var runYaraCommand = func(ctx context.Context, yaraExe, rulePath, scanPath string) ([]byte, error) {
	return exec.CommandContext(ctx, yaraExe, "-r", rulePath, scanPath).CombinedOutput()
}

func BatchScanObjectsWithYaraConfig(objects []model.ObjectFile, yc model.YaraConfig) ([]model.ThreatHit, error) {
	targets := make([]yaraScanTarget, 0, len(objects))
	for _, object := range objects {
		if strings.TrimSpace(object.Path) == "" {
			continue
		}
		targets = append(targets, yaraScanTarget{
			name:     object.Name,
			path:     object.Path,
			packetID: object.PacketID,
			source:   object.Source,
		})
	}
	return BatchScanTargetsWithYaraConfig(targets, yc)
}

func BatchScanTargetsWithYaraConfig(targets []yaraScanTarget, yc model.YaraConfig) ([]model.ThreatHit, error) {
	return BatchScanTargetsWithYaraConfigContext(context.Background(), targets, yc)
}

func BatchScanTargetsWithYaraConfigContext(parent context.Context, targets []yaraScanTarget, yc model.YaraConfig) ([]model.ThreatHit, error) {
	if len(targets) == 0 || !yc.Enabled {
		return nil, nil
	}
	if parent == nil {
		parent = context.Background()
	}

	yaraExe, err := resolveYaraExecutable(yc.Bin)
	if err != nil {
		return nil, err
	}

	bundle, err := resolveYaraRuleBundle(yc.Rules)
	if err != nil {
		return nil, err
	}

	timeout := resolveYaraTimeout(yc.TimeoutMS)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	byPath, byBase := buildYaraTargetLookup(targets)
	ruleMeta := mergedYaraRuleMeta(bundle.meta)

	grouped := map[string][]yaraScanTarget{}
	for _, target := range targets {
		dir := filepath.Dir(target.path)
		if strings.TrimSpace(dir) == "" {
			continue
		}
		grouped[dir] = append(grouped[dir], target)
	}

	dirs := make([]string, 0, len(grouped))
	for dir := range grouped {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	hits := make([]model.ThreatHit, 0, len(targets))
	var seq int64 = 300000
	var firstErr error

	for _, dir := range dirs {
		if ctx.Err() != nil {
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			break
		}
		output, runErr := runYaraCommand(ctx, yaraExe, bundle.path, dir)
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				continue
			}
			if ctx.Err() == context.DeadlineExceeded {
				if firstErr == nil {
					firstErr = fmt.Errorf("YARA 扫描超时（%s）: %s", timeout, dir)
				}
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("执行 YARA 失败: %v%s", runErr, summarizeYaraOutput(output))
			}
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			ruleID, matchedFile, ok := parseYaraOutputLine(line)
			if !ok {
				continue
			}

			target, found := resolveMatchedYaraTarget(dir, matchedFile, byPath, byBase)
			if !found {
				continue
			}

			meta, hasMeta := ruleMeta[ruleID]
			if !hasMeta {
				meta = fallbackYaraRuleMeta(ruleID)
			}

			preview := fmt.Sprintf("YARA 命中 %s: %s", readableYaraTargetSource(target.source), target.name)
			if meta.cveID != "" {
				preview += " | " + meta.cveID
			}
			hits = append(hits, model.ThreatHit{
				ID:       seq,
				PacketID: target.packetID,
				Category: meta.category,
				Rule:     meta.ruleName,
				Level:    meta.level,
				Preview:  previewText(preview),
				Match:    ruleID,
			})
			seq++
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].ID < hits[j].ID
	})

	return hits, firstErr
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

func buildYaraTargetLookup(targets []yaraScanTarget) (map[string]yaraScanTarget, map[string]yaraScanTarget) {
	byPath := make(map[string]yaraScanTarget, len(targets))
	byBase := make(map[string]yaraScanTarget, len(targets))
	baseCounts := map[string]int{}

	for _, target := range targets {
		normalizedPath := normalizeYaraPath(target.path)
		if normalizedPath != "" {
			byPath[normalizedPath] = target
		}
		base := normalizeObjectLookupKey(filepath.Base(target.path))
		if base != "" {
			baseCounts[base]++
		}
	}

	for _, target := range targets {
		base := normalizeObjectLookupKey(filepath.Base(target.path))
		if base == "" || baseCounts[base] != 1 {
			continue
		}
		byBase[base] = target
	}

	return byPath, byBase
}

func resolveMatchedYaraTarget(scanDir, matchedFile string, byPath map[string]yaraScanTarget, byBase map[string]yaraScanTarget) (yaraScanTarget, bool) {
	candidates := []string{matchedFile}
	if scanDir != "" && !filepath.IsAbs(matchedFile) {
		candidates = append(candidates, filepath.Join(scanDir, matchedFile))
	}

	for _, candidate := range candidates {
		if target, ok := byPath[normalizeYaraPath(candidate)]; ok {
			return target, true
		}
	}

	base := normalizeObjectLookupKey(filepath.Base(matchedFile))
	target, ok := byBase[base]
	return target, ok
}

func normalizeYaraPath(path string) string {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return ""
	}
	if absolute, err := filepath.Abs(clean); err == nil {
		clean = absolute
	}
	clean = filepath.Clean(clean)
	clean = filepath.ToSlash(clean)
	return strings.ToLower(clean)
}

func readableYaraTargetSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "http-stream":
		return "HTTP 重组流"
	case "tcp-stream":
		return "TCP 重组流"
	case "udp-stream":
		return "UDP 重组流"
	case "extracted", "http", "ftp":
		return "导出对象"
	default:
		if source == "" {
			return "目标"
		}
		return source
	}
}

func resolveYaraExecutable(customBin string) (string, error) {
	if custom := strings.TrimSpace(customBin); custom != "" {
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

func resolveYaraRuleBundle(customRules string) (yaraRuleBundle, error) {
	if custom := strings.TrimSpace(customRules); custom != "" {
		info, err := os.Stat(custom)
		if err != nil {
			return yaraRuleBundle{}, err
		}
		if info.IsDir() {
			return buildYaraRuleBundleFromDir(custom)
		}
		meta, _ := readYaraRuleMetaFromFile(custom)
		return yaraRuleBundle{path: custom, meta: meta}, nil
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
			meta, _ := readYaraRuleMetaFromFile(candidate)
			return yaraRuleBundle{path: candidate, meta: meta}, nil
		}
	}

	tempDir := filepath.Join(os.TempDir(), "gshark-sentinel", "yara")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return yaraRuleBundle{}, err
	}
	rulePath := filepath.Join(tempDir, "gshark-default.yar")
	allSources := yararules.AllRuleSources()
	if err := os.WriteFile(rulePath, []byte(allSources), 0o644); err != nil {
		return yaraRuleBundle{}, err
	}
	return yaraRuleBundle{
		path: rulePath,
		meta: parseYaraRuleMetaFromSource(allSources),
	}, nil
}

func buildYaraRuleBundleFromDir(dir string) (yaraRuleBundle, error) {
	files, err := collectYaraRuleFiles(dir)
	if err != nil {
		return yaraRuleBundle{}, err
	}
	if len(files) == 0 {
		return yaraRuleBundle{}, fmt.Errorf("yara rule directory has no .yar/.yara files: %s", dir)
	}

	builder := strings.Builder{}
	meta := map[string]yaraRuleMeta{}
	for _, file := range files {
		sourceBytes, readErr := os.ReadFile(file)
		if readErr != nil {
			return yaraRuleBundle{}, readErr
		}
		source := string(sourceBytes)
		builder.WriteString("\n\n// --- ")
		builder.WriteString(filepath.Base(file))
		builder.WriteString(" ---\n")
		builder.WriteString(source)
		for ruleID, ruleMeta := range parseYaraRuleMetaFromSource(source) {
			meta[ruleID] = ruleMeta
		}
	}

	tempDir := filepath.Join(os.TempDir(), "gshark-sentinel", "yara")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return yaraRuleBundle{}, err
	}
	fileHash := fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(strings.ToLower(filepath.Clean(dir)))))
	rulePath := filepath.Join(tempDir, "gshark-bundle-"+fileHash+".yar")
	if err := os.WriteFile(rulePath, []byte(builder.String()), 0o644); err != nil {
		return yaraRuleBundle{}, err
	}
	return yaraRuleBundle{path: rulePath, meta: meta}, nil
}

func collectYaraRuleFiles(dir string) ([]string, error) {
	files := make([]string, 0, 8)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yar", ".yara", ".rule", ".rules":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func readYaraRuleMetaFromFile(path string) (map[string]yaraRuleMeta, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yarc", ".yarac":
		return nil, nil
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseYaraRuleMetaFromSource(string(source)), nil
}

func parseYaraRuleMetaFromSource(source string) map[string]yaraRuleMeta {
	out := map[string]yaraRuleMeta{}
	lines := strings.Split(source, "\n")
	currentRule := ""
	inMeta := false
	fields := map[string]string{}

	flush := func() {
		if currentRule == "" {
			return
		}
		if meta, ok := ruleMetaFromFields(currentRule, fields); ok {
			out[currentRule] = meta
		}
		currentRule = ""
		inMeta = false
		fields = map[string]string{}
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "rule ") {
			flush()
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentRule = strings.TrimSpace(parts[1])
				if brace := strings.Index(currentRule, "{"); brace >= 0 {
					currentRule = strings.TrimSpace(currentRule[:brace])
				}
			}
			continue
		}
		if currentRule == "" {
			continue
		}
		switch {
		case line == "meta:":
			inMeta = true
			continue
		case strings.HasSuffix(line, "strings:") || strings.HasSuffix(line, "condition:"):
			inMeta = false
			continue
		case line == "}":
			flush()
			continue
		}
		if !inMeta {
			continue
		}
		key, value, ok := parseYaraMetaAssignment(line)
		if !ok {
			continue
		}
		fields[strings.ToLower(key)] = value
	}
	flush()
	return out
}

func parseYaraMetaAssignment(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, "\"")
	value = strings.Trim(value, "'")
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func ruleMetaFromFields(ruleID string, fields map[string]string) (yaraRuleMeta, bool) {
	meta := yaraRuleMeta{
		category: strings.TrimSpace(fields["family"]),
		ruleName: strings.TrimSpace(fields["description"]),
		level:    normalizeYaraLevel(fields["severity"]),
		cveID:    strings.TrimSpace(fields["cve"]),
	}
	if meta.category == "" {
		meta.category = strings.TrimSpace(fields["project"])
	}
	if meta.ruleName == "" {
		meta.ruleName = ruleID
	}
	if meta.level == "" {
		meta.level = "medium"
	}
	if meta.category == "" {
		meta.category = inferredYaraCategory(ruleID)
	}
	if meta.category == "" && meta.ruleName == ruleID {
		return yaraRuleMeta{}, false
	}
	return meta, true
}

func normalizeYaraLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func inferredYaraCategory(ruleID string) string {
	upper := strings.ToUpper(strings.TrimSpace(ruleID))
	switch {
	case strings.HasPrefix(upper, "TRAFFIC_CVE_"):
		return "CVE"
	case strings.Contains(upper, "WEBSHELL") || strings.Contains(upper, "BEHINDER") || strings.Contains(upper, "GODZILLA") || strings.Contains(upper, "ANTSWORD"):
		return "WebShell"
	case strings.Contains(upper, "VSHELL") || strings.Contains(upper, "REGEORG") || strings.Contains(upper, "TUNNEL"):
		return "C2"
	default:
		return ""
	}
}

func mergedYaraRuleMeta(parsed map[string]yaraRuleMeta) map[string]yaraRuleMeta {
	out := make(map[string]yaraRuleMeta, len(defaultYaraRuleMeta)+len(parsed))
	for ruleID, meta := range defaultYaraRuleMeta {
		out[ruleID] = meta
	}
	for ruleID, meta := range parsed {
		out[ruleID] = meta
	}
	return out
}

func fallbackYaraRuleMeta(ruleID string) yaraRuleMeta {
	category := inferredYaraCategory(ruleID)
	if category == "" {
		category = "OWASP"
	}
	return yaraRuleMeta{
		category: category,
		ruleName: ruleID,
		level:    "medium",
	}
}

func newYaraWarningHit(message string) model.ThreatHit {
	return model.ThreatHit{
		ID:       399999,
		PacketID: 0,
		Category: "YARA",
		Rule:     "YARA 扫描异常",
		Level:    "medium",
		Preview:  previewText(message),
		Match:    "yara:error",
	}
}

func summarizeYaraOutput(output []byte) string {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return ""
	}
	if len(trimmed) > 240 {
		trimmed = trimmed[:240] + "..."
	}
	return ": " + trimmed
}

func resolveYaraTimeout(timeoutMS int) time.Duration {
	const defaultTimeout = 25 * time.Second
	if timeoutMS <= 0 {
		return defaultTimeout
	}
	return time.Duration(timeoutMS) * time.Millisecond
}
