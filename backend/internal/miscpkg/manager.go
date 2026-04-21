package miscpkg

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var (
	moduleIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	moduleExportStripRE = regexp.MustCompile(`(?m)^\s*export\s+`)
)

const pythonHostBridgeModuleName = "gshark_misc_host"

const pythonHostBridgeSource = `import json
import os
import sys

_INPUT = json.loads(os.environ.get("GSHARK_MISC_INPUT_JSON", "{}"))
_REQ_ID = 0

def get_input():
    return _INPUT

def _call_host(method, params):
    global _REQ_ID
    _REQ_ID += 1
    current_id = str(_REQ_ID)
    message = {
        "type": "host_call",
        "id": current_id,
        "method": method,
        "params": params or {}
    }
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    raw = sys.stdin.readline()
    if not raw:
        raise RuntimeError("host bridge closed before responding")
    payload = json.loads(raw)
    if payload.get("type") != "host_response":
        raise RuntimeError("unexpected host bridge response")
    if payload.get("id") != current_id:
        raise RuntimeError("host bridge response id mismatch")
    error = payload.get("error")
    if error:
        raise RuntimeError(str(error))
    return payload.get("payload")

def scan_fields(fields, display_filter=""):
    return _call_host("scan_fields", {
        "fields": list(fields or []),
        "display_filter": display_filter or ""
    })

def emit_result(payload):
    sys.stdout.write(json.dumps({
        "type": "result",
        "payload": payload
    }, ensure_ascii=False) + "\n")
    sys.stdout.flush()

def run(handler):
    emit_result(handler(get_input()))
`

type InvokeContext struct {
	CapturePath string
	PythonPath  string
	TSharkPath  string
	ScanFields  func(filePath string, fields []string, displayFilter string) ([]map[string]string, error)
}

type loadedModule struct {
	manifest    model.MiscModuleManifest
	backendPath string
	api         packageAPI
}

type packageAPI struct {
	Method     string `json:"method"`
	Entry      string `json:"entry"`
	HostBridge bool   `json:"host_bridge,omitempty"`
}

type Manager struct {
	mu      sync.RWMutex
	baseDir string
	modules map[string]loadedModule
}

func NewManager() *Manager {
	return &Manager{
		modules: map[string]loadedModule{},
	}
}

func (m *Manager) LoadFromDir(dir string) error {
	baseDir, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		return fmt.Errorf("resolve misc module dir: %w", err)
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fmt.Errorf("create misc module dir: %w", err)
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return fmt.Errorf("read misc module dir: %w", err)
	}

	loaded := make(map[string]loadedModule)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		module, loadErr := loadModuleFromDir(filepath.Join(baseDir, entry.Name()))
		if loadErr != nil {
			continue
		}
		loaded[module.manifest.ID] = module
	}

	m.mu.Lock()
	m.baseDir = baseDir
	m.modules = loaded
	m.mu.Unlock()
	return nil
}

func (m *Manager) List() []model.MiscModuleManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]model.MiscModuleManifest, 0, len(m.modules))
	for _, module := range m.modules {
		items = append(items, cloneManifest(module.manifest))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return strings.ToLower(items[i].Title) < strings.ToLower(items[j].Title)
	})
	return items
}

func (m *Manager) Delete(id string) error {
	id = strings.TrimSpace(id)
	if err := validateModuleID(id); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	module, ok := m.modules[id]
	if !ok {
		return fmt.Errorf("misc module %s not found", id)
	}
	moduleDir, err := resolveManagedPath(m.baseDir, module.manifest.ID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(moduleDir); err != nil {
		return fmt.Errorf("delete module dir: %w", err)
	}
	delete(m.modules, id)
	return nil
}

func (m *Manager) ImportZipBytes(data []byte) (model.MiscModulePackageImportResult, error) {
	m.mu.RLock()
	baseDir := m.baseDir
	m.mu.RUnlock()
	if strings.TrimSpace(baseDir) == "" {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("misc module directory not initialized")
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("open module zip: %w", err)
	}

	pkgManifest, err := readPackageManifest(reader)
	if err != nil {
		return model.MiscModulePackageImportResult{}, err
	}
	if err := validateModuleID(pkgManifest.ID); err != nil {
		return model.MiscModulePackageImportResult{}, err
	}

	moduleDir, err := resolveManagedPath(baseDir, pkgManifest.ID)
	if err != nil {
		return model.MiscModulePackageImportResult{}, err
	}
	if _, statErr := os.Stat(moduleDir); statErr == nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("misc module %s already exists", pkgManifest.ID)
	}
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("create module dir: %w", err)
	}

	if err := extractZipToDir(reader, moduleDir); err != nil {
		_ = os.RemoveAll(moduleDir)
		return model.MiscModulePackageImportResult{}, err
	}

	module, err := loadModuleFromDir(moduleDir)
	if err != nil {
		_ = os.RemoveAll(moduleDir)
		return model.MiscModulePackageImportResult{}, err
	}

	m.mu.Lock()
	m.modules[module.manifest.ID] = module
	m.mu.Unlock()

	return model.MiscModulePackageImportResult{
		Module:        cloneManifest(module.manifest),
		InstalledPath: moduleDir,
		Message:       "模块包导入成功",
	}, nil
}

func (m *Manager) Invoke(ctx context.Context, id string, req model.MiscModuleRunRequest, runtime InvokeContext) (model.MiscModuleRunResult, error) {
	m.mu.RLock()
	module, ok := m.modules[strings.TrimSpace(id)]
	m.mu.RUnlock()
	if !ok {
		return model.MiscModuleRunResult{}, fmt.Errorf("misc module %s not found", id)
	}

	input := map[string]any{
		"values":       normalizeValues(req.Values),
		"capture_path": strings.TrimSpace(runtime.CapturePath),
		"tshark_path":  strings.TrimSpace(runtime.TSharkPath),
		"python_path":  strings.TrimSpace(runtime.PythonPath),
		"host_context": map[string]any{
			"capture_path": strings.TrimSpace(runtime.CapturePath),
			"tshark_path":  strings.TrimSpace(runtime.TSharkPath),
			"python_path":  strings.TrimSpace(runtime.PythonPath),
		},
		"module": map[string]any{
			"id":         module.manifest.ID,
			"title":      module.manifest.Title,
			"api_prefix": module.manifest.APIPrefix,
		},
	}

	var result any
	var err error
	switch strings.ToLower(filepath.Ext(module.backendPath)) {
	case ".js", ".mjs", ".cjs":
		result, err = invokeJavaScript(module.backendPath, input, runtime)
	case ".py":
		if module.api.HostBridge {
			result, err = invokePythonWithHostBridge(ctx, module.backendPath, input, runtime)
		} else {
			result, err = invokePython(ctx, module.backendPath, input, runtime.PythonPath)
		}
	default:
		err = fmt.Errorf("unsupported misc module runtime: %s", module.backendPath)
	}
	if err != nil {
		return model.MiscModuleRunResult{}, err
	}
	return normalizeRunResult(result), nil
}

func loadModuleFromDir(dir string) (loadedModule, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return loadedModule{}, fmt.Errorf("read module manifest: %w", err)
	}

	var pkg model.MiscModulePackageManifest
	if err := json.Unmarshal(rawManifest, &pkg); err != nil {
		return loadedModule{}, fmt.Errorf("parse module manifest: %w", err)
	}
	pkg.ID = strings.TrimSpace(pkg.ID)
	pkg.Title = strings.TrimSpace(pkg.Title)
	pkg.Summary = strings.TrimSpace(pkg.Summary)
	pkg.Backend = defaultIfEmpty(pkg.Backend, "backend.js")
	pkg.Form = defaultIfEmpty(pkg.Form, "form.json")
	pkg.API = defaultIfEmpty(pkg.API, "api.json")
	if err := validateModuleID(pkg.ID); err != nil {
		return loadedModule{}, err
	}
	if pkg.Title == "" {
		return loadedModule{}, fmt.Errorf("misc module title is required")
	}

	apiSchema, err := loadAPISchema(filepath.Join(dir, pkg.API))
	if err != nil {
		return loadedModule{}, err
	}
	formSchema, err := loadFormSchema(filepath.Join(dir, pkg.Form))
	if err != nil {
		return loadedModule{}, err
	}

	entry := defaultIfEmpty(apiSchema.Entry, pkg.Backend)
	backendPath, err := resolveManagedPath(dir, entry)
	if err != nil {
		return loadedModule{}, err
	}
	if _, err := os.Stat(backendPath); err != nil {
		return loadedModule{}, fmt.Errorf("read backend entry: %w", err)
	}

	interfaceSchema := &model.MiscModuleInterfaceSchema{
		Method:     defaultIfEmpty(apiSchema.Method, "POST"),
		InvokePath: fmt.Sprintf("/api/tools/misc/packages/%s/invoke", pkg.ID),
		Runtime:    runtimeFromPath(backendPath),
		Entry:      entry,
		HostBridge: apiSchema.HostBridge,
	}
	manifest := model.MiscModuleManifest{
		ID:              pkg.ID,
		Kind:            "custom",
		Title:           pkg.Title,
		Summary:         pkg.Summary,
		Tags:            append([]string(nil), pkg.Tags...),
		APIPrefix:       fmt.Sprintf("/api/tools/misc/packages/%s", pkg.ID),
		DocsPath:        "docs/misc-module-interface.md",
		RequiresCapture: pkg.RequiresCapture,
		FormSchema:      formSchema,
		InterfaceSchema: interfaceSchema,
	}
	return loadedModule{manifest: manifest, backendPath: backendPath, api: apiSchema}, nil
}

func loadAPISchema(path string) (packageAPI, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return packageAPI{}, fmt.Errorf("read api schema: %w", err)
	}
	var api packageAPI
	if err := json.Unmarshal(raw, &api); err != nil {
		return packageAPI{}, fmt.Errorf("parse api schema: %w", err)
	}
	api.Method = strings.ToUpper(strings.TrimSpace(api.Method))
	api.Entry = strings.TrimSpace(api.Entry)
	return api, nil
}

func loadFormSchema(path string) (*model.MiscModuleFormSchema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read form schema: %w", err)
	}
	var schema model.MiscModuleFormSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("parse form schema: %w", err)
	}
	if len(schema.Fields) == 0 {
		return nil, fmt.Errorf("form schema must contain at least one field")
	}
	if strings.TrimSpace(schema.SubmitLabel) == "" {
		schema.SubmitLabel = "运行模块"
	}
	if strings.TrimSpace(schema.ResultTitle) == "" {
		schema.ResultTitle = "模块结果"
	}
	return &schema, nil
}

func readPackageManifest(reader *zip.Reader) (model.MiscModulePackageManifest, error) {
	root := detectZipRoot(reader)
	for _, file := range reader.File {
		if strings.EqualFold(stripZipRoot(file.Name, root), "manifest.json") {
			rc, err := file.Open()
			if err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("open module manifest: %w", err)
			}
			defer rc.Close()

			raw, err := io.ReadAll(rc)
			if err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("read module manifest: %w", err)
			}
			var manifest model.MiscModulePackageManifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				return model.MiscModulePackageManifest{}, fmt.Errorf("parse module manifest: %w", err)
			}
			manifest.ID = strings.TrimSpace(manifest.ID)
			manifest.Title = strings.TrimSpace(manifest.Title)
			return manifest, nil
		}
	}
	return model.MiscModulePackageManifest{}, fmt.Errorf("manifest.json not found in module zip")
}

func extractZipToDir(reader *zip.Reader, dir string) error {
	root := detectZipRoot(reader)
	for _, file := range reader.File {
		relative := stripZipRoot(file.Name, root)
		if relative == "" {
			continue
		}
		targetPath, err := resolveManagedPath(dir, relative)
		if err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create module subdir: %w", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create module file dir: %w", err)
		}
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("open zipped file: %w", err)
		}
		content, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return fmt.Errorf("read zipped file: %w", readErr)
		}
		if err := os.WriteFile(targetPath, content, 0o644); err != nil {
			return fmt.Errorf("write extracted file: %w", err)
		}
	}
	return nil
}

func invokeJavaScript(path string, input map[string]any, runtime InvokeContext) (any, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vm := goja.New()
	cleaned := moduleExportStripRE.ReplaceAllString(string(source), "")
	if _, err := vm.RunString(cleaned); err != nil {
		return nil, err
	}
	value := vm.Get("onRequest")
	callable, ok := goja.AssertFunction(value)
	if !ok {
		return nil, fmt.Errorf("onRequest not found")
	}
	ctxObj := vm.NewObject()
	_ = ctxObj.Set("moduleDir", filepath.Dir(path))
	_ = ctxObj.Set("capturePath", strings.TrimSpace(runtime.CapturePath))
	_ = ctxObj.Set("tsharkPath", strings.TrimSpace(runtime.TSharkPath))
	_ = ctxObj.Set("readText", func(relPath string) string {
		target, err := resolveManagedPath(filepath.Dir(path), relPath)
		if err != nil {
			return ""
		}
		raw, err := os.ReadFile(target)
		if err != nil {
			return ""
		}
		return string(raw)
	})
	_ = ctxObj.Set("scanFields", func(call goja.FunctionCall) goja.Value {
		if strings.TrimSpace(runtime.CapturePath) == "" {
			panic(vm.NewGoError(fmt.Errorf("当前没有已加载抓包")))
		}
		fields, displayFilter, err := parseScanFieldsArgs(call)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		scanFn := runtime.ScanFields
		if scanFn == nil {
			scanFn = defaultScanFields
		}
		rows, err := scanFn(runtime.CapturePath, fields, displayFilter)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(map[string]any{
			"fields":         fields,
			"display_filter": displayFilter,
			"rows":           rows,
		})
	})
	result, err := callable(goja.Undefined(), vm.ToValue(input), ctxObj)
	if err != nil {
		return nil, err
	}
	return result.Export(), nil
}

func invokePython(ctx context.Context, path string, input map[string]any, pythonPath string) (any, error) {
	bin := strings.TrimSpace(pythonPath)
	if bin == "" {
		bin = "python"
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		_ = json.NewEncoder(stdin).Encode(input)
	}()

	rawOut, _ := io.ReadAll(stdout)
	rawErr, _ := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		if strings.TrimSpace(string(rawErr)) != "" {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(rawErr)))
		}
		return nil, err
	}

	trimmed := strings.TrimSpace(string(rawOut))
	if trimmed == "" {
		return map[string]any{"message": "模块执行完成"}, nil
	}
	var result any
	if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
		return trimmed, nil
	}
	return result, nil
}

func invokePythonWithHostBridge(ctx context.Context, path string, input map[string]any, runtime InvokeContext) (any, error) {
	bin := strings.TrimSpace(runtime.PythonPath)
	if bin == "" {
		bin = "python"
	}

	helperDir, err := os.MkdirTemp("", "gshark-misc-host-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(helperDir)

	helperPath := filepath.Join(helperDir, pythonHostBridgeModuleName+".py")
	if err := os.WriteFile(helperPath, []byte(pythonHostBridgeSource), 0o644); err != nil {
		return nil, err
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	cmd.Env = append(os.Environ(),
		"GSHARK_MISC_INPUT_JSON="+string(inputJSON),
		"PYTHONIOENCODING=utf-8",
		"PYTHONPATH="+joinPythonPath(helperDir, os.Getenv("PYTHONPATH")),
	)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var result any
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var message map[string]any
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			result = line
			continue
		}
		switch strings.TrimSpace(asString(message["type"])) {
		case "host_call":
			response := handlePythonHostCall(message, runtime)
			if _, err := io.WriteString(stdin, response+"\n"); err != nil {
				return nil, err
			}
		case "result":
			result = message["payload"]
		default:
			result = message
		}
	}
	_ = stdin.Close()
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}

	rawErr, _ := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		if strings.TrimSpace(string(rawErr)) != "" {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(rawErr)))
		}
		return nil, err
	}
	if result == nil {
		return map[string]any{"message": "模块执行完成"}, nil
	}
	return result, nil
}

func normalizeRunResult(result any) model.MiscModuleRunResult {
	switch typed := result.(type) {
	case nil:
		return model.MiscModuleRunResult{Message: "模块执行完成"}
	case string:
		return model.MiscModuleRunResult{Message: "模块执行完成", Text: typed}
	case map[string]any:
		out := model.MiscModuleRunResult{
			Message: strings.TrimSpace(asString(typed["message"])),
			Text:    asString(typed["text"]),
			Table:   parseTableResult(typed["table"]),
		}
		if output, ok := typed["output"]; ok {
			out.Output = output
		}
		if out.Message == "" {
			out.Message = "模块执行完成"
		}
		if out.Text == "" && out.Output == nil {
			out.Output = typed
		}
		return out
	default:
		return model.MiscModuleRunResult{
			Message: "模块执行完成",
			Output:  typed,
		}
	}
}

func parseTableResult(value any) *model.MiscModuleTableResult {
	tableMap, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	columnsAny, _ := tableMap["columns"].([]any)
	rowsAny, _ := tableMap["rows"].([]any)
	if len(columnsAny) == 0 {
		return nil
	}
	table := &model.MiscModuleTableResult{
		Columns: make([]model.MiscModuleTableColumn, 0, len(columnsAny)),
		Rows:    make([]map[string]string, 0, len(rowsAny)),
	}
	for _, item := range columnsAny {
		columnMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		key := strings.TrimSpace(asString(columnMap["key"]))
		if key == "" {
			continue
		}
		label := strings.TrimSpace(asString(columnMap["label"]))
		if label == "" {
			label = key
		}
		table.Columns = append(table.Columns, model.MiscModuleTableColumn{Key: key, Label: label})
	}
	for _, item := range rowsAny {
		rowMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		row := make(map[string]string, len(rowMap))
		for key, raw := range rowMap {
			row[key] = fmt.Sprint(raw)
		}
		table.Rows = append(table.Rows, row)
	}
	if len(table.Columns) == 0 {
		return nil
	}
	return table
}

func defaultScanFields(filePath string, fields []string, displayFilter string) ([]map[string]string, error) {
	rows := make([]map[string]string, 0, 64)
	err := tshark.ScanFieldRowsWithDisplayFilter(filePath, fields, displayFilter, func(parts []string) {
		row := make(map[string]string, len(fields))
		for idx, field := range fields {
			if idx < len(parts) {
				row[field] = parts[idx]
			} else {
				row[field] = ""
			}
		}
		rows = append(rows, row)
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func handlePythonHostCall(message map[string]any, runtime InvokeContext) string {
	id := strings.TrimSpace(asString(message["id"]))
	method := strings.TrimSpace(asString(message["method"]))
	params, _ := message["params"].(map[string]any)
	response := map[string]any{
		"type": "host_response",
		"id":   id,
	}
	switch method {
	case "scan_fields":
		if strings.TrimSpace(runtime.CapturePath) == "" {
			response["error"] = "当前没有已加载抓包"
			break
		}
		fields := make([]string, 0)
		if rawFields, ok := params["fields"].([]any); ok {
			for _, item := range rawFields {
				value := strings.TrimSpace(fmt.Sprint(item))
				if value != "" {
					fields = append(fields, value)
				}
			}
		}
		displayFilter := strings.TrimSpace(fmt.Sprint(params["display_filter"]))
		if len(fields) == 0 {
			response["error"] = "scan_fields requires non-empty fields"
			break
		}
		scanFn := runtime.ScanFields
		if scanFn == nil {
			scanFn = defaultScanFields
		}
		rows, err := scanFn(runtime.CapturePath, fields, displayFilter)
		if err != nil {
			response["error"] = err.Error()
			break
		}
		response["payload"] = map[string]any{
			"fields":         fields,
			"display_filter": displayFilter,
			"rows":           rows,
		}
	default:
		response["error"] = "unsupported host bridge method: " + method
	}
	raw, _ := json.Marshal(response)
	return string(raw)
}

func cloneManifest(in model.MiscModuleManifest) model.MiscModuleManifest {
	out := in
	out.Tags = append([]string(nil), in.Tags...)
	if in.FormSchema != nil {
		schema := *in.FormSchema
		schema.Fields = append([]model.MiscModuleFormField(nil), in.FormSchema.Fields...)
		for idx := range schema.Fields {
			schema.Fields[idx].Options = append([]model.MiscModuleFieldOption(nil), schema.Fields[idx].Options...)
		}
		out.FormSchema = &schema
	}
	if in.InterfaceSchema != nil {
		schema := *in.InterfaceSchema
		out.InterfaceSchema = &schema
	}
	return out
}

func runtimeFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	default:
		return "unknown"
	}
}

func joinPythonPath(paths ...string) string {
	items := make([]string, 0, len(paths))
	for _, item := range paths {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return strings.Join(items, string(os.PathListSeparator))
}

func parseScanFieldsArgs(call goja.FunctionCall) ([]string, string, error) {
	if len(call.Arguments) == 0 {
		return nil, "", fmt.Errorf("scanFields requires at least one argument")
	}
	fieldsAny := call.Arguments[0].Export()
	var fields []string
	switch typed := fieldsAny.(type) {
	case []any:
		fields = make([]string, 0, len(typed))
		for _, item := range typed {
			value := strings.TrimSpace(fmt.Sprint(item))
			if value != "" {
				fields = append(fields, value)
			}
		}
	case []string:
		fields = append(fields, typed...)
	default:
		return nil, "", fmt.Errorf("scanFields first argument must be a string array")
	}
	if len(fields) == 0 {
		return nil, "", fmt.Errorf("scanFields fields cannot be empty")
	}
	displayFilter := ""
	if len(call.Arguments) > 1 {
		displayFilter = strings.TrimSpace(fmt.Sprint(call.Arguments[1].Export()))
	}
	return fields, displayFilter, nil
}

func detectZipRoot(reader *zip.Reader) string {
	var first string
	for _, file := range reader.File {
		cleaned := filepath.ToSlash(strings.TrimSpace(file.Name))
		cleaned = strings.TrimPrefix(cleaned, "/")
		if cleaned == "" {
			continue
		}
		parts := strings.Split(cleaned, "/")
		if len(parts) == 1 {
			return ""
		}
		if strings.EqualFold(parts[0], "manifest.json") {
			return ""
		}
		if first == "" {
			first = parts[0]
			continue
		}
		if first != parts[0] {
			return ""
		}
	}
	return first
}

func stripZipRoot(name, root string) string {
	cleaned := filepath.ToSlash(strings.TrimSpace(name))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if root == "" {
		return cleaned
	}
	prefix := root + "/"
	return strings.TrimPrefix(cleaned, prefix)
}

func resolveManagedPath(baseDir, requested string) (string, error) {
	baseDir, err := filepath.Abs(strings.TrimSpace(baseDir))
	if err != nil {
		return "", fmt.Errorf("resolve base dir: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(baseDir, filepath.FromSlash(strings.TrimSpace(requested))))
	if err != nil {
		return "", fmt.Errorf("resolve module path: %w", err)
	}
	rel, err := filepath.Rel(baseDir, target)
	if err != nil {
		return "", fmt.Errorf("resolve relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes managed misc module dir", requested)
	}
	return target, nil
}

func validateModuleID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("misc module id is required")
	}
	if !moduleIDPattern.MatchString(id) {
		return fmt.Errorf("invalid misc module id %q", id)
	}
	return nil
}

func normalizeValues(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[strings.TrimSpace(key)] = value
	}
	return out
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func defaultIfEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
