package miscpkg

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dop251/goja"
)

var moduleExportStripRE = regexp.MustCompile(`(?m)^\s*export\s+`)

const (
	javascriptWorkerEnvVar          = "MEOW_TRAFFIC_MISC_JS_WORKER"
	javascriptWorkerProbePathEnvVar = "MEOW_TRAFFIC_MISC_JS_WORKER_PROBE_PATH"
	javascriptWorkerArg             = "--meow-traffic-misc-js-worker"
)

var (
	javascriptWorkerExtraEnv     = []string{}
	javascriptWorkerProcessProbe = func(vm *goja.Runtime) {
		probePath := strings.TrimSpace(os.Getenv(javascriptWorkerProbePathEnvVar))
		if probePath == "" {
			return
		}
		_ = vm.Set("workerPid", os.Getpid())
		_ = vm.Set("backendToken", os.Getenv("MEOW_TRAFFIC_BACKEND_TOKEN"))
		_ = os.WriteFile(probePath, []byte(fmt.Sprint(os.Getpid())), 0o644)
	}
)

func init() {
	if os.Getenv(javascriptWorkerEnvVar) == "1" && len(os.Args) > 1 && os.Args[1] == javascriptWorkerArg {
		os.Exit(runJavaScriptWorkerProcess(os.Stdin, os.Stdout, os.Stderr))
	}
}

func invokeJavaScript(ctx context.Context, path string, input map[string]any, runtime InvokeContext) (any, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve javascript worker executable: %w", err)
	}
	execCtx, cancel := context.WithTimeout(ctx, miscModuleExecutionTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, exe, javascriptWorkerArg)
	cmd.Env = minimalJavaScriptWorkerEnv()
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

	if err := json.NewEncoder(stdin).Encode(javascriptWorkerRequest{
		Path:  path,
		Input: input,
		Runtime: javascriptWorkerRuntime{
			CapturePath: strings.TrimSpace(runtime.CapturePath),
			TSharkPath:  strings.TrimSpace(runtime.TSharkPath),
			Permissions: append([]string(nil), runtime.Permissions...),
		},
	}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}

	stderrDone := readAllAsync(stderr)
	var result any
	var workerErr string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var message map[string]any
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			workerErr = line
			continue
		}
		switch strings.TrimSpace(asString(message["type"])) {
		case "host_call":
			response := handlePythonHostCall(execCtx, message, runtime)
			if _, err := io.WriteString(stdin, response+"\n"); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return nil, err
			}
		case "result":
			result = message["payload"]
		case "error":
			workerErr = strings.TrimSpace(asString(message["error"]))
		default:
			workerErr = line
		}
	}
	_ = stdin.Close()
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}

	rawErr := <-stderrDone
	if err := cmd.Wait(); err != nil {
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("misc module javascript execution timed out")
		}
		if errors.Is(execCtx.Err(), context.Canceled) {
			return nil, fmt.Errorf("misc module javascript execution canceled")
		}
		if workerErr != "" {
			return nil, fmt.Errorf("%s", workerErr)
		}
		if strings.TrimSpace(string(rawErr)) != "" {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(rawErr)))
		}
		return nil, err
	}
	if workerErr != "" {
		return nil, fmt.Errorf("%s", workerErr)
	}
	if result == nil {
		return map[string]any{"message": "模块执行完成"}, nil
	}
	return result, nil
}

func minimalJavaScriptWorkerEnv() []string {
	allowed := map[string]bool{
		"PATH":       true,
		"SYSTEMROOT": true,
		"WINDIR":     true,
		"TEMP":       true,
		"TMP":        true,
	}
	out := []string{javascriptWorkerEnvVar + "=1"}
	for _, e := range os.Environ() {
		if i := strings.IndexByte(e, '='); i > 0 {
			if allowed[strings.ToUpper(e[:i])] {
				out = append(out, e)
			}
		}
	}
	out = append(out, javascriptWorkerExtraEnv...)
	return out
}

type javascriptWorkerRuntime struct {
	CapturePath string   `json:"capture_path"`
	TSharkPath  string   `json:"tshark_path"`
	Permissions []string `json:"permissions"`
}

type javascriptWorkerRequest struct {
	Path    string                  `json:"path"`
	Input   map[string]any          `json:"input"`
	Runtime javascriptWorkerRuntime `json:"runtime"`
}

func runJavaScriptWorkerProcess(in io.Reader, out io.Writer, errOut io.Writer) int {
	reader := bufio.NewReader(in)
	decoder := json.NewDecoder(reader)
	bufferedOut := bufio.NewWriter(out)
	encoder := json.NewEncoder(bufferedOut)
	var req javascriptWorkerRequest
	if err := decoder.Decode(&req); err != nil {
		fmt.Fprintf(errOut, "decode javascript worker request: %v\n", err)
		return 2
	}
	bridge := func(method string, params map[string]any) (any, error) {
		return callJavaScriptHost(encoder, bufferedOut, decoder, method, params)
	}
	result, err := invokeJavaScriptInWorker(context.Background(), req.Path, req.Input, req.Runtime, bridge)
	if err != nil {
		_ = encoder.Encode(map[string]any{"type": "error", "error": javascriptExecutionError(err).Error()})
		_ = bufferedOut.Flush()
		return 1
	}
	if err := encoder.Encode(map[string]any{"type": "result", "payload": result}); err != nil {
		_ = encoder.Encode(map[string]any{"type": "error", "error": "encode javascript worker result: " + err.Error()})
		_ = bufferedOut.Flush()
		return 1
	}
	_ = bufferedOut.Flush()
	return 0
}

func callJavaScriptHost(encoder *json.Encoder, out *bufio.Writer, decoder *json.Decoder, method string, params map[string]any) (any, error) {
	id := nextJavaScriptHostCallID()
	if err := encoder.Encode(map[string]any{
		"type":   "host_call",
		"id":     id,
		"method": method,
		"params": params,
	}); err != nil {
		return nil, err
	}
	if err := out.Flush(); err != nil {
		return nil, err
	}
	var response map[string]any
	if err := decoder.Decode(&response); err != nil {
		return nil, err
	}
	if strings.TrimSpace(asString(response["type"])) != "host_response" {
		return nil, fmt.Errorf("unexpected host bridge response")
	}
	if strings.TrimSpace(asString(response["id"])) != id {
		return nil, fmt.Errorf("host bridge response id mismatch")
	}
	if errText := strings.TrimSpace(asString(response["error"])); errText != "" {
		return nil, fmt.Errorf("%s", errText)
	}
	return response["payload"], nil
}

var javascriptHostCallSeq int

func nextJavaScriptHostCallID() string {
	javascriptHostCallSeq++
	return fmt.Sprintf("%d", javascriptHostCallSeq)
}

func invokeJavaScriptInWorker(ctx context.Context, path string, input map[string]any, runtime javascriptWorkerRuntime, bridge func(method string, params map[string]any) (any, error)) (any, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	vm.SetMaxCallStackSize(10000)
	javascriptWorkerProcessProbe(vm)
	for _, name := range []string{"eval", "Function", "require", "process"} {
		if err := vm.GlobalObject().Set(name, goja.Undefined()); err != nil {
			return nil, err
		}
	}
	if err := vm.Set("globalThis.process", goja.Undefined()); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			vm.Interrupt(ctx.Err())
		case <-done:
		}
	}()

	cleaned := moduleExportStripRE.ReplaceAllString(string(source), "")
	if _, err := vm.RunString(cleaned); err != nil {
		return nil, javascriptExecutionError(err)
	}
	value := vm.Get("onRequest")
	callable, ok := goja.AssertFunction(value)
	if !ok {
		return nil, fmt.Errorf("onRequest not found")
	}
	capturePath := ""
	if hasModulePermission(runtime.Permissions, "capture.read") {
		capturePath = strings.TrimSpace(runtime.CapturePath)
	}
	ctxObj := vm.NewObject()
	_ = ctxObj.Set("moduleDir", filepath.Dir(path))
	_ = ctxObj.Set("capturePath", capturePath)
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
		if !hasModulePermission(runtime.Permissions, "host.scan") {
			panic(vm.NewGoError(fmt.Errorf("misc module missing required permission: host.scan")))
		}
		if strings.TrimSpace(runtime.CapturePath) == "" {
			panic(vm.NewGoError(fmt.Errorf("当前没有已加载抓包")))
		}
		fields, displayFilter, err := parseScanFieldsArgs(call)
		if err != nil {
			panic(vm.NewGoError(err))
		}
		payload, err := bridge("scan_fields", map[string]any{
			"fields":         fields,
			"display_filter": displayFilter,
		})
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(payload)
	})
	result, err := callable(goja.Undefined(), vm.ToValue(input), ctxObj)
	if err != nil {
		return nil, javascriptExecutionError(err)
	}
	return result.Export(), nil
}

func javascriptExecutionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("misc module javascript execution timed out")
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("misc module javascript execution canceled")
	}
	return err
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
