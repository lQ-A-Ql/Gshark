package miscpkg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const pythonHostBridgeModuleName = "MEOW_TRAFFIC_misc_host"

const pythonHostBridgeSource = `import json
import os
import sys

_INPUT = json.loads(os.environ.get("MEOW_TRAFFIC_MISC_INPUT_JSON", "{}"))
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

func minimalPythonEnv(helperDir, inputJSON string) []string {
	// Keep a small allowlist of environment variables to avoid leaking the
	// host process environment into untrusted MISC Python modules.
	allowed := map[string]bool{
		"PATH": true,
	}
	out := make([]string, 0, len(allowed)+4)
	for _, e := range os.Environ() {
		if i := strings.IndexByte(e, '='); i > 0 {
			if allowed[e[:i]] {
				out = append(out, e)
			}
		}
	}
	if inputJSON != "" {
		out = append(out, "MEOW_TRAFFIC_MISC_INPUT_JSON="+inputJSON)
	}
	out = append(out, "PYTHONIOENCODING=utf-8")
	if helperDir != "" {
		out = append(out, "PYTHONPATH="+helperDir)
	}
	return out
}

func invokePython(ctx context.Context, path string, input map[string]any, pythonPath string) (any, error) {
	bin := strings.TrimSpace(pythonPath)
	if bin == "" {
		bin = "python"
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, path)
	cmd.Env = minimalPythonEnv("", "")
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

	stderrDone := readAllAsync(stderr)
	rawOut, _ := io.ReadAll(stdout)
	rawErr := <-stderrDone
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

	helperDir, err := os.MkdirTemp("", "meow-traffic-misc-host-*")
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
	cmd.Env = minimalPythonEnv(helperDir, string(inputJSON))

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	stderrDone := readAllAsync(stderr)
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
			response := handlePythonHostCall(execCtx, message, runtime)
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

	rawErr := <-stderrDone
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

func readAllAsync(r io.Reader) <-chan []byte {
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- data
	}()
	return done
}

func handlePythonHostCall(ctx context.Context, message map[string]any, runtime InvokeContext) string {
	id := strings.TrimSpace(asString(message["id"]))
	method := strings.TrimSpace(asString(message["method"]))
	params, _ := message["params"].(map[string]any)
	response := map[string]any{
		"type": "host_response",
		"id":   id,
	}
	switch method {
	case "scan_fields":
		if !hasModulePermission(runtime.Permissions, "host.scan") {
			response["error"] = "misc module missing required permission: host.scan"
			break
		}
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
		rows, err := runScanFields(ctx, runtime, fields, displayFilter)
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
