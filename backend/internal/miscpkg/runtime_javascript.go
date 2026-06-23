package miscpkg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dop251/goja"
)

var moduleExportStripRE = regexp.MustCompile(`(?m)^\s*export\s+`)

func invokeJavaScript(ctx context.Context, path string, input map[string]any, runtime InvokeContext) (any, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	execCtx, cancel := context.WithTimeout(ctx, miscModuleExecutionTimeout)
	defer cancel()

	vm := goja.New()
	vm.SetMaxCallStackSize(10000)
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
		case <-execCtx.Done():
			vm.Interrupt(execCtx.Err())
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
		rows, err := runScanFields(execCtx, runtime, fields, displayFilter)
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
