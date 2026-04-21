package miscpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestImportZipBytesAndInvokeJavaScriptModule(t *testing.T) {
	manager := NewManager()
	baseDir := filepath.Join(t.TempDir(), "misc")
	if err := manager.LoadFromDir(baseDir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	payload := createModuleZip(t, map[string]string{
		"ioc-demo/manifest.json": `{
  "id": "ioc-demo",
  "title": "IOC Demo",
  "summary": "demo module",
  "tags": ["IOC"],
  "backend": "backend.js",
  "form": "form.json",
  "api": "api.json"
}`,
		"ioc-demo/api.json": `{
  "method": "POST",
  "entry": "backend.js"
}`,
		"ioc-demo/form.json": `{
  "description": "schema module",
  "submit_label": "运行",
  "result_title": "结果",
  "fields": [
    {
      "name": "keyword",
      "label": "Keyword",
      "type": "text",
      "default_value": "flag"
    }
  ]
}`,
		"ioc-demo/backend.js": `export function onRequest(input, ctx) {
  const scan = ctx.scanFields(["frame.number", "http.host"]);
  return {
    message: "ok",
    text: "keyword=" + String(input.values.keyword || "") + ";capture=" + String(input.capture_path || "") + ";host=" + String(scan.rows[0]["http.host"] || "")
  };
}`,
	})

	result, err := manager.ImportZipBytes(payload)
	if err != nil {
		t.Fatalf("ImportZipBytes() error = %v", err)
	}
	if result.Module.ID != "ioc-demo" {
		t.Fatalf("expected imported module id ioc-demo, got %+v", result.Module)
	}
	if result.Module.FormSchema == nil || len(result.Module.FormSchema.Fields) != 1 {
		t.Fatalf("expected form schema in imported module, got %+v", result.Module.FormSchema)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "ioc-demo", "backend.js")); err != nil {
		t.Fatalf("expected extracted backend.js, stat error = %v", err)
	}

	runResult, err := manager.Invoke(context.Background(), "ioc-demo", model.MiscModuleRunRequest{
		Values: map[string]string{"keyword": "mimikatz"},
	}, InvokeContext{
		CapturePath: "C:/captures/demo.pcapng",
		ScanFields: func(filePath string, fields []string, displayFilter string) ([]map[string]string, error) {
			if filePath != "C:/captures/demo.pcapng" {
				t.Fatalf("unexpected capture path %q", filePath)
			}
			if displayFilter != "" {
				t.Fatalf("unexpected display filter %q", displayFilter)
			}
			return []map[string]string{
				{
					"frame.number": "42",
					"http.host":    "example.com",
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if runResult.Text != "keyword=mimikatz;capture=C:/captures/demo.pcapng;host=example.com" {
		t.Fatalf("unexpected invoke result: %+v", runResult)
	}
}

func TestInvokeJavaScriptModuleCanUseScanFieldsHostAPI(t *testing.T) {
	manager := NewManager()
	baseDir := filepath.Join(t.TempDir(), "misc")
	if err := manager.LoadFromDir(baseDir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}
	payload := createModuleZip(t, map[string]string{
		"scan-demo/manifest.json": `{"id":"scan-demo","title":"Scan Demo","summary":"scan demo","backend":"backend.js"}`,
		"scan-demo/api.json":      `{"method":"POST","entry":"backend.js"}`,
		"scan-demo/form.json":     `{"fields":[{"name":"keyword","label":"Keyword","type":"text"}]}`,
		"scan-demo/backend.js": `export function onRequest(input, ctx) {
  const result = ctx.scanFields(["frame.number", "ip.src"], "tcp");
  return { text: result.rows[0]["frame.number"] + "|" + result.rows[0]["ip.src"] + "|" + input.tshark_path };
}`,
	})
	if _, err := manager.ImportZipBytes(payload); err != nil {
		t.Fatalf("ImportZipBytes() error = %v", err)
	}
	result, err := manager.Invoke(context.Background(), "scan-demo", model.MiscModuleRunRequest{}, InvokeContext{
		CapturePath: "demo.pcapng",
		TSharkPath:  "C:/Program Files/Wireshark/tshark.exe",
		ScanFields: func(filePath string, fields []string, displayFilter string) ([]map[string]string, error) {
			if displayFilter != "tcp" {
				t.Fatalf("unexpected display filter %q", displayFilter)
			}
			return []map[string]string{{"frame.number": "7", "ip.src": "10.0.0.5"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if result.Text != "7|10.0.0.5|C:/Program Files/Wireshark/tshark.exe" {
		t.Fatalf("unexpected text result: %+v", result)
	}
}

func TestInvokePythonModuleCanUseHostBridge(t *testing.T) {
	pythonBin, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available in PATH")
	}

	manager := NewManager()
	baseDir := filepath.Join(t.TempDir(), "misc")
	if err := manager.LoadFromDir(baseDir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}
	payload := createModuleZip(t, map[string]string{
		"py-bridge/manifest.json": `{"id":"py-bridge","title":"Python Bridge","summary":"python host bridge","backend":"backend.py"}`,
		"py-bridge/api.json":      `{"method":"POST","entry":"backend.py","host_bridge":true}`,
		"py-bridge/form.json":     `{"fields":[{"name":"message","label":"Message","type":"text"}]}`,
		"py-bridge/backend.py": `from gshark_misc_host import run, scan_fields

def on_request(payload):
    rows = scan_fields(["frame.number", "ip.src"], "tcp").get("rows", [])
    first = rows[0] if rows else {}
    return {
        "message": "ok",
        "text": str(payload.get("values", {}).get("message", "")),
        "table": {
            "columns": [
                {"key": "frame", "label": "Frame"},
                {"key": "src", "label": "Source"}
            ],
            "rows": [
                {
                    "frame": str(first.get("frame.number", "")),
                    "src": str(first.get("ip.src", ""))
                }
            ]
        }
    }

if __name__ == "__main__":
    run(on_request)
`,
	})
	if _, err := manager.ImportZipBytes(payload); err != nil {
		t.Fatalf("ImportZipBytes() error = %v", err)
	}
	result, err := manager.Invoke(context.Background(), "py-bridge", model.MiscModuleRunRequest{
		Values: map[string]string{"message": "hello-python"},
	}, InvokeContext{
		CapturePath: "demo.pcapng",
		PythonPath:  pythonBin,
		ScanFields: func(filePath string, fields []string, displayFilter string) ([]map[string]string, error) {
			if displayFilter != "tcp" {
				t.Fatalf("unexpected display filter %q", displayFilter)
			}
			return []map[string]string{{"frame.number": "99", "ip.src": "192.168.1.9"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if result.Text != "hello-python" {
		t.Fatalf("unexpected text result: %+v", result)
	}
	if result.Table == nil || len(result.Table.Rows) != 1 || result.Table.Rows[0]["src"] != "192.168.1.9" {
		t.Fatalf("unexpected table result: %+v", result.Table)
	}
}

func TestLoadFromDirReadsExistingModuleBundle(t *testing.T) {
	manager := NewManager()
	baseDir := filepath.Join(t.TempDir(), "misc")
	moduleDir := filepath.Join(baseDir, "demo")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	writeFile(t, filepath.Join(moduleDir, "manifest.json"), map[string]any{
		"id":      "demo",
		"title":   "Demo",
		"summary": "loaded from disk",
		"backend": "backend.js",
		"form":    "form.json",
		"api":     "api.json",
	})
	writeFile(t, filepath.Join(moduleDir, "api.json"), map[string]any{
		"method": "POST",
		"entry":  "backend.js",
	})
	writeFile(t, filepath.Join(moduleDir, "form.json"), map[string]any{
		"fields": []map[string]any{
			{
				"name":  "value",
				"label": "Value",
				"type":  "text",
			},
		},
	})
	if err := os.WriteFile(filepath.Join(moduleDir, "backend.js"), []byte(`export function onRequest(){ return "ok"; }`), 0o644); err != nil {
		t.Fatalf("WriteFile(backend.js) error = %v", err)
	}

	if err := manager.LoadFromDir(baseDir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}
	items := manager.List()
	if len(items) != 1 || items[0].ID != "demo" {
		t.Fatalf("expected one loaded module, got %+v", items)
	}
}

func TestDeleteRemovesInstalledModule(t *testing.T) {
	manager := NewManager()
	baseDir := filepath.Join(t.TempDir(), "misc")
	if err := manager.LoadFromDir(baseDir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}
	payload := createModuleZip(t, map[string]string{
		"delete-demo/manifest.json": `{"id":"delete-demo","title":"Delete Demo","summary":"delete","backend":"backend.js"}`,
		"delete-demo/api.json":      `{"method":"POST","entry":"backend.js"}`,
		"delete-demo/form.json":     `{"fields":[{"name":"value","label":"Value","type":"text"}]}`,
		"delete-demo/backend.js":    `export function onRequest(){ return "ok"; }`,
	})
	if _, err := manager.ImportZipBytes(payload); err != nil {
		t.Fatalf("ImportZipBytes() error = %v", err)
	}
	if err := manager.Delete("delete-demo"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "delete-demo")); !os.IsNotExist(err) {
		t.Fatalf("expected deleted module dir to be removed, stat err = %v", err)
	}
	if len(manager.List()) != 0 {
		t.Fatalf("expected manager list to be empty after delete, got %+v", manager.List())
	}
}

func createModuleZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("zip Create(%q) error = %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("zip Write(%q) error = %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip Close() error = %v", err)
	}
	return buffer.Bytes()
}

func writeFile(t *testing.T, path string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
