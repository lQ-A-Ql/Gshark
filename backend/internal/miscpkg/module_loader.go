package miscpkg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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
