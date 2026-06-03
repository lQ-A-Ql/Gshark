package miscpkg

import (
	"context"
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

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

func runScanFields(ctx context.Context, runtime InvokeContext, fields []string, displayFilter string) ([]map[string]string, error) {
	if runtime.ScanFieldsWithContext != nil {
		return runtime.ScanFieldsWithContext(ctx, runtime.CapturePath, fields, displayFilter)
	}
	if runtime.ScanFields != nil {
		return runtime.ScanFields(runtime.CapturePath, fields, displayFilter)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return defaultScanFields(runtime.CapturePath, fields, displayFilter)
}
