import type { MiscModuleInterfaceSchema, MiscModuleManifest, MiscModuleTableResult } from "../../core/types";
import { optionalNumber, optionalString } from "./mapperPrimitives";

export function asMiscModuleFormSchema(input: any): MiscModuleManifest["formSchema"] {
  if (!input || typeof input !== "object") return undefined;
  return {
    description: optionalString(input.description),
    submitLabel: optionalString(input.submit_label),
    resultTitle: optionalString(input.result_title),
    fields: Array.isArray(input.fields) ? input.fields.map(asMiscModuleField) : [],
  };
}

export function asMiscModuleInterfaceSchema(input: any): MiscModuleInterfaceSchema | undefined {
  if (!input || typeof input !== "object") return undefined;
  return {
    method: optionalString(input.method),
    invokePath: optionalString(input.invoke_path),
    runtime: optionalString(input.runtime),
    entry: optionalString(input.entry),
    hostBridge: Boolean(input.host_bridge),
  };
}

export function asMiscModuleTable(input: any): MiscModuleTableResult | undefined {
  if (!input || typeof input !== "object") return undefined;
  return {
    columns: Array.isArray(input.columns) ? input.columns.map(asMiscModuleColumn) : [],
    rows: Array.isArray(input.rows) ? input.rows.map(asMiscModuleRow) : [],
  };
}

function asMiscModuleField(field: any) {
  return {
    name: String(field.name ?? ""),
    label: String(field.label ?? ""),
    type: String(field.type ?? "text"),
    placeholder: optionalString(field.placeholder),
    defaultValue: optionalString(field.default_value),
    helpText: optionalString(field.help_text),
    required: Boolean(field.required),
    secret: Boolean(field.secret),
    rows: optionalNumber(field.rows),
    options: Array.isArray(field.options) ? field.options.map(asMiscModuleFieldOption) : undefined,
  };
}

function asMiscModuleFieldOption(option: any) {
  return {
    value: String(option.value ?? ""),
    label: String(option.label ?? ""),
  };
}

function asMiscModuleColumn(column: any) {
  return {
    key: String(column.key ?? ""),
    label: String(column.label ?? ""),
  };
}

function asMiscModuleRow(row: any): Record<string, string> {
  const next: Record<string, string> = {};
  for (const [key, value] of Object.entries(row ?? {})) {
    next[String(key)] = String(value ?? "");
  }
  return next;
}
