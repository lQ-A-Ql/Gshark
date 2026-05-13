import type { MiscModuleInterfaceSchema, MiscModuleManifest, MiscModuleTableResult } from "../../core/types";
import { asArray, asPlainObject, optionalNumber, optionalString } from "./mapperPrimitives";

export function asMiscModuleFormSchema(input: unknown): MiscModuleManifest["formSchema"] {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  return {
    description: optionalString(payload.description),
    submitLabel: optionalString(payload.submit_label),
    resultTitle: optionalString(payload.result_title),
    fields: asArray(payload.fields).map(asMiscModuleField),
  };
}

export function asMiscModuleInterfaceSchema(input: unknown): MiscModuleInterfaceSchema | undefined {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  return {
    method: optionalString(payload.method),
    invokePath: optionalString(payload.invoke_path),
    runtime: optionalString(payload.runtime),
    entry: optionalString(payload.entry),
    hostBridge: Boolean(payload.host_bridge),
  };
}

export function asMiscModuleTable(input: unknown): MiscModuleTableResult | undefined {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  return {
    columns: asArray(payload.columns).map(asMiscModuleColumn),
    rows: asArray(payload.rows).map(asMiscModuleRow),
  };
}

function asMiscModuleField(field: unknown) {
  const payload = asPlainObject(field) ?? {};
  return {
    name: String(payload.name ?? ""),
    label: String(payload.label ?? ""),
    type: String(payload.type ?? "text"),
    placeholder: optionalString(payload.placeholder),
    defaultValue: optionalString(payload.default_value),
    helpText: optionalString(payload.help_text),
    required: Boolean(payload.required),
    secret: Boolean(payload.secret),
    rows: optionalNumber(payload.rows),
    options: Array.isArray(payload.options) ? payload.options.map(asMiscModuleFieldOption) : undefined,
  };
}

function asMiscModuleFieldOption(option: unknown) {
  const payload = asPlainObject(option) ?? {};
  return {
    value: String(payload.value ?? ""),
    label: String(payload.label ?? ""),
  };
}

function asMiscModuleColumn(column: unknown) {
  const payload = asPlainObject(column) ?? {};
  return {
    key: String(payload.key ?? ""),
    label: String(payload.label ?? ""),
  };
}

function asMiscModuleRow(row: unknown): Record<string, string> {
  const next: Record<string, string> = {};
  for (const [key, value] of Object.entries(asPlainObject(row) ?? {})) {
    next[String(key)] = String(value ?? "");
  }
  return next;
}
