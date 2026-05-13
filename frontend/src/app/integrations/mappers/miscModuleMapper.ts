import type { MiscModuleImportResult, MiscModuleManifest, MiscModuleRunResult } from "../../core/types";
import { asArray, asPlainObject, asStringList, optionalString } from "./mapperPrimitives";
import { asMiscModuleFormSchema, asMiscModuleInterfaceSchema, asMiscModuleTable } from "./miscModuleSchemaMapper";

export function asMiscModuleManifest(input: unknown): MiscModuleManifest {
  const payload = asPlainObject(input) ?? {};
  return {
    id: String(payload.id ?? ""),
    kind: String(payload.kind ?? ""),
    title: String(payload.title ?? ""),
    summary: String(payload.summary ?? ""),
    tags: asStringList(payload.tags),
    apiPrefix: String(payload.api_prefix ?? ""),
    docsPath: optionalString(payload.docs_path),
    requiresCapture: Boolean(payload.requires_capture),
    protocolDomain: optionalString(payload.protocol_domain),
    supportsExport: Boolean(payload.supports_export),
    cancellable: Boolean(payload.cancellable),
    dependsOn: Array.isArray(payload.depends_on) ? asStringList(payload.depends_on) : undefined,
    formSchema: asMiscModuleFormSchema(payload.form_schema),
    interfaceSchema: asMiscModuleInterfaceSchema(payload.interface_schema),
  };
}

export function asMiscModuleManifests(input: unknown): MiscModuleManifest[] {
  return asArray(input).map(asMiscModuleManifest);
}

export function asMiscModuleImportResult(input: unknown): MiscModuleImportResult {
  const payload = asPlainObject(input) ?? {};
  return {
    module: asMiscModuleManifest(payload.module),
    installedPath: String(payload.installed_path ?? ""),
    message: String(payload.message ?? ""),
  };
}

export function asMiscModuleRunResult(input: unknown): MiscModuleRunResult {
  const payload = asPlainObject(input) ?? {};
  return {
    message: String(payload.message ?? ""),
    text: optionalString(payload.text),
    output: payload.output,
    table: asMiscModuleTable(payload.table),
  };
}
