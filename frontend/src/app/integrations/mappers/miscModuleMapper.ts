import type { MiscModuleImportResult, MiscModuleManifest, MiscModuleRunResult } from "../../core/types";
import { asStringList, optionalString } from "./mapperPrimitives";
import { asMiscModuleFormSchema, asMiscModuleInterfaceSchema, asMiscModuleTable } from "./miscModuleSchemaMapper";

export function asMiscModuleManifest(input: any): MiscModuleManifest {
  return {
    id: String(input.id ?? ""),
    kind: String(input.kind ?? ""),
    title: String(input.title ?? ""),
    summary: String(input.summary ?? ""),
    tags: asStringList(input.tags),
    apiPrefix: String(input.api_prefix ?? ""),
    docsPath: optionalString(input.docs_path),
    requiresCapture: Boolean(input.requires_capture),
    protocolDomain: optionalString(input.protocol_domain),
    supportsExport: Boolean(input.supports_export),
    cancellable: Boolean(input.cancellable),
    dependsOn: Array.isArray(input.depends_on) ? asStringList(input.depends_on) : undefined,
    formSchema: asMiscModuleFormSchema(input.form_schema),
    interfaceSchema: asMiscModuleInterfaceSchema(input.interface_schema),
  };
}

export function asMiscModuleManifests(input: any): MiscModuleManifest[] {
  return Array.isArray(input) ? input.map(asMiscModuleManifest) : [];
}

export function asMiscModuleImportResult(input: any): MiscModuleImportResult {
  return {
    module: asMiscModuleManifest(input.module ?? {}),
    installedPath: String(input.installed_path ?? ""),
    message: String(input.message ?? ""),
  };
}

export function asMiscModuleRunResult(input: any): MiscModuleRunResult {
  return {
    message: String(input.message ?? ""),
    text: optionalString(input.text),
    output: input.output,
    table: asMiscModuleTable(input.table),
  };
}
