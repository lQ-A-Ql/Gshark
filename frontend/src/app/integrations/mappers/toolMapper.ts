import type {
  MiscModuleImportResult,
  MiscModuleInterfaceSchema,
  MiscModuleManifest,
  MiscModuleRunResult,
  MiscModuleTableResult,
  NTLMSessionMaterial,
  SMB3RandomSessionKeyResult,
  SMB3SessionCandidate,
  WinRMDecryptResult,
} from "../../core/types";
import { asStringList } from "./mapperPrimitives";

export function asWinRMDecryptResult(input: any, fallbackPort = 0): WinRMDecryptResult {
  return {
    resultId: String(input.result_id ?? ""),
    captureName: String(input.capture_name ?? ""),
    port: Number(input.port ?? fallbackPort ?? 0),
    authMode: String(input.auth_mode ?? ""),
    previewText: String(input.preview_text ?? ""),
    previewTruncated: Boolean(input.preview_truncated),
    lineCount: Number(input.line_count ?? 0),
    frameCount: Number(input.frame_count ?? 0),
    errorFrameCount: Number(input.error_frame_count ?? 0),
    extractedFrameCount: Number(input.extracted_frame_count ?? 0),
    exportFilename: String(input.export_filename ?? "winrm-decrypt.txt"),
    message: String(input.message ?? ""),
  };
}

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

export function asSMB3SessionCandidate(input: any): SMB3SessionCandidate {
  return {
    sessionId: String(input.session_id ?? ""),
    username: String(input.username ?? ""),
    domain: String(input.domain ?? ""),
    ntProofStr: String(input.nt_proof_str ?? ""),
    encryptedSessionKey: String(input.encrypted_session_key ?? ""),
    src: String(input.src ?? ""),
    dst: String(input.dst ?? ""),
    frameNumber: String(input.frame_number ?? ""),
    timestamp: String(input.timestamp ?? ""),
    complete: Boolean(input.complete),
    displayLabel: String(input.display_label ?? ""),
  };
}

export function asSMB3SessionCandidates(input: any): SMB3SessionCandidate[] {
  return Array.isArray(input) ? input.map(asSMB3SessionCandidate) : [];
}

export function asSMB3RandomSessionKeyResult(input: any): SMB3RandomSessionKeyResult {
  return {
    randomSessionKey: String(input.random_session_key ?? ""),
    message: String(input.message ?? ""),
  };
}

export function asNTLMSessionMaterial(input: any): NTLMSessionMaterial {
  return {
    protocol: String(input.protocol ?? ""),
    transport: optionalString(input.transport),
    frameNumber: String(input.frame_number ?? ""),
    timestamp: optionalString(input.timestamp),
    src: optionalString(input.src),
    dst: optionalString(input.dst),
    srcPort: optionalString(input.src_port),
    dstPort: optionalString(input.dst_port),
    direction: optionalString(input.direction),
    username: optionalString(input.username),
    domain: optionalString(input.domain),
    userDisplay: optionalString(input.user_display),
    challenge: optionalString(input.challenge),
    ntProofStr: optionalString(input.nt_proof_str),
    encryptedSessionKey: optionalString(input.encrypted_session_key),
    sessionId: optionalString(input.session_id),
    authHeader: optionalString(input.auth_header),
    wwwAuthenticate: optionalString(input.www_authenticate),
    info: optionalString(input.info),
    complete: Boolean(input.complete),
    displayLabel: String(input.display_label ?? ""),
  };
}

export function asNTLMSessionMaterials(input: any): NTLMSessionMaterial[] {
  return Array.isArray(input) ? input.map(asNTLMSessionMaterial) : [];
}

function asMiscModuleFormSchema(input: any): MiscModuleManifest["formSchema"] {
  if (!input || typeof input !== "object") return undefined;
  return {
    description: optionalString(input.description),
    submitLabel: optionalString(input.submit_label),
    resultTitle: optionalString(input.result_title),
    fields: Array.isArray(input.fields)
      ? input.fields.map((field: any) => ({
          name: String(field.name ?? ""),
          label: String(field.label ?? ""),
          type: String(field.type ?? "text"),
          placeholder: optionalString(field.placeholder),
          defaultValue: optionalString(field.default_value),
          helpText: optionalString(field.help_text),
          required: Boolean(field.required),
          secret: Boolean(field.secret),
          rows: optionalNumber(field.rows),
          options: Array.isArray(field.options)
            ? field.options.map((option: any) => ({
                value: String(option.value ?? ""),
                label: String(option.label ?? ""),
              }))
            : undefined,
        }))
      : [],
  };
}

function asMiscModuleInterfaceSchema(input: any): MiscModuleInterfaceSchema | undefined {
  if (!input || typeof input !== "object") return undefined;
  return {
    method: optionalString(input.method),
    invokePath: optionalString(input.invoke_path),
    runtime: optionalString(input.runtime),
    entry: optionalString(input.entry),
    hostBridge: Boolean(input.host_bridge),
  };
}

function asMiscModuleTable(input: any): MiscModuleTableResult | undefined {
  if (!input || typeof input !== "object") return undefined;
  return {
    columns: Array.isArray(input.columns)
      ? input.columns.map((column: any) => ({
          key: String(column.key ?? ""),
          label: String(column.label ?? ""),
        }))
      : [],
    rows: Array.isArray(input.rows)
      ? input.rows.map((row: any) => {
          const next: Record<string, string> = {};
          for (const [key, value] of Object.entries(row ?? {})) {
            next[String(key)] = String(value ?? "");
          }
          return next;
        })
      : [],
  };
}

function optionalString(input: unknown): string | undefined {
  const value = String(input ?? "");
  return value || undefined;
}

function optionalNumber(input: unknown): number | undefined {
  const value = Number(input ?? 0);
  return value || undefined;
}
