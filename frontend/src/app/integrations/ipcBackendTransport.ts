import type { EventHandlers } from "./clients/eventClient";
import type { DesktopTransportBinding } from "./desktopTransportBinding";
import { asPacket } from "./mappers/packetStreamMapper";
import { OperationTimeoutError } from "../utils/asyncControl";
import { EventsOn } from "../../../wailsjs/runtime";

type DesktopBackendMethod = "GET" | "POST" | "DELETE";
type DesktopBackendBodyKind = "none" | "json" | "multipart";
type DesktopIpcResponseKind = "json" | "blob" | "text" | "typed-ipc";

export type DesktopIpcErrorCode =
  | "ipc_unavailable"
  | "ipc_timeout"
  | "invalid_request"
  | "generic_ipc_disabled"
  | "typed_binding_required"
  | "backend_proxy_failed"
  | "backend_error"
  | "blob_too_large";

export const DESKTOP_IPC_BLOB_MAX_BYTES = 50 * 1024 * 1024;

interface DesktopBackendRequest {
  method: DesktopBackendMethod;
  path: string;
  body_kind: DesktopBackendBodyKind;
  json_body?: unknown;
  multipart?: DesktopMultipartPart[];
  timeout_ms?: number;
}

interface DesktopMultipartPart {
  name: string;
  filename?: string;
  content_type?: string;
  value?: string;
  data_base64?: string;
}

interface DesktopBackendBlob {
  data_base64: string;
  content_type: string;
  filename?: string;
  size: number;
}

export interface IpcBackendTransport {
  requestJSON<T>(path: string, init?: RequestInit): Promise<T>;
  requestBlob(path: string, init?: RequestInit): Promise<Blob>;
  requestText(path: string, init?: RequestInit): Promise<string>;
  subscribeEvents(handlers: EventHandlers): () => void;
}

export class DesktopIpcRequestError extends Error {
  readonly code: DesktopIpcErrorCode;
  readonly endpoint: string;
  readonly durationMs: number;
  readonly transport = "desktop-ipc";

  constructor(code: DesktopIpcErrorCode, message: string, endpoint: string, durationMs: number) {
    super(message);
    this.name = "DesktopIpcRequestError";
    this.code = code;
    this.endpoint = endpoint;
    this.durationMs = durationMs;
  }
}

export interface DesktopIpcControlsOptions {
  endpoint: string;
  responseKind: DesktopIpcResponseKind;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export function createIpcBackendTransport(desktopApp: DesktopTransportBinding): IpcBackendTransport {
  return {
    async requestJSON<T>(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendJSON) {
        throw new DesktopIpcRequestError("ipc_unavailable", "Wails binding 缺少 InvokeBackendJSON", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      assertGenericIpcAllowed(desktopApp, request, "json", startedAt);
      const payload = await invokeWithLocalControls(
        () => desktopApp.InvokeBackendJSON?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "json",
      );
      return attachIpcMeta(payload as T, path, startedAt, "json", request.timeout_ms);
    },

    async requestBlob(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendBlob) {
        throw new DesktopIpcRequestError("ipc_unavailable", "Wails binding 缺少 InvokeBackendBlob", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      assertGenericIpcAllowed(desktopApp, request, "blob", startedAt);
      const payload = (await invokeWithLocalControls(
        () => desktopApp.InvokeBackendBlob?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "blob",
      )) as DesktopBackendBlob;
      assertDesktopBlobWithinLimit(payload, path, elapsedMs(startedAt));
      return attachIpcMeta(
        base64ToBlob(payload.data_base64, payload.content_type),
        path,
        startedAt,
        "blob",
        request.timeout_ms,
      );
    },

    async requestText(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendText) {
        throw new DesktopIpcRequestError("ipc_unavailable", "Wails binding 缺少 InvokeBackendText", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      assertGenericIpcAllowed(desktopApp, request, "text", startedAt);
      const text = await invokeWithLocalControls(
        () => desktopApp.InvokeBackendText?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "text",
      );
      return String(text ?? "");
    },

    subscribeEvents(handlers: EventHandlers) {
      return subscribeDesktopEvents(handlers);
    },
  };
}

export function createDisabledGenericIpcBackendTransport(): IpcBackendTransport {
  return {
    async requestJSON(path: string, init?: RequestInit): Promise<never> {
      return throwGenericIpcDisabled(path, init);
    },
    async requestBlob(path: string, init?: RequestInit) {
      return throwGenericIpcDisabled(path, init);
    },
    async requestText(path: string, init?: RequestInit) {
      return throwGenericIpcDisabled(path, init);
    },
    subscribeEvents(handlers: EventHandlers) {
      return subscribeDesktopEvents(handlers);
    },
  };
}

function throwGenericIpcDisabled(path: string, init?: RequestInit): never {
  if (init?.signal?.aborted) {
    throw new DOMException("The operation was aborted.", "AbortError");
  }
  throw new DesktopIpcRequestError(
    "generic_ipc_disabled",
    `桌面 generic IPC adapter 已被策略禁用，缺少 typed IPC 覆盖：${path}。如需回滚兼容路径，设置 VITE_DESKTOP_GENERIC_IPC_POLICY=compat。`,
    path,
    0,
  );
}

function assertGenericIpcAllowed(
  desktopApp: DesktopTransportBinding,
  request: DesktopBackendRequest,
  responseKind: DesktopIpcResponseKind,
  startedAt: number,
): void {
  const binding = migratedTypedBindingForRequest(request, responseKind);
  if (!binding || !desktopApp[binding]) {
    return;
  }
  throw new DesktopIpcRequestError(
    "typed_binding_required",
    `桌面 typed IPC 已覆盖 ${String(binding)}，禁止继续通过 generic IPC 代理：${request.path}`,
    request.path,
    elapsedMs(startedAt),
  );
}

function migratedTypedBindingForRequest(
  request: DesktopBackendRequest,
  responseKind: DesktopIpcResponseKind,
): keyof DesktopTransportBinding | undefined {
  const { pathname, searchParams } = parseDesktopRequestPath(request.path);
  const normalizedMethod = request.method;

  if (pathname === "/api/tools/runtime-config") {
    if (normalizedMethod === "GET") {
      return searchParams.get("probe") === "fast" ? "GetToolRuntimeSnapshotFast" : "GetToolRuntimeSnapshotFull";
    }
    if (normalizedMethod === "POST") {
      return searchParams.get("probe") === "fast" ? "UpdateToolRuntimeConfigFast" : "UpdateToolRuntimeConfigFull";
    }
  }
  if (pathname === "/api/mcp/config") return normalizedMethod === "POST" ? "UpdateMCPConfig" : "GetMCPStatus";
  if (pathname === "/api/capture/start") return "StartCapture";
  if (pathname === "/api/capture/stop") return "StopCapture";
  if (pathname === "/api/capture/prepare-replacement") return "PrepareCaptureReplacement";
  if (pathname === "/api/capture/close") return "CloseCapture";
  if (pathname === "/api/capture/status") return "GetCaptureStatus";
  if (pathname === "/api/packets/page") return "ListPacketsPage";
  if (pathname === "/api/packets/locate") return "LocatePacketPage";
  if (pathname === "/api/packet") return "GetPacket";
  if (pathname === "/api/hunting") return "ListThreatHits";
  if (pathname === "/api/hunting/config") {
    return normalizedMethod === "POST" ? "UpdateHuntingRuntimeConfig" : "GetHuntingRuntimeConfig";
  }
  if (pathname === "/api/analysis/vehicle/dbc") {
    if (normalizedMethod === "POST") return "AddVehicleDBC";
    if (normalizedMethod === "DELETE") return "RemoveVehicleDBC";
    return "ListVehicleDBCProfiles";
  }
  if (pathname === "/api/plugins") return "ListPlugins";
  if (pathname === "/api/plugins/source") return normalizedMethod === "POST" ? "SavePluginSource" : "GetPluginSource";
  if (pathname === "/api/plugins/add") return "AddPlugin";
  if (pathname === "/api/plugins/delete") return "DeletePlugin";
  if (pathname === "/api/plugins/toggle") return "TogglePlugin";
  if (pathname === "/api/plugins/bulk") return "SetPluginsEnabled";
  if (pathname === "/api/tools/misc/modules") return "ListMiscModules";
  if (pathname === "/api/tools/misc/import") return "ImportMiscModulePackageFromPath";
  if (normalizedMethod === "DELETE" && /^\/api\/tools\/misc\/packages\/[^/]+$/.test(pathname)) {
    return "DeleteMiscModulePackage";
  }
  if (normalizedMethod === "POST" && /^\/api\/tools\/misc\/packages\/[^/]+\/invoke$/.test(pathname)) {
    return "RunMiscModulePackage";
  }
  if (pathname === "/api/tls") return normalizedMethod === "POST" ? "UpdateTLSConfig" : "GetTLSConfig";

  if (pathname === "/api/streams/http") return "GetHttpStream";
  if (pathname === "/api/streams/raw") return "GetRawStream";
  if (pathname === "/api/streams/raw/page") return "GetRawStreamPage";
  if (pathname === "/api/streams/decode") return "DecodeStreamPayload";
  if (pathname === "/api/streams/inspect") return "InspectStreamPayload";
  if (pathname === "/api/streams/payload-sources") return "ListStreamPayloadSources";
  if (pathname === "/api/streams/index") return "ListStreamIDs";
  if (pathname === "/api/streams/payloads") return "UpdateStreamPayloads";
  if (pathname === "/api/packet/raw") return "GetPacketRawHex";
  if (pathname === "/api/packet/layers") return "GetPacketLayers";

  if (pathname === "/api/objects") return "ListObjects";
  if (pathname === "/api/objects/download") return "DownloadObjectsZip";

  if (pathname === "/api/tools/winrm-decrypt") return "RunWinRMDecrypt";
  if (pathname === "/api/tools/winrm-decrypt/export") {
    return responseKind === "text" ? "GetWinRMDecryptResultText" : "ExportWinRMDecryptResult";
  }
  if (pathname === "/api/tools/smb3-session-candidates") return "ListSMB3SessionCandidates";
  if (pathname === "/api/tools/smb3-random-session-key") return "GenerateSMB3RandomSessionKey";
  if (pathname === "/api/tools/ntlm-sessions") return "ListNTLMSessionMaterials";
  if (pathname === "/api/tools/http-login-analysis") return "GetHTTPLoginAnalysis";
  if (pathname === "/api/tools/smtp-analysis") return "GetSMTPAnalysis";
  if (pathname === "/api/tools/mysql-analysis") return "GetMySQLAnalysis";
  if (pathname === "/api/tools/shiro-rememberme") return "GetShiroRememberMeAnalysis";

  if (pathname === "/api/stats/traffic/global") return "GetGlobalTrafficStats";
  if (pathname === "/api/analysis/industrial") return "GetIndustrialAnalysis";
  if (pathname === "/api/analysis/vehicle") return "GetVehicleAnalysis";
  if (pathname === "/api/analysis/media") return "GetMediaAnalysis";
  if (pathname === "/api/analysis/media/transcribe") return "TranscribeMediaArtifact";
  if (pathname === "/api/analysis/media/transcribe/batch") {
    return normalizedMethod === "POST" ? "StartMediaBatchTranscription" : "GetMediaBatchTranscriptionStatus";
  }
  if (pathname === "/api/analysis/media/transcribe/batch/cancel") return "CancelMediaBatchTranscription";
  if (pathname === "/api/analysis/media/transcribe/batch/export") return "ExportMediaBatchTranscription";
  if (pathname === "/api/analysis/media/export") return "DownloadMediaArtifact";
  if (pathname === "/api/analysis/media/play") return "GetMediaPlaybackBlob";
  if (pathname === "/api/analysis/usb") return "GetUSBAnalysis";
  if (pathname === "/api/c2-analysis") return "GetC2SampleAnalysis";
  if (pathname === "/api/c2-analysis/decrypt") return "DecryptC2Traffic";
  if (pathname === "/api/apt-analysis") return "GetAPTAnalysis";
  if (pathname === "/api/evidence") return searchParams.has("modules") ? "GetEvidenceWithFilter" : "GetEvidence";
  return undefined;
}

function parseDesktopRequestPath(path: string): { pathname: string; searchParams: URLSearchParams } {
  try {
    const parsed = new URL(path, "http://desktop-ipc.local");
    return { pathname: parsed.pathname, searchParams: parsed.searchParams };
  } catch {
    const [pathname, query = ""] = path.split("?", 2);
    return { pathname, searchParams: new URLSearchParams(query) };
  }
}

async function toDesktopBackendRequest(path: string, init?: RequestInit): Promise<DesktopBackendRequest> {
  const method = normalizeMethod(path, init?.method);
  const timeout_ms = requestTimeoutMs(path, method);
  const body = init?.body;
  if (!body) {
    return { method, path, body_kind: "none", timeout_ms };
  }
  if (body instanceof FormData) {
    return {
      method,
      path,
      body_kind: "multipart",
      multipart: await formDataToDesktopParts(body),
      timeout_ms,
    };
  }
  if (typeof body === "string") {
    return {
      method,
      path,
      body_kind: "json",
      json_body: parseJSONBody(body),
      timeout_ms,
    };
  }
  throw new DesktopIpcRequestError(
    "invalid_request",
    `Wails IPC 暂不支持该请求体类型：${Object.prototype.toString.call(body)}`,
    path,
    0,
  );
}

function normalizeMethod(path: string, method: string | undefined): DesktopBackendMethod {
  const normalized = String(method ?? "GET")
    .trim()
    .toUpperCase();
  if (normalized === "GET" || normalized === "POST" || normalized === "DELETE") {
    return normalized;
  }
  throw new DesktopIpcRequestError(
    "invalid_request",
    `Wails IPC 请求方法不受支持：${normalized || "(empty)"} ${path}`,
    path,
    0,
  );
}

function parseJSONBody(body: string): unknown {
  const trimmed = body.trim();
  if (!trimmed) {
    return {};
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}

async function formDataToDesktopParts(form: FormData): Promise<DesktopMultipartPart[]> {
  const parts: DesktopMultipartPart[] = [];
  for (const [name, value] of form.entries()) {
    if (typeof value === "string") {
      parts.push({ name, value });
      continue;
    }
    const blob = value as Blob;
    parts.push({
      name,
      filename: value instanceof File ? value.name : undefined,
      content_type: blob.type || undefined,
      data_base64: arrayBufferToBase64(await blobToArrayBuffer(blob)),
    });
  }
  return parts;
}

async function invokeWithLocalControls<T>(
  operation: () => Promise<T> | undefined,
  path: string,
  signal: AbortSignal | undefined,
  timeoutMs: number | undefined,
  startedAt: number,
  responseKind: DesktopIpcResponseKind,
): Promise<T> {
  return withDesktopIpcControls(
    async () => {
      const result = await operation();
      if (result === undefined) {
        throw new DesktopIpcRequestError(
          "ipc_unavailable",
          `Wails binding 未返回 ${responseKind} 响应`,
          path,
          elapsedMs(startedAt),
        );
      }
      return result;
    },
    { endpoint: path, responseKind, signal, timeoutMs },
    startedAt,
  );
}

export async function withDesktopIpcControls<T>(
  operation: () => Promise<T>,
  options: DesktopIpcControlsOptions,
  startedAt = performanceNow(),
): Promise<T> {
  const { endpoint, responseKind, signal, timeoutMs } = options;
  if (signal?.aborted) {
    throw new DOMException("The operation was aborted.", "AbortError");
  }

  let abortCleanup: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const controls = new Promise<never>((_, reject) => {
    if (signal) {
      const onAbort = () => reject(new DOMException("The operation was aborted.", "AbortError"));
      signal.addEventListener("abort", onAbort, { once: true });
      abortCleanup = () => signal.removeEventListener("abort", onAbort);
    }
    if (timeoutMs && timeoutMs > 0) {
      timer = setTimeout(() => {
        reject(
          new DesktopIpcRequestError(
            "ipc_timeout",
            `Wails IPC ${responseKind} 请求超时：${endpoint}（${timeoutMs}ms）`,
            endpoint,
            elapsedMs(startedAt),
          ),
        );
      }, timeoutMs);
    }
  });

  try {
    return await Promise.race([Promise.resolve().then(() => operation()), controls]);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    if (error instanceof DesktopIpcRequestError) {
      throw error;
    }
    if (error instanceof OperationTimeoutError) {
      throw new DesktopIpcRequestError(
        "ipc_timeout",
        `Wails IPC ${responseKind} 请求超时：${endpoint}（${error.timeoutMs}ms）`,
        endpoint,
        elapsedMs(startedAt),
      );
    }
    const message = desktopIpcFailureMessage(error);
    throw new DesktopIpcRequestError(
      "backend_proxy_failed",
      `Wails IPC 数据面不可用：${endpoint}。${message}`,
      endpoint,
      elapsedMs(startedAt),
    );
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    abortCleanup?.();
  }
}

function desktopIpcFailureMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error.trim();
  }
  if (error && typeof error === "object") {
    const candidate = error as { message?: unknown; error?: unknown };
    const message = String(candidate.message ?? candidate.error ?? "").trim();
    if (message) {
      return message;
    }
  }
  return "Wails IPC 数据面请求失败";
}

function requestTimeoutMs(path: string, method: DesktopBackendMethod): number {
  if (
    path.includes("/download") ||
    path.includes("/export") ||
    path.includes("/play") ||
    path.includes("/transcribe")
  ) {
    return 60000;
  }
  if (
    method === "POST" ||
    path.startsWith("/api/analysis/") ||
    path.startsWith("/api/c2-analysis") ||
    path.startsWith("/api/apt-analysis") ||
    path.startsWith("/api/evidence") ||
    path.startsWith("/api/stats/") ||
    path.startsWith("/api/objects") ||
    path.startsWith("/api/streams")
  ) {
    return 30000;
  }
  return 15000;
}

function subscribeDesktopEvents(handlers: EventHandlers): () => void {
  const cleanups = [
    EventsOn("gshark:backend:packet", (payload) => {
      handlers.packet?.(asPacket(payload));
    }),
    EventsOn("gshark:backend:status", (payload) => {
      handlers.status?.(String((payload as { message?: unknown })?.message ?? payload ?? ""));
    }),
    EventsOn("gshark:backend:error", (payload) => {
      handlers.error?.(String((payload as { message?: unknown })?.message ?? payload ?? ""));
    }),
  ];
  return () => {
    for (const cleanup of cleanups) {
      cleanup();
    }
  };
}

function assertDesktopBlobWithinLimit(payload: DesktopBackendBlob, path: string, durationMs: number): void {
  const declaredSize = Number(payload.size ?? 0);
  if (declaredSize > DESKTOP_IPC_BLOB_MAX_BYTES) {
    throw blobTooLargeError(path, durationMs);
  }
  const dataBase64 = String(payload.data_base64 ?? "");
  const estimatedBytes = estimateBase64DecodedBytes(dataBase64);
  if (estimatedBytes > DESKTOP_IPC_BLOB_MAX_BYTES) {
    throw blobTooLargeError(path, durationMs);
  }
}

function blobTooLargeError(path: string, durationMs: number): DesktopIpcRequestError {
  return new DesktopIpcRequestError(
    "blob_too_large",
    `桌面 IPC blob 响应过大：${path} 超过 50MB，请使用原生导出或缩小选择范围。`,
    path,
    durationMs,
  );
}

function estimateBase64DecodedBytes(dataBase64: string): number {
  const normalized = dataBase64.replace(/\s/g, "");
  if (!normalized) return 0;
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.floor((normalized.length * 3) / 4) - padding;
}

function base64ToBlob(dataBase64: string, contentType: string): Blob {
  const binary = atob(dataBase64 || "");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new Blob([bytes], { type: contentType || "application/octet-stream" });
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function blobToArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
  if (typeof blob.arrayBuffer === "function") {
    return blob.arrayBuffer();
  }
  return new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("read blob failed"));
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.readAsArrayBuffer(blob);
  });
}

function attachIpcMeta<T>(
  payload: T,
  endpoint: string,
  startedAt: number,
  responseKind: DesktopIpcResponseKind,
  timeoutMs: number | undefined,
): T {
  if ((typeof payload !== "object" && typeof payload !== "function") || payload === null) {
    return payload;
  }
  Object.defineProperty(payload, "__backendRequestMeta", {
    configurable: true,
    enumerable: false,
    value: {
      transport: "desktop-ipc",
      endpoint,
      durationMs: elapsedMs(startedAt),
      authState: "desktop-proxy",
      responseKind,
      timeoutMs,
    },
  });
  return payload;
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Math.round(performanceNow() - startedAt));
}

function performanceNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}
