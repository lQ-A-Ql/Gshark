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
    return await Promise.race([Promise.resolve().then(operation), controls]);
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
