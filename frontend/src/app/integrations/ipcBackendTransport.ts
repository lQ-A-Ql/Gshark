import type { EventHandlers } from "./clients/eventClient";
import type { DesktopTransportBinding } from "./desktopTransportBinding";
import { asPacket } from "./mappers/packetStreamMapper";
import { OperationTimeoutError } from "../utils/asyncControl";
import { EventsOn } from "../../../wailsjs/runtime";

type DesktopBackendMethod = "GET" | "POST" | "DELETE";
type DesktopBackendBodyKind = "none" | "json" | "multipart";

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
  readonly endpoint: string;
  readonly durationMs: number;

  constructor(message: string, endpoint: string, durationMs: number) {
    super(message);
    this.name = "DesktopIpcRequestError";
    this.endpoint = endpoint;
    this.durationMs = durationMs;
  }
}

export function createIpcBackendTransport(desktopApp: DesktopTransportBinding): IpcBackendTransport {
  return {
    async requestJSON<T>(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendJSON) {
        throw new DesktopIpcRequestError("Wails binding 缺少 InvokeBackendJSON", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      const payload = await invokeWithLocalControls(
        () => desktopApp.InvokeBackendJSON?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "JSON",
      );
      return attachIpcMeta(payload as T, path, startedAt);
    },

    async requestBlob(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendBlob) {
        throw new DesktopIpcRequestError("Wails binding 缺少 InvokeBackendBlob", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      const payload = (await invokeWithLocalControls(
        () => desktopApp.InvokeBackendBlob?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "Blob",
      )) as DesktopBackendBlob;
      return attachIpcMeta(base64ToBlob(payload.data_base64, payload.content_type), path, startedAt);
    },

    async requestText(path: string, init?: RequestInit) {
      if (!desktopApp.InvokeBackendText) {
        throw new DesktopIpcRequestError("Wails binding 缺少 InvokeBackendText", path, 0);
      }
      const startedAt = performanceNow();
      const request = await toDesktopBackendRequest(path, init);
      const text = await invokeWithLocalControls(
        () => desktopApp.InvokeBackendText?.(request),
        path,
        init?.signal ?? undefined,
        request.timeout_ms,
        startedAt,
        "Text",
      );
      return String(text ?? "");
    },

    subscribeEvents(handlers: EventHandlers) {
      return subscribeDesktopEvents(handlers);
    },
  };
}

async function toDesktopBackendRequest(path: string, init?: RequestInit): Promise<DesktopBackendRequest> {
  const method = normalizeMethod(init?.method);
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
  throw new DesktopIpcRequestError(`Wails IPC 暂不支持该请求体类型：${Object.prototype.toString.call(body)}`, path, 0);
}

function normalizeMethod(method: string | undefined): DesktopBackendMethod {
  const normalized = String(method ?? "GET")
    .trim()
    .toUpperCase();
  if (normalized === "POST" || normalized === "DELETE") {
    return normalized;
  }
  return "GET";
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
  responseKind: string,
): Promise<T> {
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
        reject(new OperationTimeoutError(`Wails IPC ${responseKind} 请求超时：${path}`, timeoutMs));
      }, timeoutMs);
    }
  });

  try {
    const result = await Promise.race([Promise.resolve().then(operation), controls]);
    if (result === undefined) {
      throw new Error(`Wails binding 未返回 ${responseKind} 响应`);
    }
    return result;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    const message = error instanceof Error && error.message.trim() ? error.message : "Wails IPC 数据面请求失败";
    throw new DesktopIpcRequestError(`Wails IPC 数据面不可用：${path}。${message}`, path, elapsedMs(startedAt));
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    abortCleanup?.();
  }
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

function attachIpcMeta<T>(payload: T, endpoint: string, startedAt: number): T {
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
