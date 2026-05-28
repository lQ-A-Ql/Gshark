import type { EventHandlers } from "./clients/eventClient";
import { OperationTimeoutError } from "../utils/asyncControl";

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

export function assertDesktopBlobWithinLimit(payload: { data_base64?: unknown; size?: unknown }, endpoint: string): void {
  const declaredSize = Number(payload.size ?? 0);
  if (declaredSize > DESKTOP_IPC_BLOB_MAX_BYTES) {
    throw blobTooLargeError(endpoint);
  }
  const dataBase64 = String(payload.data_base64 ?? "");
  const estimatedBytes = estimateBase64DecodedBytes(dataBase64);
  if (estimatedBytes > DESKTOP_IPC_BLOB_MAX_BYTES) {
    throw blobTooLargeError(endpoint);
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

function blobTooLargeError(endpoint: string): DesktopIpcRequestError {
  return new DesktopIpcRequestError(
    "blob_too_large",
    `桌面 IPC blob 响应过大：${endpoint} 超过 50MB，请使用原生导出或缩小选择范围。`,
    endpoint,
    0,
  );
}

function estimateBase64DecodedBytes(dataBase64: string): number {
  const normalized = dataBase64.replace(/\s/g, "");
  if (!normalized) return 0;
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.floor((normalized.length * 3) / 4) - padding;
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Math.round(performanceNow() - startedAt));
}

function performanceNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}
