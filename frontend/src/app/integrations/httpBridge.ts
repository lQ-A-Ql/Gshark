import { createBackendBridgeFromTransport } from "./backendBridgeTransport";
import { createEventClient } from "./clients/eventClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { OperationTimeoutError } from "../utils/asyncControl";

const API_BASE = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";
const BACKEND_AUTH_TOKEN_TIMEOUT_MS = 1500;
const DEFAULT_HTTP_REQUEST_TIMEOUT_MS = 15000;
const ANALYSIS_HTTP_REQUEST_TIMEOUT_MS = 30000;
const LONG_HTTP_REQUEST_TIMEOUT_MS = 60000;

export interface HttpBridgeContext {
  getDesktopAppBinding(): DesktopTransportBinding | undefined;
}

export type BackendRequestErrorCode =
  | "auth_failed"
  | "token_unavailable"
  | "token_timeout"
  | "backend_unreachable"
  | "request_timeout"
  | "backend_error"
  | "old_or_incompatible_backend";

export interface BackendRequestMeta {
  transport: "http-fallback";
  endpoint: string;
  durationMs: number;
  authState: string;
  status?: number;
  transportError?: string;
}

export class BackendRequestError extends Error {
  readonly code: BackendRequestErrorCode;
  readonly endpoint: string;
  readonly status?: number;
  readonly durationMs?: number;

  constructor(
    code: BackendRequestErrorCode,
    message: string,
    options: { endpoint: string; status?: number; durationMs?: number } = { endpoint: "" },
  ) {
    super(message);
    this.name = "BackendRequestError";
    this.code = code;
    this.endpoint = options.endpoint;
    this.status = options.status;
    this.durationMs = options.durationMs;
  }
}

export async function requestJSON<T>(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<T> {
  const startedAt = performanceNow();
  const callerHadAuthorization = hasAuthorizationHeader(init?.headers);
  const firstAttempt = await sendJSONRequest(path, init, getDesktopAppBinding, false, startedAt);
  if (firstAttempt.response.status !== 401 || callerHadAuthorization || !canRefreshAuth(getDesktopAppBinding)) {
    return await decodeJSONResponse(firstAttempt, path, startedAt);
  }

  resetBackendAuthTokenCache();
  const retryAttempt = await sendJSONRequest(path, init, getDesktopAppBinding, true, startedAt);
  return await decodeJSONResponse(retryAttempt, path, startedAt);
}

async function sendJSONRequest(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
  forceAuthRefresh: boolean,
  startedAt: number,
): Promise<{ response: Response; authState: string; isDesktopFallback: boolean }> {
  const isDesktopFallback = Boolean(getDesktopAppBinding());
  const auth = await buildAuthorizedHeadersInternal(path, init?.headers, init?.body, getDesktopAppBinding, {
    forceAuthRefresh,
  });

  let response: Response;
  try {
    response = await fetchWithTimeout(
      `${API_BASE}${path}`,
      {
        ...init,
        headers: auth.headers,
      },
      path,
    );
  } catch (error) {
    throw normalizeTransportError(error, path, elapsedMs(startedAt));
  }
  return { response, authState: auth.authState, isDesktopFallback };
}

async function decodeJSONResponse<T>(
  attempt: { response: Response; authState: string; isDesktopFallback: boolean },
  path: string,
  startedAt: number,
): Promise<T> {
  const { response: res, authState } = attempt;
  if (!res.ok) {
    const detail = await readErrorDetail(res);
    const durationMs = elapsedMs(startedAt);
    if (res.status === 401) {
      resetBackendAuthTokenCache();
      throw new BackendRequestError(
        "auth_failed",
        detail && detail !== "unauthorized" ? detail : authFailureMessage(attempt.isDesktopFallback),
        { endpoint: path, status: res.status, durationMs },
      );
    }
    throw new BackendRequestError(
      "backend_error",
      detail || `backend request failed: ${res.status} ${res.statusText}`,
      { endpoint: path, status: res.status, durationMs },
    );
  }
  const payload = (await res.json()) as T;
  return attachRequestMeta(payload, {
    transport: "http-fallback",
    endpoint: path,
    durationMs: elapsedMs(startedAt),
    authState,
    status: res.status,
  });
}

export async function requestBlob(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Blob> {
  const startedAt = performanceNow();
  const callerHadAuthorization = hasAuthorizationHeader(init?.headers);
  const firstAttempt = await sendBlobRequest(path, init, getDesktopAppBinding, false, startedAt);
  if (firstAttempt.response.status === 401 && !callerHadAuthorization && canRefreshAuth(getDesktopAppBinding)) {
    resetBackendAuthTokenCache();
    const retryAttempt = await sendBlobRequest(path, init, getDesktopAppBinding, true, startedAt);
    return await decodeBlobResponse(retryAttempt, path, startedAt);
  }
  return await decodeBlobResponse(firstAttempt, path, startedAt);
}

async function sendBlobRequest(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
  forceAuthRefresh: boolean,
  startedAt: number,
): Promise<{ response: Response; authState: string; isDesktopFallback: boolean }> {
  const isDesktopFallback = Boolean(getDesktopAppBinding());
  const auth = await buildAuthorizedHeadersInternal(path, init?.headers, init?.body, getDesktopAppBinding, {
    forceAuthRefresh,
  });

  let response: Response;
  try {
    response = await fetchWithTimeout(
      `${API_BASE}${path}`,
      {
        ...init,
        headers: auth.headers,
      },
      path,
    );
  } catch (error) {
    throw normalizeTransportError(error, path, elapsedMs(startedAt));
  }
  return { response, authState: auth.authState, isDesktopFallback };
}

async function decodeBlobResponse(
  attempt: { response: Response; authState: string; isDesktopFallback: boolean },
  path: string,
  startedAt: number,
): Promise<Blob> {
  const { response: res } = attempt;
  if (!res.ok) {
    const detail = await readErrorDetail(res);
    const durationMs = elapsedMs(startedAt);
    if (res.status === 401) {
      resetBackendAuthTokenCache();
      throw new BackendRequestError(
        "auth_failed",
        detail && detail !== "unauthorized" ? detail : authFailureMessage(attempt.isDesktopFallback),
        { endpoint: path, status: res.status, durationMs },
      );
    }
    throw new BackendRequestError(
      "backend_error",
      detail || `backend request failed: ${res.status} ${res.statusText}`,
      { endpoint: path, status: res.status, durationMs },
    );
  }
  return await res.blob();
}

export async function requestText(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<string> {
  const blob = await requestBlob(path, init, getDesktopAppBinding);
  return await blob.text();
}

let backendAuthTokenPromise: Promise<string> | null = null;

export function resetBackendAuthTokenCache() {
  backendAuthTokenPromise = null;
}

export async function getBackendAuthToken(
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<string> {
  if (backendAuthTokenPromise) {
    return backendAuthTokenPromise;
  }

  const envToken = String(import.meta.env.VITE_BACKEND_TOKEN ?? "").trim();
  if (envToken) {
    backendAuthTokenPromise = Promise.resolve(envToken);
    return backendAuthTokenPromise;
  }

  const desktopApp = getDesktopAppBinding();
  if (!desktopApp?.GetBackendAuthToken) {
    return "";
  }

  backendAuthTokenPromise = readDesktopAuthToken(desktopApp)
    .then((token) => {
      if (!token) {
        backendAuthTokenPromise = null;
      }
      return token;
    })
    .catch((error) => {
      backendAuthTokenPromise = null;
      throw error;
    });

  return backendAuthTokenPromise;
}

export async function buildAuthorizedHeaders(
  path: string,
  headersInit: HeadersInit | undefined,
  body: BodyInit | null | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Headers> {
  return (await buildAuthorizedHeadersInternal(path, headersInit, body, getDesktopAppBinding)).headers;
}

async function buildAuthorizedHeadersInternal(
  path: string,
  headersInit: HeadersInit | undefined,
  body: BodyInit | null | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
  options: { forceAuthRefresh?: boolean } = {},
): Promise<{ headers: Headers; authState: string }> {
  if (options.forceAuthRefresh) {
    resetBackendAuthTokenCache();
  }
  const headers = new Headers(headersInit ?? {});
  if (!(body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let authState = "not-required";
  if (path !== "/health" && !headers.has("Authorization")) {
    const token = await getBackendAuthToken(getDesktopAppBinding);
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
      authState = "token";
    } else {
      authState = getDesktopAppBinding()?.GetBackendAuthToken ? "token-unavailable" : "none";
    }
  } else if (headers.has("Authorization")) {
    authState = "caller";
  }

  return { headers, authState };
}

export async function getBackendAuthHeaders(
  path: string,
  headersInit: HeadersInit | undefined,
  body: BodyInit | null | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Headers> {
  return buildAuthorizedHeaders(path, headersInit, body, getDesktopAppBinding);
}

export function createHttpBridge(context: HttpBridgeContext): BackendBridge {
  const request = <T>(path: string, init?: RequestInit) => requestJSON<T>(path, init, context.getDesktopAppBinding);
  const blobRequest = (path: string, init?: RequestInit) => requestBlob(path, init, context.getDesktopAppBinding);
  const textRequest = (path: string, init?: RequestInit) => requestText(path, init, context.getDesktopAppBinding);
  const authTokenGetter = () => getBackendAuthToken(context.getDesktopAppBinding);
  const eventClient = createEventClient(API_BASE, authTokenGetter);

  return createBackendBridgeFromTransport({
    requestJSON: request,
    requestBlob: blobRequest,
    requestText: textRequest,
    subscribeEvents: eventClient.subscribeEvents,
    getDesktopAppBinding: context.getDesktopAppBinding,
  });
}

async function readDesktopAuthToken(desktopApp: DesktopTransportBinding): Promise<string> {
  if (!desktopApp.GetBackendAuthToken) {
    return "";
  }
  const token = await promiseWithTimeout(
    Promise.resolve().then(() => desktopApp.GetBackendAuthToken?.()),
    BACKEND_AUTH_TOKEN_TIMEOUT_MS,
    "Wails token 初始化超时",
  );
  const normalized = String(token ?? "").trim();
  if (!normalized) {
    throw new BackendRequestError(
      "token_unavailable",
      "Wails token 尚未就绪：HTTP 数据面暂时无法鉴权，请等待后端完成启动后重试。",
      { endpoint: "/api/auth-token" },
    );
  }
  return normalized;
}

function normalizeTransportError(error: unknown, path: string, durationMs?: number): Error {
  if (isAbortError(error)) {
    return error;
  }
  if (error instanceof BackendRequestError) {
    return error;
  }
  if (error instanceof OperationTimeoutError) {
    const code: BackendRequestErrorCode =
      error.message.includes("token") || error.message.includes("Token") ? "token_timeout" : "request_timeout";
    const message =
      code === "token_timeout"
        ? `Wails token 初始化超时（${error.timeoutMs}ms）：HTTP 数据面暂时无法鉴权。`
        : `后端请求超时（${error.timeoutMs}ms）：${path}。后端可能正在计算或端口被旧实例占用。`;
    return new BackendRequestError(code, message, { endpoint: path, durationMs });
  }
  const fallback = `无法连接后端接口 ${path}，请检查桌面后端是否已启动，或 127.0.0.1:17891 是否被非兼容实例占用。`;
  if (error instanceof Error && error.message.trim()) {
    if (error.message === "Failed to fetch") {
      return new BackendRequestError("backend_unreachable", fallback, { endpoint: path, durationMs });
    }
    return new BackendRequestError("backend_unreachable", `${fallback} 原始错误: ${error.message}`, {
      endpoint: path,
      durationMs,
    });
  }
  return new BackendRequestError("backend_unreachable", fallback, { endpoint: path, durationMs });
}

function authFailureMessage(isDesktopFallback: boolean): string {
  if (isDesktopFallback) {
    return "后端鉴权失败：Wails token 不匹配或旧 binding 未同步，请清理桌面缓存、重新 build:wails 或重启 Wails dev 后重试。";
  }
  return "后端鉴权失败：token 不匹配或缺失，请检查 VITE_BACKEND_TOKEN、GSHARK_BACKEND_TOKEN、请求 Origin 或 127.0.0.1:17891 后端端口。";
}

function isAbortError(error: unknown): error is Error {
  return (
    (error instanceof Error && error.name === "AbortError") ||
    (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError")
  );
}

async function readErrorDetail(res: Response): Promise<string> {
  try {
    const payload = await res.json();
    if (payload && typeof payload.error === "string") {
      return payload.error;
    }
  } catch {
    // ignore invalid json error payload
  }
  return "";
}

async function fetchWithTimeout(url: string, init: RequestInit, path: string): Promise<Response> {
  const timeoutMs = requestTimeoutMs(path, init);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return await fetch(url, init);
  }

  const timeoutError = new OperationTimeoutError(`backend request timed out: ${path}`, timeoutMs);
  if (init.signal?.aborted) {
    throw new DOMException("The operation was aborted.", "AbortError");
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abortCleanup: (() => void) | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort(timeoutError);
      reject(timeoutError);
    }, timeoutMs);
    if (init.signal) {
      const onAbort = () => {
        const abortError = new DOMException("The operation was aborted.", "AbortError");
        controller.abort(abortError);
        reject(abortError);
      };
      init.signal.addEventListener("abort", onAbort, { once: true });
      abortCleanup = () => init.signal?.removeEventListener("abort", onAbort);
    }
  });

  try {
    return await Promise.race([fetch(url, { ...init, signal: controller.signal }), timeoutPromise]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    abortCleanup?.();
  }
}

function requestTimeoutMs(path: string, init: RequestInit): number {
  const method = String(init.method ?? "GET").toUpperCase();
  if (
    path.includes("/download") ||
    path.includes("/export") ||
    path.includes("/play") ||
    path.includes("/transcribe")
  ) {
    return LONG_HTTP_REQUEST_TIMEOUT_MS;
  }
  if (
    path.startsWith("/api/analysis/") ||
    path.startsWith("/api/c2-analysis") ||
    path.startsWith("/api/apt-analysis") ||
    path.startsWith("/api/evidence") ||
    path.startsWith("/api/stats/") ||
    path.startsWith("/api/objects") ||
    path.startsWith("/api/streams") ||
    method === "POST"
  ) {
    return ANALYSIS_HTTP_REQUEST_TIMEOUT_MS;
  }
  return DEFAULT_HTTP_REQUEST_TIMEOUT_MS;
}

function hasAuthorizationHeader(headersInit: HeadersInit | undefined): boolean {
  return new Headers(headersInit ?? {}).has("Authorization");
}

function canRefreshAuth(getDesktopAppBinding: () => DesktopTransportBinding | undefined): boolean {
  if (String(import.meta.env.VITE_BACKEND_TOKEN ?? "").trim()) {
    return true;
  }
  return Boolean(getDesktopAppBinding()?.GetBackendAuthToken);
}

function attachRequestMeta<T>(payload: T, meta: BackendRequestMeta): T {
  if ((typeof payload !== "object" && typeof payload !== "function") || payload === null) {
    return payload;
  }
  Object.defineProperty(payload, "__backendRequestMeta", {
    configurable: true,
    enumerable: false,
    value: meta,
  });
  return payload;
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Math.round(performanceNow() - startedAt));
}

function performanceNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}

function promiseWithTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new OperationTimeoutError(message, timeoutMs)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  });
}
