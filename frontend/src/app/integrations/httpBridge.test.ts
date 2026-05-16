import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildAuthorizedHeaders,
  requestJSON,
  resetBackendAuthTokenCache,
} from "./httpBridge";
import type { DesktopTransportBinding } from "./bridgeTypes";

describe("httpBridge transport helpers", () => {
  beforeEach(() => {
    resetBackendAuthTokenCache();
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    resetBackendAuthTokenCache();
  });

  it("uses desktop auth token for non-health requests and keeps health unauthenticated", async () => {
    const binding: DesktopTransportBinding = {
      GetBackendAuthToken: vi.fn(async () => " desktop-token "),
    };

    const apiHeaders = await buildAuthorizedHeaders(
      "/api/packets/page",
      undefined,
      JSON.stringify({}),
      () => binding,
    );
    const healthHeaders = await buildAuthorizedHeaders("/health", undefined, undefined, () => binding);

    expect(apiHeaders.get("Authorization")).toBe("Bearer desktop-token");
    expect(apiHeaders.get("Content-Type")).toBe("application/json");
    expect(healthHeaders.get("Authorization")).toBeNull();
    expect(binding.GetBackendAuthToken).toHaveBeenCalledTimes(1);
  });

  it("preserves caller authorization and avoids JSON content type for FormData uploads", async () => {
    const form = new FormData();
    form.append("file", new Blob(["pcap"]), "sample.pcapng");

    const headers = await buildAuthorizedHeaders(
      "/api/capture/upload",
      { Authorization: "Bearer caller-token" },
      form,
      () => ({ GetBackendAuthToken: vi.fn(async () => "desktop-token") }),
    );

    expect(headers.get("Authorization")).toBe("Bearer caller-token");
    expect(headers.get("Content-Type")).toBeNull();
  });

  it("returns backend JSON error detail when a request fails with a structured error payload", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "backend requires a matching GSHARK_BACKEND_TOKEN" }), {
        status: 401,
        statusText: "Unauthorized",
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(requestJSON("/api/capture/status", undefined, () => undefined)).rejects.toThrow(
      "backend requires a matching GSHARK_BACKEND_TOKEN",
    );
  });

  it("normalizes bare 401 responses into an actionable token mismatch message", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        statusText: "Unauthorized",
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(requestJSON("/api/tools/runtime-config", undefined, () => undefined)).rejects.toThrow(
      "token 不匹配",
    );
  });

  it("uses Wails-specific guidance for HTTP fallback auth failures", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        statusText: "Unauthorized",
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(
      requestJSON(
        "/api/tools/runtime-config",
        { headers: { Authorization: "Bearer caller-token" } },
        () => ({ GetBackendAuthToken: vi.fn(async () => "desktop-token") }),
      ),
    ).rejects.toThrow("旧 binding");
  });

  it("normalizes browser fetch failures into an actionable backend connectivity message", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValueOnce(new Error("Failed to fetch"));

    await expect(requestJSON("/api/packets/page", undefined, () => undefined)).rejects.toThrow(
      "无法连接后端接口 /api/packets/page",
    );
  });

  it("preserves AbortError identity for caller-side cancellation handling", async () => {
    const fetchMock = vi.mocked(fetch);
    const abortError = new DOMException("The operation was aborted.", "AbortError");
    fetchMock.mockRejectedValueOnce(abortError);

    await expect(requestJSON("/api/packets/page", undefined, () => undefined)).rejects.toBe(abortError);
  });

  it("does not cache an empty desktop token and recovers when the binding later returns one", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const binding: DesktopTransportBinding = {
      GetBackendAuthToken: vi.fn()
        .mockResolvedValueOnce("")
        .mockResolvedValueOnce("late-token"),
    };

    await expect(requestJSON("/api/capture/status", undefined, () => binding)).rejects.toThrow("token 尚未就绪");
    await expect(requestJSON("/api/capture/status", undefined, () => binding)).resolves.toMatchObject({ ok: true });

    expect(binding.GetBackendAuthToken).toHaveBeenCalledTimes(2);
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer late-token");
  });

  it("does not cache rejected desktop token reads", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const binding: DesktopTransportBinding = {
      GetBackendAuthToken: vi.fn()
        .mockRejectedValueOnce(new Error("binding still starting"))
        .mockResolvedValueOnce("ready-token"),
    };

    await expect(requestJSON("/api/runtime/identity", undefined, () => binding)).rejects.toThrow("binding still starting");
    await expect(requestJSON("/api/runtime/identity", undefined, () => binding)).resolves.toMatchObject({ ok: true });

    expect(binding.GetBackendAuthToken).toHaveBeenCalledTimes(2);
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer ready-token");
  });

  it("times out pending desktop token reads instead of leaving page requests loading forever", async () => {
    vi.useFakeTimers();
    const binding: DesktopTransportBinding = {
      GetBackendAuthToken: vi.fn(async () => new Promise<string>(() => undefined)),
    };

    const request = requestJSON("/api/runtime/identity", undefined, () => binding);
    const expectation = expect(request).rejects.toThrow("Wails token 初始化超时");
    await vi.advanceTimersByTimeAsync(1500);

    await expectation;
    vi.useRealTimers();
  });

  it("clears token cache and retries once after a 401", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          statusText: "Unauthorized",
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const binding: DesktopTransportBinding = {
      GetBackendAuthToken: vi.fn()
        .mockResolvedValueOnce("stale-token")
        .mockResolvedValueOnce("fresh-token"),
    };

    await expect(requestJSON("/api/runtime/identity", undefined, () => binding)).resolves.toMatchObject({ status: "ok" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((fetchMock.mock.calls[0]?.[1]?.headers as Headers).get("Authorization")).toBe("Bearer stale-token");
    expect((fetchMock.mock.calls[1]?.[1]?.headers as Headers).get("Authorization")).toBe("Bearer fresh-token");
  });

  it("times out pending backend HTTP requests with an actionable error", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockReturnValueOnce(new Promise<Response>(() => undefined));

    const request = requestJSON("/health", undefined, () => undefined);
    const expectation = expect(request).rejects.toThrow("后端请求超时");
    await vi.advanceTimersByTimeAsync(15000);

    await expectation;
    vi.useRealTimers();
  });
});
