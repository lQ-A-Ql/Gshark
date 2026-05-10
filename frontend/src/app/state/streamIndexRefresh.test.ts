import { describe, expect, it, vi } from "vitest";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { refreshStreamIndexState } from "./streamIndexRefresh";

function createOptions(overrides: Partial<Parameters<typeof refreshStreamIndexState>[0]> = {}) {
  return {
    backendConnected: true,
    activeCapturePathRef: { current: "sample.pcapng" },
    captureTaskScopeRef: { current: createCaptureTaskScope() },
    listStreamIds: vi.fn(async (protocol) => {
      if (protocol === "HTTP") return [1];
      if (protocol === "TCP") return [2, 3];
      return [4];
    }),
    setStreamIds: vi.fn(),
    setBackendStatus: vi.fn(),
    ...overrides,
  };
}

describe("streamIndexRefresh", () => {
  it("loads HTTP, TCP, and UDP stream ids for the active capture", async () => {
    const options = createOptions();

    await refreshStreamIndexState(options);

    expect(options.listStreamIds).toHaveBeenCalledTimes(3);
    expect(options.listStreamIds).toHaveBeenCalledWith("HTTP", expect.any(AbortSignal));
    expect(options.listStreamIds).toHaveBeenCalledWith("TCP", expect.any(AbortSignal));
    expect(options.listStreamIds).toHaveBeenCalledWith("UDP", expect.any(AbortSignal));
    expect(options.setStreamIds).toHaveBeenCalledWith({ http: [1], tcp: [2, 3], udp: [4] });
  });

  it("does not start work without backend connection or active capture", async () => {
    const options = createOptions({
      backendConnected: false,
      activeCapturePathRef: { current: "" },
    });

    await refreshStreamIndexState(options);

    expect(options.listStreamIds).not.toHaveBeenCalled();
    expect(options.setStreamIds).not.toHaveBeenCalled();
  });

  it("suppresses stale results when the capture changes during refresh", async () => {
    const options = createOptions({
      listStreamIds: vi.fn(async () => {
        options.activeCapturePathRef.current = "next.pcapng";
        return [9];
      }),
    });

    await refreshStreamIndexState(options);

    expect(options.setStreamIds).not.toHaveBeenCalled();
    expect(options.setBackendStatus).not.toHaveBeenCalled();
  });

  it("keeps aborts quiet", async () => {
    const options = createOptions({
      listStreamIds: vi.fn(async () => {
        options.captureTaskScopeRef.current.invalidate();
        throw new DOMException("aborted", "AbortError");
      }),
    });

    await refreshStreamIndexState(options);

    expect(options.setStreamIds).not.toHaveBeenCalled();
    expect(options.setBackendStatus).not.toHaveBeenCalled();
  });

  it("maps non-abort failures to backend status", async () => {
    const options = createOptions({
      listStreamIds: vi.fn(async () => {
        throw new Error("stream index failed");
      }),
    });

    await refreshStreamIndexState(options);

    expect(options.setStreamIds).not.toHaveBeenCalled();
    expect(options.setBackendStatus).toHaveBeenCalledWith("流索引刷新失败");
  });
});
