import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../core/types";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { resolveCapturePreloadFirstPage } from "./capturePreloadProbe";

const opened = { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 };
const packet = { id: 1, proto: "TCP" } as Packet;

function createPage(overrides: Partial<PacketsPageResult> = {}): PacketsPageResult {
  return {
    items: [packet],
    nextCursor: 1,
    total: 1,
    hasMore: false,
    ...overrides,
  };
}

function createStatus(overrides: Partial<CaptureStatus> = {}): CaptureStatus {
  return {
    filePath: opened.filePath,
    hasCapture: true,
    packetCount: 1,
    ...overrides,
  };
}

function createOptions(overrides: Partial<Parameters<typeof resolveCapturePreloadFirstPage>[0]> = {}) {
  return {
    opened,
    filter: "",
    captureSeq: 1,
    captureSeqRef: { current: 1 },
    captureTaskScopeRef: { current: createCaptureTaskScope() },
    parseFinishedRef: { current: true },
    parseErrorRef: { current: "" },
    preloadProcessedRef: { current: 0 },
    preloadTotalRef: { current: 0 },
    listPacketsPage: vi.fn(async () => createPage()),
    getCaptureStatus: vi.fn(async () => createStatus()),
    waitForCaptureSignal: vi.fn(async () => undefined),
    setTotalPackets: vi.fn(),
    setPreloadProcessed: vi.fn(),
    timeoutMs: 100,
    now: vi.fn(() => 0),
    ...overrides,
  };
}

describe("capturePreloadProbe diagnostics", () => {
  it("allows first-capture degraded finalize when status fails after parsing completes", async () => {
    const onDiagnostics = vi.fn();
    const options = createOptions({
      hadActiveCapture: false,
      getCaptureStatus: vi.fn(async () => {
        throw new Error("status endpoint unavailable");
      }),
      onDiagnostics,
    });

    await expect(resolveCapturePreloadFirstPage(options)).resolves.toEqual({
      items: [packet],
      total: 1,
      hasMore: false,
    });
    expect(onDiagnostics).toHaveBeenLastCalledWith(
      expect.objectContaining({
        phase: "ready",
        statusConfirmDegraded: true,
        lastStatusError: "status endpoint unavailable",
      }),
    );
  });

  it("does not use degraded status confirmation when switching an active capture", async () => {
    const options = createOptions({
      hadActiveCapture: true,
      getCaptureStatus: vi.fn(async () => {
        throw new Error("status endpoint unavailable");
      }),
    });

    await expect(resolveCapturePreloadFirstPage(options)).rejects.toThrow(
      "确认后端抓包状态失败: status endpoint unavailable",
    );
  });

  it("fails fast with path details when parsing finished but status points at another capture", async () => {
    const options = createOptions({
      getCaptureStatus: vi.fn(async () => createStatus({ filePath: "C:/captures/old.pcapng", packetCount: 9 })),
    });

    await expect(resolveCapturePreloadFirstPage(options)).rejects.toThrow("后端当前抓包与本次打开文件不一致");
  });
});
