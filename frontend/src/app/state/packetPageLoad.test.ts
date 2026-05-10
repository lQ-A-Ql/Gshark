import { describe, expect, it, vi } from "vitest";
import type { PacketsPageResult } from "../integrations/clients/captureClient";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { loadPacketPageState } from "./packetPageLoad";

function createPage(total = 1): PacketsPageResult {
  return {
    items: [],
    nextCursor: 100,
    total,
    hasMore: false,
  };
}

function createOptions(overrides: Partial<Parameters<typeof loadPacketPageState>[0]> = {}) {
  const options = {
    cursor: 12.8,
    pageSize: 100,
    filter: "tcp",
    activeCapturePathRef: { current: "sample.pcapng" },
    backendConnected: true,
    packetPageSeqRef: { current: 0 },
    captureTaskScopeRef: { current: createCaptureTaskScope() },
    listPacketsPage: vi.fn(async () => createPage()),
    commitPacketPage: vi.fn(),
    setIsPageLoading: vi.fn(),
    setIsFilterLoading: vi.fn(),
    setPacketPageError: vi.fn(),
    setBackendStatus: vi.fn(),
    ...overrides,
  };
  return options;
}

describe("packetPageLoad", () => {
  it("loads and commits the normalized packet page cursor", async () => {
    const options = createOptions({ cursor: 12.8, finishFilterLoading: true });
    const result = await loadPacketPageState(options);

    expect(result).toEqual(createPage());
    expect(options.packetPageSeqRef.current).toBe(1);
    expect(options.listPacketsPage).toHaveBeenCalledWith(12, 100, "tcp", expect.any(AbortSignal));
    expect(options.commitPacketPage).toHaveBeenCalledWith(12, createPage());
    expect(options.setIsPageLoading).toHaveBeenNthCalledWith(1, true);
    expect(options.setIsPageLoading).toHaveBeenLastCalledWith(false);
    expect(options.setIsFilterLoading).toHaveBeenCalledWith(false);
    expect(options.setPacketPageError).not.toHaveBeenCalled();
  });

  it("does not start a backend request without a connected active capture", async () => {
    const options = createOptions({
      backendConnected: false,
      activeCapturePathRef: { current: "" },
    });

    await expect(loadPacketPageState(options)).resolves.toBeNull();

    expect(options.listPacketsPage).not.toHaveBeenCalled();
    expect(options.commitPacketPage).not.toHaveBeenCalled();
    expect(options.setIsPageLoading).not.toHaveBeenCalled();
  });

  it("turns non-abort failures into packet-page and backend status errors", async () => {
    const options = createOptions({
      listPacketsPage: vi.fn(async () => {
        throw new Error("db locked");
      }),
    });

    await expect(loadPacketPageState(options)).resolves.toBeNull();

    expect(options.commitPacketPage).not.toHaveBeenCalled();
    expect(options.setPacketPageError).toHaveBeenCalledWith("数据面读取失败: db locked");
    expect(options.setBackendStatus).toHaveBeenCalledWith("数据面读取失败: db locked");
    expect(options.setIsPageLoading).toHaveBeenLastCalledWith(false);
  });

  it("keeps aborts quiet and leaves loading ownership with the current task", async () => {
    const options = createOptions({
      listPacketsPage: vi.fn(async (_cursor, _limit, _filter, _signal) => {
        options.captureTaskScopeRef.current.invalidate();
        throw new DOMException("aborted", "AbortError");
      }),
    });

    await expect(loadPacketPageState(options)).resolves.toBeNull();

    expect(options.commitPacketPage).not.toHaveBeenCalled();
    expect(options.setPacketPageError).not.toHaveBeenCalled();
    expect(options.setBackendStatus).not.toHaveBeenCalled();
    expect(options.setIsPageLoading).toHaveBeenCalledWith(true);
    expect(options.setIsPageLoading).not.toHaveBeenCalledWith(false);
  });

  it("ignores stale page results when a newer packet request wins", async () => {
    const options = createOptions({
      listPacketsPage: vi.fn(async () => {
        options.packetPageSeqRef.current += 1;
        return createPage(10);
      }),
    });

    await expect(loadPacketPageState(options)).resolves.toBeNull();

    expect(options.commitPacketPage).not.toHaveBeenCalled();
    expect(options.setIsPageLoading).not.toHaveBeenCalledWith(false);
  });
});
