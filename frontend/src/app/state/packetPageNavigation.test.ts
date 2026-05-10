import { describe, expect, it, vi } from "vitest";
import {
  jumpToPacketPage,
  loadNextPacketPage,
  loadPreviousPacketPage,
  retryPacketPageLoad,
} from "./packetPageNavigation";

describe("packetPageNavigation", () => {
  it("loads the next and previous packet pages from the current cursor", async () => {
    const loadPacketPage = vi.fn(async () => undefined);
    const options = { pageStartRef: { current: 40 }, pageSize: 20, loadPacketPage };

    await loadNextPacketPage(options);
    await loadPreviousPacketPage(options);

    expect(loadPacketPage).toHaveBeenNthCalledWith(1, 60);
    expect(loadPacketPage).toHaveBeenNthCalledWith(2, 20);
  });

  it("does not underflow when loading the previous page", async () => {
    const loadPacketPage = vi.fn(async () => undefined);

    await loadPreviousPacketPage({ pageStartRef: { current: 5 }, pageSize: 20, loadPacketPage });

    expect(loadPacketPage).toHaveBeenCalledWith(0);
  });

  it("jumps to a clamped packet page cursor", async () => {
    const loadPacketPage = vi.fn(async () => undefined);

    await jumpToPacketPage({ page: 99, totalPackets: 150, pageSize: 50, loadPacketPage });

    expect(loadPacketPage).toHaveBeenCalledWith(100);
  });

  it("announces retry status with the current filter and reloads the current cursor", async () => {
    const loadPacketPage = vi.fn(async () => undefined);
    const setBackendStatus = vi.fn();

    await retryPacketPageLoad({
      pageStartRef: { current: 120 },
      displayFilter: " tcp.stream eq 7 ",
      loadPacketPage,
      setBackendStatus,
    });

    expect(setBackendStatus).toHaveBeenCalledWith("正在重新读取过滤结果: tcp.stream eq 7");
    expect(loadPacketPage).toHaveBeenCalledWith(120);
  });
});
