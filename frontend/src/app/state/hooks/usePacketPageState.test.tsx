import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { usePacketPageState } from "./usePacketPageState";

const packet = (id: number): Packet =>
  ({
    id,
    time: "0.000000",
    src: "10.0.0.1",
    dst: "10.0.0.2",
    proto: "TCP",
    length: 54,
    info: `packet ${id}`,
    payload: "",
  }) as Packet;

describe("usePacketPageState", () => {
  it("owns packet page load, navigation, retry, and locate wiring", async () => {
    const activeCapturePathRef = { current: "sample.pcapng" };
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const pages = new Map<number, Packet[]>([
      [0, [packet(1)]],
      [2000, [packet(51)]],
      [100, [packet(101)]],
    ]);
    const listPacketsPage = vi.fn(async (cursor: number, _limit: number) => ({
      items: pages.get(cursor) ?? [packet(cursor + 1)],
      nextCursor: cursor + 50,
      total: 120,
      hasMore: cursor < 100,
    }));
    const locatePacketPage = vi.fn(async () => ({
      packetId: 101,
      cursor: 100,
      total: 120,
      found: true,
    }));
    const setBackendStatus = vi.fn();
    const setDisplayFilter = vi.fn();
    const loadPacket = vi.fn(async (id: number) => packet(id));
    const loadRawHex = vi.fn(async () => "");
    const loadLayers = vi.fn(async () => null);

    const { result } = renderHook(() =>
      usePacketPageState({
        activeCapturePathRef,
        backendConnected: true,
        captureTaskScopeRef,
        displayFilter: "tcp",
        listPacketsPage,
        locatePacketPage,
        loadPacket,
        loadRawHex,
        loadLayers,
        setBackendStatus,
        setDisplayFilter,
      }),
    );

    await act(async () => {
      await result.current.loadPacketPage(0);
      await result.current.loadMorePackets();
      await result.current.locatePacketById(101, "udp");
      await result.current.retryPacketPage();
    });

    expect(result.current.packets).toEqual([packet(101)]);
    expect(result.current.pageStart).toBe(100);
    expect(result.current.totalPackets).toBe(120);
    expect(result.current.hasPrevPackets).toBe(true);
    expect(result.current.hasMorePackets).toBe(false);
    expect(result.current.packetPageError).toBe("");
    expect(listPacketsPage).toHaveBeenCalledWith(0, 2000, "tcp", expect.any(AbortSignal));
    expect(listPacketsPage).toHaveBeenCalledWith(2000, 2000, "tcp", expect.any(AbortSignal));
    expect(locatePacketPage).toHaveBeenCalledWith(101, 2000, "udp", expect.any(AbortSignal));
    expect(listPacketsPage).toHaveBeenCalledWith(100, 2000, "udp", expect.any(AbortSignal));
    expect(setDisplayFilter).toHaveBeenCalledWith("udp");
    expect(result.current.selectedPacketId).toBe(101);
    expect(setBackendStatus).toHaveBeenCalledWith("正在重新读取过滤结果: tcp");
  });
});
