import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { usePacketPageNavigation } from "./usePacketPageNavigation";

describe("usePacketPageNavigation", () => {
  it("binds next, previous, jump, and retry packet navigation to provider state", async () => {
    const loadPacketPage = vi.fn(async () => undefined);
    const { result } = renderHook(() => {
      const pageStartRef = useRef(40);
      const [backendStatus, setBackendStatus] = useState("");
      const navigation = usePacketPageNavigation({
        displayFilter: "tcp.stream eq 2",
        loadPacketPage,
        pageSize: 20,
        pageStartRef,
        setBackendStatus,
        totalPackets: 95,
      });
      return { backendStatus, navigation };
    });

    await act(async () => {
      await result.current.navigation.loadMorePackets();
      await result.current.navigation.loadPrevPackets();
      await result.current.navigation.jumpToPage(99);
      await result.current.navigation.retryPacketPage();
    });

    expect(loadPacketPage).toHaveBeenNthCalledWith(1, 60);
    expect(loadPacketPage).toHaveBeenNthCalledWith(2, 20);
    expect(loadPacketPage).toHaveBeenNthCalledWith(3, 80);
    expect(loadPacketPage).toHaveBeenNthCalledWith(4, 40);
    expect(result.current.backendStatus).toBe("正在重新读取过滤结果: tcp.stream eq 2");
  });
});
