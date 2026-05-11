import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CaptureFileControls, PacketLocatorControls, PacketPagingControls } from "./WorkspaceTopControls";

describe("WorkspaceTopControls", () => {
  it("wires capture path actions", () => {
    const onCapturePathChange = vi.fn();
    const onChooseFile = vi.fn();

    render(
      <CaptureFileControls
        capturePath=""
        onCapturePathChange={onCapturePathChange}
        onChooseFile={onChooseFile}
        onOpenPath={vi.fn()}
        onStop={vi.fn()}
        disabled={false}
        backendConnected
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("输入 PCAP/PCAPNG 绝对路径"), { target: { value: "C:\\a.pcapng" } });
    fireEvent.click(screen.getByRole("button", { name: /选择文件/ }));

    expect(onCapturePathChange).toHaveBeenCalledWith("C:\\a.pcapng");
    expect(onChooseFile).toHaveBeenCalledTimes(1);
  });

  it("normalizes paging input and jumps on Enter", () => {
    const onPageInputChange = vi.fn();
    const onJumpToPage = vi.fn();

    render(
      <PacketPagingControls
        hasPrevPackets
        hasMorePackets
        isPreloadingCapture={false}
        isPageLoading={false}
        totalPackets={100}
        currentPage={2}
        totalPages={5}
        pageInput=""
        pagerItems={[1, 2, 3]}
        onPageInputChange={onPageInputChange}
        onLoadPrev={vi.fn()}
        onLoadMore={vi.fn()}
        onJumpToPage={onJumpToPage}
      />,
    );

    const input = screen.getByPlaceholderText("页");
    fireEvent.change(input, { target: { value: "x4" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onPageInputChange).toHaveBeenCalledWith("4");
    expect(onJumpToPage).toHaveBeenCalledWith(2);
  });

  it("normalizes packet locator input and skips invalid packet ids", () => {
    const onPacketIdInputChange = vi.fn();
    const onLocatePacket = vi.fn();
    const { rerender } = render(
      <PacketLocatorControls
        packetIdInput="0"
        onPacketIdInputChange={onPacketIdInputChange}
        onLocatePacket={onLocatePacket}
        disabled={false}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("分组号"), { target: { value: "pkt42" } });
    fireEvent.click(screen.getByRole("button", { name: "定位" }));
    expect(onPacketIdInputChange).toHaveBeenCalledWith("42");
    expect(onLocatePacket).not.toHaveBeenCalled();

    rerender(
      <PacketLocatorControls
        packetIdInput="42"
        onPacketIdInputChange={onPacketIdInputChange}
        onLocatePacket={onLocatePacket}
        disabled={false}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "定位" }));
    expect(onLocatePacket).toHaveBeenCalledWith(42);
  });
});
