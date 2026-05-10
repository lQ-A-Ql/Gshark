import { createRef } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { WorkspacePanels } from "./WorkspacePanels";

function renderWorkspacePanels(overrides: Partial<Parameters<typeof WorkspacePanels>[0]> = {}) {
  const props: Parameters<typeof WorkspacePanels>[0] = {
    showFilterLoadingBlankState: false,
    filterLoadingTitle: "正在扫描过滤结果",
    filterLoadingDetail: "正在读取首屏匹配结果",
    filterLoadingProgress: 20,
    packetPageError: "",
    captureName: "demo.pcapng",
    displayFilter: "",
    packets: [],
    selectedPacketId: null,
    hasMorePackets: false,
    protocolTree: [],
    selectedTreeNode: "frame",
    selectedPacket: null,
    frameBytes: [],
    selectedByteRange: null,
    selectedByteOffset: null,
    hexPanelRef: createRef<HTMLDivElement>(),
    onSelectPacket: vi.fn(),
    onDoubleClickHttp: vi.fn(),
    onFollowStream: vi.fn(),
    onRetryPacketPage: vi.fn(),
    onLoadMorePackets: vi.fn(),
    onSelectTreeNode: vi.fn(),
    onSelectByte: vi.fn(),
    registerNodeRef: vi.fn(),
    ...overrides,
  };

  render(<WorkspacePanels {...props} />);
  return props;
}

describe("WorkspacePanels", () => {
  it("shows packet page failures instead of an empty packet table", () => {
    renderWorkspacePanels({
      packetPageError: "数据面读取失败: 无法连接后端接口 /api/packets/page",
      displayFilter: "tcp.stream eq 3",
    });

    expect(screen.getByText("数据包读取失败")).toBeInTheDocument();
    expect(screen.getByText("数据面读取失败: 无法连接后端接口 /api/packets/page")).toBeInTheDocument();
    expect(screen.getByText("tcp.stream eq 3")).toBeInTheDocument();
  });

  it("lets the user retry the current packet page", () => {
    const onRetryPacketPage = vi.fn();
    renderWorkspacePanels({
      packetPageError: "数据面读取失败: 127.0.0.1:17891 被非兼容实例占用",
      onRetryPacketPage,
    });

    fireEvent.click(screen.getByRole("button", { name: "重试读取当前页" }));

    expect(onRetryPacketPage).toHaveBeenCalledTimes(1);
  });
});
