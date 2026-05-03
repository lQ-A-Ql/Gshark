import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PacketVirtualTable } from "./PacketVirtualTable";
import type { Packet } from "../core/types";
import { getPointerFloatingPosition } from "../utils/viewportPosition";

describe("PacketVirtualTable", () => {
  const packet: Packet = {
    id: 1,
    time: "12:00:00.000",
    src: "192.168.1.10",
    srcPort: 50000,
    dst: "10.0.0.5",
    dstPort: 443,
    proto: "TLS",
    displayProtocol: "TLSv1.3",
    length: 128,
    info: "Client Hello",
    payload: "",
    streamId: 7,
  };

  it("renders tshark display protocol in the protocol column", () => {
    render(
      <div style={{ height: 480 }}>
        <PacketVirtualTable
          packets={[packet]}
          selectedPacketId={null}
          onSelect={vi.fn()}
          onDoubleClickHttp={vi.fn()}
          onFollowStream={vi.fn()}
        />
      </div>,
    );

    expect(screen.getByText("TLSv1.3")).toBeInTheDocument();
  });

  it("renders the packet context menu in document.body to avoid transformed ancestors", () => {
    render(
      <div style={{ height: 480, transform: "translateY(10px) scale(0.98)" }}>
        <PacketVirtualTable
          packets={[packet]}
          selectedPacketId={null}
          onSelect={vi.fn()}
          onDoubleClickHttp={vi.fn()}
          onFollowStream={vi.fn()}
        />
      </div>,
    );

    fireEvent.contextMenu(screen.getByText("Client Hello"), { clientX: 120, clientY: 160 });

    const menu = screen.getByRole("menu");
    expect(menu).toBeInTheDocument();
    expect(menu.parentElement).toBe(document.body);
  });

  it("positions the rendered context menu inside the viewport", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 800 });
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 600 });

    render(
      <div style={{ height: 480 }}>
        <PacketVirtualTable
          packets={[packet]}
          selectedPacketId={null}
          onSelect={vi.fn()}
          onDoubleClickHttp={vi.fn()}
          onFollowStream={vi.fn()}
        />
      </div>,
    );

    fireEvent.contextMenu(screen.getByText("Client Hello"), { clientX: 790, clientY: 590 });

    const menu = screen.getByRole("menu");
    expect(menu).toHaveStyle({ left: "596px", top: "470px" });
  });

  it("keeps context menus inside the viewport", () => {
    const floating = { width: 192, height: 118 };
    const viewport = { width: 800, height: 600 };

    expect(getPointerFloatingPosition(120, 160, floating, { viewport })).toEqual({ x: 120, y: 160 });
    expect(getPointerFloatingPosition(790, 590, floating, { viewport })).toEqual({ x: 596, y: 470 });
    expect(getPointerFloatingPosition(-20, -10, floating, { viewport })).toEqual({ x: 12, y: 12 });
  });

  it("keeps context menu coordinates usable in very small viewports", () => {
    expect(
      getPointerFloatingPosition(120, 160, { width: 192, height: 118 }, { viewport: { width: 160, height: 100 } }),
    ).toEqual({ x: 12, y: 12 });
  });
});
