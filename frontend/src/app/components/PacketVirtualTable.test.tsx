import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PacketVirtualTable } from "./PacketVirtualTable";
import type { Packet } from "../core/types";

describe("PacketVirtualTable", () => {
  it("renders tshark display protocol in the protocol column", () => {
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
});
