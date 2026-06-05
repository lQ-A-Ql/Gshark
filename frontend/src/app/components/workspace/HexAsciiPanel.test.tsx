import { createRef } from "react";
import { render, screen } from "@testing-library/react";
import { PanelGroup } from "react-resizable-panels";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { HexAsciiPanel } from "./HexAsciiPanel";

function makePacket(overrides: Partial<Packet> = {}): Packet {
  return {
    id: 42,
    time: "01:02:03.456",
    src: "10.0.0.1",
    srcPort: 51515,
    dst: "10.0.0.2",
    dstPort: 443,
    proto: "TLS",
    displayProtocol: "TLSv1.3",
    length: 128,
    info: "Client Hello",
    payload: "hello",
    ...overrides,
  };
}

describe("HexAsciiPanel", () => {
  it("renders JA3 and JA3S values when the selected packet includes tls fingerprints", () => {
    render(
      <PanelGroup direction="horizontal">
        <HexAsciiPanel
          packet={makePacket({
            tlsFingerprint: {
              ja3Hash: "72a589da586844d7f0818ce684948eea",
              ja3sHash: "b742b407517bac9536a77a7b0fee28e9",
            },
          })}
          frameBytes={[0x68, 0x69]}
          selectedByteRange={null}
          selectedByteOffset={null}
          panelRef={createRef<HTMLDivElement>()}
          onSelectByte={vi.fn()}
        />
      </PanelGroup>,
    );

    expect(screen.getByText("JA3 / JA3S")).toBeInTheDocument();
    expect(screen.getByText("JA3 Hash")).toBeInTheDocument();
    expect(screen.getByText("72a589da586844d7f0818ce684948eea")).toBeInTheDocument();
    expect(screen.getByText("JA3S Hash")).toBeInTheDocument();
    expect(screen.getByText("b742b407517bac9536a77a7b0fee28e9")).toBeInTheDocument();
  });

  it("shows an honest availability note for TLS packets without fingerprint data", () => {
    render(
      <PanelGroup direction="horizontal">
        <HexAsciiPanel
          packet={makePacket()}
          frameBytes={[0x68, 0x69]}
          selectedByteRange={null}
          selectedByteOffset={null}
          panelRef={createRef<HTMLDivElement>()}
          onSelectByte={vi.fn()}
        />
      </PanelGroup>,
    );

    expect(screen.getByText("当前 TLS / HTTPS 数据包未提供 JA3 或 JA3S 指纹；仅在后端已解析到 `tls_fingerprint` 时显示。")).toBeInTheDocument();
    expect(screen.queryByText("JA3 Hash")).not.toBeInTheDocument();
  });

  it("does not show a fingerprint availability note for non-TLS packets without fingerprint data", () => {
    render(
      <PanelGroup direction="horizontal">
        <HexAsciiPanel
          packet={makePacket({ proto: "TCP", displayProtocol: "TCP", dstPort: 80 })}
          frameBytes={[0x68, 0x69]}
          selectedByteRange={null}
          selectedByteOffset={null}
          panelRef={createRef<HTMLDivElement>()}
          onSelectByte={vi.fn()}
        />
      </PanelGroup>,
    );

    expect(screen.queryByText(/未提供 JA3 或 JA3S 指纹/)).not.toBeInTheDocument();
  });
});
