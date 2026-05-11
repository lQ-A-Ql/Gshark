import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAnalysis } from "./C2Analysis.testFixtures";

const mocks = vi.hoisted(() => ({
  getC2SampleAnalysis: vi.fn(),
  decryptC2Traffic: vi.fn(),
  navigate: vi.fn(),
  clipboardWriteText: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/c2.pcapng",
      name: "c2.pcapng",
      sizeBytes: 4096,
    },
    totalPackets: 256,
    captureRevision: 1,
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
  },
}));

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  backendClients: {
    analysis: {
      getC2SampleAnalysis: mocks.getC2SampleAnalysis,
    },
  },
  bridge: {
    decryptC2Traffic: mocks.decryptC2Traffic,
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import C2Analysis from "./C2Analysis";

describe("C2Analysis candidate interactions", () => {
  let seed = 0;

  beforeEach(() => {
    seed += 1;
    mocks.sentinelState.backendConnected = true;
    mocks.sentinelState.isPreloadingCapture = false;
    mocks.sentinelState.totalPackets = 256 + seed;
    mocks.sentinelState.captureRevision = seed;
    mocks.sentinelState.fileMeta = {
      path: `C:/captures/c2-candidates-${seed}.pcapng`,
      name: `c2-candidates-${seed}.pcapng`,
      sizeBytes: 4096,
    };
    mocks.getC2SampleAnalysis.mockReset();
    mocks.decryptC2Traffic.mockReset();
    mocks.navigate.mockReset();
    mocks.clipboardWriteText.mockReset();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: mocks.clipboardWriteText },
      configurable: true,
    });
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null);
    mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 7 });
    mocks.getC2SampleAnalysis.mockResolvedValue(createAnalysis({
      totalMatchedPackets: 1,
      families: [{ label: "CS", count: 1 }],
      conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "HTTPS", count: 3 }],
      cs: {
        ...createAnalysis().cs,
        candidateCount: 1,
        channels: [{ label: "https", count: 1 }],
        indicators: [{ label: "beacon-like", count: 1 }],
        candidates: [
          {
            packetId: 42,
            streamId: 7,
            time: "2026-04-29T00:20:00Z",
            family: "cs",
            channel: "https",
            source: "10.0.0.5:443",
            destination: "10.0.0.8:51512",
            host: "c2.example.test",
            uri: "/submit.php?id=42",
            method: "GET",
            indicatorType: "beacon",
            indicatorValue: "GET/POST pair",
            confidence: 60,
            summary: "周期性 HTTPS 回连候选",
            evidence: "samples=4 avg=60s jitter=0.05",
            actorHints: ["SilverFox-compatible-field"],
            tags: ["sleep-like"],
            transportTraits: ["https"],
            infrastructureHints: ["https-c2-compatible"],
            ttpTags: ["periodic-callback"],
          },
        ],
        notes: ["CS 静态 profile 仅作为弱信号"],
      },
      notes: ["C2 evidence model ready"],
    }));
  });

  it("copies HTTP display filter from C2 candidate rows", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

    fireEvent.click(screen.getAllByTitle("生成 HTTP 显示过滤器并复制到剪贴板").at(-1)!);

    await waitFor(() => {
      expect(mocks.clipboardWriteText).toHaveBeenCalledWith(
        'http.host == "c2.example.test" && http.request.uri contains "/submit.php?id=42"',
      );
    });
  });

  it("expands candidate context without opening a stream", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

    expect(screen.queryByText("10.0.0.5:443 → 10.0.0.8:51512")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /展开 C2 候选详情 #42/ }));

    await waitFor(() => {
      expect(screen.getByText("10.0.0.5:443 → 10.0.0.8:51512")).toBeInTheDocument();
      expect(screen.getAllByText("c2.example.test").length).toBeGreaterThan(0);
      expect(screen.getAllByText("/submit.php?id=42").length).toBeGreaterThan(0);
      expect(screen.getByText("samples=4 avg=60s jitter=0.05")).toBeInTheDocument();
      expect(screen.getAllByText("https-c2-compatible").length).toBeGreaterThan(0);
      expect(screen.getAllByText("periodic-callback").length).toBeGreaterThan(0);
      expect(screen.getByText("Typed Record Preview")).toBeInTheDocument();
    });
  });

  it("links C2 candidates back to packet and stream evidence", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

    fireEvent.click(screen.getAllByRole("button", { name: /定位到包/ }).at(-1)!);

    await waitFor(() => {
      expect(mocks.sentinelState.locatePacketById).toHaveBeenCalledWith(42);
      expect(mocks.navigate).toHaveBeenCalledWith("/");
    });

    fireEvent.click(screen.getAllByRole("button", { name: /打开关联流/ }).at(-1)!);

    await waitFor(() => {
      expect(mocks.sentinelState.preparePacketStream).toHaveBeenCalledWith(42, "HTTP");
      expect(mocks.navigate).toHaveBeenCalledWith("/http-stream", { state: { streamId: 7 } });
    });
  });
});
