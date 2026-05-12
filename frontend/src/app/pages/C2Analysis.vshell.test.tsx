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

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getC2SampleAnalysis: mocks.getC2SampleAnalysis,
      decryptC2Traffic: mocks.decryptC2Traffic,
    },
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

describe("C2Analysis VShell workflow", () => {
  let seed = 0;

  beforeEach(() => {
    seed += 1;
    mocks.sentinelState.backendConnected = true;
    mocks.sentinelState.isPreloadingCapture = false;
    mocks.sentinelState.totalPackets = 256 + seed;
    mocks.sentinelState.captureRevision = seed;
    mocks.sentinelState.fileMeta = {
      path: `C:/captures/c2-${seed}.pcapng`,
      name: `c2-${seed}.pcapng`,
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
      families: [{ label: "VShell", count: 1 }],
      conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "TCP", count: 2 }],
      vshell: {
        ...createAnalysis().vshell,
        candidateCount: 1,
        matchedRuleCount: 1,
        channels: [{ label: "tcp", count: 1 }],
        streamAggregates: [
          {
            streamId: 9,
            protocol: "TCP",
            totalPackets: 6,
            archMarkers: [{ label: "l64", count: 1 }],
            lengthPrefixCount: 3,
            shortPackets: 4,
            longPackets: 1,
            transitions: 2,
            heartbeatAvg: "10.0s",
            heartbeatJitter: "0%",
            intervals: [10, 10, 10],
            hasWebSocket: false,
            listenerHints: [{ label: "vshell-listener-port", count: 1 }],
            packets: [81, 82, 83],
            confidence: 74,
            summary: "VShell stream-level 候选",
          },
        ],
        notes: ["VShell listener 证据已汇总"],
      },
      notes: ["C2 evidence model ready"],
    }));
    mocks.decryptC2Traffic.mockResolvedValue({
      family: "vshell",
      status: "completed",
      totalCandidates: 1,
      decryptedCount: 1,
      failedCount: 0,
      records: [
        {
          packetId: 81,
          streamId: 9,
          direction: "client_to_server",
          algorithm: "vshell-aes-gcm-md5-salt",
          keyStatus: "verified",
          confidence: 90,
          plaintextPreview: "{\"cmd\":\"whoami\"}",
          rawLength: 64,
          decryptedLength: 16,
          tags: ["base64"],
        },
      ],
      notes: ["VShell decrypt note"],
    });
  });

  it("renders C2 evidence model and switches tabs without refetching", async () => {
    render(<C2Analysis />);

    await screen.findByText("C2 样本分析");

    expect(mocks.getC2SampleAnalysis).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /VShell/ }));

    await waitFor(() => {
      expect(screen.getByText("WebSocket 握手")).toBeInTheDocument();
      expect(screen.getAllByText("长度前缀").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("架构标记").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("Listener hints")).toBeInTheDocument();
      expect(screen.getByText("VShell listener 证据已汇总")).toBeInTheDocument();
    });
    expect(mocks.getC2SampleAnalysis).toHaveBeenCalledTimes(1);
  });

  it("falls back to VShell candidate evidence when stream aggregates are empty", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createAnalysis({
      totalMatchedPackets: 1,
      families: [{ label: "VShell", count: 1 }],
      conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "TCP", count: 2 }],
      vshell: {
        ...createAnalysis().vshell,
        candidateCount: 1,
        matchedRuleCount: 1,
        channels: [{ label: "websocket", count: 1 }],
        indicators: [{ label: "websocket-listener", count: 1 }],
        streamAggregates: [],
        candidates: [
          {
            packetId: 81,
            streamId: 9,
            time: "2026-05-02T12:00:00Z",
            family: "vshell",
            channel: "websocket",
            source: "10.0.0.5:51234",
            destination: "10.0.0.8:443",
            indicatorType: "websocket-listener",
            indicatorValue: "ws_ listener / l64",
            confidence: 62,
            summary: "VShell WebSocket 候选，包含 ws_ 参数与 l64 marker",
            evidence: "length prefix and listener port hint",
            tags: ["websocket", "l64", "listener"],
            transportTraits: ["length-prefix"],
            infrastructureHints: ["listener-port"],
            ttpTags: ["heartbeat-like"],
          },
        ],
        notes: ["VShell 候选尚未形成 stream 聚合"],
      },
    }));

    render(<C2Analysis />);

    fireEvent.click(await screen.findByRole("button", { name: /VShell/ }));

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getByText(/摘要卡片会并列融合 stream 聚合与候选弱信号/)).toBeInTheDocument();
    expect(screen.getAllByText("candidates").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("stream 握手 / candidates ws 参数合并计数")).toBeInTheDocument();
    expect(screen.getByText("4 字节长度前缀观察次数，合并 stream 与候选弱信号")).toBeInTheDocument();
    expect(screen.getByText(/最高置信 62% · packet #81 \/ stream 9/)).toBeInTheDocument();
    expect(screen.getByText("VShell WebSocket 候选，包含 ws_ 参数与 l64 marker")).toBeInTheDocument();
    expect(screen.getByText("VShell 候选尚未形成 stream 聚合")).toBeInTheDocument();
  });

  it("merges VShell stream aggregate and candidate evidence in the summary cards", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createAnalysis({
      totalMatchedPackets: 2,
      families: [{ label: "VShell", count: 2 }],
      vshell: {
        ...createAnalysis().vshell,
        candidateCount: 2,
        matchedRuleCount: 2,
        streamAggregates: [
          {
            streamId: 9,
            protocol: "TCP",
            totalPackets: 8,
            archMarkers: [{ label: "l64", count: 1 }],
            lengthPrefixCount: 2,
            shortPackets: 4,
            longPackets: 2,
            transitions: 3,
            heartbeatAvg: "10.0s",
            heartbeatJitter: "4%",
            intervals: [10, 11, 9],
            hasWebSocket: true,
            wsParams: "a=l64&t=ws_",
            listenerHints: [{ label: "vshell-listener-port", count: 1 }],
            packets: [81, 82, 83],
            confidence: 70,
            summary: "stream aggregate with websocket",
          },
        ],
        candidates: [
          {
            packetId: 81,
            streamId: 9,
            family: "vshell",
            channel: "websocket",
            indicatorType: "websocket-listener",
            indicatorValue: "ws_ listener / l64",
            confidence: 66,
            summary: "VShell candidate websocket listener",
            evidence: "length prefix and listener hint",
            tags: ["websocket", "l64", "listener"],
            transportTraits: ["length-prefix", "heartbeat"],
            infrastructureHints: ["listener-port"],
            ttpTags: ["heartbeat-like"],
          },
        ],
      },
    }));

    render(<C2Analysis />);
    fireEvent.click(await screen.findByRole("button", { name: /VShell/ }));

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getByText(/最高置信 66% · packet #81 \/ stream 9/)).toBeInTheDocument();
    expect(screen.getAllByText("stream + candidates").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("VShell candidate websocket listener")).toBeInTheDocument();
  });

  it("explains VShell candidate fallback when stream aggregates exist but contain no signal counts", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createAnalysis({
      totalMatchedPackets: 1,
      families: [{ label: "VShell", count: 1 }],
      vshell: {
        ...createAnalysis().vshell,
        candidateCount: 1,
        matchedRuleCount: 1,
        streamAggregates: [
          {
            streamId: 17,
            protocol: "TCP",
            totalPackets: 2,
            archMarkers: [],
            lengthPrefixCount: 0,
            shortPackets: 2,
            longPackets: 0,
            transitions: 0,
            heartbeatAvg: "",
            heartbeatJitter: "",
            intervals: [],
            hasWebSocket: false,
            listenerHints: [],
            packets: [171, 172],
            confidence: 28,
            summary: "低样本 stream，暂未形成聚合画像",
          },
        ],
        candidates: [
          {
            packetId: 171,
            streamId: 17,
            time: "2026-05-02T12:30:00Z",
            family: "vshell",
            channel: "tcp",
            source: "10.0.0.5:51234",
            destination: "10.0.0.8:443",
            indicatorType: "tcp-listener",
            indicatorValue: "listener port with length prefix",
            confidence: 54,
            summary: "VShell TCP 候选，包含 length prefix listener hint",
            evidence: "length prefix / listener",
            tags: ["listener"],
            transportTraits: ["length-prefix"],
            infrastructureHints: ["listener-port"],
            ttpTags: [],
          },
        ],
      },
    }));

    render(<C2Analysis />);

    fireEvent.click(await screen.findByRole("button", { name: /VShell/ }));

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getAllByText("candidates").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("VShell TCP 候选，包含 length prefix listener hint")).toBeInTheDocument();
  });
});
