import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { C2SampleAnalysis } from "../core/types";

const mocks = vi.hoisted(() => ({
  getC2SampleAnalysis: vi.fn(),
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
  bridge: {
    getC2SampleAnalysis: mocks.getC2SampleAnalysis,
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import C2Analysis, { buildC2SampleAnalysisCacheKey } from "./C2Analysis";

function createAnalysis(overrides: Partial<C2SampleAnalysis> = {}): C2SampleAnalysis {
  const family = {
    candidateCount: 0,
    matchedRuleCount: 0,
    channels: [],
    indicators: [],
    conversations: [],
    beaconPatterns: [],
    hostUriAggregates: [],
    dnsAggregates: [],
    streamAggregates: [],
    candidates: [],
    notes: [],
    relatedActors: [],
    deliveryChains: [],
  };
  return {
    totalMatchedPackets: 0,
    families: [],
    conversations: [],
    cs: { ...family },
    vshell: { ...family },
    notes: [],
    ...overrides,
  };
}

describe("C2Analysis", () => {
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
        hostUriAggregates: [
          {
            host: "c2.example.test",
            uri: "/submit.php?id=42",
            channel: "https",
            total: 4,
            getCount: 2,
            postCount: 2,
            methods: [
              { label: "GET", count: 2 },
              { label: "POST", count: 2 },
            ],
            firstTime: "12:00:00.000000",
            lastTime: "12:03:00.000000",
            avgInterval: "60.0s",
            jitter: "0%",
            streams: [7],
            packets: [42, 43, 44, 45],
            confidence: 76,
            summary: "4 HTTP 候选 · GET=2 · POST=2 · avg=60.0s · jitter=0%",
          },
        ],
        dnsAggregates: [
          {
            qname: "abcdefg.example.com",
            total: 6,
            maxLabelLength: 7,
            queryTypes: [
              { label: "TXT", count: 4 },
              { label: "A", count: 2 },
            ],
            txtCount: 4,
            nullCount: 0,
            cnameCount: 0,
            requestCount: 6,
            responseCount: 0,
            firstTime: "12:00:00.000000",
            lastTime: "12:05:00.000000",
            avgInterval: "60.0s",
            jitter: "10%",
            packets: [51, 52, 53, 54, 55, 56],
            confidence: 66,
            summary: "6 DNS 查询 · TXT=4 · avg=60.0s · jitter=10% · req=6",
          },
        ],
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
      vshell: {
        ...createAnalysis().vshell,
        candidateCount: 1,
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
            hasWebSocket: false,
            listenerHints: [{ label: "vshell-listener-port", count: 1 }],
            packets: [81, 82, 83],
            confidence: 74,
            summary: "VShell stream-level 候选",
          },
        ],
        notes: ["VShell listener 骨架已就绪"],
      },
      notes: ["C2 skeleton ready"],
    }));
  });

  it("renders C2 skeleton and switches tabs without refetching", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("C2 样本分析")).toBeInTheDocument();
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

    expect(mocks.getC2SampleAnalysis).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /VShell/ }));

    await waitFor(() => {
      expect(screen.getByText("WebSocket 握手")).toBeInTheDocument();
      expect(screen.getByText("VShell listener 骨架已就绪")).toBeInTheDocument();
    });
    expect(mocks.getC2SampleAnalysis).toHaveBeenCalledTimes(1);
  });

  it("renders CS Host and URI aggregation profile", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("CS Host / URI 聚合画像")).toBeInTheDocument();
      expect(screen.getByText("4 HTTP 候选 · GET=2 · POST=2 · avg=60.0s · jitter=0%")).toBeInTheDocument();
      expect(screen.getByText("GET 2")).toBeInTheDocument();
      expect(screen.getByText("POST 2")).toBeInTheDocument();
      expect(screen.getAllByText("60.0s").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("GET:2")).toBeInTheDocument();
      expect(screen.getByText("POST:2")).toBeInTheDocument();
      expect(screen.getAllByRole("button", { name: /定位到包/ }).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByRole("button", { name: /打开关联流/ }).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByRole("button", { name: /Host/ }).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByRole("button", { name: /URI/ }).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByRole("button", { name: /过滤器/ }).length).toBeGreaterThanOrEqual(1);
    });
  });

  it("renders CS DNS Beacon aggregation profile", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("CS DNS Beacon 聚合画像")).toBeInTheDocument();
      expect(screen.getByText("abcdefg.example.com")).toBeInTheDocument();
      expect(screen.getByText("6 DNS 查询 · TXT=4 · avg=60.0s · jitter=10% · req=6")).toBeInTheDocument();
      expect(screen.getAllByText((content, element) => element?.textContent === "TXT 4").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((content, element) => element?.textContent === "A 2").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((content, element) => element?.textContent === "req 6").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((content, element) => element?.textContent === "resp 0").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("copies DNS and VShell stream display filters from aggregate rows", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("abcdefg.example.com")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTitle("生成 DNS 显示过滤器并复制到剪贴板"));

    await waitFor(() => {
      expect(mocks.clipboardWriteText).toHaveBeenCalledWith('dns.qry.name contains "abcdefg.example.com" && dns.qry.type == 16');
    });

    fireEvent.click(screen.getByRole("button", { name: /VShell/ }));

    await waitFor(() => {
      expect(screen.getByText("VShell stream-level 候选")).toBeInTheDocument();
      expect(screen.getByText("l64 1")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTitle("生成 TCP Stream 过滤器并复制到剪贴板"));

    await waitFor(() => {
      expect(mocks.clipboardWriteText).toHaveBeenCalledWith("tcp.stream == 9");
    });
  });

  it("expands DNS and VShell aggregate detail panels", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("abcdefg.example.com")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /展开 DNS 聚合详情 abcdefg\.example\.com/ }));

    await waitFor(() => {
      expect(screen.getByText("DNS Aggregate Detail")).toBeInTheDocument();
      expect(screen.getByText("dns-beacon-review")).toBeInTheDocument();
      expect(screen.getByText("Packet 时间序列")).toBeInTheDocument();
      expect(screen.getAllByText("51, 52, 53, 54, 55, 56").length).toBeGreaterThanOrEqual(1);
    });

    fireEvent.click(screen.getByRole("button", { name: /VShell/ }));

    await waitFor(() => {
      expect(screen.getByText("VShell stream-level 候选")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /展开 VShell Stream 聚合详情 9/ }));

    await waitFor(() => {
      expect(screen.getByText("VShell Stream Detail")).toBeInTheDocument();
      expect(screen.getByText("stream-level-review")).toBeInTheDocument();
      expect(screen.getAllByText("81, 82, 83").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("vshell-listener-port:1").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("copies HTTP display filter from C2 candidate rows", async () => {
    render(<C2Analysis />);

    await waitFor(() => {
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

    fireEvent.click(screen.getAllByTitle("生成 HTTP 显示过滤器并复制到剪贴板").at(-1)!);

    await waitFor(() => {
      expect(mocks.clipboardWriteText).toHaveBeenCalledWith('http.host == "c2.example.test" && http.request.uri contains "/submit.php?id=42"');
    });
  });

  it("builds cache key from capture identity", () => {
    expect(buildC2SampleAnalysisCacheKey(3, "C:/captures/demo.pcapng", 99)).toBe("3::C:/captures/demo.pcapng::99");
    expect(buildC2SampleAnalysisCacheKey(3, "", 99)).toBe("");
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
