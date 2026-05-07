import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { C2SampleAnalysis } from "../core/types";

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
  bridge: {
    getC2SampleAnalysis: mocks.getC2SampleAnalysis,
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

import { buildC2SampleAnalysisCacheKey } from "../features/c2/useC2Analysis";
import C2Analysis from "./C2Analysis";

function findAncestorWithClass(node: Element, className: string) {
  let current: Element | null = node;
  while (current) {
    if (current.classList.contains(className)) return current;
    current = current.parentElement;
  }
  return null;
}

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
            intervals: [60, 60, 60],
            streams: [7],
            packets: [42, 43, 44, 45],
            confidence: 76,
            signalTags: ["stable-interval", "get-post-tasking-shape", "non-browser-context"],
            scoreFactors: [
              { name: "stable-interval", weight: 10, direction: "positive", summary: "稳定时间间隔表明周期性通信" },
              { name: "get-post-tasking-shape", weight: 8, direction: "positive", summary: "GET/POST 组合符合任务下发与结果回传模式" },
              { name: "non-browser-context", weight: 3, direction: "positive", summary: "非浏览器上下文" },
            ],
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
            intervals: [60, 60, 60, 60, 60],
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

    await waitFor(() => {
      expect(screen.getByText("C2 样本分析")).toBeInTheDocument();
      expect(screen.getByText("周期性 HTTPS 回连候选")).toBeInTheDocument();
    });

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
      expect(screen.getByText("Scoring Factors")).toBeInTheDocument();
      expect(screen.getAllByText("Interval Sparkline").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("stable-interval").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("get-post-tasking-shape").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("non-browser-context").length).toBeGreaterThanOrEqual(1);
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
      expect(screen.getAllByText((_content, element) => element?.textContent === "TXT 4").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((_content, element) => element?.textContent === "A 2").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((_content, element) => element?.textContent === "req 6").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText((_content, element) => element?.textContent === "resp 0").length).toBeGreaterThanOrEqual(1);
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
      expect(screen.getAllByText("Interval Sparkline").length).toBeGreaterThanOrEqual(1);
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

  it("submits VShell decrypt request with vkey and salt", async () => {
    render(<C2Analysis />);

    fireEvent.click(await screen.findByRole("button", { name: /VShell/ }));
    const modeSelect = screen.getByRole("combobox", { name: "模式" });
    expect(modeSelect).toHaveTextContent("auto：三 KDF + GCM/CBC 自动尝试");
    expect(modeSelect).toHaveClass("rounded-xl", "border-slate-200", "shadow-sm");
    fireEvent.change(screen.getByLabelText(/vkey/), { target: { value: "verify-me" } });
    fireEvent.change(screen.getByLabelText(/salt/), { target: { value: "qwe123qwe" } });
    fireEvent.click(screen.getByRole("button", { name: /批量解密候选流量/ }));

    await waitFor(() => {
      expect(mocks.decryptC2Traffic).toHaveBeenCalledWith(expect.objectContaining({
        family: "vshell",
        vshell: expect.objectContaining({ vkey: "verify-me", salt: "qwe123qwe", mode: "auto" }),
      }));
      expect(screen.getByText(/解密结果 · completed/)).toBeInTheDocument();
      const preview = screen.getByText("{\"cmd\":\"whoami\"}");
      expect(preview).toBeInTheDocument();
      expect(preview.tagName.toLowerCase()).toBe("pre");
      expect(preview).toHaveClass("max-h-72", "overflow-x-auto", "overflow-y-auto", "whitespace-pre-wrap", "break-words");
      expect(preview).not.toHaveClass("max-h-32", "overflow-auto");
      const boundedTable = findAncestorWithClass(preview, "max-h-[520px]");
      expect(boundedTable).not.toBeNull();
      expect(boundedTable).toHaveClass("overflow-auto");
      expect(screen.getByText("raw:64B")).toBeInTheDocument();
      expect(screen.getByText("dec:16B")).toBeInTheDocument();
    });
  });

  it("keeps late VShell plaintext visible by default and discoverable with search", async () => {
    const targetPlaintext = "hacked_by_fallsnow&paperplane(QAQ)";
    mocks.decryptC2Traffic.mockResolvedValueOnce({
      family: "vshell",
      status: "completed",
      totalCandidates: 90,
      decryptedCount: 90,
      failedCount: 0,
      records: Array.from({ length: 90 }, (_, index) => ({
        packetId: 6500 + index,
        streamId: 23,
        direction: index % 2 === 0 ? "client_to_server" : "server_to_client",
        algorithm: "vshell-aes-gcm-md5-salt",
        keyStatus: "verified",
        confidence: 90,
        plaintextPreview: index === 89 ? targetPlaintext : `noise-frame-${index}`,
        rawLength: 64,
        decryptedLength: index === 89 ? targetPlaintext.length : 16,
      })),
      notes: ["VShell decrypt note"],
    });

    render(<C2Analysis />);

    fireEvent.click(await screen.findByRole("button", { name: /VShell/ }));
    fireEvent.change(screen.getByLabelText(/vkey/), { target: { value: "fallsnow" } });
    fireEvent.change(screen.getByLabelText(/salt/), { target: { value: "paperplane" } });
    fireEvent.click(screen.getByRole("button", { name: /批量解密候选流量/ }));

    expect(await screen.findByText(targetPlaintext)).toBeInTheDocument();
    expect(screen.getByText("展示 90 / 90 条")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "显示全部" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "仅显示前 80" })).not.toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("搜索明文、算法、stream、packet"), { target: { value: "hacked_by" } });
    expect(await screen.findByText("展示 1 / 1 条")).toBeInTheDocument();
    expect(screen.getByText(targetPlaintext)).toBeInTheDocument();
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
