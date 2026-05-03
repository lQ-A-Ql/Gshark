import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { APTAnalysis } from "../core/types";

const mocks = vi.hoisted(() => ({
  getAPTAnalysis: vi.fn(),
  navigate: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/apt.pcapng",
      name: "apt.pcapng",
      sizeBytes: 4096,
    },
    totalPackets: 512,
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
    getAPTAnalysis: mocks.getAPTAnalysis,
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import AptAnalysis, { buildAPTAnalysisCacheKey } from "./AptAnalysis";

function createAnalysis(overrides: Partial<APTAnalysis> = {}): APTAnalysis {
  return {
    totalEvidence: 1,
    actors: [{ label: "Silver Fox / 银狐", count: 1 }],
    sampleFamilies: [{ label: "ValleyRAT", count: 1 }],
    campaignStages: [{ label: "delivery", count: 1 }],
    transportTraits: [{ label: "https-c2", count: 1 }],
    infrastructureHints: [{ label: "fallback-c2", count: 1 }],
    relatedC2Families: [{ label: "cs", count: 1 }],
    profiles: [
      {
        id: "silver-fox",
        name: "Silver Fox / 银狐",
        aliases: ["Swimming Snake", "银狐"],
        summary: "Silver Fox 画像已接入 C2 证据链，仍需跨模块复核。",
        confidence: 65,
        evidenceCount: 1,
        sampleFamilies: [{ label: "ValleyRAT", count: 1 }],
        campaignStages: [{ label: "delivery", count: 1 }],
        transportTraits: [{ label: "https-c2", count: 1 }],
        infrastructureHints: [{ label: "fallback-c2", count: 1 }],
        relatedC2Families: [{ label: "cs", count: 1 }],
        ttpTags: [{ label: "encrypted-c2", count: 1 }],
        scoreFactors: [
          { name: "hfs-download-chain", weight: 8, direction: "positive", sourceModule: "c2-analysis", summary: "HFS 下载链" },
          { name: "valleyrat-family-hint", weight: 7, direction: "positive", sourceModule: "c2-analysis", summary: "ValleyRAT 家族线索" },
          { name: "https-c2", weight: 3, direction: "positive", sourceModule: "c2-analysis", summary: "HTTPS C2 弱传输线索" },
          { name: "missing-object-evidence", weight: 0, direction: "missing", sourceModule: "profile", summary: "缺失 Object Export 证据" },
        ],
        notes: ["端口、路径、单个 IOC 仅作为弱观察位。"],
      },
    ],
    evidence: [
      {
        packetId: 42,
        streamId: 7,
        time: "12:00:00.000000",
        actorId: "silver-fox",
        actorName: "Silver Fox / 银狐",
        sourceModule: "c2-analysis",
        family: "cs",
        evidenceType: "c2-indicator",
        evidenceValue: "c2.example.test",
        confidence: 65,
        source: "10.0.0.5:50100",
        destination: "10.0.0.9:443",
        host: "c2.example.test",
        uri: "/api/checkin",
        sampleFamily: "ValleyRAT",
        campaignStage: "delivery",
        transportTraits: ["https-c2"],
        infrastructureHints: ["hfs-download-chain", "fallback-c2"],
        ttpTags: ["encrypted-c2"],
        tags: ["actor-hint"],
        scoreFactors: [
          { name: "hfs-download-chain", weight: 8, direction: "positive", sourceModule: "c2-analysis", summary: "HFS 下载链" },
          { name: "valleyrat-family-hint", weight: 7, direction: "positive", sourceModule: "c2-analysis", summary: "ValleyRAT 家族线索" },
        ],
        summary: "C2 技术证据关联 Silver Fox 候选",
      },
    ],
    notes: ["APT registry 已接入，未实现组织仅作为框架预置展示。"],
    ...overrides,
  };
}

describe("AptAnalysis", () => {
  let seed = 0;

  beforeEach(() => {
    seed += 1;
    mocks.sentinelState.backendConnected = true;
    mocks.sentinelState.isPreloadingCapture = false;
    mocks.sentinelState.totalPackets = 512 + seed;
    mocks.sentinelState.captureRevision = seed;
    mocks.sentinelState.fileMeta = {
      path: `C:/captures/apt-${seed}.pcapng`,
      name: `apt-${seed}.pcapng`,
      sizeBytes: 4096,
    };
    mocks.getAPTAnalysis.mockReset();
    mocks.navigate.mockReset();
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null);
    mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 7 });
    mocks.getAPTAnalysis.mockResolvedValue(createAnalysis());
  });

  it("renders APT registry and Silver Fox actor profile", async () => {
    render(<AptAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("APT 组织画像")).toBeInTheDocument();
      expect(screen.getAllByText("Silver Fox / 银狐").length).toBeGreaterThan(0);
      expect(screen.getAllByText("样本家族").length).toBeGreaterThan(0);
      expect(screen.getAllByText("ValleyRAT").length).toBeGreaterThan(0);
      expect(screen.getAllByText("https-c2").length).toBeGreaterThan(0);
      expect(screen.getByText("APT28 / Fancy Bear")).toBeInTheDocument();
      expect(screen.getByText("Lazarus Group")).toBeInTheDocument();
      expect(screen.getAllByText("已接入检测").length).toBeGreaterThan(0);
      expect(screen.getAllByText("框架预置").length).toBeGreaterThan(0);
      expect(screen.getAllByText("待样本验证").length).toBeGreaterThan(0);
      expect(screen.getAllByText("不参与本轮评分").length).toBeGreaterThan(0);
      expect(screen.getByText("C2 Evidence")).toBeInTheDocument();
      expect(screen.getByText("Delivery / Object")).toBeInTheDocument();
      expect(screen.getAllByText(/c2-analysis · c2-indicator/).length).toBeGreaterThan(0);
      expect(screen.getAllByText("C2 技术证据关联 Silver Fox 候选").length).toBeGreaterThan(0);
      expect(screen.getByText("Evidence Timeline")).toBeInTheDocument();
      expect(screen.getAllByText("hfs-download-chain").length).toBeGreaterThan(0);
      expect(screen.getByText(/缺失 Object Export 证据/)).toBeInTheDocument();
    });
    expect(mocks.getAPTAnalysis).toHaveBeenCalledTimes(1);
  });

  it("builds cache key from capture identity", () => {
    expect(buildAPTAnalysisCacheKey(3, "C:/captures/demo.pcapng", 99)).toBe("3::C:/captures/demo.pcapng::99");
    expect(buildAPTAnalysisCacheKey(3, "   ", 99)).toBe("");
  });
});
