import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createVShellCandidateFallbackAnalysis,
  createVShellCandidateMergeAnalysis,
  createVShellCandidateNoSignalAnalysis,
  createVShellListenerAnalysis,
} from "./C2Analysis.vshellFixtures";

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

vi.mock("../state/contexts/BackendContext", () => ({
  useBackend: () => ({
    backendConnected: mocks.sentinelState.backendConnected,
  }),
}));
vi.mock("../state/contexts/CaptureContext", () => ({
  useCapture: () => ({
    isPreloadingCapture: mocks.sentinelState.isPreloadingCapture,
    fileMeta: mocks.sentinelState.fileMeta,
    captureRevision: mocks.sentinelState.captureRevision,
  }),
}));
vi.mock("../state/contexts/PacketContext", () => ({
  usePacket: () => ({
    totalPackets: mocks.sentinelState.totalPackets,
    locatePacketById: mocks.sentinelState.locatePacketById,
  }),
}));
vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({
    preparePacketStream: mocks.sentinelState.preparePacketStream,
  }),
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
  return { ...actual, useNavigate: () => mocks.navigate };
});
import C2Analysis from "./C2Analysis";

async function openVShellFamilySection() {
  fireEvent.click(await screen.findByRole("button", { name: /^Family CS \/ VShell 画像$/ }));
  fireEvent.click(screen.getByRole("button", { name: /^VShell TCP/ }));
}

function openEvidenceSection() {
  fireEvent.click(screen.getByRole("button", { name: /^证据 候选表与复核 notes$/ }));
}

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
    mocks.getC2SampleAnalysis.mockReset(); mocks.decryptC2Traffic.mockReset();
    mocks.navigate.mockReset(); mocks.clipboardWriteText.mockReset();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: mocks.clipboardWriteText },
      configurable: true,
    });
    mocks.sentinelState.locatePacketById.mockReset(); mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null); mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 7 });
    mocks.getC2SampleAnalysis.mockResolvedValue(createVShellListenerAnalysis());
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

    await openVShellFamilySection();

    await waitFor(() => {
      expect(screen.getByText("WebSocket 握手")).toBeInTheDocument();
      expect(screen.getAllByText("长度前缀").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("架构标记").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("Listener hints")).toBeInTheDocument();
    });

    openEvidenceSection();
    await waitFor(() => {
      expect(screen.getByText("VShell listener 证据已汇总")).toBeInTheDocument();
    });
    expect(mocks.getC2SampleAnalysis).toHaveBeenCalledTimes(1);
  });

  it("falls back to VShell candidate evidence when stream aggregates are empty", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createVShellCandidateFallbackAnalysis());

    render(<C2Analysis />);

    await openVShellFamilySection();

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getByText(/摘要卡片会并列融合 stream 聚合与候选弱信号/)).toBeInTheDocument();
    expect(screen.getAllByText("candidates").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("stream 握手 / candidates ws 参数合并计数")).toBeInTheDocument();
    expect(screen.getByText("4 字节长度前缀观察次数，合并 stream 与候选弱信号")).toBeInTheDocument();
    expect(screen.getByText(/最高置信 62% · packet #81 \/ stream 9/)).toBeInTheDocument();

    openEvidenceSection();
    await waitFor(() => {
      expect(screen.getByText("VShell WebSocket 候选，包含 ws_ 参数与 l64 marker")).toBeInTheDocument();
      expect(screen.getByText("VShell 候选尚未形成 stream 聚合")).toBeInTheDocument();
    });
  });

  it("merges VShell stream aggregate and candidate evidence in the summary cards", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createVShellCandidateMergeAnalysis());

    render(<C2Analysis />);
    await openVShellFamilySection();

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getByText(/最高置信 66% · packet #81 \/ stream 9/)).toBeInTheDocument();
    expect(screen.getAllByText("stream + candidates").length).toBeGreaterThanOrEqual(1);

    openEvidenceSection();
    await waitFor(() => {
      expect(screen.getByText("VShell candidate websocket listener")).toBeInTheDocument();
    });
  });

  it("explains VShell candidate fallback when stream aggregates exist but contain no signal counts", async () => {
    mocks.getC2SampleAnalysis.mockResolvedValueOnce(createVShellCandidateNoSignalAnalysis());

    render(<C2Analysis />);

    await openVShellFamilySection();

    expect(await screen.findByText(/已形成 VShell candidates 候选证据/)).toBeInTheDocument();
    expect(screen.getAllByText("candidates").length).toBeGreaterThanOrEqual(1);

    openEvidenceSection();
    await waitFor(() => {
      expect(screen.getByText("VShell TCP 候选，包含 length prefix listener hint")).toBeInTheDocument();
    });
  });
});
