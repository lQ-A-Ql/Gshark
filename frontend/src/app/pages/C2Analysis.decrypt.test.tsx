import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAnalysis, findAncestorWithClass } from "./C2Analysis.testFixtures";

const mocks = vi.hoisted(() => ({
  getC2SampleAnalysis: vi.fn(),
  decryptC2Traffic: vi.fn(),
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
    useNavigate: () => vi.fn(),
  };
});

import C2Analysis from "./C2Analysis";

describe("C2Analysis decrypt workflow", () => {
  let seed = 0;

  beforeEach(() => {
    seed += 1;
    mocks.sentinelState.backendConnected = true;
    mocks.sentinelState.isPreloadingCapture = false;
    mocks.sentinelState.totalPackets = 256 + seed;
    mocks.sentinelState.captureRevision = seed;
    mocks.sentinelState.fileMeta = {
      path: `C:/captures/c2-decrypt-${seed}.pcapng`,
      name: `c2-decrypt-${seed}.pcapng`,
      sizeBytes: 4096,
    };
    mocks.getC2SampleAnalysis.mockReset();
    mocks.decryptC2Traffic.mockReset();
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null);
    mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "TCP", streamId: 9 });
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
});
