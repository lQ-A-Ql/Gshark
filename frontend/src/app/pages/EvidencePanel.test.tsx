import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UnifiedEvidenceRecord } from "../features/evidence/evidenceSchema";

const mocks = vi.hoisted(() => ({
  getEvidenceWithFilter: vi.fn(),
  downloadText: vi.fn(),
  navigate: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/evidence.pcapng",
      name: "evidence.pcapng",
      sizeBytes: 4096,
    },
    totalPackets: 200,
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
    getEvidenceWithFilter: mocks.getEvidenceWithFilter,
  },
}));

vi.mock("../utils/browserFile", () => ({
  downloadText: mocks.downloadText,
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import EvidencePanel from "./EvidencePanel";

function createRecord(overrides: Partial<UnifiedEvidenceRecord>): UnifiedEvidenceRecord {
  return {
    id: "record-1",
    module: "vehicle",
    sourceType: "uds-transaction",
    summary: "UDS 高价值事务: 0x27 Security Access",
    confidence: 82,
    confidenceLabel: "high",
    severity: "high",
    tags: ["UDS", "0x27", "Security Access"],
    caveats: ["中置信信号，不应单独作为强归因结论。"],
    ...overrides,
  };
}

describe("EvidencePanel", () => {
  beforeEach(() => {
    mocks.getEvidenceWithFilter.mockReset();
    mocks.downloadText.mockReset();
    mocks.navigate.mockReset();
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null);
    mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "TCP", streamId: 1 });
    mocks.getEvidenceWithFilter.mockImplementation(async (modules?: string[]) => {
      const vehicle = createRecord({
        id: "vehicle-1",
        module: "vehicle",
        summary: "UDS 负响应: 0x27 Security Access / 安全访问被拒",
        severity: "high",
        confidence: 82,
        confidenceLabel: "high",
        packetId: 101,
        value: "0x0e80 → 0x07e0 / security access denied",
      });
      const usb = createRecord({
        id: "usb-1",
        module: "usb",
        sourceType: "mass-storage-write",
        summary: "USB 存储写入: WRITE(10) / Bus 1 Device 2 / LUN 0",
        severity: "medium",
        confidence: 60,
        confidenceLabel: "medium",
        packetId: 201,
        value: "len=4096 / status=ok",
        tags: ["USB", "Mass Storage", "write"],
      });

      if (modules?.includes("vehicle")) {
        return [vehicle];
      }
      if (modules?.includes("usb")) {
        return [usb];
      }
      return [vehicle, usb];
    });
  });

  it("renders core module filters including vehicle and usb, without a MISC filter", async () => {
    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getByText("证据链总览")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "车机分析" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "USB 分析" })).toBeInTheDocument();
      expect(screen.getByText("UDS 负响应: 0x27 Security Access / 安全访问被拒")).toBeInTheDocument();
      expect(screen.getByText("USB 存储写入: WRITE(10) / Bus 1 Device 2 / LUN 0")).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: "MISC" })).not.toBeInTheDocument();
    expect(mocks.getEvidenceWithFilter).toHaveBeenCalledWith(undefined, expect.anything());
  });

  it("filters by module, search, and severity before exporting JSON", async () => {
    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getByText("UDS 负响应: 0x27 Security Access / 安全访问被拒")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "车机分析" }));

    await waitFor(() => {
      expect(mocks.getEvidenceWithFilter).toHaveBeenLastCalledWith(["vehicle"], expect.anything());
    });

    fireEvent.change(screen.getByPlaceholderText("搜索摘要、值、标签..."), {
      target: { value: "安全访问" },
    });
    fireEvent.click(screen.getByRole("button", { name: "高危 · 1" }));
    fireEvent.click(screen.getByRole("button", { name: /JSON/ }));

    expect(mocks.downloadText).toHaveBeenCalledTimes(1);
    const [, payload] = mocks.downloadText.mock.calls[0];
    expect(payload).toContain("安全访问被拒");
    expect(payload).not.toContain("USB 存储写入");
  });
});
