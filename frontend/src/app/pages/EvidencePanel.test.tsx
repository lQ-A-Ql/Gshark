import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { UnifiedEvidenceRecord } from "../core/evidenceTypes";

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
    evidence: {
      getEvidenceWithFilter: mocks.getEvidenceWithFilter,
    },
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

const LARGE_RECORD_COUNT = 500;

function clickEvidenceRow(summary: string) {
  const table = getEvidenceTable();
  const cell = within(table).getByText(summary);
  const row = cell.closest("tr");
  expect(row).not.toBeNull();
  fireEvent.click(row!);
}

function getEvidenceTable() {
  const table = screen.getByRole("columnheader", { name: "调查摘要" }).closest("table");
  expect(table).not.toBeNull();
  return table!;
}

function getEvidenceTableRowCount() {
  return getEvidenceTable().querySelectorAll("tbody tr").length;
}

function getEvidenceSummaryFromRow(rowIndex: number) {
  const table = getEvidenceTable();
  const rows = table.querySelectorAll("tbody tr");
  const row = rows.item(rowIndex);
  expect(row).not.toBeNull();
  const summaryText = row!.querySelector("td:nth-child(3) .truncate")?.textContent?.trim() ?? "";
  expect(summaryText).not.toBe("");
  return summaryText;
}

function getDetailPanel(summary: string) {
  const match = screen.getAllByText(summary).find((node) => {
    const section = node.closest("section");
    return section != null && within(section).queryByText("Actions") != null;
  });
  expect(match).not.toBeUndefined();
  return match!.closest("section")!;
}

function getDetailActionsSection(summary: string) {
  const panel = getDetailPanel(summary);
  const actionsHeading = within(panel).getByText("Actions");
  const section = actionsHeading.closest("section");
  expect(section).not.toBeNull();
  return section!;
}

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

function createLargeEvidenceSet(count = LARGE_RECORD_COUNT): UnifiedEvidenceRecord[] {
  return Array.from({ length: count }, (_, index) =>
    createRecord({
      id: `bulk-${index + 1}`,
      module: index % 2 === 0 ? "vehicle" : "usb",
      sourceType: index % 2 === 0 ? "uds-transaction" : "mass-storage-write",
      summary: `Bulk evidence ${index + 1}`,
      severity: index % 5 === 0 ? "high" : "medium",
      confidence: 90 - (index % 40),
      confidenceLabel: index % 5 === 0 ? "high" : "medium",
      packetId: index + 1,
      value: index === count - 1 ? "needle-match" : `value-${index + 1}`,
      tags: index === count - 1 ? ["bulk", "needle-tag"] : ["bulk"],
    }),
  );
}

describe("EvidencePanel", () => {
  beforeEach(() => {
    mocks.getEvidenceWithFilter.mockReset();
    mocks.downloadText.mockReset();
    mocks.navigate.mockReset();
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.captureRevision = 1;
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
      expect(screen.getByText("统一证据调查报告")).toBeInTheDocument();
      expect(screen.getAllByText("UDS 负响应: 0x27 Security Access / 安全访问被拒").length).toBeGreaterThan(0);
      expect(screen.getAllByText("USB 存储写入: WRITE(10) / Bus 1 Device 2 / LUN 0").length).toBeGreaterThan(0);
    });

    expect(screen.queryByRole("button", { name: "MISC" })).not.toBeInTheDocument();
    expect(mocks.getEvidenceWithFilter).toHaveBeenCalledWith(undefined, expect.anything());
  });

  it("filters by module, search, and severity before exporting JSON", async () => {
    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getAllByText("UDS 负响应: 0x27 Security Access / 安全访问被拒").length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getByRole("button", { name: "车机分析" }));

    await waitFor(() => {
      expect(mocks.getEvidenceWithFilter).toHaveBeenLastCalledWith(["vehicle"], expect.anything());
    });

    fireEvent.change(screen.getByPlaceholderText("搜索摘要、IOC、规则、主机、URI、标签..."), {
      target: { value: "安全访问" },
    });
    fireEvent.click(screen.getByRole("button", { name: "高危 · 1" }));
    fireEvent.click(screen.getByRole("button", { name: /JSON/ }));

    expect(mocks.downloadText).toHaveBeenCalledTimes(1);
    const [, payload] = mocks.downloadText.mock.calls[0];
    expect(payload).toContain("安全访问被拒");
    expect(payload).not.toContain("USB 存储写入");
  });

  it("renders sparse optional-contract records without undefined text or invented fallback rows", async () => {
    mocks.sentinelState.captureRevision = 2;
    mocks.getEvidenceWithFilter.mockImplementation(async () => [
      createRecord({
        id: "misc:webshell-minimal",
        module: "misc",
        sourceType: "webshell",
        summary: "WebShell candidate without exposed version",
        family: "china_chopper",
        value: undefined,
        confidence: undefined,
        confidenceLabel: "unknown",
        packetId: undefined,
        streamId: undefined,
        tags: [],
        caveats: [],
      }),
      createRecord({
        id: "hunt:rule-minimal",
        module: "hunting",
        sourceType: "ioc",
        summary: "Rule evidence without packet binding",
        value: undefined,
        confidence: undefined,
        confidenceLabel: "unknown",
        packetId: undefined,
        streamId: undefined,
        tags: [],
        caveats: [],
      }),
    ]);

    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getAllByText("WebShell candidate without exposed version").length).toBeGreaterThan(0);
      expect(screen.getAllByText("Rule evidence without packet binding").length).toBeGreaterThan(0);
    });

    clickEvidenceRow("WebShell candidate without exposed version");

    expect(screen.queryByText("undefined")).not.toBeInTheDocument();
    expect(screen.queryByText("china_chopper")).not.toBeInTheDocument();
    expect(
      within(getDetailPanel("WebShell candidate without exposed version")).getByText("菜刀 / China Chopper"),
    ).toBeInTheDocument();
    expect(
      within(getDetailPanel("WebShell candidate without exposed version")).getAllByText("WebShell").length,
    ).toBeGreaterThan(0);
    expect(
      within(getDetailPanel("WebShell candidate without exposed version")).getAllByText("未提供").length,
    ).toBeGreaterThan(0);

    clickEvidenceRow("Rule evidence without packet binding");
    expect(
      within(getDetailPanel("Rule evidence without packet binding")).getByText("IOC API unavailable"),
    ).toBeInTheDocument();
    expect(screen.queryByText("evil.example")).not.toBeInTheDocument();
    expect(screen.queryByText("packet #")).not.toBeInTheDocument();
    expect(screen.getAllByText("--").length).toBeGreaterThan(0);
  });

  it("renders packet and stream actions only when valid navigation context exists", async () => {
    mocks.sentinelState.captureRevision = 4;
    mocks.getEvidenceWithFilter.mockImplementation(async () => [
      createRecord({
        id: "hunt:packet-only",
        module: "hunting",
        sourceType: "ja3",
        summary: "JA3 packet-only evidence",
        packetId: 88,
        streamId: undefined,
        ja3Hash: "72a589da586844d7f0818ce684948eea",
      }),
      createRecord({
        id: "hunt:no-context",
        module: "hunting",
        sourceType: "playbook",
        summary: "Playbook evidence without navigation context",
        packetId: undefined,
        streamId: undefined,
      }),
    ]);

    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getAllByText("JA3 packet-only evidence").length).toBeGreaterThan(0);
    });

    expect(
      within(getDetailActionsSection("JA3 packet-only evidence")).getByRole("button", { name: "定位到包" }),
    ).toBeInTheDocument();
    expect(
      within(getDetailActionsSection("JA3 packet-only evidence")).queryByRole("button", { name: "打开关联流" }),
    ).not.toBeInTheDocument();

    clickEvidenceRow("Playbook evidence without navigation context");

    await waitFor(() => {
      expect(
        within(getDetailActionsSection("Playbook evidence without navigation context")).getByText(
          "当前记录未提供有效的包号或关联流 ID，因此不显示跳转操作。",
        ),
      ).toBeInTheDocument();
    });
    expect(
      within(getDetailActionsSection("Playbook evidence without navigation context")).queryByRole("button", {
        name: "定位到包",
      }),
    ).not.toBeInTheDocument();
    expect(
      within(getDetailActionsSection("Playbook evidence without navigation context")).queryByRole("button", {
        name: "打开关联流",
      }),
    ).not.toBeInTheDocument();
    expect(
      within(getDetailPanel("Playbook evidence without navigation context")).getAllByText("Playbook").length,
    ).toBeGreaterThan(0);
    expect(
      within(getDetailPanel("Playbook evidence without navigation context")).getByText("Playbook 未提供"),
    ).toBeInTheDocument();
  });

  it("shows an empty evidence state without fake rows and exports an empty result safely", async () => {
    mocks.sentinelState.captureRevision = 3;
    mocks.getEvidenceWithFilter.mockImplementation(async () => []);

    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getByText("当前抓包未产生证据记录")).toBeInTheDocument();
      expect(screen.getByText("共 0 条证据 / 模块 0 个")).toBeInTheDocument();
    });

    expect(screen.queryByText("UDS 负响应: 0x27 Security Access / 安全访问被拒")).not.toBeInTheDocument();
    expect(screen.queryByText("USB 存储写入: WRITE(10) / Bus 1 Device 2 / LUN 0")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /JSON/ }));

    expect(mocks.downloadText).toHaveBeenCalledTimes(1);
    const [, payload] = mocks.downloadText.mock.calls[0];
    expect(payload).toBe("[]");
  });

  it("caps initial rendering to 200 rows, expands by 200, and exports all filtered records", async () => {
    mocks.sentinelState.captureRevision = 5;
    const records = createLargeEvidenceSet();
    mocks.getEvidenceWithFilter.mockImplementation(async () => records);

    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getByText("Showing 200 of 500 evidence records")).toBeInTheDocument();
      expect(screen.getAllByText("Bulk evidence 1").length).toBeGreaterThan(0);
    });

    expect(getEvidenceTableRowCount()).toBe(200);

    fireEvent.click(screen.getByRole("button", { name: "Show next 200" }));

    await waitFor(() => {
      expect(screen.getByText("Showing 400 of 500 evidence records")).toBeInTheDocument();
    });

    expect(getEvidenceTableRowCount()).toBe(400);

    fireEvent.change(screen.getByPlaceholderText("搜索摘要、IOC、规则、主机、URI、标签..."), {
      target: { value: "needle-match" },
    });

    await waitFor(() => {
      expect(screen.queryByText("Showing 200 of 500 evidence records")).not.toBeInTheDocument();
      expect(screen.getAllByText("Bulk evidence 500").length).toBeGreaterThan(0);
      expect(screen.queryByText("Bulk evidence 1")).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /JSON/ }));

    expect(mocks.downloadText).toHaveBeenCalledTimes(1);
    const [, payload] = mocks.downloadText.mock.calls[0];
    expect(payload).toContain("Bulk evidence 500");
    expect(payload).not.toContain("Bulk evidence 1");
    expect(mocks.getEvidenceWithFilter).toHaveBeenCalledTimes(1);
  });

  it("resets selection to the first visible record when filters move the prior selection outside the visible slice", async () => {
    mocks.sentinelState.captureRevision = 6;
    const records = createLargeEvidenceSet();
    mocks.getEvidenceWithFilter.mockImplementation(async () => records);

    render(<EvidencePanel />);

    await waitFor(() => {
      expect(screen.getAllByText("Bulk evidence 1").length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getByRole("button", { name: "Show next 200" }));

    await waitFor(() => {
      expect(screen.getByText("Showing 400 of 500 evidence records")).toBeInTheDocument();
    });

    const selectedSummary = getEvidenceSummaryFromRow(399);
    clickEvidenceRow(selectedSummary);

    await waitFor(() => {
      expect(getDetailPanel(selectedSummary)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText("搜索摘要、IOC、规则、主机、URI、标签..."), {
      target: { value: "Bulk evidence 1" },
    });

    await waitFor(() => {
      expect(getDetailPanel("Bulk evidence 1")).toBeInTheDocument();
    });

    expect(screen.queryByText(selectedSummary)).not.toBeInTheDocument();
  });
});
