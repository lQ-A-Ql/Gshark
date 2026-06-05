import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ThreatHit } from "../core/types";
import ThreatHunting from "./ThreatHunting";

const pageState = vi.hoisted(() => ({
  backendConnected: true,
  threatHits: [
    {
      id: 11,
      packetId: 11,
      category: "CTF",
      rule: "flag-prefix",
      level: "high",
      preview: "flag{demo}",
      match: "flag{",
    },
  ] as ThreatHit[],
  isThreatAnalysisLoading: false,
  threatAnalysisProgress: {
    phase: "idle",
    current: 0,
    total: 0,
    message: "",
  },
  locatePacketById: vi.fn(),
  preparePacketStream: vi.fn(),
  playbookWorkspaceMessage: "狩猎剧本工作区",
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => vi.fn(),
  };
});

vi.mock("../state/contexts/BackendContext", () => ({
  useBackend: () => ({ backendConnected: pageState.backendConnected }),
}));

vi.mock("../state/contexts/AnalysisContext", () => ({
  useAnalysis: () => ({
    threatHits: pageState.threatHits,
    isThreatAnalysisLoading: pageState.isThreatAnalysisLoading,
    threatAnalysisProgress: pageState.threatAnalysisProgress,
  }),
}));

vi.mock("../state/contexts/PacketContext", () => ({
  usePacket: () => ({ locatePacketById: pageState.locatePacketById }),
}));

vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({ preparePacketStream: pageState.preparePacketStream }),
}));

vi.mock("../features/hunting/useThreatHuntingWorkbench", () => ({
  useThreatHuntingWorkbench: () => ({
    hits: pageState.threatHits,
    selectedHit: pageState.threatHits[0]?.id ?? null,
    selected: pageState.threatHits[0] ?? null,
    stats: { ctf: 1, owasp: 0, anomaly: 0 },
    prefixText: "flag{",
    yaraEnabled: true,
    yaraBin: "yara64.exe",
    yaraRules: "rules",
    yaraTimeoutMs: 30000,
    configBusy: false,
    huntBusy: false,
    statusText: "狩猎就绪",
    setSelectedHit: vi.fn(),
    setPrefixText: vi.fn(),
    setYaraEnabled: vi.fn(),
    setYaraBin: vi.fn(),
    setYaraRules: vi.fn(),
    setYaraTimeoutMs: vi.fn(),
    runHunt: vi.fn(),
    loadConfig: vi.fn(),
    applyConfigAndRun: vi.fn(),
  }),
}));

vi.mock("../features/hunting/PlaybookWorkspaceSection", () => ({
  PlaybookWorkspaceSection: () => (
    <div data-testid="playbook-workspace-stub">{pageState.playbookWorkspaceMessage}</div>
  ),
}));

describe("ThreatHunting", () => {
  beforeEach(() => {
    pageState.backendConnected = true;
    pageState.threatHits = [
      {
        id: 11,
        packetId: 11,
        category: "CTF",
        rule: "flag-prefix",
        level: "high",
        preview: "flag{demo}",
        match: "flag{",
      },
    ];
    pageState.isThreatAnalysisLoading = false;
    pageState.threatAnalysisProgress = { phase: "idle", current: 0, total: 0, message: "" };
    pageState.playbookWorkspaceMessage = "狩猎剧本工作区";
    pageState.locatePacketById.mockReset();
    pageState.preparePacketStream.mockReset();
  });

  it("renders the hunting workbench with the embedded playbook workspace", () => {
    render(
      <MemoryRouter>
        <ThreatHunting />
      </MemoryRouter>,
    );

    expect(screen.getByText("威胁狩猎中心")).toBeInTheDocument();
    expect(screen.getByTestId("playbook-workspace-stub")).toBeInTheDocument();
  });

  it("keeps the page rendering when the embedded playbook area reports an API failure", () => {
    pageState.playbookWorkspaceMessage = "Playbook 区域不可用: HTTP 503";

    render(
      <MemoryRouter>
        <ThreatHunting />
      </MemoryRouter>,
    );

    expect(screen.getByText("威胁狩猎中心")).toBeInTheDocument();
    expect(screen.getByText("Playbook 区域不可用: HTTP 503")).toBeInTheDocument();
  });
});
