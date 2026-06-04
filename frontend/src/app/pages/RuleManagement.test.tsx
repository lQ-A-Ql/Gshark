import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RuleStatus, RulePack, RuleUpdateResult } from "../features/rules/useRuleManagement";

const mocks = vi.hoisted(() => ({
  fetchStatus: vi.fn(),
  togglePack: vi.fn(),
  checkUpdates: vi.fn(),
  downloadPack: vi.fn(),
  updateConfig: vi.fn(),
}));

vi.mock("../features/rules/useRuleManagement", () => ({
  useRuleManagement: () => ({
    status: mocks.status ?? null,
    loading: mocks.loading ?? false,
    error: mocks.error ?? null,
    fetchStatus: mocks.fetchStatus,
    togglePack: mocks.togglePack,
    checkUpdates: mocks.checkUpdates,
    downloadPack: mocks.downloadPack,
    updateConfig: mocks.updateConfig,
  }),
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => vi.fn(),
  };
});

import RuleManagement from "./RuleManagement";

function createPack(overrides: Partial<RulePack> = {}): RulePack {
  return {
    id: "test-pack-1",
    name: "Test Pack",
    description: "A test rule pack",
    source: "remote",
    version: { major: 1, minor: 0, patch: 0, tag: "", released_at: "2025-01-01T00:00:00Z" },
    enabled: true,
    rule_count: 10,
    checksum: "abc123def456",
    updated_at: "2025-01-01T00:00:00Z",
    rules: [],
    ...overrides,
  };
}

function createStatus(overrides: Partial<RuleStatus> = {}): RuleStatus {
  return {
    packs: [],
    total_rules: 0,
    enabled_rules: 0,
    disabled_rules: 0,
    last_update: "2025-01-01T00:00:00Z",
    update_config: {
      remote_url: "",
      auto_update: false,
      update_interval_hours: 24,
      cache_dir: "",
    },
    conflicts: [],
    ...overrides,
  };
}

describe("RuleManagement", () => {
  beforeEach(() => {
    mocks.status = undefined;
    mocks.loading = false;
    mocks.error = undefined;
    mocks.fetchStatus.mockReset();
    mocks.togglePack.mockReset();
    mocks.checkUpdates.mockReset();
    mocks.downloadPack.mockReset();
    mocks.updateConfig.mockReset();
  });

  it("renders the AnalysisHero with title", () => {
    mocks.status = createStatus();
    render(<RuleManagement />);

    expect(screen.getByText("规则管理")).toBeInTheDocument();
    expect(screen.getByText("RULE MANAGEMENT")).toBeInTheDocument();
  });

  it("shows loading state when loading", () => {
    mocks.loading = true;
    render(<RuleManagement />);

    expect(screen.getByText("加载中...")).toBeInTheDocument();
  });

  it("shows error state when error occurs", () => {
    mocks.error = "Failed to fetch rule status";
    mocks.status = createStatus();
    render(<RuleManagement />);

    expect(screen.getByText("Failed to fetch rule status")).toBeInTheDocument();
  });

  it("renders rule packs list", () => {
    mocks.status = createStatus({
      packs: [
        createPack({ id: "pack-1", name: "YARA Pack 1", enabled: true }),
        createPack({ id: "pack-2", name: "YARA Pack 2", enabled: false }),
      ],
      total_rules: 20,
      enabled_rules: 10,
      disabled_rules: 10,
    });
    render(<RuleManagement />);

    expect(screen.getByText("YARA Pack 1")).toBeInTheDocument();
    expect(screen.getByText("YARA Pack 2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /禁用规则包 YARA Pack 1/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /启用规则包 YARA Pack 2/i })).toBeInTheDocument();
  });

  it("calls togglePack when toggle button clicked", () => {
    mocks.status = createStatus({
      packs: [createPack({ id: "pack-1", name: "YARA Pack 1", enabled: true })],
    });
    mocks.togglePack.mockResolvedValue(undefined);
    render(<RuleManagement />);

    const toggleButton = screen.getByRole("button", { name: /禁用规则包/i });
    fireEvent.click(toggleButton);

    expect(mocks.togglePack).toHaveBeenCalledWith("pack-1", false);
  });

  it("calls checkUpdates when check updates button clicked", async () => {
    mocks.status = createStatus();
    mocks.checkUpdates.mockResolvedValue([
      {
        pack_id: "pack-1",
        old_version: { major: 1, minor: 0, patch: 0, tag: "", released_at: "" },
        new_version: { major: 1, minor: 1, patch: 0, tag: "", released_at: "" },
        updated: true,
        downloaded_rules: 5,
        error: "",
      },
    ] as RuleUpdateResult[]);
    render(<RuleManagement />);

    const checkButton = screen.getByRole("button", { name: /检查规则更新/i });
    fireEvent.click(checkButton);

    await waitFor(() => {
      expect(mocks.checkUpdates).toHaveBeenCalled();
    });
  });
});
