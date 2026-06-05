import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { HuntingPlaybook, Hypothesis, SavedSearch } from "../../core/types/huntingPlaybook";
import { PlaybookWorkspaceSection } from "./PlaybookWorkspaceSection";

const hookState = vi.hoisted(() => ({
  playbooks: [] as HuntingPlaybook[],
  playbooksLoading: false,
  playbooksError: "",
  selectedPlaybook: null as string | null,
  playbookRunning: false,
  lastRunResult: null,
  setSelectedPlaybook: vi.fn(),
  runPlaybook: vi.fn(),
  deletePlaybook: vi.fn(),
  savedSearches: [] as SavedSearch[],
  savedSearchesLoading: false,
  savedSearchesError: "",
  executeSavedSearch: vi.fn(),
  deleteSavedSearch: vi.fn(),
  hypotheses: [] as Hypothesis[],
  hypothesesLoading: false,
  hypothesesError: "",
  updateHypothesisStatus: vi.fn(),
  refreshAll: vi.fn(),
  statusText: "",
}));

vi.mock("./usePlaybookManagement", () => ({
  usePlaybookManagement: () => hookState,
}));

describe("PlaybookWorkspaceSection", () => {
  beforeEach(() => {
    hookState.playbooks = [];
    hookState.playbooksLoading = false;
    hookState.playbooksError = "";
    hookState.selectedPlaybook = null;
    hookState.playbookRunning = false;
    hookState.lastRunResult = null;
    hookState.savedSearches = [];
    hookState.savedSearchesLoading = false;
    hookState.savedSearchesError = "";
    hookState.deleteSavedSearch.mockReset();
    hookState.hypotheses = [];
    hookState.hypothesesLoading = false;
    hookState.hypothesesError = "";
    hookState.statusText = "";
    hookState.setSelectedPlaybook.mockReset();
    hookState.runPlaybook.mockReset();
    hookState.deletePlaybook.mockReset();
    hookState.executeSavedSearch.mockReset();
    hookState.updateHypothesisStatus.mockReset();
    hookState.refreshAll.mockReset();
  });

  it("renders the embedded playbook workspace with localized empty states", () => {
    render(<PlaybookWorkspaceSection backendConnected />);

    expect(screen.getByText("狩猎剧本工作区")).toBeInTheDocument();
    expect(screen.getByText('暂无剧本。点击上方"新建剧本"创建第一个威胁狩猎剧本。')).toBeInTheDocument();
    expect(screen.getByText("暂无保存的搜索。")).toBeInTheDocument();
    expect(screen.getByText("暂无假设。创建假设以驱动威胁狩猎调查。")).toBeInTheDocument();
  });

  it("localizes API failures inside the playbook area", () => {
    hookState.playbooksError = "HTTP 503";
    hookState.savedSearchesError = "saved-search failure";
    hookState.hypothesesError = "hypothesis failure";

    render(<PlaybookWorkspaceSection backendConnected />);

    expect(screen.getByText("Playbook 区域不可用: HTTP 503")).toBeInTheDocument();
    expect(screen.getByText("Playbook 保存的搜索不可用: saved-search failure")).toBeInTheDocument();
    expect(screen.getByText("调查假设区域不可用: hypothesis failure")).toBeInTheDocument();
  });
});
