import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AnalysisWorkbenchShell } from "./AnalysisWorkbenchShell";
import type { AnalysisWorkbenchSection } from "./analysisWorkbenchTypes";

const sections: AnalysisWorkbenchSection[] = [
  { id: "overview", title: "总览", description: "总体指标", group: "Overview", badge: 2 },
  { id: "details", title: "明细", description: "数据表", group: "Workspace" },
  { id: "disabled", title: "禁用项", group: "Workspace", disabled: true },
];

describe("AnalysisWorkbenchShell", () => {
  it("passes through nav item ids and expanded state", () => {
    render(
      <AnalysisWorkbenchShell
        sections={[
          { id: "module:webshell", title: "WebShell", group: "Modules", testId: "module-webshell", expanded: true },
        ]}
        selectedSection="module:webshell"
        onSectionChange={vi.fn()}
      >
        <div>当前内容</div>
      </AnalysisWorkbenchShell>,
    );

    expect(screen.getByTestId("module-webshell")).toHaveAttribute("aria-expanded", "true");
  });

  it("renders grouped sections, header, active button and scroll container", () => {
    render(
      <AnalysisWorkbenchShell sections={sections} selectedSection="overview" onSectionChange={vi.fn()}>
        <div>当前内容</div>
      </AnalysisWorkbenchShell>,
    );

    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("Workspace")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /总览/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getAllByText("总体指标").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByTestId("analysis-workbench-scroll")).toHaveClass("overflow-auto");
    expect(screen.getByText("当前内容")).toBeInTheDocument();
  });

  it("changes section from enabled buttons only", () => {
    const onSectionChange = vi.fn();
    render(
      <AnalysisWorkbenchShell sections={sections} selectedSection="overview" onSectionChange={onSectionChange}>
        <div>当前内容</div>
      </AnalysisWorkbenchShell>,
    );

    fireEvent.click(screen.getByRole("button", { name: /明细/ }));
    expect(onSectionChange).toHaveBeenCalledWith("details");

    fireEvent.click(screen.getByRole("button", { name: /禁用项/ }));
    expect(onSectionChange).toHaveBeenCalledTimes(1);
  });

  it("supports multiple active ids for object navigation plus a selected section", () => {
    render(
      <AnalysisWorkbenchShell
        sections={[
          { id: "actor:silver-fox", title: "Silver Fox", group: "Actors" },
          { id: "profile", title: "画像", group: "Sections" },
        ]}
        selectedSection="profile"
        activeSectionIds={["actor:silver-fox", "profile"]}
        onSectionChange={vi.fn()}
      >
        <div>当前内容</div>
      </AnalysisWorkbenchShell>,
    );

    expect(screen.getByRole("button", { name: /Silver Fox/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /画像/ })).toHaveAttribute("aria-pressed", "true");
  });
});
