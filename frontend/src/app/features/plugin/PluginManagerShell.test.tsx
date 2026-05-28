import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PluginManagerShell } from "./PluginManagerShell";

const PLUGINS = [
  { id: "p1", name: "Alpha Plugin", version: "1.0", tag: "alpha", author: "test", enabled: true, entry: "alpha.js", runtime: "js", capabilities: ["packet.read"] },
  { id: "p2", name: "Beta Plugin", version: "2.0", tag: "beta", author: "test", enabled: false, entry: "beta.py", runtime: "py", capabilities: ["threat.emit", "logging"] },
];

describe("PluginManagerShell", () => {
  it("renders plugin list", () => {
    render(
      <PluginManagerShell
        plugins={PLUGINS}
        loading={false}
        error=""
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={vi.fn()}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    expect(screen.getByText("Alpha Plugin")).toBeInTheDocument();
    expect(screen.getByText("Beta Plugin")).toBeInTheDocument();
    expect(screen.getByText("2 个插件")).toBeInTheDocument();
  });

  it("shows empty state when no plugins", () => {
    render(
      <PluginManagerShell
        plugins={[]}
        loading={false}
        error=""
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={vi.fn()}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    expect(screen.getByText("暂无插件")).toBeInTheDocument();
  });

  it("shows loading state", () => {
    render(
      <PluginManagerShell
        plugins={[]}
        loading={true}
        error=""
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={vi.fn()}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    expect(screen.getByText("正在加载插件列表...")).toBeInTheDocument();
  });

  it("shows error state", () => {
    render(
      <PluginManagerShell
        plugins={[]}
        loading={false}
        error="加载失败"
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={vi.fn()}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    expect(screen.getByText("加载失败")).toBeInTheDocument();
  });

  it("opens add dialog", () => {
    render(
      <PluginManagerShell
        plugins={[]}
        loading={false}
        error=""
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={vi.fn()}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByText("添加插件"));
    expect(screen.getByText("添加新插件")).toBeInTheDocument();
  });

  it("calls onToggle when toggle button clicked", () => {
    const onToggle = vi.fn();
    render(
      <PluginManagerShell
        plugins={PLUGINS}
        loading={false}
        error=""
        onAdd={vi.fn()}
        onDelete={vi.fn()}
        onToggle={onToggle}
        onBulkToggle={vi.fn()}
        onOpenSource={vi.fn()}
      />,
    );

    const toggleButtons = screen.getAllByLabelText("禁用 Alpha Plugin");
    fireEvent.click(toggleButtons[0]);
    expect(onToggle).toHaveBeenCalledWith("p1");
  });
});
