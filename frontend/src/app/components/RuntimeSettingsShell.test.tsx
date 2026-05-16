import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ToolRuntimeConfig } from "../core/types";
import { RuntimeSettingsHeader } from "./RuntimeSettingsHeader";
import { RuntimeSettingsFooter } from "./RuntimeSettingsShell";

const form: ToolRuntimeConfig = {
  tsharkPath: "",
  ffmpegPath: "",
  pythonPath: "",
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

describe("RuntimeSettingsShell", () => {
  it("shows runtime probe failure details instead of generic missing cards", () => {
    render(
      <RuntimeSettingsHeader
        form={form}
        snapshot={null}
        probeState="failed"
        probeTransport="desktop-ipc"
        probeError="Wails IPC runtime snapshot failed"
        onClose={vi.fn()}
      />,
    );

    expect(screen.getAllByText("失败")).toHaveLength(4);
    expect(screen.getByText(/探测失败 · Wails IPC：Wails IPC runtime snapshot failed/)).toBeInTheDocument();
  });

  it("surfaces the latest probe failure in the footer", () => {
    render(
      <RuntimeSettingsFooter
        notice=""
        backendConnected
        probeState="failed"
        probeTransport="http-fallback"
        probeError="后端鉴权失败"
      />,
    );

    expect(screen.getByText(/最近一次探测失败（HTTP fallback）：后端鉴权失败/)).toBeInTheDocument();
  });

  it("surfaces successful HTTP fallback diagnostics in the footer", () => {
    render(
      <RuntimeSettingsFooter
        notice=""
        backendConnected
        probeState="ready"
        probeTransport="http-fallback"
        probeError=""
        probeTransportError="runtime ipc unavailable"
      />,
    );

    expect(
      screen.getByText(/最近一次探测已通过 HTTP fallback 完成；备用链路原因：runtime ipc unavailable/),
    ).toBeInTheDocument();
  });
});
