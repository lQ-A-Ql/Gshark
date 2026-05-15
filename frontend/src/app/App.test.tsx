import { act, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupGate } from "./App";

const sentinelState = vi.hoisted(() => ({
  backendConnected: true,
  backendStatus: "后端已连接",
  tsharkStatus: {
    available: false,
    path: "",
    message: "未检测到 TShark，可在设置中配置",
    customPath: "",
    usingCustomPath: false,
  },
  isTSharkChecking: true,
  toolRuntimeCheckDegraded: false,
  setTSharkPath: vi.fn(),
}));

vi.mock("react-router", () => ({
  RouterProvider: () => <div data-testid="main-app" />,
}));

vi.mock("./routes", () => ({
  router: {},
}));

vi.mock("./state/SentinelContext", () => ({
  useSentinel: () => sentinelState,
  SentinelProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

describe("StartupGate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    sentinelState.backendConnected = true;
    sentinelState.isTSharkChecking = true;
    sentinelState.tsharkStatus.available = false;
    sentinelState.tsharkStatus.message = "未检测到 TShark，可在设置中配置";
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("enters the main app after backend connection even while TShark probing is degraded or slow", async () => {
    render(<StartupGate />);

    expect(screen.getByText("启动中")).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });

    expect(screen.getByTestId("main-app")).toBeInTheDocument();
  });
});
