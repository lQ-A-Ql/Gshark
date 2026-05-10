import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  navigate: vi.fn(),
  sentinelState: {
    fileMeta: {
      path: "",
      name: "",
      sizeBytes: 0,
    },
    backendConnected: true,
    backendStatus: "后端已连接",
    captureTransaction: {
      phase: "idle",
      reason: "",
      message: "",
      pendingCaptureName: "",
      pendingCapturePath: "",
      hasActiveCapture: false,
    },
    tsharkStatus: {
      available: true,
      path: "tshark",
      message: "",
    },
    recentCaptures: [],
    openCapture: vi.fn(),
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

vi.mock("../state/SentinelContext", () => ({
  formatBytes: (value: number) => `${value} B`,
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../../assets/logo.png", () => ({
  default: "logo.png",
}));

import AnalysisCockpit from "./AnalysisCockpit";

describe("AnalysisCockpit capture import", () => {
  beforeEach(() => {
    mocks.navigate.mockReset();
    mocks.sentinelState.openCapture.mockReset();
    mocks.sentinelState.fileMeta.path = "";
    mocks.sentinelState.fileMeta.name = "";
    mocks.sentinelState.fileMeta.sizeBytes = 0;
    mocks.sentinelState.openCapture.mockResolvedValue(true);
  });

  it("navigates to workspace after a capture opens from the cockpit welcome state", async () => {
    render(<AnalysisCockpit />);

    fireEvent.click(screen.getByRole("button", { name: "选择文件" }));

    await waitFor(() => {
      expect(mocks.sentinelState.openCapture).toHaveBeenCalledWith(undefined);
    });
    expect(mocks.navigate).toHaveBeenCalledWith("/");
  });

  it("stays on the cockpit welcome state when capture open fails", async () => {
    mocks.sentinelState.openCapture.mockResolvedValue(false);

    render(<AnalysisCockpit />);

    fireEvent.click(screen.getByRole("button", { name: "选择文件" }));

    await waitFor(() => {
      expect(mocks.sentinelState.openCapture).toHaveBeenCalledWith(undefined);
    });
    expect(mocks.navigate).not.toHaveBeenCalled();
  });
});
