import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import {
  allowTSharkDirAction,
  refreshTSharkAllowedDirsAction,
  removeTSharkAllowedDirAction,
} from "./toolRuntimeTSharkActions";

const bridgeMocks = vi.hoisted(() => ({
  allowTSharkDir: vi.fn(),
  removeTSharkAllowedDir: vi.fn(),
  listTSharkAllowedDirs: vi.fn(),
}));

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    runtime: {
      allowTSharkDir: bridgeMocks.allowTSharkDir,
      removeTSharkAllowedDir: bridgeMocks.removeTSharkAllowedDir,
      listTSharkAllowedDirs: bridgeMocks.listTSharkAllowedDirs,
    },
  },
}));

const emptyConfig: ToolRuntimeConfig = {
  tsharkPath: "",
  tsharkAllowedDirs: [],
  ffmpegPath: "",
  pythonPath: "",
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

function createSnapshot(
  tsharkOverrides: Partial<ToolRuntimeSnapshot["tshark"]> = {},
  configOverride: Partial<ToolRuntimeConfig> = {},
): ToolRuntimeSnapshot {
  return {
    config: { ...emptyConfig, ...configOverride },
    tshark: {
      available: false,
      path: "",
      message: "unavailable",
      usingCustomPath: false,
      ...tsharkOverrides,
    },
    ffmpeg: { available: false, path: "", message: "unavailable", usingCustomPath: false },
    speech: {
      available: false,
      message: "unavailable",
      engine: "",
      language: "",
      pythonAvailable: false,
      ffmpegAvailable: false,
      voskAvailable: false,
      modelAvailable: false,
    },
    yara: {
      available: false,
      enabled: false,
      message: "unavailable",
      usingCustomBin: false,
      usingCustomRules: false,
      timeoutMs: 25000,
    },
  };
}

function createStatus(overrides: Partial<TSharkStatus> = {}): TSharkStatus {
  return {
    available: false,
    path: "",
    message: "unavailable",
    customPath: "",
    usingCustomPath: false,
    ...overrides,
  };
}

describe("allowTSharkDirAction", () => {
  beforeEach(() => {
    localStorage.clear();
    bridgeMocks.allowTSharkDir.mockReset();
  });

  it("deduplicates directories case-insensitively", async () => {
    bridgeMocks.allowTSharkDir.mockResolvedValue(createStatus({ extraAllowedDir: "C:/Tools" }));
    const setBackendStatus = vi.fn();
    const setTsharkStatus = vi.fn();
    const setToolRuntimeSnapshot = vi.fn();

    await allowTSharkDirAction("C:/Tools", true, {
      setBackendStatus,
      setTsharkStatus,
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot({ customPath: "C:/Tools/tshark.exe" }),
    });

    expect(bridgeMocks.allowTSharkDir).toHaveBeenCalledWith("C:/Tools");
    expect(setTsharkStatus).toHaveBeenCalled();
    expect(setToolRuntimeSnapshot).toHaveBeenCalled();
  });

  it("appends a new directory and persists it", async () => {
    bridgeMocks.allowTSharkDir.mockResolvedValue(
      createStatus({ available: true, path: "C:/Tools/tshark.exe", extraAllowedDir: "C:/Tools" }),
    );
    const setBackendStatus = vi.fn();
    const setTsharkStatus = vi.fn();
    const setToolRuntimeSnapshot = vi.fn();

    await allowTSharkDirAction("C:/Tools", true, {
      setBackendStatus,
      setTsharkStatus,
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot(),
    });

    expect(bridgeMocks.allowTSharkDir).toHaveBeenCalledWith("C:/Tools");
    expect(setBackendStatus).toHaveBeenCalled();
  });

  it("updates local config when backend is disconnected", async () => {
    const setBackendStatus = vi.fn();
    const setTsharkStatus = vi.fn();
    const setToolRuntimeSnapshot = vi.fn();

    await allowTSharkDirAction("C:/Tools", false, {
      setBackendStatus,
      setTsharkStatus,
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot(),
    });

    expect(bridgeMocks.allowTSharkDir).not.toHaveBeenCalled();
    expect(setToolRuntimeSnapshot).toHaveBeenCalled();
  });
});

describe("removeTSharkAllowedDirAction", () => {
  beforeEach(() => {
    localStorage.clear();
    bridgeMocks.removeTSharkAllowedDir.mockReset();
  });

  it("removes a directory and refreshes status", async () => {
    bridgeMocks.removeTSharkAllowedDir.mockResolvedValue(createStatus({ available: true, path: "tshark.exe" }));
    const setBackendStatus = vi.fn();
    const setTsharkStatus = vi.fn();
    const setToolRuntimeSnapshot = vi.fn();

    await removeTSharkAllowedDirAction("C:/Tools", true, {
      setBackendStatus,
      setTsharkStatus,
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot({}, { tsharkAllowedDirs: ["C:/Tools"] }),
    });

    expect(bridgeMocks.removeTSharkAllowedDir).toHaveBeenCalledWith("C:/Tools");
    expect(setTsharkStatus).toHaveBeenCalled();
  });

  it("updates local config when backend is disconnected", async () => {
    const setBackendStatus = vi.fn();
    const setTsharkStatus = vi.fn();
    const setToolRuntimeSnapshot = vi.fn();

    await removeTSharkAllowedDirAction("C:/Tools", false, {
      setBackendStatus,
      setTsharkStatus,
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot({}, { tsharkAllowedDirs: ["C:/Tools"] }),
    });

    expect(bridgeMocks.removeTSharkAllowedDir).not.toHaveBeenCalled();
    expect(setToolRuntimeSnapshot).toHaveBeenCalled();
  });
});

describe("refreshTSharkAllowedDirsAction", () => {
  beforeEach(() => {
    localStorage.clear();
    bridgeMocks.listTSharkAllowedDirs.mockReset();
  });

  it("returns backend allowed dirs and updates config", async () => {
    bridgeMocks.listTSharkAllowedDirs.mockResolvedValue(["C:/Tools"]);
    const setToolRuntimeSnapshot = vi.fn();

    const dirs = await refreshTSharkAllowedDirsAction(true, {
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot(),
    });

    expect(dirs).toEqual(["C:/Tools"]);
    expect(bridgeMocks.listTSharkAllowedDirs).toHaveBeenCalled();
    expect(setToolRuntimeSnapshot).toHaveBeenCalled();
  });

  it("falls back to local config when backend is disconnected", async () => {
    const setToolRuntimeSnapshot = vi.fn();

    const dirs = await refreshTSharkAllowedDirsAction(false, {
      setToolRuntimeSnapshot,
      toolRuntimeSnapshot: createSnapshot({}, { tsharkAllowedDirs: ["C:/Local"] }),
    });

    expect(dirs).toEqual(["C:/Local"]);
    expect(bridgeMocks.listTSharkAllowedDirs).not.toHaveBeenCalled();
  });
});
