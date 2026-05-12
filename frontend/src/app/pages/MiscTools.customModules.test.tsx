import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resetMiscToolsMocks } from "./MiscTools.testFixtures";

const mocks = vi.hoisted(() => ({
  listMiscModules: vi.fn(),
  importMiscModulePackage: vi.fn(),
  deleteMiscModule: vi.fn(),
  runMiscModule: vi.fn(),
  getHTTPLoginAnalysis: vi.fn(),
  getMySQLAnalysis: vi.fn(),
  getSMTPAnalysis: vi.fn(),
  getShiroRememberMeAnalysis: vi.fn(),
  decodeStreamPayload: vi.fn(),
  inspectStreamPayload: vi.fn(),
  listStreamPayloadSources: vi.fn(),
  listNTLMSessionMaterials: vi.fn(),
  listSMB3SessionCandidates: vi.fn(),
  generateSMB3RandomSessionKey: vi.fn(),
  runWinRMDecrypt: vi.fn(),
  getWinRMDecryptResultText: vi.fn(),
  exportWinRMDecryptResult: vi.fn(),
  navigate: vi.fn(),
  sentinelState: {
    fileMeta: {
      name: "capture.pcapng",
      sizeBytes: 2048,
      path: "C:/captures/capture.pcapng",
    },
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
    setActiveStream: vi.fn(),
  },
}));

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  backendClients: {
    miscModule: {
      listMiscModules: mocks.listMiscModules,
      importMiscModulePackage: mocks.importMiscModulePackage,
      deleteMiscModule: mocks.deleteMiscModule,
      runMiscModule: mocks.runMiscModule,
    },
    securityMaterial: {
      runWinRMDecrypt: mocks.runWinRMDecrypt,
      getWinRMDecryptResultText: mocks.getWinRMDecryptResultText,
      exportWinRMDecryptResult: mocks.exportWinRMDecryptResult,
    },
    stream: { decodeStreamPayload: mocks.decodeStreamPayload, inspectStreamPayload: mocks.inspectStreamPayload, listStreamPayloadSources: mocks.listStreamPayloadSources },
  },
  bridge: {
    listMiscModules: mocks.listMiscModules,
    importMiscModulePackage: mocks.importMiscModulePackage,
    deleteMiscModule: mocks.deleteMiscModule,
    runMiscModule: mocks.runMiscModule,
    getHTTPLoginAnalysis: mocks.getHTTPLoginAnalysis,
    getMySQLAnalysis: mocks.getMySQLAnalysis,
    getSMTPAnalysis: mocks.getSMTPAnalysis,
    getShiroRememberMeAnalysis: mocks.getShiroRememberMeAnalysis,
    decodeStreamPayload: mocks.decodeStreamPayload,
    inspectStreamPayload: mocks.inspectStreamPayload,
    listStreamPayloadSources: mocks.listStreamPayloadSources,
    listNTLMSessionMaterials: mocks.listNTLMSessionMaterials,
    listSMB3SessionCandidates: mocks.listSMB3SessionCandidates,
    generateSMB3RandomSessionKey: mocks.generateSMB3RandomSessionKey,
    runWinRMDecrypt: mocks.runWinRMDecrypt,
    getWinRMDecryptResultText: mocks.getWinRMDecryptResultText,
    exportWinRMDecryptResult: mocks.exportWinRMDecryptResult,
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import MiscTools from "./MiscTools";

describe("MiscTools custom modules", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("renders generic cards for registered custom modules without dedicated renderer", async () => {
    mocks.listMiscModules.mockResolvedValueOnce([
      {
        id: "custom-demo",
        kind: "custom",
        title: "Custom Demo",
        summary: "custom module summary",
        tags: ["Custom"],
        apiPrefix: "/api/tools/misc/custom-demo",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: false,
      },
    ]);

    render(<MiscTools />);

    expect((await screen.findAllByText("Custom Demo")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("custom module summary").length).toBeGreaterThan(0);
    expect(screen.getByText(/API 前缀:/)).toBeInTheDocument();
  });

  it("renders enhanced misc module metadata chips in the generic renderer", async () => {
    mocks.listMiscModules.mockResolvedValueOnce([
      {
        id: "custom-demo",
        kind: "custom",
        title: "Custom Demo",
        summary: "custom module summary",
        tags: ["Custom"],
        apiPrefix: "/api/tools/misc/custom-demo",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "HTTP / Auth",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "http"],
      },
    ]);

    render(<MiscTools />);

    expect((await screen.findAllByText("Custom Demo")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("HTTP / Auth").length).toBeGreaterThan(0);
    expect(screen.getAllByText("需要抓包").length).toBeGreaterThan(0);
    expect(screen.getByText("域: HTTP / Auth")).toBeInTheDocument();
    expect(screen.getAllByText("支持导出").length).toBeGreaterThan(0);
    expect(screen.getAllByText("支持中断").length).toBeGreaterThan(0);
    expect(screen.getByText("依赖: capture, http")).toBeInTheDocument();
  });

  it("deletes installed custom modules and refreshes the list", async () => {
    const confirmMock = vi.spyOn(window, "confirm").mockReturnValue(true);
    mocks.listMiscModules
      .mockResolvedValueOnce([
        {
          id: "custom-demo",
          kind: "custom",
          title: "Custom Demo",
          summary: "custom module summary",
          tags: ["Custom"],
          apiPrefix: "/api/tools/misc/packages/custom-demo",
          docsPath: "docs/misc-module-interface.md",
          requiresCapture: false,
        },
      ])
      .mockResolvedValueOnce([]);

    render(<MiscTools />);

    expect((await screen.findAllByText("Custom Demo")).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /删除模块/ }));

    await waitFor(() => {
      expect(mocks.deleteMiscModule).toHaveBeenCalledWith("custom-demo");
      expect(mocks.listMiscModules).toHaveBeenCalledTimes(2);
    });
    expect(await screen.findByText("当前筛选下没有可展示的 MISC 模块。")).toBeInTheDocument();
    confirmMock.mockRestore();
  });

  it("renders schema-driven custom modules and submits through the generic invoke bridge", async () => {
    mocks.listMiscModules.mockResolvedValueOnce([
      {
        id: "ioc-demo",
        kind: "custom",
        title: "IOC Demo",
        summary: "schema driven module",
        tags: ["IOC"],
        apiPrefix: "/api/tools/misc/packages/ioc-demo",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: false,
        interfaceSchema: {
          invokePath: "/api/tools/misc/packages/ioc-demo/invoke",
          runtime: "javascript",
        },
        formSchema: {
          description: "使用统一卡片模板渲染",
          submitLabel: "执行 IOC 模块",
          resultTitle: "执行结果",
          fields: [
            {
              name: "keyword",
              label: "Keyword",
              type: "text",
              defaultValue: "mimikatz",
            },
          ],
        },
      },
    ]);

    render(<MiscTools />);

    expect((await screen.findAllByText("IOC Demo")).length).toBeGreaterThan(0);
    expect(screen.getByText("使用统一卡片模板渲染")).toBeInTheDocument();

    const input = screen.getByLabelText("Keyword") as HTMLInputElement;
    expect(input.value).toBe("mimikatz");

    fireEvent.change(input, { target: { value: "cmd.exe" } });
    fireEvent.click(screen.getByRole("button", { name: "执行 IOC 模块" }));

    await waitFor(() => {
      expect(mocks.runMiscModule).toHaveBeenCalledWith("ioc-demo", { keyword: "cmd.exe" });
    });
    expect(await screen.findByText("generic result")).toBeInTheDocument();
    expect(screen.getByText("Field")).toBeInTheDocument();
    expect(screen.getByText("cmd.exe")).toBeInTheDocument();
  });
});
