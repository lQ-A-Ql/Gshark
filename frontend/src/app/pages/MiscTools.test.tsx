import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listMiscModules: vi.fn(),
  importMiscModulePackage: vi.fn(),
  deleteMiscModule: vi.fn(),
  runMiscModule: vi.fn(),
  listSMB3SessionCandidates: vi.fn(),
  generateSMB3RandomSessionKey: vi.fn(),
  runWinRMDecrypt: vi.fn(),
  getWinRMDecryptResultText: vi.fn(),
  exportWinRMDecryptResult: vi.fn(),
  sentinelState: {
    fileMeta: {
      name: "capture.pcapng",
      sizeBytes: 2048,
      path: "C:/captures/capture.pcapng",
    },
  },
}));

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  bridge: {
    listMiscModules: mocks.listMiscModules,
    importMiscModulePackage: mocks.importMiscModulePackage,
    deleteMiscModule: mocks.deleteMiscModule,
    runMiscModule: mocks.runMiscModule,
    listSMB3SessionCandidates: mocks.listSMB3SessionCandidates,
    generateSMB3RandomSessionKey: mocks.generateSMB3RandomSessionKey,
    runWinRMDecrypt: mocks.runWinRMDecrypt,
    getWinRMDecryptResultText: mocks.getWinRMDecryptResultText,
    exportWinRMDecryptResult: mocks.exportWinRMDecryptResult,
  },
}));

import MiscTools from "./MiscTools";

describe("MiscTools SMB3 session candidates", () => {
  beforeEach(() => {
    mocks.sentinelState.fileMeta.path = "C:/captures/capture.pcapng";
    mocks.sentinelState.fileMeta.name = "capture.pcapng";
    mocks.listMiscModules.mockReset();
    mocks.importMiscModulePackage.mockReset();
    mocks.deleteMiscModule.mockReset();
    mocks.runMiscModule.mockReset();
    mocks.listSMB3SessionCandidates.mockReset();
    mocks.generateSMB3RandomSessionKey.mockReset();
    mocks.runWinRMDecrypt.mockReset();
    mocks.getWinRMDecryptResultText.mockReset();
    mocks.exportWinRMDecryptResult.mockReset();
    mocks.deleteMiscModule.mockResolvedValue(undefined);
    mocks.runMiscModule.mockResolvedValue({
      message: "ok",
      text: "generic result",
      table: {
        columns: [
          { key: "field", label: "Field" },
          { key: "value", label: "Value" },
        ],
        rows: [
          { field: "keyword", value: "cmd.exe" },
        ],
      },
    });
    mocks.listMiscModules.mockResolvedValue([
      {
        id: "winrm-decrypt",
        kind: "builtin",
        title: "WinRM 解密辅助",
        summary: "winrm summary",
        tags: ["WinRM"],
        apiPrefix: "/api/tools/winrm-decrypt",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
      },
      {
        id: "smb3-session-key",
        kind: "builtin",
        title: "SMB3 Random Session Key",
        summary: "smb summary",
        tags: ["SMB3"],
        apiPrefix: "/api/tools/smb3",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
      },
    ]);
    mocks.listSMB3SessionCandidates.mockResolvedValue([
      {
        sessionId: "0x1122334455667788",
        username: "Administrator",
        domain: "LAB",
        ntProofStr: "00112233445566778899aabbccddeeff",
        encryptedSessionKey: "ffeeddccbbaa99887766554433221100",
        src: "10.0.0.10",
        dst: "10.0.0.20",
        frameNumber: "101",
        timestamp: "Apr 21",
        complete: true,
        displayLabel: "0x1122334455667788 | LAB\\Administrator | 10.0.0.10 -> 10.0.0.20 | 帧 #101",
      },
      {
        sessionId: "0x1122334455667788",
        username: "Guest",
        domain: "",
        ntProofStr: "",
        encryptedSessionKey: "",
        src: "10.0.0.10",
        dst: "10.0.0.20",
        frameNumber: "102",
        timestamp: "Apr 21",
        complete: false,
        displayLabel: "0x1122334455667788 | Guest | 10.0.0.10 -> 10.0.0.20 | 帧 #102",
      },
    ]);
  });

  it("loads candidates and renders detailed selector options", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalledTimes(1);
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
    });

    expect(await screen.findByText("已发现 2 条候选，其中 1 条材料完整")).toBeInTheDocument();
    expect(screen.getByTestId("smb-session-candidate-101")).toBeInTheDocument();
    expect(screen.getByTestId("smb-session-candidate-102")).toBeInTheDocument();
    expect(screen.getByText("LAB\\Administrator")).toBeInTheDocument();
    expect(screen.getByText("Guest")).toBeInTheDocument();
  });

  it("autofills non-hash fields after selecting a candidate and keeps hash editable", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalled();
    });

    const hashInput = screen.getByLabelText("NTLM Hash (十六进制)") as HTMLInputElement;
    fireEvent.change(hashInput, { target: { value: "31d6cfe0d16ae931b73c59d7e0c089c0" } });

    fireEvent.click(screen.getByTestId("smb-session-candidate-101"));

    expect((screen.getByLabelText("Username (用户名)") as HTMLInputElement).value).toBe("Administrator");
    expect((screen.getByLabelText("Domain (域名/可留空)") as HTMLInputElement).value).toBe("LAB");
    expect((screen.getByLabelText("NTProofStr") as HTMLInputElement).value).toBe("00112233445566778899aabbccddeeff");
    expect((screen.getByLabelText("Encrypted Session Key") as HTMLInputElement).value).toBe("ffeeddccbbaa99887766554433221100");
    expect(hashInput.value).toBe("31d6cfe0d16ae931b73c59d7e0c089c0");

    fireEvent.change(screen.getByLabelText("Username (用户名)"), { target: { value: "Admin2" } });
    expect((screen.getByLabelText("Username (用户名)") as HTMLInputElement).value).toBe("Admin2");
  });

  it("does not load candidates when no capture is active", () => {
    mocks.sentinelState.fileMeta.path = "";

    render(<MiscTools />);

    return waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();
      const selector = screen.getByTestId("smb-session-candidate-select");
      expect(selector).toHaveAttribute("aria-disabled", "true");
      expect(selector).toHaveTextContent("未加载抓包，请先在主工作区导入文件");
    });
  });

  it("shows a concise error when candidate loading fails", async () => {
    mocks.listSMB3SessionCandidates.mockRejectedValueOnce(new Error("扫描 SMB3 Session 候选失败"));

    render(<MiscTools />);

    expect(await screen.findByText("扫描 SMB3 Session 候选失败")).toBeInTheDocument();
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

    expect(await screen.findByText("Custom Demo")).toBeInTheDocument();
    expect(screen.getByText("custom module summary")).toBeInTheDocument();
    expect(screen.getByText(/API 前缀:/)).toBeInTheDocument();
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

    expect(await screen.findByText("Custom Demo")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /删除模块/ }));

    await waitFor(() => {
      expect(mocks.deleteMiscModule).toHaveBeenCalledWith("custom-demo");
      expect(mocks.listMiscModules).toHaveBeenCalledTimes(2);
    });
    expect(await screen.findByText("当前没有可展示的 MISC 模块。")).toBeInTheDocument();
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

    expect(await screen.findByText("IOC Demo")).toBeInTheDocument();
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
