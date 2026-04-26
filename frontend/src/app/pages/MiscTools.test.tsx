import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listMiscModules: vi.fn(),
  importMiscModulePackage: vi.fn(),
  deleteMiscModule: vi.fn(),
  runMiscModule: vi.fn(),
  getHTTPLoginAnalysis: vi.fn(),
  getMySQLAnalysis: vi.fn(),
  getSMTPAnalysis: vi.fn(),
  getShiroRememberMeAnalysis: vi.fn(),
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
  bridge: {
    listMiscModules: mocks.listMiscModules,
    importMiscModulePackage: mocks.importMiscModulePackage,
    deleteMiscModule: mocks.deleteMiscModule,
    runMiscModule: mocks.runMiscModule,
    getHTTPLoginAnalysis: mocks.getHTTPLoginAnalysis,
    getMySQLAnalysis: mocks.getMySQLAnalysis,
    getSMTPAnalysis: mocks.getSMTPAnalysis,
    getShiroRememberMeAnalysis: mocks.getShiroRememberMeAnalysis,
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

async function expandModule(moduleID: string) {
  const toggle = await screen.findByTestId(`misc-module-toggle-${moduleID}`);
  fireEvent.click(toggle);
}

describe("MiscTools SMB3 session candidates", () => {
  beforeEach(() => {
    mocks.sentinelState.fileMeta.path = "C:/captures/capture.pcapng";
    mocks.sentinelState.fileMeta.name = "capture.pcapng";
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.sentinelState.setActiveStream.mockReset();
    mocks.sentinelState.locatePacketById.mockResolvedValue(null);
    mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 44 });
    mocks.sentinelState.setActiveStream.mockResolvedValue(undefined);
    mocks.listMiscModules.mockReset();
    mocks.importMiscModulePackage.mockReset();
    mocks.deleteMiscModule.mockReset();
    mocks.runMiscModule.mockReset();
    mocks.getHTTPLoginAnalysis.mockReset();
    mocks.getMySQLAnalysis.mockReset();
    mocks.getSMTPAnalysis.mockReset();
    mocks.getShiroRememberMeAnalysis.mockReset();
    mocks.listNTLMSessionMaterials.mockReset();
    mocks.listSMB3SessionCandidates.mockReset();
    mocks.generateSMB3RandomSessionKey.mockReset();
    mocks.runWinRMDecrypt.mockReset();
    mocks.getWinRMDecryptResultText.mockReset();
    mocks.exportWinRMDecryptResult.mockReset();
    mocks.navigate.mockReset();
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
    mocks.getHTTPLoginAnalysis.mockResolvedValue({
      totalAttempts: 1,
      candidateEndpoints: 1,
      successCount: 1,
      failureCount: 0,
      uncertainCount: 0,
      bruteforceCount: 0,
      endpoints: [
        {
          key: "POST|demo.local|/login",
          method: "POST",
          host: "demo.local",
          path: "/login",
          attemptCount: 1,
          successCount: 1,
          failureCount: 0,
          uncertainCount: 0,
          requestKeys: ["username", "password"],
          responseIndicators: ["set-cookie"],
        },
      ],
      attempts: [
        {
          packetId: 11,
          streamId: 9,
          method: "POST",
          host: "demo.local",
          path: "/login",
          username: "alice",
          passwordPresent: true,
          statusCode: 302,
          result: "success",
          reason: "redirect",
        },
      ],
      notes: ["demo note"],
    });
    mocks.getSMTPAnalysis.mockResolvedValue({
      sessionCount: 1,
      messageCount: 1,
      authCount: 1,
      attachmentHintCount: 1,
      sessions: [
        {
          streamId: 7,
          client: "10.0.0.10",
          server: "10.0.0.20",
          clientPort: 51234,
          serverPort: 25,
          helo: "demo.local",
          authMechanisms: ["LOGIN"],
          authUsername: "alice",
          authPasswordSeen: true,
          mailFrom: ["alice@example.com"],
          rcptTo: ["bob@example.com"],
          commandCount: 6,
          messageCount: 1,
          attachmentHints: 1,
          commands: [
            { packetId: 201, direction: "client", command: "EHLO", summary: "EHLO demo.local" },
            { packetId: 202, direction: "client", command: "AUTH", summary: "AUTH LOGIN" },
          ],
          statusHints: ["AUTH"],
          messages: [
            {
              sequence: 1,
              subject: "Quarterly Report",
              from: "Alice <alice@example.com>",
              to: "Bob <bob@example.com>",
              attachmentNames: ["report.zip"],
              bodyPreview: "Please find the report attached.",
              packetIds: [203, 204],
            },
          ],
          possibleCleartext: true,
        },
      ],
      notes: ["SMTP note"],
    });
    mocks.getMySQLAnalysis.mockResolvedValue({
      sessionCount: 1,
      loginCount: 1,
      queryCount: 2,
      errorCount: 1,
      resultsetCount: 1,
      sessions: [
        {
          streamId: 12,
          client: "10.0.0.10",
          server: "10.0.0.30",
          clientPort: 52000,
          serverPort: 3306,
          serverVersion: "8.0.36",
          connectionId: 77,
          username: "app",
          database: "inventory",
          authPlugin: "mysql_native_password",
          loginPacketId: 301,
          loginSuccess: true,
          queryCount: 2,
          okCount: 1,
          errCount: 1,
          resultsetCount: 1,
          commandTypes: ["LOGIN", "COM_QUERY"],
          queries: [
            { packetId: 302, command: "COM_QUERY", sql: "SELECT * FROM users", responseKind: "RESULTSET", responsePacketId: 303 },
            { packetId: 304, command: "COM_QUERY", sql: "DELETE FROM audit_logs", responseKind: "ERR", responseCode: 1096, responsePacketId: 305, responseSummary: "syntax error" },
          ],
          serverEvents: [
            { packetId: 300, kind: "HANDSHAKE", summary: "8.0.36" },
            { packetId: 305, kind: "ERR", code: 1096, summary: "syntax error" },
          ],
          notes: ["识别到用户名 app"],
        },
      ],
      notes: ["MySQL note"],
    });
    mocks.getShiroRememberMeAnalysis.mockResolvedValue({
      candidateCount: 1,
      hitCount: 1,
      candidates: [
        {
          packetId: 401,
          streamId: 44,
          time: "2026-04-26T13:14:15Z",
          src: "10.0.0.10",
          dst: "10.0.0.20",
          host: "shiro.demo",
          path: "/dashboard",
          sourceHeader: "Cookie",
          cookieName: "rememberMe",
          cookiePreview: "QmFzZTY0U2FtcGxl",
          decodeOK: true,
          encryptedLength: 48,
          aesBlockAligned: true,
          possibleCBC: true,
          possibleGCM: true,
          hitCount: 1,
          keyResults: [
            {
              label: "shiro-default",
              base64: "kPH+bIxk5D2deZiIxcaaaA==",
              algorithm: "AES-CBC",
              hit: true,
              payloadClass: "org.apache.shiro.subject.SimplePrincipalCollection",
              preview: "org.apache.shiro.subject.SimplePrincipalCollection",
            },
          ],
          notes: ["命中 1 个候选密钥"],
        },
      ],
      notes: ["Shiro note"],
    });
    mocks.listNTLMSessionMaterials.mockResolvedValue([
      {
        protocol: "HTTP",
        transport: "NTLMSSP",
        frameNumber: "55",
        timestamp: "Apr 21",
        src: "10.0.0.10",
        dst: "10.0.0.20",
        direction: "client->server",
        username: "Administrator",
        domain: "LAB",
        userDisplay: "LAB\\Administrator",
        challenge: "11223344",
        ntProofStr: "00112233445566778899aabbccddeeff",
        encryptedSessionKey: "ffeeddccbbaa99887766554433221100",
        sessionId: "0x99",
        info: "NTLM auth",
        complete: true,
        displayLabel: "LAB\\Administrator | HTTP | 帧 #55",
      },
      {
        protocol: "SMB3",
        transport: "NTLMSSP",
        frameNumber: "56",
        timestamp: "Apr 21",
        src: "10.0.0.10",
        dst: "10.0.0.20",
        direction: "server->client",
        username: "Guest",
        domain: "",
        userDisplay: "Guest",
        challenge: "",
        ntProofStr: "",
        encryptedSessionKey: "",
        sessionId: "0x100",
        info: "guest auth",
        complete: false,
        displayLabel: "Guest | SMB3 | 帧 #56",
      },
    ]);
    mocks.listMiscModules.mockResolvedValue([
      {
        id: "http-login-analysis",
        kind: "builtin",
        title: "HTTP 登录行为分析",
        summary: "http auth summary",
        tags: ["HTTP", "Login"],
        apiPrefix: "/api/tools/http-login-analysis",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "HTTP / Auth",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "http"],
      },
      {
        id: "mysql-session-analysis",
        kind: "builtin",
        title: "MySQL 会话重建",
        summary: "mysql summary",
        tags: ["MySQL", "DB"],
        apiPrefix: "/api/tools/mysql-analysis",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "MySQL / Database",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "mysql"],
      },
      {
        id: "smtp-session-analysis",
        kind: "builtin",
        title: "SMTP 会话重建",
        summary: "smtp summary",
        tags: ["SMTP", "Mail"],
        apiPrefix: "/api/tools/smtp-analysis",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "SMTP / Mail",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "smtp"],
      },
      {
        id: "shiro-rememberme-analysis",
        kind: "builtin",
        title: "Shiro rememberMe 分析",
        summary: "shiro summary",
        tags: ["Shiro", "rememberMe"],
        apiPrefix: "/api/tools/shiro-rememberme",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "HTTP / Shiro",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "http"],
      },
      {
        id: "winrm-decrypt",
        kind: "builtin",
        title: "WinRM 解密辅助",
        summary: "winrm summary",
        tags: ["WinRM"],
        apiPrefix: "/api/tools/winrm-decrypt",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "NTLM / WinRM",
        supportsExport: true,
        cancellable: true,
        dependsOn: ["capture", "http", "ntlm"],
      },
      {
        id: "ntlm-session-materials",
        kind: "builtin",
        title: "NTLM 会话材料中心",
        summary: "ntlm summary",
        tags: ["NTLM", "HTTP", "WinRM", "SMB3"],
        apiPrefix: "/api/tools/ntlm-sessions",
        docsPath: "docs/misc-module-interface.md",
        requiresCapture: true,
        protocolDomain: "NTLM",
        supportsExport: true,
        cancellable: false,
        dependsOn: ["capture", "ntlm"],
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
        protocolDomain: "SMB3 / NTLM",
        supportsExport: false,
        cancellable: false,
        dependsOn: ["capture", "ntlm"],
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
      expect(mocks.getHTTPLoginAnalysis).toHaveBeenCalledTimes(1);
      expect(mocks.getMySQLAnalysis).toHaveBeenCalledTimes(1);
      expect(mocks.getSMTPAnalysis).toHaveBeenCalledTimes(1);
      expect(mocks.getShiroRememberMeAnalysis).toHaveBeenCalledTimes(1);
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
    });

    await expandModule("ntlm-session-materials");
    await expandModule("mysql-session-analysis");
    await expandModule("smtp-session-analysis");
    await expandModule("shiro-rememberme-analysis");
    await expandModule("smb3-session-key");

    expect(await screen.findByText("已发现 2 条候选，其中 1 条材料完整")).toBeInTheDocument();
    expect(screen.getByTestId("smb-session-candidate-101")).toBeInTheDocument();
    expect(screen.getByTestId("smb-session-candidate-102")).toBeInTheDocument();
    expect(screen.getAllByText("LAB\\Administrator").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Guest").length).toBeGreaterThan(0);
    expect(screen.getAllByText("MySQL 会话重建").length).toBeGreaterThan(0);
    expect(screen.getByText("DELETE FROM audit_logs")).toBeInTheDocument();
    expect(screen.getAllByText("SMTP 会话重建").length).toBeGreaterThan(0);
    expect(screen.getByText("Quarterly Report")).toBeInTheDocument();
    expect(screen.getAllByText("Shiro rememberMe 分析").length).toBeGreaterThan(0);
    expect(screen.getByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument();
  });

  it("links Shiro rememberMe candidates back to packet and stream evidence", async () => {
    render(<MiscTools />);

    await expandModule("shiro-rememberme-analysis");
    expect(await screen.findByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "定位到包" }));
    await waitFor(() => {
      expect(mocks.sentinelState.locatePacketById).toHaveBeenCalledWith(401);
    });
    expect(mocks.navigate).toHaveBeenCalledWith("/");

    fireEvent.click(screen.getByRole("button", { name: "打开关联流" }));
    await waitFor(() => {
      expect(mocks.sentinelState.preparePacketStream).toHaveBeenCalledWith(401, "HTTP");
    });
    expect(mocks.navigate).toHaveBeenCalledWith("/http-stream", { state: { streamId: 44 } });
  });

  it("autofills non-hash fields after selecting a candidate and keeps hash editable", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalled();
    });

    await expandModule("smb3-session-key");

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
      expect(mocks.getHTTPLoginAnalysis).not.toHaveBeenCalled();
      expect(mocks.getMySQLAnalysis).not.toHaveBeenCalled();
      expect(mocks.getSMTPAnalysis).not.toHaveBeenCalled();
      expect(mocks.getShiroRememberMeAnalysis).not.toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();
    }).then(async () => {
      await expandModule("smb3-session-key");
      const selector = screen.getByTestId("smb-session-candidate-select");
      expect(selector).toHaveAttribute("aria-disabled", "true");
      expect(selector).toHaveTextContent("未加载抓包，请先在主工作区导入文件");
    });
  });

  it("shows a concise error when candidate loading fails", async () => {
    mocks.listSMB3SessionCandidates.mockRejectedValueOnce(new Error("扫描 SMB3 Session 候选失败"));

    render(<MiscTools />);

    await expandModule("smb3-session-key");
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
