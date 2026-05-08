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

async function expandModule(moduleID: string) {
  const toggle = await screen.findByTestId(`misc-module-toggle-${moduleID}`);
  fireEvent.click(toggle);
}

describe("MiscTools SMB3 session candidates", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("renders the MISC payload decoder workbench and decodes a Base64 candidate", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    fireEvent.click(await screen.findByRole("button", { name: "示例" }, { timeout: 10000 }));
    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }, { timeout: 5000 }));

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith("pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==", expect.any(AbortSignal));
    });
    expect(await screen.findByText("参数 pass")).toBeInTheDocument();
    expect(screen.getByText("无需抓包")).toBeInTheDocument();
    expect(screen.getByText("可取消")).toBeInTheDocument();
    expect(screen.getAllByText("支持导出").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("实验性")).toBeInTheDocument();
    expect(screen.getByText("候选可疑与低置信结果需要人工确认")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Base64" }));

    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalledWith(
        "base64",
        "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        {},
        expect.any(AbortSignal),
      );
    });
    expect(await screen.findByText("assert($_POST['cmd']);")).toBeInTheDocument();
    expect(screen.getByText("置信度 96%")).toBeInTheDocument();
    expect(screen.getByText("keyword:assert")).toBeInTheDocument();
    expect(screen.getByText("Behinder (ECB): AES-ECB 密文长度非法")).toBeInTheDocument();
  }, 20000);

  it("loads suspicious URI sources and fills the payload textarea from a selected source", async () => {
    mocks.listStreamPayloadSources.mockResolvedValueOnce([
      {
        id: "pkt-81-form-pass",
        method: "POST",
        host: "web.test",
        uri: "/shell.php",
        packetId: 81,
        streamId: 9,
        sourceType: "form",
        paramName: "pass",
        payload: "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        preview: "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        confidence: 92,
        signals: ["suspicious-uri", "suspicious-param", "script-after-base64"],
        decoderHints: ["antsword", "base64"],
        familyHint: "antsword_like",
        sourceRole: "script_or_command",
        decoderOptionsHint: {
          decoder: "antsword",
          pass: "pass",
          extractParam: true,
          urlDecodeRounds: 1,
        },
      },
    ]);
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    expect(await screen.findByText("可疑 URI / 参数来源")).toBeInTheDocument();
    const sourceText = await screen.findByText(/web\.test\/shell\.php/);
    const sourceButton = sourceText.closest("button");
    expect(sourceButton).toBeTruthy();
    fireEvent.click(sourceButton!);

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith("YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==", expect.any(AbortSignal));
    });
    expect(screen.getByDisplayValue("YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==")).toBeInTheDocument();
    expect(screen.getByText(/当前输入来自 packet #81/)).toBeInTheDocument();
    expect((await screen.findAllByText("antsword_like")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("script_or_command").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("antsword").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "AntSword" }));
    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalledWith(
        "antsword",
        "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        expect.objectContaining({
          pass: "pass",
          extractParam: true,
          urlDecodeRounds: 1,
        }),
        expect.any(AbortSignal),
      );
    });
  });

  it("keeps Godzilla source hints when payload re-inspection is weaker", async () => {
    mocks.listStreamPayloadSources.mockResolvedValueOnce([
      {
        id: "pkt-82-form-7f0e6f",
        method: "POST",
        host: "web.test",
        uri: "/index.jsp",
        packetId: 82,
        streamId: 10,
        sourceType: "form",
        paramName: "7f0e6f",
        payload: "AAECAwQFBgcICQoLDA0ODw==",
        preview: "AAECAwQFBgcICQoLDA0ODw==",
        confidence: 96,
        signals: ["godzilla_like", "encrypted_blob", "godzilla-random-param"],
        decoderHints: ["godzilla", "auto"],
        familyHint: "godzilla_like",
        sourceRole: "encrypted_blob",
        decoderOptionsHint: {
          decoder: "godzilla",
          pass: "7f0e6f",
          extractParam: true,
          urlDecodeRounds: 1,
          inputEncoding: "base64",
          cipher: "aes_ecb",
          stripMarkers: true,
        },
      },
    ]);
    mocks.inspectStreamPayload.mockResolvedValueOnce({
      normalizedPayload: "AAECAwQFBgcICQoLDA0ODw==",
      candidates: [
        {
          id: "payload-0",
          label: "当前 payload",
          kind: "payload",
          value: "AAECAwQFBgcICQoLDA0ODw==",
          preview: "AAECAwQFBgcICQoLDA0ODw==",
          confidence: 78,
          decoderHints: ["behinder", "godzilla", "auto"],
          fingerprints: ["base64-aes-block"],
          familyHint: "aes_webshell_like",
          sourceRole: "encrypted_blob",
          decoderOptionsHint: {
            decoder: "behinder",
            extractParam: false,
            urlDecodeRounds: 1,
            inputEncoding: "base64",
            deriveKeyFromPass: true,
          },
        },
      ],
      suggestedCandidateId: "payload-0",
      suggestedDecoder: "behinder",
      suggestedFamily: "aes_webshell_like",
      confidence: 78,
      reasons: ["候选值 Base64 解码后长度符合 AES 分组且可打印率低。"],
    });

    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    const sourceText = await screen.findByText(/web\.test\/index\.jsp/);
    const sourceButton = sourceText.closest("button");
    expect(sourceButton).toBeTruthy();
    fireEvent.click(sourceButton!);

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith("AAECAwQFBgcICQoLDA0ODw==", expect.any(AbortSignal));
    });
    fireEvent.click(screen.getByRole("button", { name: "Godzilla" }));

    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalled();
    });
    const [, , options] = mocks.decodeStreamPayload.mock.calls.at(-1)!;
    expect(options).toMatchObject({
      pass: "7f0e6f",
      extractParam: true,
      urlDecodeRounds: 1,
      inputEncoding: "base64",
      cipher: "aes_ecb",
      stripMarkers: true,
    });
    expect((options as Record<string, unknown>).key ?? "").toBe("");
  });

  it("keeps manual payload workflow available when no capture is loaded", async () => {
    mocks.sentinelState.fileMeta.path = "";
    mocks.sentinelState.fileMeta.name = "";
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    expect(await screen.findByText(/可先手动粘贴 payload/)).toBeInTheDocument();
    expect(mocks.listStreamPayloadSources).not.toHaveBeenCalled();
  });

  it("keeps low-confidence auto detection as an explicit review state", async () => {
    mocks.inspectStreamPayload.mockResolvedValueOnce({
      normalizedPayload: "just-random-text",
      candidates: [
        {
          id: "payload-0",
          label: "当前 payload",
          kind: "payload",
          value: "just-random-text",
          confidence: 15,
          decoderHints: ["auto"],
          fingerprints: [],
        },
      ],
      suggestedCandidateId: "payload-0",
      suggestedDecoder: "auto",
      suggestedFamily: "plain",
      confidence: 15,
      reasons: ["已提取出可操作 payload 候选。"],
    });
    mocks.decodeStreamPayload.mockRejectedValueOnce(new Error("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空"));

    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), { target: { value: "just-random-text" } });
    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("当前 payload")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "自动检测" }));

    expect(await screen.findByText("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空")).toBeInTheDocument();
  });

  it("re-runs payload inspection when the same input is submitted again", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), {
      target: { value: "pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==" },
    });

    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledTimes(1);
    });

    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledTimes(2);
    });
  });

  it("shows an immediate hint and skips inspect for empty payload input", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder");

    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("请输入 payload 后再识别候选。")).toBeInTheDocument();
    expect(mocks.inspectStreamPayload).not.toHaveBeenCalled();
  });

  it("loads candidates and renders detailed selector options", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalledTimes(1);
      expect(mocks.getHTTPLoginAnalysis).toHaveBeenCalledTimes(1);
    });
    expect(mocks.getMySQLAnalysis).not.toHaveBeenCalled();
    expect(mocks.getSMTPAnalysis).not.toHaveBeenCalled();
    expect(mocks.getShiroRememberMeAnalysis).not.toHaveBeenCalled();
    expect(mocks.listNTLMSessionMaterials).not.toHaveBeenCalled();
    expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();

    await expandModule("ntlm-session-materials");
    await waitFor(() => {
      expect(mocks.listNTLMSessionMaterials).toHaveBeenCalledTimes(1);
    });

    await expandModule("mysql-session-analysis");
    await waitFor(() => {
      expect(mocks.getMySQLAnalysis).toHaveBeenCalledTimes(1);
    });

    await expandModule("smtp-session-analysis");
    await waitFor(() => {
      expect(mocks.getSMTPAnalysis).toHaveBeenCalledTimes(1);
    });

    await expandModule("shiro-rememberme-analysis");
    await waitFor(() => {
      expect(mocks.getShiroRememberMeAnalysis).toHaveBeenCalledTimes(1);
    });

    await expandModule("smb3-session-key");
    await waitFor(() => {
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
    });

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
    });
    expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();

    await expandModule("smb3-session-key");
    await waitFor(() => {
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
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
