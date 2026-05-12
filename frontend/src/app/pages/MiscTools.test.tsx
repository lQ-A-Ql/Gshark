import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";

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
    analysis: { getHTTPLoginAnalysis: mocks.getHTTPLoginAnalysis, getMySQLAnalysis: mocks.getMySQLAnalysis, getSMTPAnalysis: mocks.getSMTPAnalysis, getShiroRememberMeAnalysis: mocks.getShiroRememberMeAnalysis },
    securityMaterial: { listNTLMSessionMaterials: mocks.listNTLMSessionMaterials },
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

const SAMPLE_BASE64_PAYLOAD = "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==";

describe("MiscTools payload and session analysis", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("renders the MISC payload decoder workbench and decodes a Base64 candidate", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByRole("button", { name: "识别候选" })).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: "示例" }, { timeout: 10000 }));
    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }, { timeout: 5000 }));

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith(`pass=${SAMPLE_BASE64_PAYLOAD}`, expect.any(AbortSignal));
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
        SAMPLE_BASE64_PAYLOAD,
        {},
        expect.any(AbortSignal),
      );
    });
    expect(await screen.findByText("assert($_POST['cmd']);")).toBeInTheDocument();
    expect(screen.getByText("置信度 96%")).toBeInTheDocument();
    expect(screen.getByText("keyword:assert")).toBeInTheDocument();
    expect(screen.getByText("Behinder (ECB): AES-ECB 密文长度非法")).toBeInTheDocument();
  }, 30000);

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
        payload: SAMPLE_BASE64_PAYLOAD,
        preview: SAMPLE_BASE64_PAYLOAD,
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

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    expect(await screen.findByText("可疑 URI / 参数来源")).toBeInTheDocument();
    const sourceText = await screen.findByText(/web\.test\/shell\.php/);
    const sourceButton = sourceText.closest("button");
    expect(sourceButton).toBeTruthy();
    fireEvent.click(sourceButton!);

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith(SAMPLE_BASE64_PAYLOAD, expect.any(AbortSignal));
    });
    expect(screen.getByDisplayValue(SAMPLE_BASE64_PAYLOAD)).toBeInTheDocument();
    expect(screen.getByText(/当前输入来自 packet #81/)).toBeInTheDocument();
    expect((await screen.findAllByText("antsword_like")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("script_or_command").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("antsword").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "AntSword" }));
    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalledWith(
        "antsword",
        SAMPLE_BASE64_PAYLOAD,
        expect.objectContaining({
          pass: "pass",
          extractParam: true,
          urlDecodeRounds: 1,
        }),
        expect.any(AbortSignal),
      );
    });
  });

  it("keeps manual payload workflow available when no capture is loaded", async () => {
    mocks.sentinelState.fileMeta.path = "";
    mocks.sentinelState.fileMeta.name = "";
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

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
    mocks.decodeStreamPayload.mockRejectedValueOnce(
      new Error("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空"),
    );

    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), {
      target: { value: "just-random-text" },
    });
    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("当前 payload")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "自动检测" }));

    expect(
      await screen.findByText("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空"),
    ).toBeInTheDocument();
  });

  it("re-runs payload inspection when the same input is submitted again", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), {
      target: { value: `pass=${SAMPLE_BASE64_PAYLOAD}` },
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

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByRole("button", { name: "识别候选" })).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("请输入 payload 后再识别候选。")).toBeInTheDocument();
    expect(mocks.inspectStreamPayload).not.toHaveBeenCalled();
  });
});
