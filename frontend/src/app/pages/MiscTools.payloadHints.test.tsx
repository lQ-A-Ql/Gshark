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
    analysis: {
      getHTTPLoginAnalysis: mocks.getHTTPLoginAnalysis,
      getMySQLAnalysis: mocks.getMySQLAnalysis,
      getSMTPAnalysis: mocks.getSMTPAnalysis,
      getShiroRememberMeAnalysis: mocks.getShiroRememberMeAnalysis,
    },
    miscModule: { listMiscModules: mocks.listMiscModules, importMiscModulePackage: mocks.importMiscModulePackage },
    securityMaterial: { listNTLMSessionMaterials: mocks.listNTLMSessionMaterials, runWinRMDecrypt: mocks.runWinRMDecrypt, getWinRMDecryptResultText: mocks.getWinRMDecryptResultText, exportWinRMDecryptResult: mocks.exportWinRMDecryptResult },
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

describe("MiscTools payload source hints", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
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

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByText("可疑 URI / 参数来源")).toBeInTheDocument();
    });

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
  }, 30000);
});
