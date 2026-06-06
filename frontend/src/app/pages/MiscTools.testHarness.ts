import { vi } from "vitest";

const miscToolsMocks = vi.hoisted(() => ({
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
    fileMeta: { name: "capture.pcapng", sizeBytes: 2048, path: "C:/captures/capture.pcapng" },
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
    setActiveStream: vi.fn(),
  },
}));

export function getMiscToolsMocks() {
  return miscToolsMocks;
}

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => miscToolsMocks.sentinelState,
}));
vi.mock("../state/contexts/PacketContext", () => ({
  usePacket: () => ({
    locatePacketById: miscToolsMocks.sentinelState.locatePacketById,
  }),
}));
vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({
    preparePacketStream: miscToolsMocks.sentinelState.preparePacketStream,
    setActiveStream: miscToolsMocks.sentinelState.setActiveStream,
  }),
}));
vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getHTTPLoginAnalysis: miscToolsMocks.getHTTPLoginAnalysis,
      getMySQLAnalysis: miscToolsMocks.getMySQLAnalysis,
      getSMTPAnalysis: miscToolsMocks.getSMTPAnalysis,
      getShiroRememberMeAnalysis: miscToolsMocks.getShiroRememberMeAnalysis,
    },
    miscModule: {
      listMiscModules: miscToolsMocks.listMiscModules,
      importMiscModulePackage: miscToolsMocks.importMiscModulePackage,
    },
    securityMaterial: {
      listNTLMSessionMaterials: miscToolsMocks.listNTLMSessionMaterials,
      listSMB3SessionCandidates: miscToolsMocks.listSMB3SessionCandidates,
      generateSMB3RandomSessionKey: miscToolsMocks.generateSMB3RandomSessionKey,
      runWinRMDecrypt: miscToolsMocks.runWinRMDecrypt,
      getWinRMDecryptResultText: miscToolsMocks.getWinRMDecryptResultText,
      exportWinRMDecryptResult: miscToolsMocks.exportWinRMDecryptResult,
    },
    stream: {
      decodeStreamPayload: miscToolsMocks.decodeStreamPayload,
      inspectStreamPayload: miscToolsMocks.inspectStreamPayload,
      listStreamPayloadSources: miscToolsMocks.listStreamPayloadSources,
    },
  },
  bridge: {
    listMiscModules: miscToolsMocks.listMiscModules,
    importMiscModulePackage: miscToolsMocks.importMiscModulePackage,
    deleteMiscModule: miscToolsMocks.deleteMiscModule,
    runMiscModule: miscToolsMocks.runMiscModule,
    getHTTPLoginAnalysis: miscToolsMocks.getHTTPLoginAnalysis,
    getMySQLAnalysis: miscToolsMocks.getMySQLAnalysis,
    getSMTPAnalysis: miscToolsMocks.getSMTPAnalysis,
    getShiroRememberMeAnalysis: miscToolsMocks.getShiroRememberMeAnalysis,
    decodeStreamPayload: miscToolsMocks.decodeStreamPayload,
    inspectStreamPayload: miscToolsMocks.inspectStreamPayload,
    listStreamPayloadSources: miscToolsMocks.listStreamPayloadSources,
    listNTLMSessionMaterials: miscToolsMocks.listNTLMSessionMaterials,
    listSMB3SessionCandidates: miscToolsMocks.listSMB3SessionCandidates,
    generateSMB3RandomSessionKey: miscToolsMocks.generateSMB3RandomSessionKey,
    runWinRMDecrypt: miscToolsMocks.runWinRMDecrypt,
    getWinRMDecryptResultText: miscToolsMocks.getWinRMDecryptResultText,
    exportWinRMDecryptResult: miscToolsMocks.exportWinRMDecryptResult,
  },
}));
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => miscToolsMocks.navigate };
});
