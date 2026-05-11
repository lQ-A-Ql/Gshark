import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  analysisClient: {
    getGlobalTrafficStats: vi.fn(),
    getIndustrialAnalysis: vi.fn(),
    getVehicleAnalysis: vi.fn(),
    getUSBAnalysis: vi.fn(),
    getC2SampleAnalysis: vi.fn(),
    getAPTAnalysis: vi.fn(),
    getEvidence: vi.fn(),
    getEvidenceWithFilter: vi.fn(),
  },
  huntingClient: {
    listThreatHits: vi.fn(),
    getHuntingRuntimeConfig: vi.fn(),
    updateHuntingRuntimeConfig: vi.fn(),
  },
  objectClient: {
    listObjects: vi.fn(),
    downloadObjectsZip: vi.fn(),
  },
  eventClient: {
    subscribeEvents: vi.fn(() => vi.fn()),
  },
}));

vi.mock("./clients/analysisClient", () => ({
  createAnalysisClient: vi.fn(() => mocks.analysisClient),
}));
vi.mock("./clients/huntingClient", () => ({
  createHuntingClient: vi.fn(() => mocks.huntingClient),
}));
vi.mock("./clients/objectClient", () => ({
  createObjectClient: vi.fn(() => mocks.objectClient),
}));
vi.mock("./clients/eventClient", () => ({
  createEventClient: vi.fn(() => mocks.eventClient),
}));

vi.mock("./clients/c2DecryptClient", () => ({ createC2DecryptClient: vi.fn(() => ({ decryptC2Traffic: vi.fn() })) }));
vi.mock("./clients/captureClient", () => ({
  createCaptureClient: vi.fn(() => ({
    openPcapFile: vi.fn(),
    startStreamingPackets: vi.fn(),
    stopStreamingPackets: vi.fn(),
    prepareCaptureReplacement: vi.fn(),
    closeCapture: vi.fn(),
    getCaptureStatus: vi.fn(),
    listPackets: vi.fn(),
    listPacketsPage: vi.fn(),
    locatePacketPage: vi.fn(),
    getPacket: vi.fn(),
  })),
}));
vi.mock("./clients/desktopClient", () => ({
  createDesktopClient: vi.fn(() => ({
    isAvailable: vi.fn(),
    getDesktopBackendStatus: vi.fn(),
    checkAppUpdate: vi.fn(),
    installAppUpdate: vi.fn(),
    openDBCFile: vi.fn(),
  })),
}));
vi.mock("./clients/mediaClient", () => ({
  createMediaClient: vi.fn(() => ({
    getMediaAnalysis: vi.fn(),
    transcribeMediaArtifact: vi.fn(),
    startMediaBatchTranscription: vi.fn(),
    getMediaBatchTranscriptionStatus: vi.fn(),
    cancelMediaBatchTranscription: vi.fn(),
    exportMediaBatchTranscription: vi.fn(),
    downloadMediaArtifact: vi.fn(),
    getMediaPlaybackBlob: vi.fn(),
  })),
}));
vi.mock("./clients/pluginClient", () => ({
  createPluginClient: vi.fn(() => ({
    listVehicleDBCProfiles: vi.fn(),
    addVehicleDBC: vi.fn(),
    removeVehicleDBC: vi.fn(),
    listPlugins: vi.fn(),
    getPluginSource: vi.fn(),
    savePluginSource: vi.fn(),
    addPlugin: vi.fn(),
    deletePlugin: vi.fn(),
    togglePlugin: vi.fn(),
    setPluginsEnabled: vi.fn(),
    getTLSConfig: vi.fn(),
    updateTLSConfig: vi.fn(),
  })),
}));
vi.mock("./clients/streamClient", () => ({
  createStreamClient: vi.fn(() => ({
    getHttpStream: vi.fn(),
    getRawStream: vi.fn(),
    getRawStreamPage: vi.fn(),
    decodeStreamPayload: vi.fn(),
    inspectStreamPayload: vi.fn(),
    listStreamPayloadSources: vi.fn(),
    updateStreamPayloads: vi.fn(),
    listStreamIds: vi.fn(),
    getPacketRawHex: vi.fn(),
    getPacketLayers: vi.fn(),
  })),
}));
vi.mock("./clients/toolClient", () => ({
  createToolClient: vi.fn(() => ({
    runWinRMDecrypt: vi.fn(),
    getWinRMDecryptResultText: vi.fn(),
    exportWinRMDecryptResult: vi.fn(),
    listMiscModules: vi.fn(),
    importMiscModulePackage: vi.fn(),
    deleteMiscModule: vi.fn(),
    runMiscModule: vi.fn(),
    listSMB3SessionCandidates: vi.fn(),
    generateSMB3RandomSessionKey: vi.fn(),
    listNTLMSessionMaterials: vi.fn(),
    getHTTPLoginAnalysis: vi.fn(),
    getSMTPAnalysis: vi.fn(),
    getMySQLAnalysis: vi.fn(),
    getShiroRememberMeAnalysis: vi.fn(),
  })),
}));
vi.mock("./clients/toolRuntimeClient", () => ({
  createToolRuntimeClient: vi.fn(() => ({
    checkTShark: vi.fn(),
    checkFFmpeg: vi.fn(),
    checkSpeechToText: vi.fn(),
    getToolRuntimeSnapshot: vi.fn(),
    updateToolRuntimeConfig: vi.fn(),
    setTSharkPath: vi.fn(),
  })),
}));

import { createHttpBridge } from "./httpBridge";

describe("createHttpBridge aggregation", () => {
  it("wires mainline evidence/report methods to the expected subclients", async () => {
    const signal = new AbortController().signal;
    const handlers = { status: vi.fn() };
    const unsubscribe = vi.fn();
    mocks.eventClient.subscribeEvents.mockReturnValueOnce(unsubscribe);
    mocks.analysisClient.getUSBAnalysis.mockResolvedValueOnce({ report: { summary: [{ title: "USB" }] } });
    mocks.analysisClient.getC2SampleAnalysis.mockResolvedValueOnce({ cs: { report: { summary: [{ title: "CS" }] } } });
    mocks.analysisClient.getEvidenceWithFilter.mockResolvedValueOnce([{ id: "vehicle-1" }]);
    mocks.objectClient.listObjects.mockResolvedValueOnce([{ id: 3, name: "invoice.txt" }]);
    mocks.huntingClient.listThreatHits.mockResolvedValueOnce([{ id: 7, rule: "Flag 嗅探" }]);

    const bridge = createHttpBridge({ getDesktopAppBinding: () => undefined });

    await expect(bridge.getUSBAnalysis(signal)).resolves.toMatchObject({ report: { summary: [{ title: "USB" }] } });
    await expect(bridge.getC2SampleAnalysis(signal)).resolves.toMatchObject({
      cs: { report: { summary: [{ title: "CS" }] } },
    });
    await expect(bridge.getEvidenceWithFilter(["vehicle"], signal)).resolves.toMatchObject([{ id: "vehicle-1" }]);
    await expect(bridge.listObjects(signal)).resolves.toMatchObject([{ id: 3, name: "invoice.txt" }]);
    await expect(bridge.listThreatHits(["flag{"], signal)).resolves.toMatchObject([{ id: 7, rule: "Flag 嗅探" }]);

    const stop = bridge.subscribeEvents(handlers);
    stop();

    expect(mocks.analysisClient.getUSBAnalysis).toHaveBeenCalledWith(signal);
    expect(mocks.analysisClient.getC2SampleAnalysis).toHaveBeenCalledWith(signal);
    expect(mocks.analysisClient.getEvidenceWithFilter).toHaveBeenCalledWith(["vehicle"], signal);
    expect(mocks.objectClient.listObjects).toHaveBeenCalledWith(signal);
    expect(mocks.huntingClient.listThreatHits).toHaveBeenCalledWith(["flag{"], signal);
    expect(mocks.eventClient.subscribeEvents).toHaveBeenCalledWith(handlers);
    expect(unsubscribe).toHaveBeenCalled();
  });

  it("routes object downloads through the object client", async () => {
    const bridge = createHttpBridge({ getDesktopAppBinding: () => undefined });
    await bridge.downloadObjectsZip([1, 2, 3]);
    expect(mocks.objectClient.downloadObjectsZip).toHaveBeenCalledWith([1, 2, 3]);
  });
});
