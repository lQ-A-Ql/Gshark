import { createAnalysisClient } from "./clients/analysisClient";
import { createC2DecryptClient } from "./clients/c2DecryptClient";
import { createCaptureClient } from "./clients/captureClient";
import { createDesktopClient } from "./clients/desktopClient";
import type { EventHandlers } from "./clients/eventClient";
import { createHuntingClient } from "./clients/huntingClient";
import { createMediaClient } from "./clients/mediaClient";
import { createObjectClient } from "./clients/objectClient";
import { createPluginClient } from "./clients/pluginClient";
import { createStreamClient } from "./clients/streamClient";
import { createToolClient } from "./clients/toolClient";
import { createToolRuntimeClient } from "./clients/toolRuntimeClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

export type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
export type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;
export type TextRequest = (path: string, init?: RequestInit) => Promise<string>;
export type EventSubscriber = (handlers: EventHandlers) => () => void;

export interface BackendBridgeTransport {
  requestJSON: JsonRequest;
  requestBlob: BlobRequest;
  requestText: TextRequest;
  subscribeEvents: EventSubscriber;
  getDesktopAppBinding(): DesktopTransportBinding | undefined;
}

export function createBackendBridgeFromTransport(transport: BackendBridgeTransport): BackendBridge {
  const mediaClient = createMediaClient(transport.requestJSON, transport.requestBlob);
  const analysisClient = createAnalysisClient(transport.requestJSON);
  const pluginClient = createPluginClient(transport.requestJSON);
  const streamClient = createStreamClient(transport.requestJSON);
  const toolClient = createToolClient(transport.requestJSON, transport.requestText, transport.requestBlob);
  const captureClient = createCaptureClient(transport.requestJSON, transport.getDesktopAppBinding);
  const toolRuntimeClient = createToolRuntimeClient(transport.requestJSON);
  const objectClient = createObjectClient(transport.requestJSON, transport.requestBlob);
  const huntingClient = createHuntingClient(transport.requestJSON);
  const c2DecryptClient = createC2DecryptClient(transport.requestJSON);
  const desktopClient = createDesktopClient(transport.requestJSON, transport.getDesktopAppBinding);

  return {
    isAvailable: desktopClient.isAvailable,
    getDesktopBackendStatus: desktopClient.getDesktopBackendStatus,
    checkAppUpdate: desktopClient.checkAppUpdate,
    installAppUpdate: desktopClient.installAppUpdate,

    checkTShark: toolRuntimeClient.checkTShark,
    checkFFmpeg: toolRuntimeClient.checkFFmpeg,
    checkSpeechToText: toolRuntimeClient.checkSpeechToText,
    getToolRuntimeSnapshot: toolRuntimeClient.getToolRuntimeSnapshot,
    updateToolRuntimeConfig: toolRuntimeClient.updateToolRuntimeConfig,
    setTSharkPath: toolRuntimeClient.setTSharkPath,

    openPcapFile: captureClient.openPcapFile,
    startStreamingPackets: captureClient.startStreamingPackets,
    stopStreamingPackets: captureClient.stopStreamingPackets,
    prepareCaptureReplacement: captureClient.prepareCaptureReplacement,
    closeCapture: captureClient.closeCapture,
    getCaptureStatus: captureClient.getCaptureStatus,
    listPackets: captureClient.listPackets,
    listPacketsPage: captureClient.listPacketsPage,

    openDBCFile: desktopClient.openDBCFile,

    locatePacketPage: captureClient.locatePacketPage,
    getPacket: captureClient.getPacket,

    listThreatHits: huntingClient.listThreatHits,
    getHuntingRuntimeConfig: huntingClient.getHuntingRuntimeConfig,
    updateHuntingRuntimeConfig: huntingClient.updateHuntingRuntimeConfig,

    listObjects: objectClient.listObjects,
    downloadObjectsZip: objectClient.downloadObjectsZip,

    getHttpStream: streamClient.getHttpStream,
    getRawStream: streamClient.getRawStream,
    getRawStreamPage: streamClient.getRawStreamPage,
    decodeStreamPayload: streamClient.decodeStreamPayload,
    inspectStreamPayload: streamClient.inspectStreamPayload,
    listStreamPayloadSources: streamClient.listStreamPayloadSources,
    updateStreamPayloads: streamClient.updateStreamPayloads,
    listStreamIds: streamClient.listStreamIds,
    getPacketRawHex: streamClient.getPacketRawHex,
    getPacketLayers: streamClient.getPacketLayers,

    getGlobalTrafficStats: analysisClient.getGlobalTrafficStats,
    getIndustrialAnalysis: analysisClient.getIndustrialAnalysis,
    getVehicleAnalysis: analysisClient.getVehicleAnalysis,

    getMediaAnalysis: mediaClient.getMediaAnalysis,
    transcribeMediaArtifact: mediaClient.transcribeMediaArtifact,
    startMediaBatchTranscription: mediaClient.startMediaBatchTranscription,
    getMediaBatchTranscriptionStatus: mediaClient.getMediaBatchTranscriptionStatus,
    cancelMediaBatchTranscription: mediaClient.cancelMediaBatchTranscription,
    exportMediaBatchTranscription: mediaClient.exportMediaBatchTranscription,

    getUSBAnalysis: analysisClient.getUSBAnalysis,
    getC2SampleAnalysis: analysisClient.getC2SampleAnalysis,

    decryptC2Traffic: c2DecryptClient.decryptC2Traffic,

    getAPTAnalysis: analysisClient.getAPTAnalysis,
    getEvidence: analysisClient.getEvidence,
    getEvidenceWithFilter: analysisClient.getEvidenceWithFilter,

    downloadMediaArtifact: mediaClient.downloadMediaArtifact,
    getMediaPlaybackBlob: mediaClient.getMediaPlaybackBlob,

    listVehicleDBCProfiles: pluginClient.listVehicleDBCProfiles,
    addVehicleDBC: pluginClient.addVehicleDBC,
    removeVehicleDBC: pluginClient.removeVehicleDBC,
    listPlugins: pluginClient.listPlugins,
    getPluginSource: pluginClient.getPluginSource,
    savePluginSource: pluginClient.savePluginSource,
    addPlugin: pluginClient.addPlugin,
    deletePlugin: pluginClient.deletePlugin,
    togglePlugin: pluginClient.togglePlugin,
    setPluginsEnabled: pluginClient.setPluginsEnabled,
    getTLSConfig: pluginClient.getTLSConfig,
    updateTLSConfig: pluginClient.updateTLSConfig,

    runWinRMDecrypt: toolClient.runWinRMDecrypt,
    getWinRMDecryptResultText: toolClient.getWinRMDecryptResultText,
    exportWinRMDecryptResult: toolClient.exportWinRMDecryptResult,
    listMiscModules: toolClient.listMiscModules,
    importMiscModulePackage: toolClient.importMiscModulePackage,
    deleteMiscModule: toolClient.deleteMiscModule,
    runMiscModule: toolClient.runMiscModule,
    listSMB3SessionCandidates: toolClient.listSMB3SessionCandidates,
    generateSMB3RandomSessionKey: toolClient.generateSMB3RandomSessionKey,
    listNTLMSessionMaterials: toolClient.listNTLMSessionMaterials,
    getHTTPLoginAnalysis: toolClient.getHTTPLoginAnalysis,
    getSMTPAnalysis: toolClient.getSMTPAnalysis,
    getMySQLAnalysis: toolClient.getMySQLAnalysis,
    getShiroRememberMeAnalysis: toolClient.getShiroRememberMeAnalysis,

    subscribeEvents: transport.subscribeEvents,
  };
}
