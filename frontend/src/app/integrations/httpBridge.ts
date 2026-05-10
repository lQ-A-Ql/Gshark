import { createAnalysisClient } from "./clients/analysisClient";
import { createC2DecryptClient } from "./clients/c2DecryptClient";
import { createCaptureClient } from "./clients/captureClient";
import { createDesktopClient } from "./clients/desktopClient";
import { createEventClient } from "./clients/eventClient";
import { createHuntingClient } from "./clients/huntingClient";
import { createMediaClient } from "./clients/mediaClient";
import { createObjectClient } from "./clients/objectClient";
import { createPluginClient } from "./clients/pluginClient";
import { createStreamClient } from "./clients/streamClient";
import { createToolClient } from "./clients/toolClient";
import { createToolRuntimeClient } from "./clients/toolRuntimeClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

const API_BASE = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";

export interface HttpBridgeContext {
  getDesktopAppBinding(): DesktopTransportBinding | undefined;
}

export async function requestJSON<T>(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<T> {
  const headers = await buildAuthorizedHeaders(path, init?.headers, init?.body, getDesktopAppBinding);

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
  } catch (error) {
    throw normalizeTransportError(error, path);
  }
  if (!res.ok) {
    let detail = "";
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === "string") {
        detail = payload.error;
      }
    } catch {
      // ignore invalid json error payload
    }
    throw new Error(detail || `backend request failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export async function requestBlob(
  path: string,
  init: RequestInit | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Blob> {
  const headers = await buildAuthorizedHeaders(path, init?.headers, init?.body, getDesktopAppBinding);

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
  } catch (error) {
    throw normalizeTransportError(error, path);
  }
  if (!res.ok) {
    let detail = "";
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === "string") {
        detail = payload.error;
      }
    } catch {
      // ignore invalid json error payload
    }
    throw new Error(detail || `backend request failed: ${res.status} ${res.statusText}`);
  }
  return await res.blob();
}

let backendAuthTokenPromise: Promise<string> | null = null;

export function resetBackendAuthTokenCache() {
  backendAuthTokenPromise = null;
}

export async function getBackendAuthToken(getDesktopAppBinding: () => DesktopTransportBinding | undefined): Promise<string> {
  if (backendAuthTokenPromise) {
    return backendAuthTokenPromise;
  }

  backendAuthTokenPromise = (async () => {
    const envToken = String(import.meta.env.VITE_BACKEND_TOKEN ?? "").trim();
    if (envToken) {
      return envToken;
    }

    const desktopApp = getDesktopAppBinding();
    if (desktopApp?.GetBackendAuthToken) {
      const token = await desktopApp.GetBackendAuthToken();
      return String(token ?? "").trim();
    }

    return "";
  })();

  return backendAuthTokenPromise;
}

export async function buildAuthorizedHeaders(
  path: string,
  headersInit: HeadersInit | undefined,
  body: BodyInit | null | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Headers> {
  const headers = new Headers(headersInit ?? {});
  if (!(body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (path !== "/health" && !headers.has("Authorization")) {
    const token = await getBackendAuthToken(getDesktopAppBinding);
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return headers;
}

export async function getBackendAuthHeaders(
  path: string,
  headersInit: HeadersInit | undefined,
  body: BodyInit | null | undefined,
  getDesktopAppBinding: () => DesktopTransportBinding | undefined,
): Promise<Headers> {
  return buildAuthorizedHeaders(path, headersInit, body, getDesktopAppBinding);
}

export function createHttpBridge(context: HttpBridgeContext): BackendBridge {
  const request = <T>(path: string, init?: RequestInit) =>
    requestJSON<T>(path, init, context.getDesktopAppBinding);
  const blobRequest = (path: string, init?: RequestInit) =>
    requestBlob(path, init, context.getDesktopAppBinding);
  const buildHeaders = (path: string, headersInit?: HeadersInit, body?: BodyInit | null) =>
    buildAuthorizedHeaders(path, headersInit, body, context.getDesktopAppBinding);
  const authTokenGetter = () => getBackendAuthToken(context.getDesktopAppBinding);

  const mediaClient = createMediaClient(request, blobRequest);
  const analysisClient = createAnalysisClient(request);
  const pluginClient = createPluginClient(request);
  const streamClient = createStreamClient(request);
  const toolClient = createToolClient(request, API_BASE, buildHeaders);
  const captureClient = createCaptureClient(request, context.getDesktopAppBinding);
  const toolRuntimeClient = createToolRuntimeClient(request);
  const objectClient = createObjectClient(request, blobRequest);
  const huntingClient = createHuntingClient(request);
  const c2DecryptClient = createC2DecryptClient(request);
  const eventClient = createEventClient(API_BASE, authTokenGetter);
  const desktopClient = createDesktopClient(request, context.getDesktopAppBinding);

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

    subscribeEvents: eventClient.subscribeEvents,
  };
}

function normalizeTransportError(error: unknown, path: string): Error {
  if (isAbortError(error)) {
    return error;
  }
  const fallback = `无法连接后端接口 ${path}，请检查桌面后端是否已启动，或 127.0.0.1:17891 是否被非兼容实例占用。`;
  if (error instanceof Error && error.message.trim()) {
    if (error.message === "Failed to fetch") {
      return new Error(fallback);
    }
    return new Error(`${fallback} 原始错误: ${error.message}`);
  }
  return new Error(fallback);
}

function isAbortError(error: unknown): error is Error {
  return (
    error instanceof Error && error.name === "AbortError"
  ) || (
    typeof DOMException !== "undefined" &&
    error instanceof DOMException &&
    error.name === "AbortError"
  );
}
