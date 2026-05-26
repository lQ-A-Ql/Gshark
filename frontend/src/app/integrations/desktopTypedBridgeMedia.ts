import { downloadBlob } from "../utils/browserFile";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedBlobCall, typedCall } from "./desktopTypedBridgeCore";
import { asMediaAnalysis, asMediaTranscription, asSpeechBatchTaskStatus } from "./mappers/mediaMapper";

export function createMediaTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async getMediaAnalysis(forceRefresh = false, signal) {
      return asMediaAnalysis(
        await typedCall(
          () => desktopApp.GetMediaAnalysis!(forceRefresh),
          "DesktopApp.GetMediaAnalysis",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async transcribeMediaArtifact(token, force = false) {
      return asMediaTranscription(
        await typedCall(
          () => desktopApp.TranscribeMediaArtifact!(token, force),
          "DesktopApp.TranscribeMediaArtifact",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async startMediaBatchTranscription(force = false) {
      return asSpeechBatchTaskStatus(
        await typedCall(
          () => desktopApp.StartMediaBatchTranscription!(force),
          "DesktopApp.StartMediaBatchTranscription",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async getMediaBatchTranscriptionStatus() {
      return asSpeechBatchTaskStatus(
        await typedCall(
          () => desktopApp.GetMediaBatchTranscriptionStatus!(),
          "DesktopApp.GetMediaBatchTranscriptionStatus",
        ),
      );
    },
    async cancelMediaBatchTranscription() {
      return asSpeechBatchTaskStatus(
        await typedCall(() => desktopApp.CancelMediaBatchTranscription!(), "DesktopApp.CancelMediaBatchTranscription"),
      );
    },
    async exportMediaBatchTranscription(format) {
      const blob = await typedBlobCall(
        () => desktopApp.ExportMediaBatchTranscription!(format),
        "DesktopApp.ExportMediaBatchTranscription",
      );
      downloadBlob(`media-transcription.${format}`, blob);
    },
    async downloadMediaArtifact(token, filename) {
      const blob = await typedBlobCall(
        () => desktopApp.DownloadMediaArtifact!(token),
        "DesktopApp.DownloadMediaArtifact",
      );
      downloadBlob(filename, blob);
    },
    async getMediaPlaybackBlob(token) {
      return await typedBlobCall(() => desktopApp.GetMediaPlaybackBlob!(token), "DesktopApp.GetMediaPlaybackBlob");
    },
  };
}
