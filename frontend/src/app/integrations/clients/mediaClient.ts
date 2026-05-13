import type { MediaAnalysis, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { downloadBlob } from "../../utils/browserFile";
import { asMediaAnalysis, asMediaTranscription, asSpeechBatchTaskStatus } from "../mappers/mediaMapper";
import type {
  MediaAnalysisWireDTO,
  MediaTranscriptionWireDTO,
  SpeechBatchTaskStatusWireDTO,
} from "../wire/mediaWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;

export interface MediaClient {
  getMediaAnalysis(forceRefresh?: boolean, signal?: AbortSignal): Promise<MediaAnalysis>;
  transcribeMediaArtifact(token: string, force?: boolean): Promise<MediaTranscription>;
  startMediaBatchTranscription(force?: boolean): Promise<SpeechBatchTaskStatus>;
  getMediaBatchTranscriptionStatus(): Promise<SpeechBatchTaskStatus>;
  cancelMediaBatchTranscription(): Promise<SpeechBatchTaskStatus>;
  exportMediaBatchTranscription(format: "txt" | "json"): Promise<void>;
  downloadMediaArtifact(token: string, filename: string): Promise<void>;
  getMediaPlaybackBlob(token: string): Promise<Blob>;
}

export function createMediaClient(request: JsonRequest, requestBlob: BlobRequest): MediaClient {
  return {
    async getMediaAnalysis(forceRefresh = false, signal?: AbortSignal) {
      const payload = await request<MediaAnalysisWireDTO>(
        forceRefresh ? "/api/analysis/media?refresh=1" : "/api/analysis/media",
        { signal },
      );
      return asMediaAnalysis(payload);
    },

    async transcribeMediaArtifact(token: string, force = false) {
      const payload = await request<MediaTranscriptionWireDTO>("/api/analysis/media/transcribe", {
        method: "POST",
        body: JSON.stringify({ token, force }),
      });
      return asMediaTranscription(payload);
    },

    async startMediaBatchTranscription(force = false) {
      const payload = await request<SpeechBatchTaskStatusWireDTO>("/api/analysis/media/transcribe/batch", {
        method: "POST",
        body: JSON.stringify({ force }),
      });
      return asSpeechBatchTaskStatus(payload);
    },

    async getMediaBatchTranscriptionStatus() {
      const payload = await request<SpeechBatchTaskStatusWireDTO>("/api/analysis/media/transcribe/batch");
      return asSpeechBatchTaskStatus(payload);
    },

    async cancelMediaBatchTranscription() {
      const payload = await request<SpeechBatchTaskStatusWireDTO>("/api/analysis/media/transcribe/batch/cancel", {
        method: "POST",
        body: JSON.stringify({}),
      });
      return asSpeechBatchTaskStatus(payload);
    },

    async exportMediaBatchTranscription(format: "txt" | "json") {
      const blob = await requestBlob(
        `/api/analysis/media/transcribe/batch/export?format=${encodeURIComponent(format)}`,
      );
      downloadBlob(`media-transcription.${format}`, blob);
    },

    async downloadMediaArtifact(token: string, filename: string) {
      const blob = await requestBlob(`/api/analysis/media/export?token=${encodeURIComponent(token)}`);
      downloadBlob(filename, blob);
    },

    async getMediaPlaybackBlob(token: string) {
      return await requestBlob(`/api/analysis/media/play?token=${encodeURIComponent(token)}`);
    },
  };
}
