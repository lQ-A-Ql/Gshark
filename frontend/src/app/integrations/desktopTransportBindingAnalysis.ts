export interface DesktopAnalysisBinding {
  GetGlobalTrafficStats?: () => Promise<unknown>;
  GetIndustrialAnalysis?: () => Promise<unknown>;
  GetVehicleAnalysis?: () => Promise<unknown>;
  GetMediaAnalysis?: (forceRefresh: boolean) => Promise<unknown>;
  TranscribeMediaArtifact?: (token: string, force: boolean) => Promise<unknown>;
  StartMediaBatchTranscription?: (force: boolean) => Promise<unknown>;
  GetMediaBatchTranscriptionStatus?: () => Promise<unknown>;
  CancelMediaBatchTranscription?: () => Promise<unknown>;
  ExportMediaBatchTranscription?: (format: string) => Promise<unknown>;
  DownloadMediaArtifact?: (token: string) => Promise<unknown>;
  GetMediaPlaybackBlob?: (token: string) => Promise<unknown>;
  GetUSBAnalysis?: (hidSource: string, hidEventLimit: number) => Promise<unknown>;
  GetC2SampleAnalysis?: () => Promise<unknown>;
  DecryptC2Traffic?: (request: unknown) => Promise<unknown>;
  GetAPTAnalysis?: () => Promise<unknown>;
  GetEvidence?: () => Promise<unknown>;
  GetEvidenceWithFilter?: (modules: string[]) => Promise<unknown>;
}
