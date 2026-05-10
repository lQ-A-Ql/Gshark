import type { MediaAnalysis } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";
import { asMediaSession } from "./mediaSessionMapper";
export { asMediaTranscription } from "./mediaTranscriptionMapper";
export { asSpeechBatchTaskStatus } from "./speechBatchMapper";

export function asMediaAnalysis(payload: any): MediaAnalysis {
  return {
    totalMediaPackets: Number(payload?.total_media_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    applications: Array.isArray(payload?.applications) ? payload.applications.map(asBucket) : [],
    sessions: Array.isArray(payload?.sessions) ? payload.sessions.map(asMediaSession) : [],
    notes: asStringList(payload?.notes),
  };
}
