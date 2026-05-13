import type { MediaAnalysis } from "../../core/types";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";
import { asMediaSession } from "./mediaSessionMapper";
export { asMediaTranscription } from "./mediaTranscriptionMapper";
export { asSpeechBatchTaskStatus } from "./speechBatchMapper";

export function asMediaAnalysis(input: unknown): MediaAnalysis {
  const payload = asPlainObject(input);
  return {
    totalMediaPackets: Number(payload?.total_media_packets ?? 0),
    protocols: asArray(payload?.protocols).map(asBucket),
    applications: asArray(payload?.applications).map(asBucket),
    sessions: asArray(payload?.sessions).map(asMediaSession),
    notes: asStringList(payload?.notes),
  };
}
