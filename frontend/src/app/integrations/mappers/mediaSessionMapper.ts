import type { MediaArtifact, MediaSession } from "../../core/types";
import { asPlainObject, asStringList } from "./mapperPrimitives";

function asMediaArtifact(input: unknown): MediaArtifact {
  const item = asPlainObject(input);
  return {
    token: String(item?.token ?? ""),
    name: String(item?.name ?? ""),
    codec: String(item?.codec ?? "") || undefined,
    format: String(item?.format ?? "") || undefined,
    sizeBytes: Number(item?.size_bytes ?? 0),
  };
}

export function asMediaSession(input: unknown): MediaSession {
  const item = asPlainObject(input);
  return {
    id: String(item?.id ?? ""),
    mediaType: String(item?.media_type ?? ""),
    family: String(item?.family ?? ""),
    application: String(item?.application ?? ""),
    source: String(item?.source ?? ""),
    sourcePort: Number(item?.source_port ?? 0),
    destination: String(item?.destination ?? ""),
    destinationPort: Number(item?.destination_port ?? 0),
    transport: String(item?.transport ?? ""),
    ssrc: String(item?.ssrc ?? "") || undefined,
    payloadType: String(item?.payload_type ?? "") || undefined,
    codec: String(item?.codec ?? "") || undefined,
    clockRate: Number(item?.clock_rate ?? 0) || undefined,
    startTime: String(item?.start_time ?? "") || undefined,
    endTime: String(item?.end_time ?? "") || undefined,
    packetCount: Number(item?.packet_count ?? 0),
    gapCount: Number(item?.gap_count ?? 0),
    controlSummary: String(item?.control_summary ?? "") || undefined,
    tags: asStringList(item?.tags),
    notes: asStringList(item?.notes),
    artifact: item?.artifact ? asMediaArtifact(item.artifact) : undefined,
  };
}
