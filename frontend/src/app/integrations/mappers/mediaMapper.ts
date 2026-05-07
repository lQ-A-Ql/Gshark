import type { MediaAnalysis } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";

export function asMediaAnalysis(payload: any): MediaAnalysis {
  return {
    totalMediaPackets: Number(payload?.total_media_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    applications: Array.isArray(payload?.applications) ? payload.applications.map(asBucket) : [],
    sessions: Array.isArray(payload?.sessions)
      ? payload.sessions.map((item: any) => ({
          id: String(item.id ?? ""),
          mediaType: String(item.media_type ?? ""),
          family: String(item.family ?? ""),
          application: String(item.application ?? ""),
          source: String(item.source ?? ""),
          sourcePort: Number(item.source_port ?? 0),
          destination: String(item.destination ?? ""),
          destinationPort: Number(item.destination_port ?? 0),
          transport: String(item.transport ?? ""),
          ssrc: String(item.ssrc ?? "") || undefined,
          payloadType: String(item.payload_type ?? "") || undefined,
          codec: String(item.codec ?? "") || undefined,
          clockRate: Number(item.clock_rate ?? 0) || undefined,
          startTime: String(item.start_time ?? "") || undefined,
          endTime: String(item.end_time ?? "") || undefined,
          packetCount: Number(item.packet_count ?? 0),
          gapCount: Number(item.gap_count ?? 0),
          controlSummary: String(item.control_summary ?? "") || undefined,
          tags: asStringList(item.tags),
          notes: asStringList(item.notes),
          artifact: item.artifact
            ? {
                token: String(item.artifact.token ?? ""),
                name: String(item.artifact.name ?? ""),
                codec: String(item.artifact.codec ?? "") || undefined,
                format: String(item.artifact.format ?? "") || undefined,
                sizeBytes: Number(item.artifact.size_bytes ?? 0),
              }
            : undefined,
        }))
      : [],
    notes: asStringList(payload?.notes),
  };
}
