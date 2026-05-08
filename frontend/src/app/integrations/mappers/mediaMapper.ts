import type { MediaAnalysis, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
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

export function asMediaTranscription(payload: any): MediaTranscription {
  return {
    token: String(payload?.token ?? ""),
    sessionId: String(payload?.session_id ?? ""),
    title: String(payload?.title ?? ""),
    text: String(payload?.text ?? ""),
    language: String(payload?.language ?? ""),
    engine: String(payload?.engine ?? ""),
    status: String(payload?.status ?? ""),
    error: String(payload?.error ?? "") || undefined,
    cached: Boolean(payload?.cached),
    durationSeconds: Number(payload?.duration_seconds ?? 0),
    segments: Array.isArray(payload?.segments)
      ? payload.segments.map((item: any) => ({
          startSeconds: Number(item.start_seconds ?? 0),
          endSeconds: Number(item.end_seconds ?? 0),
          text: String(item.text ?? ""),
        }))
      : [],
  };
}

export function asSpeechBatchTaskStatus(input: any): SpeechBatchTaskStatus {
  return {
    taskId: String(input?.task_id ?? ""),
    total: Number(input?.total ?? 0),
    queued: Number(input?.queued ?? 0),
    running: Number(input?.running ?? 0),
    completed: Number(input?.completed ?? 0),
    failed: Number(input?.failed ?? 0),
    skipped: Number(input?.skipped ?? 0),
    currentToken: String(input?.current_token ?? "") || undefined,
    currentLabel: String(input?.current_label ?? "") || undefined,
    done: Boolean(input?.done),
    cancelled: Boolean(input?.cancelled),
    items: Array.isArray(input?.items)
      ? input.items.map((item: any) => ({
          token: String(item.token ?? ""),
          sessionId: String(item.session_id ?? ""),
          mediaLabel: String(item.media_label ?? ""),
          title: String(item.title ?? ""),
          status: String(item.status ?? "queued") as SpeechBatchTaskStatus["items"][number]["status"],
          error: String(item.error ?? "") || undefined,
          cached: Boolean(item.cached),
          text: String(item.text ?? "") || undefined,
        }))
      : [],
  };
}
