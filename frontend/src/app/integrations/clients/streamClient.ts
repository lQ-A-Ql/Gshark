import type {
  BinaryStream,
  HttpStream,
  StreamDecodeResult,
  StreamPayloadCandidate,
  StreamPayloadInspection,
  StreamPayloadSource,
} from "../../core/types";
import { asArray, asPlainObject, asStringList } from "../mappers/mapperPrimitives";
import { asBinaryStream, asHttpStream } from "../mappers/packetStreamMapper";
import type {
  StreamDecodeResultWireDTO,
  StreamPayloadCandidateWireDTO,
  StreamPayloadInspectionWireDTO,
} from "../wire/streamDecodeWireDtos";
import type { BinaryStreamWireDTO, HttpStreamWireDTO, StreamPayloadUpdateWireDTO } from "../wire/streamPayloadWireDtos";
import type { StreamPayloadSourceWireDTO } from "../wire/streamPayloadSourceWireDtos";
import type { PacketLayersWireDTO, PacketRawHexWireDTO, StreamIndexWireDTO } from "../wire/streamWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface StreamClient {
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(
    protocol: "TCP" | "UDP",
    streamId: number,
    cursor: number,
    limit: number,
    signal?: AbortSignal,
  ): Promise<BinaryStream>;
  decodeStreamPayload(
    decoder: string,
    payload: string,
    options?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<StreamDecodeResult>;
  inspectStreamPayload(payload: string, signal?: AbortSignal): Promise<StreamPayloadInspection>;
  listStreamPayloadSources(signal?: AbortSignal, limit?: number): Promise<StreamPayloadSource[]>;
  updateStreamPayloads(
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
    signal?: AbortSignal,
  ): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP", signal?: AbortSignal): Promise<number[]>;
  getPacketRawHex(packetId: number, signal?: AbortSignal): Promise<string>;
  getPacketLayers(packetId: number, signal?: AbortSignal): Promise<Record<string, unknown> | null>;
}

export function createStreamClient(request: JsonRequest): StreamClient {
  return {
    async getHttpStream(streamId: number, signal?: AbortSignal) {
      const stream = await request<HttpStreamWireDTO>(
        `/api/streams/http?streamId=${encodeURIComponent(String(streamId))}`,
        {
          signal,
        },
      );
      return asHttpStream(stream);
    },

    async getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal) {
      const stream = await request<BinaryStreamWireDTO>(
        `/api/streams/raw?protocol=${protocol}&streamId=${encodeURIComponent(String(streamId))}`,
        { signal },
      );
      return asBinaryStream(stream, protocol);
    },

    async getRawStreamPage(
      protocol: "TCP" | "UDP",
      streamId: number,
      cursor: number,
      limit: number,
      signal?: AbortSignal,
    ) {
      const stream = await request<BinaryStreamWireDTO>(
        `/api/streams/raw/page?protocol=${protocol}&streamId=${encodeURIComponent(String(streamId))}&cursor=${encodeURIComponent(String(cursor))}&limit=${encodeURIComponent(String(limit))}`,
        { signal },
      );
      return asBinaryStream(stream, protocol);
    },

    async decodeStreamPayload(
      decoder: string,
      payload: string,
      options: Record<string, unknown> = {},
      signal?: AbortSignal,
    ) {
      const result = await request<StreamDecodeResultWireDTO>("/api/streams/decode", {
        method: "POST",
        signal,
        body: JSON.stringify({
          decoder,
          payload,
          options,
        }),
      });
      return {
        decoder: String(result.decoder ?? decoder) as StreamDecodeResult["decoder"],
        summary: String(result.summary ?? ""),
        text: String(result.text ?? ""),
        bytesHex: String(result.bytes_hex ?? ""),
        encoding: String(result.encoding ?? ""),
        confidence: Number(result.confidence ?? 0) || undefined,
        warnings: asStringList(result.warnings),
        signals: asStringList(result.signals),
        attemptErrors: asStringList(result.attempt_errors),
      };
    },

    async inspectStreamPayload(payload: string, signal?: AbortSignal) {
      const result = await request<StreamPayloadInspectionWireDTO>("/api/streams/inspect", {
        method: "POST",
        signal,
        body: JSON.stringify({ payload }),
      });
      return {
        normalizedPayload: String(result.normalized_payload ?? ""),
        candidates: asArray(result.candidates).map((value) => asStreamPayloadCandidate(value)),
        suggestedCandidateId: String(result.suggested_candidate_id ?? "") || undefined,
        suggestedDecoder: String(result.suggested_decoder ?? "") || undefined,
        suggestedFamily: String(result.suggested_family ?? "") || undefined,
        confidence: Number(result.confidence ?? 0) || undefined,
        reasons: asStringList(result.reasons),
      } as StreamPayloadInspection;
    },

    async listStreamPayloadSources(signal?: AbortSignal, limit = 500) {
      const query = new URLSearchParams();
      query.set("limit", String(limit));
      const payload = await request<StreamPayloadSourceWireDTO[]>(`/api/streams/payload-sources?${query.toString()}`, {
        signal,
      });
      return asArray(payload).map((item) => asStreamPayloadSource(item));
    },

    async updateStreamPayloads(
      protocol: "HTTP" | "TCP" | "UDP",
      streamId: number,
      patches: Array<{ index: number; body: string }>,
      signal?: AbortSignal,
    ) {
      const payload = await request<StreamPayloadUpdateWireDTO>("/api/streams/payloads", {
        method: "POST",
        signal,
        body: JSON.stringify({
          protocol,
          stream_id: streamId,
          patches,
        }),
      });
      return protocol === "HTTP" ? asHttpStream(payload) : asBinaryStream(payload, protocol);
    },

    async listStreamIds(protocol: "HTTP" | "TCP" | "UDP", signal?: AbortSignal) {
      const payload = await request<StreamIndexWireDTO>(`/api/streams/index?protocol=${encodeURIComponent(protocol)}`, {
        signal,
      });
      const ids = Array.isArray(payload.ids) ? payload.ids : [];
      return ids
        .map((id: unknown) => Number(id))
        .filter((id: number) => Number.isFinite(id) && id >= 0)
        .sort((a: number, b: number) => a - b);
    },

    async getPacketRawHex(packetId: number, signal?: AbortSignal) {
      const payload = await request<PacketRawHexWireDTO>(`/api/packet/raw?id=${encodeURIComponent(String(packetId))}`, {
        signal,
      });
      return String(payload.raw_hex ?? "");
    },

    async getPacketLayers(packetId: number, signal?: AbortSignal) {
      const payload = await request<PacketLayersWireDTO>(
        `/api/packet/layers?id=${encodeURIComponent(String(packetId))}`,
        {
          signal,
        },
      );
      const layers = payload.layers;
      if (layers && typeof layers === "object" && !Array.isArray(layers)) {
        return layers as Record<string, unknown>;
      }
      return null;
    },
  };
}

function asStreamPayloadCandidate(input: unknown): StreamPayloadCandidate {
  const item = (asPlainObject(input) ?? {}) as StreamPayloadCandidateWireDTO;
  return {
    id: String(item.id ?? ""),
    label: String(item.label ?? ""),
    kind: String(item.kind ?? ""),
    paramName: String(item.param_name ?? "") || undefined,
    value: String(item.value ?? ""),
    preview: String(item.preview ?? "") || undefined,
    confidence: Number(item.confidence ?? 0) || undefined,
    decoderHints: asStringList(item.decoder_hints),
    fingerprints: asStringList(item.fingerprints),
    familyHint: String(item.family_hint ?? "") || undefined,
    decoderOptionsHint: asPlainObject(item.decoder_options_hint),
    sourceRole: String(item.source_role ?? "") || undefined,
  };
}

function asStreamPayloadSource(input: unknown): StreamPayloadSource {
  const item = (asPlainObject(input) ?? {}) as StreamPayloadSourceWireDTO;
  return {
    id: String(item.id ?? ""),
    method: String(item.method ?? "") || undefined,
    host: String(item.host ?? "") || undefined,
    uri: String(item.uri ?? "") || undefined,
    packetId: Number(item.packet_id ?? 0),
    streamId: Number(item.stream_id ?? 0) || undefined,
    sourceType: String(item.source_type ?? "") || undefined,
    paramName: String(item.param_name ?? "") || undefined,
    payload: String(item.payload ?? ""),
    preview: String(item.preview ?? "") || undefined,
    confidence: Number(item.confidence ?? 0) || undefined,
    signals: asStringList(item.signals),
    decoderHints: asStringList(item.decoder_hints),
    familyHint: String(item.family_hint ?? "") || undefined,
    decoderOptionsHint: asPlainObject(item.decoder_options_hint),
    sourceRole: String(item.source_role ?? "") || undefined,
    contentType: String(item.content_type ?? "") || undefined,
    occurrenceCount: Number(item.occurrence_count ?? 0) || undefined,
    firstTime: String(item.first_time ?? "") || undefined,
    lastTime: String(item.last_time ?? "") || undefined,
    repeatWindowSeconds: Number(item.repeat_window_seconds ?? 0) || undefined,
    relatedPackets: asArray(item.related_packets)
      .map((value) => Number(value ?? 0))
      .filter(Boolean),
    ruleReasons: asStringList(item.rule_reasons),
  };
}
