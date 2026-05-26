import type { StreamDecodeResult, StreamPayloadCandidate, StreamPayloadInspection, StreamPayloadSource } from "../core/types";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";
import { asArray, asPlainObject, asStringList } from "./mappers/mapperPrimitives";
import { asBinaryStream, asHttpStream } from "./mappers/packetStreamMapper";
import type {
  StreamDecodeResultWireDTO,
  StreamPayloadCandidateWireDTO,
  StreamPayloadInspectionWireDTO,
} from "./wire/streamDecodeWireDtos";
import type { StreamPayloadSourceWireDTO } from "./wire/streamPayloadSourceWireDtos";
import type { PacketLayersWireDTO, PacketRawHexWireDTO, StreamIndexWireDTO } from "./wire/streamWireDtos";

export function createStreamTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async getHttpStream(streamId, signal) {
      return asHttpStream(await typedCall(() => desktopApp.GetHttpStream!(streamId), "DesktopApp.GetHttpStream", signal));
    },
    async getRawStream(protocol, streamId, signal) {
      return asBinaryStream(
        await typedCall(() => desktopApp.GetRawStream!(protocol, streamId), "DesktopApp.GetRawStream", signal),
        protocol,
      );
    },
    async getRawStreamPage(protocol, streamId, cursor, limit, signal) {
      return asBinaryStream(
        await typedCall(
          () => desktopApp.GetRawStreamPage!(protocol, streamId, cursor, limit),
          "DesktopApp.GetRawStreamPage",
          signal,
        ),
        protocol,
      );
    },
    async decodeStreamPayload(decoder, payload, options = {}, signal) {
      return asStreamDecodeResult(
        await typedCall(
          () => desktopApp.DecodeStreamPayload!({ decoder, payload, options }),
          "DesktopApp.DecodeStreamPayload",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
        decoder,
      );
    },
    async inspectStreamPayload(payload, signal) {
      return asStreamPayloadInspection(
        await typedCall(
          () => desktopApp.InspectStreamPayload!(payload),
          "DesktopApp.InspectStreamPayload",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async listStreamPayloadSources(signal, limit = 500) {
      const rows = await typedCall(
        () => desktopApp.ListStreamPayloadSources!(limit),
        "DesktopApp.ListStreamPayloadSources",
        signal,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return asArray(rows).map(asStreamPayloadSource);
    },
    async updateStreamPayloads(protocol, streamId, patches, signal) {
      const payload = await typedCall(
        () => desktopApp.UpdateStreamPayloads!(protocol, streamId, patches),
        "DesktopApp.UpdateStreamPayloads",
        signal,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return protocol === "HTTP" ? asHttpStream(payload) : asBinaryStream(payload, protocol);
    },
    async listStreamIds(protocol, signal) {
      const payload = (await typedCall(
        () => desktopApp.ListStreamIDs!(protocol),
        "DesktopApp.ListStreamIDs",
        signal,
      )) as StreamIndexWireDTO;
      return asArray(payload.ids)
        .map((id) => Number(id))
        .filter((id) => Number.isFinite(id) && id >= 0)
        .sort((a, b) => a - b);
    },
    async getPacketRawHex(packetId, signal) {
      const payload = (await typedCall(
        () => desktopApp.GetPacketRawHex!(packetId),
        "DesktopApp.GetPacketRawHex",
        signal,
      )) as PacketRawHexWireDTO;
      return String(payload.raw_hex ?? "");
    },
    async getPacketLayers(packetId, signal) {
      const payload = (await typedCall(
        () => desktopApp.GetPacketLayers!(packetId),
        "DesktopApp.GetPacketLayers",
        signal,
      )) as PacketLayersWireDTO;
      return asPlainObject(payload.layers) ?? null;
    },
  };
}

function asStreamDecodeResult(input: unknown, decoder: string): StreamDecodeResult {
  const result = (asPlainObject(input) ?? {}) as StreamDecodeResultWireDTO;
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
}

function asStreamPayloadInspection(input: unknown): StreamPayloadInspection {
  const result = (asPlainObject(input) ?? {}) as StreamPayloadInspectionWireDTO;
  return {
    normalizedPayload: String(result.normalized_payload ?? ""),
    candidates: asArray(result.candidates).map(asStreamPayloadCandidate),
    suggestedCandidateId: String(result.suggested_candidate_id ?? "") || undefined,
    suggestedDecoder: String(result.suggested_decoder ?? "") || undefined,
    suggestedFamily: String(result.suggested_family ?? "") || undefined,
    confidence: Number(result.confidence ?? 0) || undefined,
    reasons: asStringList(result.reasons),
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
