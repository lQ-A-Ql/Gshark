import type { C2DNSAggregate, C2HTTPEndpointAggregate, C2StreamAggregate } from "../../core/types";
import {
  asArray,
  asBucket,
  asPlainObject,
  asPositiveFiniteNumbers,
  asPositiveNumbers,
  asStringList,
} from "./mapperPrimitives";
import { asC2ScoreFactor } from "./c2IndicatorMapper";

export function asC2HTTPEndpointAggregate(input: unknown): C2HTTPEndpointAggregate {
  const item = asPlainObject(input);
  return {
    host: String(item?.host ?? ""),
    uri: String(item?.uri ?? ""),
    channel: String(item?.channel ?? "") || undefined,
    total: Number(item?.total ?? 0),
    getCount: Number(item?.get_count ?? 0),
    postCount: Number(item?.post_count ?? 0),
    methods: asArray(item?.methods).map(asBucket),
    firstTime: String(item?.first_time ?? "") || undefined,
    lastTime: String(item?.last_time ?? "") || undefined,
    avgInterval: String(item?.avg_interval ?? "") || undefined,
    jitter: String(item?.jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item?.intervals),
    streams: asPositiveNumbers(item?.streams),
    packets: asPositiveNumbers(item?.packets),
    representativePacket: Number(item?.representative_packet ?? 0) || undefined,
    confidence: Number(item?.confidence ?? 0) || undefined,
    signalTags: asStringList(item?.signal_tags),
    scoreFactors: asArray(item?.score_factors).map(asC2ScoreFactor),
    summary: String(item?.summary ?? ""),
  };
}

export function asC2DNSAggregate(input: unknown): C2DNSAggregate {
  const item = asPlainObject(input);
  return {
    qname: String(item?.qname ?? ""),
    total: Number(item?.total ?? 0),
    maxLabelLength: Number(item?.max_label_length ?? 0),
    queryTypes: asArray(item?.query_types).map(asBucket),
    txtCount: Number(item?.txt_count ?? 0),
    nullCount: Number(item?.null_count ?? 0),
    cnameCount: Number(item?.cname_count ?? 0),
    requestCount: Number(item?.request_count ?? 0),
    responseCount: Number(item?.response_count ?? 0),
    firstTime: String(item?.first_time ?? "") || undefined,
    lastTime: String(item?.last_time ?? "") || undefined,
    avgInterval: String(item?.avg_interval ?? "") || undefined,
    jitter: String(item?.jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item?.intervals),
    packets: asPositiveNumbers(item?.packets),
    confidence: Number(item?.confidence ?? 0) || undefined,
    summary: String(item?.summary ?? ""),
  };
}

export function asC2StreamAggregate(input: unknown): C2StreamAggregate {
  const item = asPlainObject(input);
  return {
    streamId: Number(item?.stream_id ?? 0),
    protocol: String(item?.protocol ?? "") || undefined,
    totalPackets: Number(item?.total_packets ?? 0),
    archMarkers: asArray(item?.arch_markers).map(asBucket),
    lengthPrefixCount: Number(item?.length_prefix_count ?? 0),
    shortPackets: Number(item?.short_packets ?? 0),
    longPackets: Number(item?.long_packets ?? 0),
    transitions: Number(item?.transitions ?? 0),
    heartbeatAvg: String(item?.heartbeat_avg ?? "") || undefined,
    heartbeatJitter: String(item?.heartbeat_jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item?.intervals),
    hasWebSocket: Boolean(item?.has_websocket),
    wsParams: String(item?.ws_params ?? "") || undefined,
    listenerHints: asArray(item?.listener_hints).map(asBucket),
    firstTime: String(item?.first_time ?? "") || undefined,
    lastTime: String(item?.last_time ?? "") || undefined,
    packets: asPositiveNumbers(item?.packets),
    confidence: Number(item?.confidence ?? 0) || undefined,
    summary: String(item?.summary ?? ""),
  };
}
