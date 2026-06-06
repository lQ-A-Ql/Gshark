import type { UDPTunnelAnalysis } from "../../core/types";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

const n = (value: unknown) => Number(value ?? 0);
const s = (value: unknown) => String(value ?? "");

export function asUDPTunnelAnalysis(input: unknown): UDPTunnelAnalysis {
  const payload = asPlainObject(input) ?? {};
  return {
    totalSuspicious: n(payload.total_suspicious),
    dnsTunnelHits: asArray(payload.dns_tunnel_hits).map((hit) => {
      const h = asPlainObject(hit) ?? {};
      return {
        baseDomain: s(h.base_domain),
        queryCount: n(h.query_count),
        uniqueSubdomains: n(h.unique_subdomains),
        avgSubdomainLen: n(h.avg_subdomain_len),
        maxPayloadSize: n(h.max_payload_size),
        entropyScore: n(h.entropy_score),
        confidence: n(h.confidence),
        firstPacketId: n(h.first_packet_id),
        evidence: s(h.evidence),
      };
    }),
    udpTunnelHits: asArray(payload.udp_tunnel_hits).map((hit) => {
      const h = asPlainObject(hit) ?? {};
      return {
        source: s(h.source),
        destination: s(h.destination),
        port: n(h.port),
        packetCount: n(h.packet_count),
        bytesTotal: n(h.bytes_total),
        avgPayloadLen: n(h.avg_payload_len),
        stddevLen: n(h.stddev_len),
        durationSec: n(h.duration_sec),
        confidence: n(h.confidence),
        firstPacketId: n(h.first_packet_id),
        protocol: s(h.protocol),
      };
    }),
    notes: asStringList(payload.notes),
  };
}
