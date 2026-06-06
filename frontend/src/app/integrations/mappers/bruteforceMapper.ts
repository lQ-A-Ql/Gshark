import type { BruteforceAnalysis } from "../../core/types";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

const n = (value: unknown) => Number(value ?? 0);
const s = (value: unknown) => String(value ?? "");

export function asBruteforceAnalysis(input: unknown): BruteforceAnalysis {
  const payload = asPlainObject(input) ?? {};
  return {
    totalSuspicious: n(payload.total_suspicious),
    portScanHits: asArray(payload.port_scan_hits).map((hit) => {
      const h = asPlainObject(hit) ?? {};
      return {
        sourceIp: s(h.source_ip),
        targetIp: s(h.target_ip),
        uniquePortsHit: n(h.unique_ports_hit),
        synCount: n(h.syn_count),
        rstCount: n(h.rst_count),
        openPorts: asArray(h.open_ports).map(n),
        durationSec: n(h.duration_sec),
        scanType: s(h.scan_type),
        confidence: n(h.confidence),
        firstPacketId: n(h.first_packet_id),
      };
    }),
    dirBruteforceHits: asArray(payload.dir_bruteforce_hits).map((hit) => {
      const h = asPlainObject(hit) ?? {};
      return {
        sourceIp: s(h.source_ip),
        targetHost: s(h.target_host),
        totalRequests: n(h.total_requests),
        status404Count: n(h.status_404_count),
        status403Count: n(h.status_403_count),
        status200Count: n(h.status_200_count),
        uniquePaths: n(h.unique_paths),
        requestsPerSec: n(h.requests_per_sec),
        samplePaths: asStringList(h.sample_paths),
        confidence: n(h.confidence),
        firstPacketId: n(h.first_packet_id),
      };
    }),
    notes: asStringList(payload.notes),
  };
}
