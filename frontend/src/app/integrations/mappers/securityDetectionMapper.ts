import type { BruteforceAnalysis, UDPTunnelAnalysis } from "../../core/types";

export function asUDPTunnelAnalysis(payload: any): UDPTunnelAnalysis {
  return {
    totalSuspicious: payload?.total_suspicious ?? 0,
    dnsTunnelHits: (payload?.dns_tunnel_hits ?? []).map((h: any) => ({
      baseDomain: h.base_domain,
      queryCount: h.query_count,
      uniqueSubdomains: h.unique_subdomains,
      avgSubdomainLen: h.avg_subdomain_len,
      maxPayloadSize: h.max_payload_size,
      entropyScore: h.entropy_score,
      confidence: h.confidence,
      firstPacketId: h.first_packet_id,
      evidence: h.evidence,
    })),
    udpTunnelHits: (payload?.udp_tunnel_hits ?? []).map((h: any) => ({
      source: h.source,
      destination: h.destination,
      port: h.port,
      packetCount: h.packet_count,
      bytesTotal: h.bytes_total,
      avgPayloadLen: h.avg_payload_len,
      stddevLen: h.stddev_len,
      durationSec: h.duration_sec,
      confidence: h.confidence,
      firstPacketId: h.first_packet_id,
      protocol: h.protocol,
    })),
    notes: payload?.notes ?? [],
  };
}

export function asBruteforceAnalysis(payload: any): BruteforceAnalysis {
  return {
    totalSuspicious: payload?.total_suspicious ?? 0,
    portScanHits: (payload?.port_scan_hits ?? []).map((h: any) => ({
      sourceIp: h.source_ip,
      targetIp: h.target_ip,
      uniquePortsHit: h.unique_ports_hit,
      synCount: h.syn_count,
      rstCount: h.rst_count,
      openPorts: h.open_ports ?? [],
      durationSec: h.duration_sec,
      scanType: h.scan_type,
      confidence: h.confidence,
      firstPacketId: h.first_packet_id,
    })),
    dirBruteforceHits: (payload?.dir_bruteforce_hits ?? []).map((h: any) => ({
      sourceIp: h.source_ip,
      targetHost: h.target_host,
      totalRequests: h.total_requests,
      status404Count: h.status_404_count,
      status403Count: h.status_403_count,
      status200Count: h.status_200_count,
      uniquePaths: h.unique_paths,
      requestsPerSec: h.requests_per_sec,
      samplePaths: h.sample_paths ?? [],
      confidence: h.confidence,
      firstPacketId: h.first_packet_id,
    })),
    notes: payload?.notes ?? [],
  };
}
