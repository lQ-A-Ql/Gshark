import type { GlobalTrafficStats } from "../../core/types";
import { asBucket } from "./mapperPrimitives";

export function asGlobalTrafficStats(payload: any): GlobalTrafficStats {
  return {
    totalPackets: Number(payload?.total_packets ?? 0),
    protocolKinds: Number(payload?.protocol_kinds ?? 0),
    timeline: Array.isArray(payload?.timeline) ? payload.timeline.map(asBucket) : [],
    protocolDist: Array.isArray(payload?.protocol_dist) ? payload.protocol_dist.map(asBucket) : [],
    topTalkers: Array.isArray(payload?.top_talkers) ? payload.top_talkers.map(asBucket) : [],
    topHostnames: Array.isArray(payload?.top_hostnames) ? payload.top_hostnames.map(asBucket) : [],
    topDomains: Array.isArray(payload?.top_domains) ? payload.top_domains.map(asBucket) : [],
    topSrcIPs: Array.isArray(payload?.top_src_ips) ? payload.top_src_ips.map(asBucket) : [],
    topDstIPs: Array.isArray(payload?.top_dst_ips) ? payload.top_dst_ips.map(asBucket) : [],
    topComputerNames: Array.isArray(payload?.top_computer_names) ? payload.top_computer_names.map(asBucket) : [],
    topDestPorts: Array.isArray(payload?.top_dest_ports) ? payload.top_dest_ports.map(asBucket) : [],
    topSrcPorts: Array.isArray(payload?.top_src_ports) ? payload.top_src_ports.map(asBucket) : [],
  };
}
