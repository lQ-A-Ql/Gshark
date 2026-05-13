import type { GlobalTrafficStats } from "../../core/types";
import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";

export function asGlobalTrafficStats(input: unknown): GlobalTrafficStats {
  const payload = asPlainObject(input) ?? {};
  return {
    totalPackets: Number(payload.total_packets ?? 0),
    protocolKinds: Number(payload.protocol_kinds ?? 0),
    timeline: asArray(payload.timeline).map(asBucket),
    protocolDist: asArray(payload.protocol_dist).map(asBucket),
    topTalkers: asArray(payload.top_talkers).map(asBucket),
    topHostnames: asArray(payload.top_hostnames).map(asBucket),
    topDomains: asArray(payload.top_domains).map(asBucket),
    topSrcIPs: asArray(payload.top_src_ips).map(asBucket),
    topDstIPs: asArray(payload.top_dst_ips).map(asBucket),
    topComputerNames: asArray(payload.top_computer_names).map(asBucket),
    topDestPorts: asArray(payload.top_dest_ports).map(asBucket),
    topSrcPorts: asArray(payload.top_src_ports).map(asBucket),
  };
}
