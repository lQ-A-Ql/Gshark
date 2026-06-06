import type { GlobalTrafficStats, TrafficConversation } from "../../core/types";
import { normalizeTrafficTimelineBuckets } from "../../features/traffic/trafficTimeline";
import type { GlobalTrafficStatsWireDTO } from "../wire/trafficWireDtos";
import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";
import { asTrafficConversation } from "./trafficConversationMapper";
import { asTrafficProtocolTreeNode } from "./trafficProtocolHierarchyMapper";

export function asGlobalTrafficStats(input: unknown): GlobalTrafficStats {
  const payload: GlobalTrafficStatsWireDTO = asPlainObject(input) ?? {};
  return {
    totalPackets: Number(payload.total_packets ?? 0),
    protocolKinds: Number(payload.protocol_kinds ?? 0),
    timeline: normalizeTrafficTimelineBuckets(asArray(payload.timeline).map(asBucket)),
    protocolDist: asArray(payload.protocol_dist).map(asBucket),
    topTalkers: asArray(payload.top_talkers).map(asBucket),
    topConversations: asArray(payload.top_conversations)
      .map(asTrafficConversation)
      .filter((entry): entry is TrafficConversation => Boolean(entry)),
    topHostnames: asArray(payload.top_hostnames).map(asBucket),
    topDomains: asArray(payload.top_domains).map(asBucket),
    topSrcIPs: asArray(payload.top_src_ips).map(asBucket),
    topDstIPs: asArray(payload.top_dst_ips).map(asBucket),
    topComputerNames: asArray(payload.top_computer_names).map(asBucket),
    topDestPorts: asArray(payload.top_dest_ports).map(asBucket),
    topSrcPorts: asArray(payload.top_src_ports).map(asBucket),
    protocolHierarchy: asArray(payload.protocol_hierarchy).map(asTrafficProtocolTreeNode),
  };
}
