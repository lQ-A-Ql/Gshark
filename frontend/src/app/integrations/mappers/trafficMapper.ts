import type { GlobalTrafficStats, TrafficConversation, TrafficProtocolTreeNode } from "../../core/types";
import { normalizeTrafficTimelineBuckets } from "../../features/traffic/trafficTimeline";
import type { GlobalTrafficStatsWireDTO, TrafficConversationWireDTO } from "../wire/trafficWireDtos";
import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";

function asTrafficProtocolTreeNode(input: unknown): TrafficProtocolTreeNode {
  const obj = asPlainObject(input) ?? {};
  return {
    name: String(obj.name ?? ""),
    count: Number(obj.count ?? 0),
    children: asArray(obj.children).map(asTrafficProtocolTreeNode),
  };
}

function asTrafficConversation(input: unknown): TrafficConversation | undefined {
  const payload: TrafficConversationWireDTO = asPlainObject(input) ?? {};
  const src = String(payload.src ?? "").trim();
  const dst = String(payload.dst ?? "").trim();

  if (!src || !dst) {
    return undefined;
  }

  return {
    src,
    dst,
    count: Number(payload.count ?? 0),
  };
}

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
