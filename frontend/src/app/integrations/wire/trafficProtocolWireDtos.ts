import type { TrafficBucketWireDTO, TrafficConversationWireDTO } from "./trafficBucketWireDtos";

export interface TrafficProtocolTreeNodeWireDTO {
  name: string;
  count: number;
  children?: TrafficProtocolTreeNodeWireDTO[];
}

export interface GlobalTrafficStatsWireDTO extends Record<string, unknown> {
  total_packets?: number;
  protocol_kinds?: number;
  timeline?: TrafficBucketWireDTO[];
  protocol_dist?: TrafficBucketWireDTO[];
  top_talkers?: TrafficBucketWireDTO[];
  top_conversations?: TrafficConversationWireDTO[];
  top_hostnames?: TrafficBucketWireDTO[];
  top_domains?: TrafficBucketWireDTO[];
  top_src_ips?: TrafficBucketWireDTO[];
  top_dst_ips?: TrafficBucketWireDTO[];
  top_computer_names?: TrafficBucketWireDTO[];
  top_dest_ports?: TrafficBucketWireDTO[];
  top_src_ports?: TrafficBucketWireDTO[];
  protocol_hierarchy?: TrafficProtocolTreeNodeWireDTO[];
}
