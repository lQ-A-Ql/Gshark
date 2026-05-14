export interface GlobalTrafficStatsWireDTO extends Record<string, unknown> {
  total_packets?: unknown;
  protocol_kinds?: unknown;
  timeline?: unknown;
  protocol_dist?: unknown;
  top_talkers?: unknown;
  top_hostnames?: unknown;
  top_domains?: unknown;
  top_src_ips?: unknown;
  top_dst_ips?: unknown;
  top_computer_names?: unknown;
  top_dest_ports?: unknown;
  top_src_ports?: unknown;
}
