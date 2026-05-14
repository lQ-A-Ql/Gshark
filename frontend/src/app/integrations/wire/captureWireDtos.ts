export interface CaptureStatusWireDTO extends Record<string, unknown> {
  file_path?: unknown;
  filePath?: unknown;
  has_capture?: unknown;
  hasCapture?: unknown;
  packet_count?: unknown;
  packetCount?: unknown;
}

export interface PacketWireDTO extends Record<string, unknown> {
  id?: unknown;
  timestamp?: unknown;
  source_ip?: unknown;
  source_port?: unknown;
  dest_ip?: unknown;
  dest_port?: unknown;
  protocol?: unknown;
  display_protocol?: unknown;
  length?: unknown;
  info?: unknown;
  payload?: unknown;
  raw_hex?: unknown;
  stream_id?: unknown;
  ip_header_len?: unknown;
  l4_header_len?: unknown;
  color_features?: unknown;
}

export interface PacketColorFeaturesWireDTO extends Record<string, unknown> {
  tcp_analysis_flags?: unknown;
  tcp_window_update?: unknown;
  tcp_keep_alive?: unknown;
  tcp_keep_alive_ack?: unknown;
  tcp_rst?: unknown;
  tcp_syn?: unknown;
  tcp_fin?: unknown;
  hsrp_state?: unknown;
  ospf_msg?: unknown;
  icmp_type?: unknown;
  icmpv6_type?: unknown;
  ipv4_ttl?: unknown;
  ipv6_hop_limit?: unknown;
  stp_topology_change?: unknown;
  checksum_bad?: unknown;
  broadcast?: unknown;
  has_smb?: unknown;
  has_nbss?: unknown;
  has_nbns?: unknown;
  has_netbios?: unknown;
  has_dcerpc?: unknown;
  has_systemd_journal?: unknown;
  has_sysdig?: unknown;
  has_hsrp?: unknown;
  has_eigrp?: unknown;
  has_ospf?: unknown;
  has_bgp?: unknown;
  has_cdp?: unknown;
  has_vrrp?: unknown;
  has_carp?: unknown;
  has_gvrp?: unknown;
  has_igmp?: unknown;
  has_ismp?: unknown;
  has_rip?: unknown;
  has_glbp?: unknown;
}

export interface PacketsPageWireDTO extends Record<string, unknown> {
  items?: unknown;
  next_cursor?: unknown;
  total?: unknown;
  has_more?: unknown;
  filtering?: unknown;
}

export interface PacketLocateWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  cursor?: unknown;
  total?: unknown;
  found?: unknown;
}
