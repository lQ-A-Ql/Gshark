export interface CaptureStatusWireDTO extends Record<string, unknown> {
  file_path?: unknown;
  filePath?: unknown;
  has_capture?: unknown;
  hasCapture?: unknown;
  packet_count?: unknown;
  packetCount?: unknown;
}

export interface PacketWireDTO extends Record<string, unknown> {
  id?: number;
  timestamp?: string;
  source_ip?: string;
  source_port?: number;
  dest_ip?: string;
  dest_port?: number;
  protocol?: string;
  display_protocol?: string;
  length?: number;
  info?: string;
  payload?: string;
  raw_hex?: string;
  stream_id?: number;
  ip_header_len?: number;
  l4_header_len?: number;
  color_features?: PacketColorFeaturesWireDTO;
  udp_payload_hex?: string;
}

export interface PacketColorFeaturesWireDTO extends Record<string, unknown> {
  tcp_analysis_flags?: boolean;
  tcp_window_update?: boolean;
  tcp_keep_alive?: boolean;
  tcp_keep_alive_ack?: boolean;
  tcp_rst?: boolean;
  tcp_syn?: boolean;
  tcp_fin?: boolean;
  hsrp_state?: number;
  ospf_msg?: number;
  icmp_type?: number;
  icmpv6_type?: number;
  ipv4_ttl?: number;
  ipv6_hop_limit?: number;
  stp_topology_change?: boolean;
  checksum_bad?: boolean;
  broadcast?: boolean;
  has_smb?: boolean;
  has_nbss?: boolean;
  has_nbns?: boolean;
  has_netbios?: boolean;
  has_dcerpc?: boolean;
  has_systemd_journal?: boolean;
  has_sysdig?: boolean;
  has_hsrp?: boolean;
  has_eigrp?: boolean;
  has_ospf?: boolean;
  has_bgp?: boolean;
  has_cdp?: boolean;
  has_vrrp?: boolean;
  has_carp?: boolean;
  has_gvrp?: boolean;
  has_igmp?: boolean;
  has_ismp?: boolean;
  has_rip?: boolean;
  has_glbp?: boolean;
  has_pim?: boolean;
}

export interface PacketsPageWireDTO extends Record<string, unknown> {
  items?: PacketWireDTO[];
  next_cursor?: number;
  total?: number;
  has_more?: boolean;
  filtering?: boolean;
}

export interface PacketLocateWireDTO extends Record<string, unknown> {
  packet_id?: number;
  cursor?: number;
  total?: number;
  found?: boolean;
}
