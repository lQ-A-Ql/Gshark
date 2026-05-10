import type { Packet } from "../../core/types";

export function asPacket(input: any): Packet {
  const color = input.color_features ?? {};
  return {
    id: Number(input.id ?? 0),
    time: normalizePacketTime(input.timestamp),
    src: String(input.source_ip ?? ""),
    srcPort: Number(input.source_port ?? 0),
    dst: String(input.dest_ip ?? ""),
    dstPort: Number(input.dest_port ?? 0),
    proto: String(input.protocol ?? "OTHER") as Packet["proto"],
    displayProtocol: String(input.display_protocol ?? "").trim() || undefined,
    length: Number(input.length ?? 0),
    info: String(input.info ?? ""),
    payload: String(input.payload ?? ""),
    rawHex: String(input.raw_hex ?? "") || undefined,
    streamId: Number(input.stream_id ?? 0),
    ipHeaderLen: Number(input.ip_header_len ?? 0) || undefined,
    l4HeaderLen: Number(input.l4_header_len ?? 0) || undefined,
    colorFeatures: {
      tcpAnalysisFlags: Boolean(color.tcp_analysis_flags),
      tcpWindowUpdate: Boolean(color.tcp_window_update),
      tcpKeepAlive: Boolean(color.tcp_keep_alive),
      tcpKeepAliveAck: Boolean(color.tcp_keep_alive_ack),
      tcpRst: Boolean(color.tcp_rst),
      tcpSyn: Boolean(color.tcp_syn),
      tcpFin: Boolean(color.tcp_fin),
      hsrpState: Number(color.hsrp_state ?? 0) || undefined,
      ospfMsg: Number(color.ospf_msg ?? 0) || undefined,
      icmpType: Number(color.icmp_type ?? 0) || undefined,
      icmpv6Type: Number(color.icmpv6_type ?? 0) || undefined,
      ipv4Ttl: Number(color.ipv4_ttl ?? 0) || undefined,
      ipv6HopLimit: Number(color.ipv6_hop_limit ?? 0) || undefined,
      stpTopologyChange: Boolean(color.stp_topology_change),
      checksumBad: Boolean(color.checksum_bad),
      broadcast: Boolean(color.broadcast),
      hasSmb: Boolean(color.has_smb),
      hasNbss: Boolean(color.has_nbss),
      hasNbns: Boolean(color.has_nbns),
      hasNetbios: Boolean(color.has_netbios),
      hasDcerpc: Boolean(color.has_dcerpc),
      hasSystemdJournal: Boolean(color.has_systemd_journal),
      hasSysdig: Boolean(color.has_sysdig),
      hasHsrp: Boolean(color.has_hsrp),
      hasEigrp: Boolean(color.has_eigrp),
      hasOspf: Boolean(color.has_ospf),
      hasBgp: Boolean(color.has_bgp),
      hasCdp: Boolean(color.has_cdp),
      hasVrrp: Boolean(color.has_vrrp),
      hasCarp: Boolean(color.has_carp),
      hasGvrp: Boolean(color.has_gvrp),
      hasIgmp: Boolean(color.has_igmp),
      hasIsmp: Boolean(color.has_ismp),
      hasRip: Boolean(color.has_rip),
      hasGlbp: Boolean(color.has_glbp),
      hasPim: Boolean(color.has_pim),
    },
  };
}

function normalizePacketTime(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "";

  if (/^\d{13,}$/.test(raw)) {
    const ms = Number(raw.slice(0, 13));
    if (!Number.isNaN(ms)) {
      const d = new Date(ms);
      return `${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, "0")}`;
    }
  }

  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    const iso = parsed.toISOString();
    return iso.slice(11, 23);
  }

  return raw.length > 16 ? `${raw.slice(0, 13)}...` : raw;
}
