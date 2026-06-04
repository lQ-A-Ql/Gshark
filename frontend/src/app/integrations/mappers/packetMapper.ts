import type { Packet } from "../../core/types";
import type { PacketColorFeaturesWireDTO, PacketWireDTO } from "../wire/captureWireDtos";
import { asPlainObject } from "./mapperPrimitives";

const VALID_PROTOCOLS = new Set(["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSHv2", "TLS", "ARP", "ICMP", "ICMPV6", "USB"]);

function asProtocol(raw: unknown): Packet["proto"] {
  const s = String(raw ?? "OTHER").toUpperCase();
  return VALID_PROTOCOLS.has(s) ? (s as Packet["proto"]) : "OTHER";
}

export function asPacket(input: unknown): Packet {
  const payload: PacketWireDTO = asPlainObject(input) ?? {};
  const color: PacketColorFeaturesWireDTO = asPlainObject(payload.color_features) ?? {};
  return {
    id: Number(payload.id ?? 0),
    time: normalizePacketTime(payload.timestamp),
    src: String(payload.source_ip ?? ""),
    srcPort: Number(payload.source_port ?? 0),
    dst: String(payload.dest_ip ?? ""),
    dstPort: Number(payload.dest_port ?? 0),
    proto: asProtocol(payload.protocol),
    displayProtocol: String(payload.display_protocol ?? "").trim() || undefined,
    length: Number(payload.length ?? 0),
    info: String(payload.info ?? ""),
    payload: String(payload.payload ?? ""),
    rawHex: String(payload.raw_hex ?? "") || undefined,
    streamId: Number(payload.stream_id ?? 0),
    ipHeaderLen: Number(payload.ip_header_len ?? 0) || undefined,
    l4HeaderLen: Number(payload.l4_header_len ?? 0) || undefined,
    colorFeatures: asColorFeatures(color),
  };
}

function asColorFeatures(c: PacketColorFeaturesWireDTO) {
  const b = (v: unknown) => Boolean(v);
  const n = (v: unknown) => Number(v ?? 0) || undefined;
  return {
    tcpAnalysisFlags: b(c.tcp_analysis_flags),
    tcpWindowUpdate: b(c.tcp_window_update),
    tcpKeepAlive: b(c.tcp_keep_alive),
    tcpKeepAliveAck: b(c.tcp_keep_alive_ack),
    tcpRst: b(c.tcp_rst),
    tcpSyn: b(c.tcp_syn),
    tcpFin: b(c.tcp_fin),
    hsrpState: n(c.hsrp_state),
    ospfMsg: n(c.ospf_msg),
    icmpType: n(c.icmp_type),
    icmpv6Type: n(c.icmpv6_type),
    ipv4Ttl: n(c.ipv4_ttl),
    ipv6HopLimit: n(c.ipv6_hop_limit),
    stpTopologyChange: b(c.stp_topology_change),
    checksumBad: b(c.checksum_bad),
    broadcast: b(c.broadcast),
    hasSmb: b(c.has_smb),
    hasNbss: b(c.has_nbss),
    hasNbns: b(c.has_nbns),
    hasNetbios: b(c.has_netbios),
    hasDcerpc: b(c.has_dcerpc),
    hasSystemdJournal: b(c.has_systemd_journal),
    hasSysdig: b(c.has_sysdig),
    hasHsrp: b(c.has_hsrp),
    hasEigrp: b(c.has_eigrp),
    hasOspf: b(c.has_ospf),
    hasBgp: b(c.has_bgp),
    hasCdp: b(c.has_cdp),
    hasVrrp: b(c.has_vrrp),
    hasCarp: b(c.has_carp),
    hasGvrp: b(c.has_gvrp),
    hasIgmp: b(c.has_igmp),
    hasIsmp: b(c.has_ismp),
    hasRip: b(c.has_rip),
    hasGlbp: b(c.has_glbp),
    hasPim: b(c.has_pim),
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
    return parsed.toISOString().slice(11, 23);
  }
  return raw.length > 16 ? `${raw.slice(0, 13)}...` : raw;
}
