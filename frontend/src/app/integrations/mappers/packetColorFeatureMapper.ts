import type { PacketColorFeaturesWireDTO, TLSFingerprintWireDTO } from "../wire/captureWireDtos";

export function asTLSFingerprint(fingerprint: TLSFingerprintWireDTO) {
  const ja3Hash = asOptionalString(fingerprint.ja3_hash);
  const ja3sHash = asOptionalString(fingerprint.ja3s_hash);
  const ja3Raw = asOptionalString(fingerprint.ja3_raw);
  const ja3sRaw = asOptionalString(fingerprint.ja3s_raw);
  if (!ja3Hash && !ja3sHash && !ja3Raw && !ja3sRaw) return undefined;
  return {
    ja3Hash,
    ja3sHash,
    ja3Raw,
    ja3sRaw,
  };
}

export function asColorFeatures(c: PacketColorFeaturesWireDTO) {
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

function asOptionalString(value: unknown) {
  const normalized = String(value ?? "").trim();
  return normalized || undefined;
}
