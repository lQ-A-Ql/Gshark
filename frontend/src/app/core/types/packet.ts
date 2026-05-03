export type Protocol = "TCP" | "UDP" | "HTTP" | "HTTPS" | "DNS" | "SSHv2" | "TLS" | "ARP" | "ICMP" | "ICMPV6" | "USB" | "OTHER";

export interface PacketColorFeatures {
  tcpAnalysisFlags?: boolean;
  tcpWindowUpdate?: boolean;
  tcpKeepAlive?: boolean;
  tcpKeepAliveAck?: boolean;
  tcpRst?: boolean;
  tcpSyn?: boolean;
  tcpFin?: boolean;

  hsrpState?: number;
  ospfMsg?: number;
  icmpType?: number;
  icmpv6Type?: number;

  ipv4Ttl?: number;
  ipv6HopLimit?: number;

  stpTopologyChange?: boolean;
  checksumBad?: boolean;
  broadcast?: boolean;

  hasSmb?: boolean;
  hasNbss?: boolean;
  hasNbns?: boolean;
  hasNetbios?: boolean;
  hasDcerpc?: boolean;
  hasSystemdJournal?: boolean;
  hasSysdig?: boolean;
  hasHsrp?: boolean;
  hasEigrp?: boolean;
  hasOspf?: boolean;
  hasBgp?: boolean;
  hasCdp?: boolean;
  hasVrrp?: boolean;
  hasCarp?: boolean;
  hasGvrp?: boolean;
  hasIgmp?: boolean;
  hasIsmp?: boolean;
  hasRip?: boolean;
  hasGlbp?: boolean;
  hasPim?: boolean;
}

export interface Packet {
  id: number;
  time: string;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  proto: Protocol;
  displayProtocol?: string;
  length: number;
  info: string;
  payload: string;
  rawHex?: string;
  statusCode?: number;
  method?: string;
  streamId?: number;
  ipHeaderLen?: number;
  l4HeaderLen?: number;
  colorFeatures?: PacketColorFeatures;
}

export interface ProtocolTreeNode {
  id: string;
  label: string;
  byteRange?: [number, number];
  children?: ProtocolTreeNode[];
}

export type ThreatLevel = "critical" | "high" | "medium" | "low";

export interface ThreatHit {
  id: number;
  packetId: number;
  category: string;
  rule: string;
  level: ThreatLevel;
  preview: string;
  match: string;
}

export interface ExtractedObject {
  id: number;
  packetId: number;
  name: string;
  sizeBytes: number;
  mime: string;
  source: "HTTP" | "FTP";
}
