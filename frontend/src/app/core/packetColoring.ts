import type { Packet } from "./types";

export interface PacketColorStyle {
  ruleName: string;
  backgroundColor: string;
  backgroundGradient: string;
  color: string;
}

interface ParsedColorRule {
  name: string;
  expr: string;
  bg: [number, number, number];
  fg: [number, number, number];
  match: (packet: Packet, text: string) => boolean;
}

const WIRESHARK_COLORING_TEXT = `@Bad TCP@tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack@[8000,18000,22000][65535,40000,40000]
@HSRP State Change@hsrp.state != 8 && hsrp.state != 16@[8000,18000,22000][65535,65535,45000]
@Spanning Tree Topology  Change@stp.type == 0x80@[8000,18000,22000][65535,65535,45000]
@OSPF State Change@ospf.msg != 1@[8000,18000,22000][65535,65535,45000]
@ICMP errors@icmp.type in { 3..5, 11 } || icmpv6.type in { 1..4 }@[8000,18000,22000][50000,65535,35000]
@ARP@arp@[65535,63000,58000][8000,18000,22000]
@ICMP@icmp || icmpv6@[65535,60000,65535][8000,18000,22000]
@TCP RST@tcp.flags.reset eq 1@[55000,10000,10000][65535,65535,45000]
@SCTP ABORT@sctp.chunk_type eq ABORT@[55000,10000,10000][65535,65535,45000]
@IPv4 TTL low or unexpected@(ip.dst != 224.0.0.0/4 && ip.ttl < 5 && !(pim || ospf || eigrp || bgp || tcp.port==179)) || (ip.dst == 224.0.0.0/24 && ip.dst != 224.0.0.251 && ip.ttl != 1 && !(vrrp || carp || eigrp || rip || glbp))@[55000,10000,10000][65535,63000,62000]
@IPv6 hop limit low or unexpected@(ipv6.dst != ff00::/8 && ipv6.hlim < 5 && !( ospf|| bgp || tcp.port==179)) || (ipv6.dst==ff00::/8 && ipv6.hlim not in {1, 64, 255})@[55000,10000,10000][65535,63000,62000]
@Checksum Errors@eth.fcs.status=="Bad" || ip.checksum.status=="Bad" || tcp.checksum.status=="Bad" || udp.checksum.status=="Bad" || sctp.checksum.status=="Bad" || mstp.checksum.status=="Bad" || cdp.checksum.status=="Bad" || edp.checksum.status=="Bad" || wlan.fcs.status=="Bad" || stt.checksum.status=="Bad"@[8000,18000,22000][65535,40000,40000]
@SMB@smb || nbss || nbns || netbios@[65535,65535,56000][8000,18000,22000]
@HTTP@http || tcp.port == 80 || http2@[62000,65535,55000][8000,18000,22000]
@DCERPC@dcerpc@[55000,42000,65535][8000,18000,22000]
@Routing@hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp@[65535,64000,58000][8000,18000,22000]
@TCP SYN/FIN@tcp.flags & 0x02 || tcp.flags.fin == 1@[48000,48000,48000][8000,18000,22000]
@TCP@tcp@[62000,61500,65535][8000,18000,22000]
@UDP@udp@[59000,64000,65535][8000,18000,22000]
@Broadcast@eth[0] & 1@[65535,65535,65535][52000,53000,51000]
@System Event@systemd_journal || sysdig@[61500,61500,61500][15000,35000,48000]`;

function parseRGB16Triplet(value: string): [number, number, number] {
  const parts = value.split(",").map((x) => Number(x.trim()));
  if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n))) {
    return [0, 0, 0];
  }
  return [parts[0], parts[1], parts[2]];
}

function rgb16ToCss(color16: [number, number, number]): string {
  const [r16, g16, b16] = color16;
  const r8 = Math.max(0, Math.min(255, Math.round(r16 / 257)));
  const g8 = Math.max(0, Math.min(255, Math.round(g16 / 257)));
  const b8 = Math.max(0, Math.min(255, Math.round(b16 / 257)));
  return `rgb(${r8}, ${g8}, ${b8})`;
}

function rgb16ToRgba(color16: [number, number, number], alpha: number): string {
  const [r16, g16, b16] = color16;
  const r8 = Math.max(0, Math.min(255, Math.round(r16 / 257)));
  const g8 = Math.max(0, Math.min(255, Math.round(g16 / 257)));
  const b8 = Math.max(0, Math.min(255, Math.round(b16 / 257)));
  const safeAlpha = Math.max(0, Math.min(1, alpha));
  return `rgba(${r8}, ${g8}, ${b8}, ${safeAlpha})`;
}

function isProto(packet: Packet, values: string[]): boolean {
  const proto = String(packet.proto ?? "").toUpperCase();
  return values.some((v) => proto === v);
}

function includesAny(text: string, words: string[]): boolean {
  return words.some((word) => text.includes(word));
}

function buildMatcher(ruleName: string, expr: string): (packet: Packet, text: string) => boolean {
  const e = expr.toLowerCase();

  switch (ruleName) {
    case "Bad TCP":
      return (p, t) => {
        const f = p.colorFeatures;
        if (f?.tcpAnalysisFlags && !f.tcpWindowUpdate && !f.tcpKeepAlive && !f.tcpKeepAliveAck) {
          return true;
        }
        return isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) && includesAny(t, ["retransmission", "duplicate ack", "out-of-order", "rst", "reset", "previous segment not captured"]);
      };
    case "HSRP State Change":
      return (p, t) => {
        const state = p.colorFeatures?.hsrpState;
        if (state != null && state > 0) {
          return state !== 8 && state !== 16;
        }
        return t.includes("hsrp");
      };
    case "Spanning Tree Topology  Change":
      return (p, t) => Boolean(p.colorFeatures?.stpTopologyChange) || t.includes("spanning tree") || t.includes("stp");
    case "OSPF State Change":
      return (p, t) => {
        const msg = p.colorFeatures?.ospfMsg;
        if (msg != null && msg > 0) {
          return msg !== 1;
        }
        return t.includes("ospf");
      };
    case "ICMP errors":
      return (p, t) => {
        const icmp = p.colorFeatures?.icmpType;
        const icmpv6 = p.colorFeatures?.icmpv6Type;
        const icmpErr = icmp != null && ((icmp >= 3 && icmp <= 5) || icmp === 11);
        const icmpv6Err = icmpv6 != null && icmpv6 >= 1 && icmpv6 <= 4;
        return icmpErr || icmpv6Err || includesAny(t, ["destination unreachable", "time-to-live exceeded", "ttl exceeded", "icmp error"]);
      };
    case "ARP":
      return (p, t) => isProto(p, ["ARP"]) || t.includes("arp");
    case "ICMP":
      return (p, t) => isProto(p, ["ICMP", "ICMPV6"]) || t.includes("icmp");
    case "TCP RST":
      return (p, t) => Boolean(p.colorFeatures?.tcpRst) || (isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) && (t.includes("tcp reset") || t.includes("[rst") || t.includes(" rst")));
    case "SCTP ABORT":
      return (_p, t) => t.includes("sctp") && t.includes("abort");
    case "IPv4 TTL low or unexpected":
      return (p, t) => {
        const ttl = p.colorFeatures?.ipv4Ttl ?? 0;
        if (ttl > 0 && ttl < 5) {
          return true;
        }
        return includesAny(t, ["ttl", "time-to-live", "hop limit"]) && includesAny(t, ["exceeded", "low", "unexpected"]);
      };
    case "IPv6 hop limit low or unexpected":
      return (p, t) => {
        const hlim = p.colorFeatures?.ipv6HopLimit ?? 0;
        if (hlim > 0 && (hlim < 5 || ![1, 64, 255].includes(hlim))) {
          return true;
        }
        return t.includes("ipv6") && includesAny(t, ["hop limit", "hlim", "ttl"]);
      };
    case "Checksum Errors":
      return (p, t) => Boolean(p.colorFeatures?.checksumBad) || includesAny(t, ["bad checksum", "checksum bad", "fcs bad", "malformed packet"]);
    case "SMB":
      return (p, t) => Boolean(p.colorFeatures?.hasSmb || p.colorFeatures?.hasNetbios || p.colorFeatures?.hasNbss || p.colorFeatures?.hasNbns) || includesAny(t, ["smb", "netbios", "nbss", "nbns"]);
    case "HTTP":
      return (p, t) => isProto(p, ["HTTP", "HTTPS"]) || t.includes("http/1.") || t.includes("http/2") || p.srcPort === 80 || p.dstPort === 80;
    case "DCERPC":
      return (p, t) => Boolean(p.colorFeatures?.hasDcerpc) || t.includes("dcerpc");
    case "Routing":
      return (p, t) => {
        const f = p.colorFeatures;
        if (f?.hasHsrp || f?.hasEigrp || f?.hasOspf || f?.hasBgp || f?.hasCdp || f?.hasVrrp || f?.hasCarp || f?.hasGvrp || f?.hasIgmp || f?.hasIsmp || f?.hasRip || f?.hasGlbp || f?.hasPim) {
          return true;
        }
        return includesAny(t, ["hsrp", "eigrp", "ospf", "bgp", "cdp", "vrrp", "carp", "gvrp", "igmp", "ismp", "rip", "glbp", "pim"]);
      };
    case "TCP SYN/FIN":
      return (p, t) => Boolean(p.colorFeatures?.tcpSyn || p.colorFeatures?.tcpFin) || (isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) && includesAny(t, ["[syn", " syn", "[fin", " fin"]));
    case "TCP":
      return (p) => isProto(p, ["TCP"]);
    case "UDP":
      return (p) => isProto(p, ["UDP"]);
    case "Broadcast":
      return (p, t) => Boolean(p.colorFeatures?.broadcast) || p.dst === "255.255.255.255" || t.includes("broadcast");
    case "System Event":
      return (p, t) => Boolean(p.colorFeatures?.hasSystemdJournal || p.colorFeatures?.hasSysdig) || t.includes("systemd") || t.includes("sysdig") || t.includes("journal");
    default:
      return (p, t) => {
        if (e.includes("tcp") && isProto(p, ["TCP"])) return true;
        if (e.includes("udp") && isProto(p, ["UDP"])) return true;
        if (e.includes("http") && isProto(p, ["HTTP", "HTTPS"])) return true;
        if (e.includes("arp") && isProto(p, ["ARP"])) return true;
        if (e.includes("icmp") && (isProto(p, ["ICMP", "ICMPV6"]) || t.includes("icmp"))) return true;
        return false;
      };
  }
}

function parseRuleLine(line: string): ParsedColorRule | null {
  const trimmed = line.trim();
  if (!trimmed || !trimmed.startsWith("@")) return null;

  const match = /^@([^@]+)@([^@]+)@\[([^\]]+)\]\[([^\]]+)\]$/.exec(trimmed);
  if (!match) return null;

  const name = match[1].trim();
  const expr = match[2].trim();
  const bg = parseRGB16Triplet(match[3]);
  const fg = parseRGB16Triplet(match[4]);

  return {
    name,
    expr,
    bg,
    fg,
    match: buildMatcher(name, expr),
  };
}

function parseRules(text: string): ParsedColorRule[] {
  return text
    .split(/\r?\n/)
    .map((line) => parseRuleLine(line))
    .filter((rule): rule is ParsedColorRule => rule != null);
}

const RULES = parseRules(WIRESHARK_COLORING_TEXT);

export function getPacketColorStyle(packet: Packet): PacketColorStyle | null {
  const text = `${packet.info ?? ""} ${packet.payload ?? ""}`.toLowerCase();
  const matched = RULES.find((rule) => rule.match(packet, text));
  if (!matched) return null;

  // 提高对比度：增加alpha值
  const strong = rgb16ToRgba(matched.bg, 0.85);
  const mid = rgb16ToRgba(matched.bg, 0.45);
  const clear = rgb16ToRgba(matched.bg, 0.05);
  
  // 所有字体统一为黑色
  const fontColor = "rgb(0, 0, 0)";
  
  return {
    ruleName: matched.name,
    backgroundColor: rgb16ToCss(matched.bg),
    backgroundGradient: `linear-gradient(90deg, ${strong} 0%, ${mid} 42%, ${clear} 100%)`,
    color: fontColor,
  };
}
