import type { Packet } from "./types";

function isProto(packet: Packet, values: string[]): boolean {
  const proto = String(packet.proto ?? "").toUpperCase();
  return values.some((value) => proto === value);
}

function includesAny(text: string, words: string[]): boolean {
  return words.some((word) => text.includes(word));
}

export function buildPacketColorMatcher(ruleName: string, expr: string): (packet: Packet, text: string) => boolean {
  const e = expr.toLowerCase();

  switch (ruleName) {
    case "Bad TCP":
      return (p, t) => {
        const f = p.colorFeatures;
        if (f?.tcpAnalysisFlags && !f.tcpWindowUpdate && !f.tcpKeepAlive && !f.tcpKeepAliveAck) return true;
        return (
          isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) &&
          includesAny(t, ["retransmission", "duplicate ack", "out-of-order", "rst", "reset", "previous segment not captured"])
        );
      };
    case "HSRP State Change":
      return (p, t) => {
        const state = p.colorFeatures?.hsrpState;
        if (state != null && state > 0) return state !== 8 && state !== 16;
        return t.includes("hsrp");
      };
    case "Spanning Tree Topology  Change":
      return (p, t) => Boolean(p.colorFeatures?.stpTopologyChange) || t.includes("spanning tree") || t.includes("stp");
    case "OSPF State Change":
      return (p, t) => {
        const msg = p.colorFeatures?.ospfMsg;
        if (msg != null && msg > 0) return msg !== 1;
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
      return (p, t) =>
        Boolean(p.colorFeatures?.tcpRst) ||
        (isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) && (t.includes("tcp reset") || t.includes("[rst") || t.includes(" rst")));
    case "SCTP ABORT":
      return (_p, t) => t.includes("sctp") && t.includes("abort");
    case "IPv4 TTL low or unexpected":
      return (p, t) => {
        const ttl = p.colorFeatures?.ipv4Ttl ?? 0;
        if (ttl > 0 && ttl < 5) return true;
        return includesAny(t, ["ttl", "time-to-live", "hop limit"]) && includesAny(t, ["exceeded", "low", "unexpected"]);
      };
    case "IPv6 hop limit low or unexpected":
      return (p, t) => {
        const hlim = p.colorFeatures?.ipv6HopLimit ?? 0;
        if (hlim > 0 && (hlim < 5 || ![1, 64, 255].includes(hlim))) return true;
        return t.includes("ipv6") && includesAny(t, ["hop limit", "hlim", "ttl"]);
      };
    case "Checksum Errors":
      return (p, t) => Boolean(p.colorFeatures?.checksumBad) || includesAny(t, ["bad checksum", "checksum bad", "fcs bad", "malformed packet"]);
    case "SMB":
      return (p, t) =>
        Boolean(p.colorFeatures?.hasSmb || p.colorFeatures?.hasNetbios || p.colorFeatures?.hasNbss || p.colorFeatures?.hasNbns) ||
        includesAny(t, ["smb", "netbios", "nbss", "nbns"]);
    case "HTTP":
      return (p, t) => isProto(p, ["HTTP", "HTTPS"]) || t.includes("http/1.") || t.includes("http/2") || p.srcPort === 80 || p.dstPort === 80;
    case "DCERPC":
      return (p, t) => Boolean(p.colorFeatures?.hasDcerpc) || t.includes("dcerpc");
    case "Routing":
      return (p, t) => {
        const f = p.colorFeatures;
        if (f?.hasHsrp || f?.hasEigrp || f?.hasOspf || f?.hasBgp || f?.hasCdp || f?.hasVrrp || f?.hasCarp || f?.hasGvrp || f?.hasIgmp || f?.hasIsmp || f?.hasRip || f?.hasGlbp || f?.hasPim) return true;
        return includesAny(t, ["hsrp", "eigrp", "ospf", "bgp", "cdp", "vrrp", "carp", "gvrp", "igmp", "ismp", "rip", "glbp", "pim"]);
      };
    case "TCP SYN/FIN":
      return (p, t) =>
        Boolean(p.colorFeatures?.tcpSyn || p.colorFeatures?.tcpFin) ||
        (isProto(p, ["TCP", "HTTP", "HTTPS", "TLS"]) && includesAny(t, ["[syn", " syn", "[fin", " fin"]));
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
