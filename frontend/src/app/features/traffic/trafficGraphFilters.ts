export function filterForProtocolBucket(label: string) {
  const normalized = label.toUpperCase();
  switch (normalized) {
    case "HTTP":
      return "http";
    case "HTTPS":
    case "TLS":
    case "TLSV1.2":
    case "TLSV1.3":
      return "tls";
    case "DNS":
      return "dns";
    case "TCP":
      return "tcp";
    case "UDP":
      return "udp";
    case "ARP":
      return "arp";
    case "ICMP":
      return "icmp";
    case "ICMPV6":
      return "icmpv6";
    case "USB":
      return "usb";
    case "MODBUS":
    case "S7COMM":
    case "DNP3":
    case "CIP":
    case "BACNET":
    case "IEC104":
    case "OPCUA":
    case "PN_RT":
      return "modbus or s7comm or dnp3 or cip or bacnet or iec104 or opcua or pn_rt";
    case "CAN":
    case "J1939":
    case "DOIP":
    case "UDS":
      return "can or j1939 or doip or uds";
    case "RTP":
    case "RTCP":
    case "SIP":
    case "SDP":
      return "rtp or rtcp or sip or sdp";
    default:
      return normalized.toLowerCase();
  }
}

export function filterForIpBucket(label: string, direction: "src" | "dst") {
  const target = label.trim();
  if (!target) return "";
  if (target.includes(":")) {
    return direction === "src" ? `ipv6.src == ${target}` : `ipv6.dst == ${target}`;
  }
  return direction === "src" ? `ip.src == ${target}` : `ip.dst == ${target}`;
}

export function filterForDomainBucket(label: string) {
  const target = label.trim();
  if (!target) return "";
  return `http.host contains "${target}" or dns.qry.name contains "${target}" or tls.handshake.extensions_server_name contains "${target}"`;
}

export function filterForPortBucket(label: string) {
  const port = label.trim();
  if (!port) return "";
  return `tcp.port == ${port} or udp.port == ${port}`;
}
