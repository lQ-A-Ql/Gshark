export const INDUSTRIAL_FILTER = "modbus or s7comm or dnp3 or cip or bacnet or iec104 or opcua or pn_rt";
export const VEHICLE_FILTER = "can or j1939 or doip or uds";
export const MEDIA_FILTER = "rtp or rtcp or sip or sdp";

export function filterForProtocol(label: string) {
  switch (label) {
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
      return INDUSTRIAL_FILTER;
    case "CAN":
    case "J1939":
    case "DOIP":
    case "UDS":
      return VEHICLE_FILTER;
    case "RTP":
    case "RTCP":
    case "SIP":
    case "SDP":
      return MEDIA_FILTER;
    default:
      return "";
  }
}
