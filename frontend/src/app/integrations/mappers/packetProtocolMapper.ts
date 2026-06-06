import type { Packet } from "../../core/types";

const VALID_PROTOCOLS = new Set(["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSHv2", "TLS", "ARP", "ICMP", "ICMPV6", "USB"]);

export function asProtocol(raw: unknown): Packet["proto"] {
  const s = String(raw ?? "OTHER").toUpperCase();
  return VALID_PROTOCOLS.has(s) ? (s as Packet["proto"]) : "OTHER";
}
