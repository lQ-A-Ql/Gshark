import type { Packet } from "./types";
import { formatLeafValue, layerTitle } from "./protocolLayerFormat";

export function summarizeLayer(layerName: string, layer: Record<string, unknown>, packet: Packet | null): string {
  switch (layerName) {
    case "frame": {
      const number = pickLayerValue(layer, ["frame_frame_number", "frame.number"]) ?? String(packet?.id ?? "?");
      const wireLength = pickLayerValue(layer, ["frame_frame_len", "frame.len"]) ?? String(packet?.length ?? 0);
      const capturedLength = pickLayerValue(layer, ["frame_frame_cap_len", "frame.cap_len"]) ?? wireLength;
      const wireBits = toInteger(wireLength) * 8;
      const capturedBits = toInteger(capturedLength) * 8;
      return `Frame ${number}: ${wireLength} bytes on wire (${wireBits} bits), ${capturedLength} bytes captured (${capturedBits} bits)`;
    }
    case "eth":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["eth_eth_src_resolved", "eth_eth_src", "eth.src_resolved", "eth.src"]) || "unknown"}, Dst: ${pickLayerValue(layer, ["eth_eth_dst_resolved", "eth_eth_dst", "eth.dst_resolved", "eth.dst"]) || "unknown"}`;
    case "ip":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["ip_ip_src_host", "ip_ip_src", "ip.src_host", "ip.src"]) || packet?.src || "unknown"}, Dst: ${pickLayerValue(layer, ["ip_ip_dst_host", "ip_ip_dst", "ip.dst_host", "ip.dst"]) || packet?.dst || "unknown"}`;
    case "ipv6":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["ipv6_ipv6_src_host", "ipv6_ipv6_src", "ipv6.src_host", "ipv6.src"]) || packet?.src || "unknown"}, Dst: ${pickLayerValue(layer, ["ipv6_ipv6_dst_host", "ipv6_ipv6_dst", "ipv6.dst_host", "ipv6.dst"]) || packet?.dst || "unknown"}`;
    case "tcp":
      return `${layerTitle(layerName)}, Src Port: ${pickLayerValue(layer, ["tcp_tcp_srcport", "tcp.srcport"]) || packet?.srcPort || "?"}, Dst Port: ${pickLayerValue(layer, ["tcp_tcp_dstport", "tcp.dstport"]) || packet?.dstPort || "?"}`;
    case "udp":
      return `${layerTitle(layerName)}, Src Port: ${pickLayerValue(layer, ["udp_udp_srcport", "udp.srcport"]) || packet?.srcPort || "?"}, Dst Port: ${pickLayerValue(layer, ["udp_udp_dstport", "udp.dstport"]) || packet?.dstPort || "?"}`;
    case "http": {
      const method = pickLayerValue(layer, ["http_http_request_method", "http.request.method"]);
      const uri = pickLayerValue(layer, ["http_http_request_full_uri", "http_http_request_uri", "http.request.uri"]);
      const status = pickLayerValue(layer, ["http_http_response_code", "http.response.code"]);
      if (method || uri) {
        return `${layerTitle(layerName)}${method || uri ? `: ${[method, uri].filter(Boolean).join(" ")}` : ""}`;
      }
      if (status) {
        return `${layerTitle(layerName)}: ${status}`;
      }
      return layerTitle(layerName);
    }
    case "igmp": {
      const version = pickLayerValue(layer, ["igmp_igmp_version"]);
      return version ? `${layerTitle(layerName)} v${version}` : layerTitle(layerName);
    }
    default: {
      const summaryText = pickLayerValue(layer, ["text"]);
      return summaryText ? `${layerTitle(layerName)}: ${summaryText}` : layerTitle(layerName);
    }
  }
}

export function normalizeLayerName(layerName: string): string {
  return layerName.trim().toLowerCase();
}

export function pickLayerValue(layer: Record<string, unknown>, candidates: string[]): string {
  for (const candidate of candidates) {
    const normalizedCandidate = candidate.toLowerCase();
    for (const [key, value] of Object.entries(layer)) {
      const normalizedKey = key.toLowerCase();
      if (normalizedKey === normalizedCandidate || normalizedKey.endsWith(normalizedCandidate)) {
        const rendered = summarizeFieldValue(value);
        if (rendered) {
          return rendered;
        }
      }
    }
  }
  return "";
}

function summarizeFieldValue(value: unknown): string {
  if (Array.isArray(value)) {
    const items = value.map((item) => formatLeafValue(item)).filter(Boolean);
    return items.join(", ");
  }
  return formatLeafValue(value);
}

function toInteger(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}
