import type { Packet, ProtocolTreeNode } from "./types";
import { computePacketByteLayout, type PacketByteLayout } from "./packetByteLayout";
import { buildProtocolTree } from "./protocolTree";
import { buildFieldLabel, formatLeafValue, humanizeFieldName, isRecord, layerTitle, stripLayerPrefix } from "./protocolLayerFormat";
import { orderLayerEntries, orderLayerFields } from "./protocolLayerOrdering";
import { normalizeLayerName, summarizeLayer } from "./protocolLayerSummary";

export function buildProtocolTreeFromLayers(layers: unknown, packet: Packet | null): ProtocolTreeNode[] {
  if (!isRecord(layers)) {
    return buildProtocolTree(packet);
  }

  const layout = packet ? computePacketByteLayout(packet) : null;
  const entries = orderLayerEntries(layers);
  if (entries.length === 0) {
    return buildProtocolTree(packet);
  }

  const layerNodes = entries.map(([key, value], index) =>
    buildLayerTreeNode(String(key), value, `layer-${index}`, resolveLayerByteRange(String(key), layout), packet),
  );

  if (!packet || entries.some(([key]) => normalizeLayerName(String(key)) === "frame")) {
    return layerNodes;
  }

  return [
    {
      id: "frame",
      label: `Frame ${packet.id}: ${packet.length} bytes on wire (${packet.length * 8} bits)`,
      byteRange: layout?.frameRange ?? [0, Math.max(packet.length - 1, 0)],
      children: [
        { id: "frame-time", label: `Arrival Time: ${packet.time || "N/A"}` },
        { id: "frame-info", label: `Info: ${packet.info || "N/A"}` },
      ],
    },
    ...layerNodes,
  ];
}

function buildLayerTreeNode(
  layerName: string,
  value: unknown,
  id: string,
  byteRange: [number, number] | undefined,
  packet: Packet | null,
): ProtocolTreeNode {
  const normalizedLayer = normalizeLayerName(layerName);
  if (!isRecord(value)) {
    return {
      id,
      byteRange,
      label: `${layerTitle(normalizedLayer)}: ${formatLeafValue(value)}`,
    };
  }

  const fields = orderLayerFields(normalizedLayer, value);
  return {
    id,
    label: summarizeLayer(normalizedLayer, value, packet),
    byteRange,
    children: fields.map(([fieldKey, fieldValue], index) =>
      toFieldTreeNode(
        normalizedLayer,
        String(fieldKey),
        fieldValue,
        `${id}-${index}`,
        resolveChildByteRange(String(fieldKey), byteRange),
      ),
    ),
  };
}

function toFieldTreeNode(
  layerName: string,
  fieldName: string,
  value: unknown,
  id: string,
  byteRange?: [number, number],
): ProtocolTreeNode {
  const strippedName = stripLayerPrefix(fieldName, layerName);
  if (Array.isArray(value)) {
    if (value.every((item) => !isRecord(item) && !Array.isArray(item))) {
      const rendered = value.map((item) => formatLeafValue(item)).filter(Boolean);
      return {
        id,
        byteRange,
        label: buildFieldLabel(strippedName, rendered.join(", ")),
      };
    }
    return {
      id,
      byteRange,
      label: `${humanizeFieldName(strippedName)} (${value.length})`,
      children: value.map((item, idx) => toFieldTreeNode(layerName, `[${idx}]`, item, `${id}-${idx}`, byteRange)),
    };
  }

  if (isRecord(value)) {
    const entries = Object.entries(value);
    return {
      id,
      byteRange,
      label: humanizeFieldName(strippedName),
      children: entries.map(([key, child], idx) =>
        toFieldTreeNode(layerName, String(key), child, `${id}-${idx}`, byteRange),
      ),
    };
  }

  if (strippedName.toLowerCase() === "text") {
    return {
      id,
      byteRange,
      label: formatLeafValue(value),
    };
  }

  return {
    id,
    byteRange,
    label: buildFieldLabel(strippedName, formatLeafValue(value)),
  };
}

function resolveLayerByteRange(layerName: string, layout: PacketByteLayout | null): [number, number] | undefined {
  if (!layout) return undefined;
  const name = layerName.toLowerCase();

  if (name === "frame") return layout.frameRange;
  if (name === "eth" || name === "sll" || name === "sll2") return layout.ethernetRange;
  if (name === "ip" || name === "ipv4" || name === "ipv6") return layout.ipRange;
  if (name === "tcp" || name === "udp" || name === "icmp" || name === "icmpv6" || name === "igmp")
    return layout.transportRange;
  if (
    name === "http" ||
    name === "tls" ||
    name === "ssl" ||
    name === "data" ||
    name === "dns" ||
    name === "quic" ||
    name === "ssh" ||
    name === "ftp" ||
    name === "smb" ||
    name === "smb2" ||
    name === "nbss" ||
    name === "nbns"
  ) {
    return layout.payloadRange;
  }
  return undefined;
}

function resolveChildByteRange(_name: string, inheritedRange?: [number, number]): [number, number] | undefined {
  return inheritedRange;
}
