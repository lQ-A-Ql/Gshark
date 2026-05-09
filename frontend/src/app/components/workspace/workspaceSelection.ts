import type { Packet, ProtocolTreeNode } from "../../core/types";

export function buildFrameBytes(packet: Packet | null, selectedRawHex?: string): number[] {
  if (!packet) return [];

  const rawHex = selectedRawHex && selectedRawHex.trim() ? selectedRawHex : packet.rawHex;
  if (rawHex && rawHex.trim()) {
    const cleaned = rawHex.replace(/[^0-9a-fA-F]/g, "");
    if (cleaned.length >= 2) {
      const evenHex = cleaned.length % 2 === 0 ? cleaned : cleaned.slice(0, -1);
      const out: number[] = [];
      for (let i = 0; i < evenHex.length; i += 2) {
        const byte = Number.parseInt(evenHex.slice(i, i + 2), 16);
        if (Number.isFinite(byte)) {
          out.push(byte);
        }
      }
      if (out.length > 0) {
        return out;
      }
    }
  }

  // Never synthesize bytes with zero padding; only render true frame bytes.
  return [];
}

export function findClosestNodeByOffset(offset: number, nodes: ProtocolTreeNode[]): string | null {
  const matches: { id: string; span: number }[] = [];

  const walk = (node: ProtocolTreeNode) => {
    if (node.byteRange && offset >= node.byteRange[0] && offset <= node.byteRange[1]) {
      matches.push({ id: node.id, span: node.byteRange[1] - node.byteRange[0] });
    }
    node.children?.forEach(walk);
  };

  nodes.forEach(walk);
  if (matches.length === 0) return null;
  matches.sort((a, b) => a.span - b.span);
  return matches[0].id;
}
