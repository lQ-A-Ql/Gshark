import { useEffect, useMemo, useRef, useState } from "react";
import type { Packet, ProtocolTreeNode } from "../../core/types";
import { buildFrameBytes, findClosestNodeByOffset } from "./workspaceSelection";

export function useWorkspaceProtocolSelection(
  selectedPacket: Packet | null,
  selectedPacketRawHex: string,
  protocolTree: ProtocolTreeNode[],
) {
  const [selectedTreeNode, setSelectedTreeNode] = useState<string>("frame");
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null);
  const treeRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const hexPanelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setSelectedTreeNode("frame");
    setSelectedByteOffset(null);
  }, [selectedPacket?.id]);

  useEffect(() => {
    treeRefs.current.get(selectedTreeNode)?.scrollIntoView({ block: "nearest" });
  }, [selectedTreeNode]);

  useEffect(() => {
    if (selectedByteOffset == null || !hexPanelRef.current) return;
    hexPanelRef.current
      .querySelector<HTMLButtonElement>(`button[data-byte='${selectedByteOffset}']`)
      ?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [selectedByteOffset]);

  const treeRangeMap = useMemo(() => {
    const map = new Map<string, [number, number]>();
    const walk = (node: ProtocolTreeNode) => {
      if (node.byteRange) map.set(node.id, node.byteRange);
      node.children?.forEach(walk);
    };
    protocolTree.forEach(walk);
    return map;
  }, [protocolTree]);

  const frameBytes = useMemo(
    () => buildFrameBytes(selectedPacket, selectedPacketRawHex),
    [selectedPacket, selectedPacketRawHex],
  );
  const selectedByteRange = treeRangeMap.get(selectedTreeNode) ?? null;

  const handleSelectTreeNode = (nodeId: string) => {
    setSelectedTreeNode(nodeId);
    const range = treeRangeMap.get(nodeId);
    if (range) setSelectedByteOffset(range[0]);
  };

  const handleSelectByte = (offset: number) => {
    setSelectedByteOffset(offset);
    const matched = findClosestNodeByOffset(offset, protocolTree);
    if (matched) setSelectedTreeNode(matched);
  };

  const registerNodeRef = (id: string, el: HTMLDivElement | null) => {
    if (el) treeRefs.current.set(id, el);
    else treeRefs.current.delete(id);
  };

  return {
    selectedTreeNode,
    selectedByteOffset,
    selectedByteRange,
    frameBytes,
    hexPanelRef,
    handleSelectTreeNode,
    handleSelectByte,
    registerNodeRef,
  };
}
