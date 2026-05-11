import { useCallback } from "react";
import { useNavigate } from "react-router";
import type { Packet, StreamProtocol } from "../core/types";

export type WorkspaceStreamTarget = "http" | "tcp" | "udp";

interface UseWorkspaceStreamNavigationOptions {
  selectPacket: (packetId: number) => void;
  setActiveStream: (protocol: StreamProtocol, streamId: number) => void | Promise<void>;
}

export function useWorkspaceStreamNavigation({
  selectPacket,
  setActiveStream,
}: UseWorkspaceStreamNavigationOptions) {
  const navigate = useNavigate();

  const openHttpStream = useCallback(() => {
    navigate("/http-stream");
  }, [navigate]);

  const followStream = useCallback(
    (packet: Packet, target: WorkspaceStreamTarget) => {
      if (packet.streamId == null) return;
      const route = getWorkspaceStreamRoute(target);
      selectPacket(packet.id);
      void setActiveStream(route.protocol, packet.streamId);
      navigate(route.path, { state: { streamId: packet.streamId } });
    },
    [navigate, selectPacket, setActiveStream],
  );

  return { followStream, openHttpStream };
}

function getWorkspaceStreamRoute(target: WorkspaceStreamTarget): { path: string; protocol: StreamProtocol } {
  if (target === "http") {
    return { path: "/http-stream", protocol: "HTTP" };
  }
  if (target === "udp") {
    return { path: "/udp-stream", protocol: "UDP" };
  }
  return { path: "/tcp-stream", protocol: "TCP" };
}
