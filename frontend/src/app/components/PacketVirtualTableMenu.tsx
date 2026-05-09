import type { Ref } from "react";
import type { Packet } from "../core/types";
import type { ViewportSafePositionState } from "../hooks/useViewportSafePosition";
import { FloatingSurface } from "./ui/FloatingSurface";

type PacketVirtualTableMenuProps = {
  menuRef: Ref<HTMLDivElement>;
  menuPosition: ViewportSafePositionState<Packet> | null;
  onFollowStream: (packet: Packet, target: "http" | "tcp" | "udp") => void;
  onClose: () => void;
};

export function PacketVirtualTableMenu({
  menuRef,
  menuPosition,
  onFollowStream,
  onClose,
}: PacketVirtualTableMenuProps) {
  if (!menuPosition) {
    return null;
  }

  const followStream = (target: "http" | "tcp" | "udp") => {
    onFollowStream(menuPosition.context, target);
    onClose();
  };

  return (
    <FloatingSurface
      floatingRef={menuRef}
      role="menu"
      className="w-48 py-1.5"
      x={menuPosition.x}
      y={menuPosition.y}
      onContextMenu={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
      onPointerDown={(event) => event.stopPropagation()}
      onClick={(event) => event.stopPropagation()}
    >
      <button
        type="button"
        role="menuitem"
        className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
        onClick={() => followStream("tcp")}
      >
        追踪 TCP 流
      </button>
      <button
        type="button"
        role="menuitem"
        className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
        onClick={() => followStream("udp")}
      >
        追踪 UDP 流
      </button>
      <button
        type="button"
        role="menuitem"
        className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
        onClick={() => followStream("http")}
      >
        追踪 HTTP 会话
      </button>
    </FloatingSurface>
  );
}
