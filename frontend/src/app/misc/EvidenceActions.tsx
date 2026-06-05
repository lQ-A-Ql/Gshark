import { Crosshair, Network } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { Button } from "../components/ui/button";
import { usePacket } from "../state/contexts/PacketContext";
import { useStream } from "../state/contexts/StreamContext";

type EvidenceAction = "" | "packet" | "stream";
type EvidenceProtocol = "HTTP" | "TCP" | "UDP";

interface EvidenceActionsProps {
  packetId?: number | null;
  streamId?: number | null;
  preferredProtocol?: EvidenceProtocol;
  disabled?: boolean;
  className?: string;
}

export function EvidenceActions({
  packetId,
  streamId,
  preferredProtocol,
  disabled = false,
  className = "",
}: EvidenceActionsProps) {
  const navigate = useNavigate();
  const { locatePacketById } = usePacket();
  const { preparePacketStream } = useStream();
  const [pending, setPending] = useState<EvidenceAction>("");
  const normalizedPacketId = Number.isFinite(Number(packetId)) ? Math.floor(Number(packetId)) : 0;
  const normalizedStreamId = Number.isFinite(Number(streamId)) ? Math.floor(Number(streamId)) : 0;
  const packetActionDisabled = disabled || normalizedPacketId <= 0 || pending !== "";
  const streamActionDisabled = disabled || normalizedPacketId <= 0 || normalizedStreamId <= 0 || pending !== "";
  const showPacketAction = normalizedPacketId > 0;
  const showStreamAction = normalizedPacketId > 0 && normalizedStreamId > 0;

  async function locatePacket() {
    if (packetActionDisabled) return;
    setPending("packet");
    try {
      await locatePacketById(normalizedPacketId);
      navigate("/");
    } finally {
      setPending("");
    }
  }

  async function openStream() {
    if (streamActionDisabled) return;
    setPending("stream");
    try {
      const prepared = await preparePacketStream(normalizedPacketId, preferredProtocol);
      if (!prepared.protocol || prepared.streamId == null) {
        navigate("/");
        return;
      }
      navigate(streamRouteFor(prepared.protocol), { state: { streamId: prepared.streamId } });
    } finally {
      setPending("");
    }
  }

  return (
    <div className={`flex flex-wrap gap-2 ${className}`}>
      {showPacketAction ? (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void locatePacket()}
          disabled={packetActionDisabled}
          title="跳转到主工作区并定位该证据包"
          className="h-8 gap-1.5 px-3 text-xs text-slate-700 hover:text-amber-700"
        >
          <Crosshair className="h-3.5 w-3.5" />
          {pending === "packet" ? "定位中..." : "定位到包"}
        </Button>
      ) : null}
      {showStreamAction ? (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void openStream()}
          disabled={streamActionDisabled}
          title="打开该证据包所在的 HTTP/TCP/UDP 流"
          className="h-8 gap-1.5 px-3 text-xs text-blue-700 hover:text-blue-800"
        >
          <Network className="h-3.5 w-3.5" />
          {pending === "stream" ? "打开中..." : "打开关联流"}
        </Button>
      ) : null}
    </div>
  );
}

function streamRouteFor(protocol: EvidenceProtocol) {
  if (protocol === "HTTP") return "/http-stream";
  if (protocol === "UDP") return "/udp-stream";
  return "/tcp-stream";
}
