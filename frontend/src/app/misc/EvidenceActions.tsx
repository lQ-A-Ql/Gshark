import { Crosshair, Network } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { Button } from "../components/ui/button";
import { useSentinel } from "../state/SentinelContext";

type EvidenceAction = "" | "packet" | "stream";
type EvidenceProtocol = "HTTP" | "TCP" | "UDP";

interface EvidenceActionsProps {
  packetId?: number | null;
  preferredProtocol?: EvidenceProtocol;
  disabled?: boolean;
  className?: string;
}

export function EvidenceActions({ packetId, preferredProtocol, disabled = false, className = "" }: EvidenceActionsProps) {
  const navigate = useNavigate();
  const { locatePacketById, preparePacketStream } = useSentinel();
  const [pending, setPending] = useState<EvidenceAction>("");
  const normalizedPacketId = Number.isFinite(Number(packetId)) ? Math.floor(Number(packetId)) : 0;
  const actionDisabled = disabled || normalizedPacketId <= 0 || pending !== "";

  async function locatePacket() {
    if (actionDisabled) return;
    setPending("packet");
    try {
      await locatePacketById(normalizedPacketId);
      navigate("/");
    } finally {
      setPending("");
    }
  }

  async function openStream() {
    if (actionDisabled) return;
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
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={() => void locatePacket()}
        disabled={actionDisabled}
        title="跳转到主工作区并定位该证据包"
        className="h-8 gap-1.5 border-slate-200 bg-white px-3 text-xs text-slate-700 hover:border-amber-200 hover:bg-amber-50 hover:text-amber-700"
      >
        <Crosshair className="h-3.5 w-3.5" />
        {pending === "packet" ? "定位中..." : "定位到包"}
      </Button>
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={() => void openStream()}
        disabled={actionDisabled}
        title="打开该证据包所在的 HTTP/TCP/UDP 流"
        className="h-8 gap-1.5 border-blue-200 bg-blue-50 px-3 text-xs text-blue-700 hover:bg-blue-100"
      >
        <Network className="h-3.5 w-3.5" />
        {pending === "stream" ? "打开中..." : "打开关联流"}
      </Button>
    </div>
  );
}

function streamRouteFor(protocol: EvidenceProtocol) {
  if (protocol === "HTTP") return "/http-stream";
  if (protocol === "UDP") return "/udp-stream";
  return "/tcp-stream";
}
