import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { buildCaptureOverview, type CaptureRecommendation } from "../core/captureOverview";
import { useSentinel } from "../state/SentinelContext";
import { CaptureMissionOverviewHeader } from "./CaptureMissionOverviewHeader";
import {
  CapturePayloadShortcutPanel,
  CaptureQuickFiltersPanel,
  CaptureRecommendationsPanel,
  CaptureSuspiciousHitsPanel,
} from "./CaptureMissionPanels";
import { useCaptureMissionOverviewBundle } from "./useCaptureMissionOverviewBundle";

export function CaptureMissionControl() {
  const navigate = useNavigate();
  const {
    packets,
    totalPackets,
    selectedPacket,
    threatHits,
    extractedObjects,
    streamIds,
    setDisplayFilter,
    applyFilter,
    locatePacketById,
    preparePacketStream,
    setActiveStream,
    fileMeta,
    backendConnected,
    isPreloadingCapture,
  } = useSentinel();
  const [pendingAction, setPendingAction] = useState("");
  const captureKey = useMemo(() => (
    fileMeta.path ? `${fileMeta.path}::${totalPackets}` : ""
  ), [fileMeta.path, totalPackets]);
  const { overviewBundle, overviewLoading } = useCaptureMissionOverviewBundle({
    backendConnected,
    captureKey,
    isPreloadingCapture,
  });

  const overview = useMemo(() => buildCaptureOverview({
    stats: overviewBundle?.stats ?? null,
    packets,
    threatHits,
    extractedObjects,
    streamIds,
    industrial: overviewBundle?.industrial ?? null,
    vehicle: overviewBundle?.vehicle ?? null,
    media: overviewBundle?.media ?? null,
    usb: overviewBundle?.usb ?? null,
  }), [extractedObjects, overviewBundle, packets, streamIds, threatHits]);

  const applyWorkspaceFilter = useCallback((filter: string) => {
    setDisplayFilter(filter);
    applyFilter(filter);
    navigate("/");
  }, [applyFilter, navigate, setDisplayFilter]);

  const openRecommendation = useCallback(async (item: CaptureRecommendation) => {
    if (item.filter) {
      setDisplayFilter(item.filter);
    }

    if (item.route === "/http-stream" && streamIds.http.length > 0) {
      const streamId = streamIds.http[0];
      await setActiveStream("HTTP", streamId);
      navigate("/http-stream", { state: { streamId } });
      return;
    }
    if (item.route === "/tcp-stream" && streamIds.tcp.length > 0) {
      const streamId = streamIds.tcp[0];
      await setActiveStream("TCP", streamId);
      navigate("/tcp-stream", { state: { streamId } });
      return;
    }
    if (item.route === "/udp-stream" && streamIds.udp.length > 0) {
      const streamId = streamIds.udp[0];
      await setActiveStream("UDP", streamId);
      navigate("/udp-stream", { state: { streamId } });
      return;
    }
    if ((item.route === "/http-stream" || item.route === "/tcp-stream" || item.route === "/udp-stream") && item.filter) {
      applyWorkspaceFilter(item.filter);
      return;
    }
    navigate(item.route);
  }, [applyWorkspaceFilter, navigate, setActiveStream, setDisplayFilter, streamIds.http, streamIds.tcp, streamIds.udp]);

  const jumpToThreatPacket = useCallback(async (packetId: number) => {
    setPendingAction(`packet:${packetId}`);
    try {
      await locatePacketById(packetId);
      navigate("/");
    } finally {
      setPendingAction("");
    }
  }, [locatePacketById, navigate]);

  const openThreatStream = useCallback(async (packetId: number) => {
    setPendingAction(`stream:${packetId}`);
    try {
      const prepared = await preparePacketStream(packetId);
      if (!prepared.protocol || prepared.streamId == null) {
        navigate("/");
        return;
      }
      if (prepared.protocol === "HTTP") {
        navigate("/http-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      if (prepared.protocol === "UDP") {
        navigate("/udp-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      navigate("/tcp-stream", { state: { streamId: prepared.streamId } });
    } finally {
      setPendingAction("");
    }
  }, [navigate, preparePacketStream]);

  const openSelectedPacketStream = useCallback(async () => {
    if (!selectedPacket) return;
    await openThreatStream(selectedPacket.id);
  }, [openThreatStream, selectedPacket]);

  return (
    <section className="border-b border-border bg-[linear-gradient(180deg,rgba(239,246,255,0.9)_0%,rgba(255,255,255,0.96)_100%)] px-4 py-4">
      <div className="overflow-hidden rounded-[28px] border border-slate-200 bg-white/95 shadow-[0_28px_80px_-48px_rgba(15,23,42,0.45)]">
        <div className="border-b border-slate-200 px-5 py-5">
          <CaptureMissionOverviewHeader
            extractedObjectCount={extractedObjects.length}
            fileName={fileMeta.name}
            fileSizeBytes={fileMeta.sizeBytes}
            overview={overview}
            overviewLoading={overviewLoading}
            streamCounts={{
              http: streamIds.http.length,
              tcp: streamIds.tcp.length,
              udp: streamIds.udp.length,
            }}
            threatHighCount={threatHits.filter((hit) => hit.level === "critical" || hit.level === "high").length}
            threatTotal={threatHits.length}
            totalPackets={totalPackets}
            onOpenHunting={() => navigate("/hunting")}
            onOpenTrafficGraph={() => navigate("/traffic-graph")}
          />
          <CaptureQuickFiltersPanel quickFilters={overview.quickFilters} onApplyFilter={applyWorkspaceFilter} />
        </div>

        <div className="grid gap-4 p-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
          <CaptureRecommendationsPanel
            recommendations={overview.recommendations}
            onOpenRecommendation={openRecommendation}
            onApplyFilter={applyWorkspaceFilter}
          />
          <CaptureSuspiciousHitsPanel
            hits={overview.suspiciousHits}
            pendingAction={pendingAction}
            onOpenAll={() => navigate("/hunting")}
            onJumpToPacket={jumpToThreatPacket}
            onOpenStream={openThreatStream}
          />
        </div>

        <CapturePayloadShortcutPanel
          selectedPacket={selectedPacket}
          onOpenCurrentStream={openSelectedPacketStream}
          onOpenMisc={() => navigate("/misc")}
        />
      </div>
    </section>
  );
}
