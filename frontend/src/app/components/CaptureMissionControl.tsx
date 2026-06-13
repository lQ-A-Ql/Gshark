import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { buildCaptureOverview, type CaptureRecommendation } from "../core/captureOverview";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";
import { useStream } from "../state/contexts/StreamContext";
import { useFilter } from "../state/contexts/FilterContext";
import { useAnalysis } from "../state/contexts/AnalysisContext";
import { openCaptureRecommendation } from "./CaptureMissionNavigation";
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
  const { backendConnected } = useBackend();
  const { fileMeta, isPreloadingCapture } = useCapture();
  const { packets, totalPackets, selectedPacket, locatePacketById } = usePacket();
  const { streamIds, setActiveStream, preparePacketStream } = useStream();
  const { setDisplayFilter, applyFilter } = useFilter();
  const { threatHits, extractedObjects } = useAnalysis();
  const [pendingAction, setPendingAction] = useState("");
  const captureKey = useMemo(
    () => (fileMeta.path ? `${fileMeta.path}::${totalPackets}` : ""),
    [fileMeta.path, totalPackets],
  );
  const { overviewBundle, overviewLoading } = useCaptureMissionOverviewBundle({
    backendConnected,
    captureKey,
    isPreloadingCapture,
  });

  const overview = useMemo(
    () =>
      buildCaptureOverview({
        stats: overviewBundle?.stats ?? null,
        packets,
        threatHits,
        extractedObjects,
        streamIds,
        industrial: overviewBundle?.industrial ?? null,
        vehicle: overviewBundle?.vehicle ?? null,
        media: overviewBundle?.media ?? null,
        usb: overviewBundle?.usb ?? null,
      }),
    [extractedObjects, overviewBundle, packets, streamIds, threatHits],
  );

  const applyWorkspaceFilter = useCallback(
    (filter: string) => {
      setDisplayFilter(filter);
      applyFilter(filter);
      navigate("/");
    },
    [applyFilter, navigate, setDisplayFilter],
  );

  const openRecommendation = useCallback(
    async (item: CaptureRecommendation) => {
      await openCaptureRecommendation({
        item,
        streamIds,
        setDisplayFilter,
        setActiveStream,
        applyWorkspaceFilter,
        navigate,
      });
    },
    [applyWorkspaceFilter, navigate, setActiveStream, setDisplayFilter, streamIds],
  );

  const jumpToThreatPacket = useCallback(
    async (packetId: number) => {
      setPendingAction(`packet:${packetId}`);
      try {
        await locatePacketById(packetId);
        navigate("/");
      } finally {
        setPendingAction("");
      }
    },
    [locatePacketById, navigate],
  );

  const openThreatStream = useCallback(
    async (packetId: number) => {
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
    },
    [navigate, preparePacketStream],
  );

  const openSelectedPacketStream = useCallback(async () => {
    if (!selectedPacket) return;
    await openThreatStream(selectedPacket.id);
  }, [openThreatStream, selectedPacket]);

  return (
    <section className="px-4 py-4">
      <div className="meow-tile meow-workbench-panel overflow-hidden">
        <div className="meow-tile-header px-4 py-4 sm:px-5">
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

        <div className="meow-tile-grid grid xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
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
