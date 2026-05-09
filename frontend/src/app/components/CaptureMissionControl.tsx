import {
  Activity,
  FileWarning,
  Network,
  ShieldAlert,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { buildCaptureOverview, type CaptureRecommendation } from "../core/captureOverview";
import type { GlobalTrafficStats, IndustrialAnalysis, MediaAnalysis, USBAnalysis, VehicleAnalysis } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import {
  CapturePayloadShortcutPanel,
  CaptureQuickFiltersPanel,
  CaptureRecommendationsPanel,
  CaptureSuspiciousHitsPanel,
} from "./CaptureMissionPanels";
import { MetricCard } from "./DesignSystem";

interface OverviewBundle {
  stats: GlobalTrafficStats | null;
  industrial: IndustrialAnalysis | null;
  vehicle: VehicleAnalysis | null;
  media: MediaAnalysis | null;
  usb: USBAnalysis | null;
}

const overviewCache = new Map<string, OverviewBundle>();

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
  const [overviewBundle, setOverviewBundle] = useState<OverviewBundle | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [pendingAction, setPendingAction] = useState("");
  const captureKey = useMemo(() => (
    fileMeta.path ? `${fileMeta.path}::${totalPackets}` : ""
  ), [fileMeta.path, totalPackets]);

  useEffect(() => {
    if (!backendConnected || !captureKey || isPreloadingCapture) {
      setOverviewBundle(null);
      setOverviewLoading(false);
      return;
    }

    if (overviewCache.has(captureKey)) {
      setOverviewBundle(overviewCache.get(captureKey) ?? null);
      setOverviewLoading(false);
      return;
    }

    let cancelled = false;
    const abortController = new AbortController();
    setOverviewLoading(true);
    void Promise.all([
      bridge.getGlobalTrafficStats(abortController.signal).catch(() => null),
      bridge.getIndustrialAnalysis(abortController.signal).catch(() => null),
      bridge.getVehicleAnalysis(abortController.signal).catch(() => null),
      bridge.getMediaAnalysis(false, abortController.signal).catch(() => null),
      bridge.getUSBAnalysis(abortController.signal).catch(() => null),
    ]).then(([stats, industrial, vehicle, media, usb]) => {
      if (cancelled) return;
      const next = { stats, industrial, vehicle, media, usb };
      overviewCache.set(captureKey, next);
      setOverviewBundle(next);
    }).finally(() => {
      if (!cancelled) {
        setOverviewLoading(false);
      }
    });

    return () => {
      cancelled = true;
      abortController.abort();
    };
  }, [backendConnected, captureKey, isPreloadingCapture]);

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

  const statCards = useMemo(() => ([
    {
      label: "总包数",
      value: totalPackets.toLocaleString(),
      detail: `当前文件 ${formatBytes(fileMeta.sizeBytes)}`,
      icon: <Activity className="h-4 w-4 text-emerald-600" />,
      tone: "emerald" as const,
    },
    {
      label: "可疑命中",
      value: threatHits.length.toLocaleString(),
      detail: `${threatHits.filter((hit) => hit.level === "critical" || hit.level === "high").length} 条高危`,
      icon: <ShieldAlert className="h-4 w-4 text-rose-600" />,
      tone: "rose" as const,
    },
    {
      label: "流数量",
      value: (streamIds.http.length + streamIds.tcp.length + streamIds.udp.length).toLocaleString(),
      detail: `HTTP ${streamIds.http.length} / TCP ${streamIds.tcp.length} / UDP ${streamIds.udp.length}`,
      icon: <Network className="h-4 w-4 text-blue-600" />,
      tone: "blue" as const,
    },
    {
      label: "提取对象",
      value: extractedObjects.length.toLocaleString(),
      detail: extractedObjects.length > 0 ? "可直接跳转附件提取页" : "暂未发现可导出对象",
      icon: <FileWarning className="h-4 w-4 text-amber-600" />,
      tone: "amber" as const,
    },
  ]), [extractedObjects.length, fileMeta.sizeBytes, streamIds.http.length, streamIds.tcp.length, streamIds.udp.length, threatHits, totalPackets]);

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
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-semibold tracking-[0.18em] text-blue-700">ANALYSIS COCKPIT</div>
              <h2 className="mt-2 text-2xl font-semibold text-slate-950">{overview.headline}</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{overview.summary}</p>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1">{fileMeta.name}</span>
                {overview.topProtocols.map((item) => (
                  <span key={item.label} className="rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-blue-700">
                    {item.label} {item.count}
                  </span>
                ))}
                {overviewLoading && (
                  <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-amber-700">正在汇总专项分析</span>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => navigate("/hunting")}
                className="inline-flex items-center gap-2 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-medium text-rose-700 transition-all hover:bg-rose-100"
              >
                <ShieldAlert className="h-4 w-4" />
                威胁狩猎
              </button>
              <button
                onClick={() => navigate("/traffic-graph")}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-all hover:bg-slate-100"
              >
                <Network className="h-4 w-4" />
                流量图
              </button>
            </div>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {statCards.map((item) => (
              <MetricCard key={item.label} label={item.label} value={item.value} hint={item.detail} icon={item.icon} tone={item.tone} />
            ))}
          </div>

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
