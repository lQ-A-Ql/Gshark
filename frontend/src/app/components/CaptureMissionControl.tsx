import {
  Activity,
  ArrowRight,
  Binary,
  Car,
  Clapperboard,
  Factory,
  FileWarning,
  Filter,
  Network,
  ShieldAlert,
  Usb,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { buildCaptureOverview, type CaptureRecommendation } from "../core/captureOverview";
import type { GlobalTrafficStats, IndustrialAnalysis, MediaAnalysis, USBAnalysis, VehicleAnalysis } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import { StreamDecoderWorkbench } from "./StreamDecoderWorkbench";

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
    setOverviewLoading(true);
    void Promise.all([
      bridge.getGlobalTrafficStats().catch(() => null),
      bridge.getIndustrialAnalysis().catch(() => null),
      bridge.getVehicleAnalysis().catch(() => null),
      bridge.getMediaAnalysis().catch(() => null),
      bridge.getUSBAnalysis().catch(() => null),
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
    },
    {
      label: "可疑命中",
      value: threatHits.length.toLocaleString(),
      detail: `${threatHits.filter((hit) => hit.level === "critical" || hit.level === "high").length} 条高危`,
      icon: <ShieldAlert className="h-4 w-4 text-rose-600" />,
    },
    {
      label: "流数量",
      value: (streamIds.http.length + streamIds.tcp.length + streamIds.udp.length).toLocaleString(),
      detail: `HTTP ${streamIds.http.length} / TCP ${streamIds.tcp.length} / UDP ${streamIds.udp.length}`,
      icon: <Network className="h-4 w-4 text-blue-600" />,
    },
    {
      label: "提取对象",
      value: extractedObjects.length.toLocaleString(),
      detail: extractedObjects.length > 0 ? "可直接跳转附件提取页" : "暂未发现可导出对象",
      icon: <FileWarning className="h-4 w-4 text-amber-600" />,
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
              <StatCard key={item.label} label={item.label} value={item.value} detail={item.detail} icon={item.icon} />
            ))}
          </div>

          {overview.quickFilters.length > 0 && (
            <div className="mt-5 rounded-[24px] border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Filter className="h-4 w-4 text-blue-600" />
                推荐过滤器
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {overview.quickFilters.map((item) => (
                  <button
                    key={`${item.label}-${item.filter}`}
                    onClick={() => applyWorkspaceFilter(item.filter)}
                    className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 transition-all hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
                    title={item.reason}
                  >
                    <span className="font-medium">{item.label}</span>
                    <span className="font-mono text-slate-500">{item.filter}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="grid gap-4 p-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
          <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
            <div className="mb-3 text-sm font-semibold text-slate-900">推荐入口</div>
            <div className="grid gap-3 md:grid-cols-2">
              {overview.recommendations.map((item) => (
                <RecommendationCard
                  key={item.key}
                  title={item.label}
                  summary={item.summary}
                  score={item.score}
                  icon={iconForRecommendation(item.key)}
                  onOpen={() => void openRecommendation(item)}
                  onFilter={item.filter ? () => applyWorkspaceFilter(item.filter!) : undefined}
                />
              ))}
            </div>
          </div>

          <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-900">优先处理的命中</div>
              <button
                onClick={() => navigate("/hunting")}
                className="text-xs font-medium text-blue-700 hover:text-blue-800"
              >
                打开全部
              </button>
            </div>
            {overview.suspiciousHits.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-xs leading-5 text-slate-500">
                当前默认规则还没有给出明显命中，可以先从推荐过滤器和协议分布切入，再按需要重跑狩猎。
              </div>
            ) : (
              <div className="space-y-3">
                {overview.suspiciousHits.map((hit) => (
                  <div key={hit.id} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">#{hit.packetId}</span>
                          <span className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-medium text-rose-700">{hit.rule}</span>
                          <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">{hit.level}</span>
                        </div>
                        <div className="mt-2 text-sm font-medium text-slate-900">{hit.preview || hit.match || "可疑命中"}</div>
                        <div className="mt-1 line-clamp-2 font-mono text-[11px] leading-5 text-slate-500">{hit.match}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <button
                          onClick={() => void jumpToThreatPacket(hit.packetId)}
                          disabled={pendingAction.length > 0}
                          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {pendingAction === `packet:${hit.packetId}` ? "定位中" : "定位到包"}
                        </button>
                        <button
                          onClick={() => void openThreatStream(hit.packetId)}
                          disabled={pendingAction.length > 0}
                          className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-2 text-xs font-medium text-blue-700 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {pendingAction === `stream:${hit.packetId}` ? "打开中" : "打开关联流"}
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="border-t border-slate-200 p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">Payload 快速解码</div>
              <div className="mt-1 text-xs text-slate-500">
                当前选中数据包就能直接尝试 Base64、Behinder、AntSword、Godzilla 解码；如果需要更长上下文，再打开关联流继续分析。
              </div>
            </div>
            {selectedPacket && (
              <div className="flex flex-wrap items-center gap-2">
                <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] text-slate-600">
                  Packet #{selectedPacket.id} / {selectedPacket.displayProtocol || selectedPacket.proto}
                </div>
                {selectedPacket.streamId != null && selectedPacket.streamId >= 0 && (
                  <button
                    onClick={() => void openSelectedPacketStream()}
                    className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
                  >
                    打开当前关联流
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>

          {selectedPacket ? (
            <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.92fr)_minmax(0,1.08fr)]">
              <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
                <div className="text-sm font-semibold text-slate-900">当前数据包上下文</div>
                <div className="mt-3 space-y-3 text-xs">
                  <InfoRow label="端点" value={`${selectedPacket.src}:${selectedPacket.srcPort} -> ${selectedPacket.dst}:${selectedPacket.dstPort}`} mono />
                  <InfoRow label="协议" value={selectedPacket.displayProtocol || selectedPacket.proto} />
                  <InfoRow label="长度" value={`${selectedPacket.length} bytes`} />
                  <InfoRow label="说明" value={selectedPacket.info || "(no info)"} />
                </div>
              </div>
              <StreamDecoderWorkbench
                payload={selectedPacket.payload ?? ""}
                chunkLabel={`当前数据包 #${selectedPacket.id}`}
                tone="blue"
              />
            </div>
          ) : (
            <div className="rounded-[24px] border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center text-xs leading-5 text-slate-500">
              选中一条数据包后，这里会直接出现 payload 解码工作台。
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function iconForRecommendation(key: CaptureRecommendation["key"]) {
  if (key === "industrial") return <Factory className="h-4 w-4 text-blue-600" />;
  if (key === "vehicle") return <Car className="h-4 w-4 text-emerald-600" />;
  if (key === "usb") return <Usb className="h-4 w-4 text-amber-600" />;
  if (key === "media") return <Clapperboard className="h-4 w-4 text-violet-600" />;
  if (key === "payload") return <Binary className="h-4 w-4 text-rose-600" />;
  return <Network className="h-4 w-4 text-sky-600" />;
}

function StatCard({
  label,
  value,
  detail,
  icon,
}: {
  label: string;
  value: string;
  detail: string;
  icon: ReactNode;
}) {
  return (
    <div className="rounded-[22px] border border-slate-200 bg-slate-50 px-4 py-4">
      <div className="flex items-center justify-between text-xs text-slate-500">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-2 text-2xl font-semibold text-slate-950">{value}</div>
      <div className="mt-1 text-xs leading-5 text-slate-500">{detail}</div>
    </div>
  );
}

function RecommendationCard({
  title,
  summary,
  score,
  icon,
  onOpen,
  onFilter,
}: {
  title: string;
  summary: string;
  score: number;
  icon: ReactNode;
  onOpen: () => void;
  onFilter?: () => void;
}) {
  return (
    <div className="rounded-[22px] border border-slate-200 bg-white px-4 py-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
          {icon}
          {title}
        </div>
        <div className="rounded-full border border-blue-100 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700">
          匹配度 {score}
        </div>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-600">{summary}</p>
      <div className="mt-4 flex items-center gap-2">
        <button
          onClick={onOpen}
          className="inline-flex items-center gap-2 rounded-xl border border-blue-200 bg-blue-50 px-3 py-2 text-xs font-medium text-blue-700 hover:bg-blue-100"
        >
          进入模块
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
        {onFilter && (
          <button
            onClick={onFilter}
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100"
          >
            先应用过滤器
          </button>
        )}
      </div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-3 py-2">
      <div className="text-[11px] font-medium tracking-[0.12em] text-slate-500">{label}</div>
      <div className={`mt-1 break-all text-sm text-slate-900 ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}
