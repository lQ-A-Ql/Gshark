import { ArrowRight, Binary, Car, Clapperboard, Factory, Filter, Network, Usb } from "lucide-react";
import type { ReactNode } from "react";
import type { CaptureOverviewSnapshot, CaptureRecommendation } from "../core/captureOverview";
import type { Packet, ThreatHit } from "../core/types";

type CaptureQuickFiltersPanelProps = {
  quickFilters: CaptureOverviewSnapshot["quickFilters"];
  onApplyFilter: (filter: string) => void;
};

export function CaptureQuickFiltersPanel({ quickFilters, onApplyFilter }: CaptureQuickFiltersPanelProps) {
  if (quickFilters.length === 0) {
    return null;
  }

  return (
    <div className="mt-5 rounded-[24px] border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <Filter className="h-4 w-4 text-blue-600" />
        推荐过滤器
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {quickFilters.map((item) => (
          <button
            key={`${item.label}-${item.filter}`}
            onClick={() => onApplyFilter(item.filter)}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 transition-all hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
            title={item.reason}
          >
            <span className="font-medium">{item.label}</span>
            <span className="font-mono text-slate-500">{item.filter}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

type CaptureRecommendationsPanelProps = {
  recommendations: CaptureOverviewSnapshot["recommendations"];
  onOpenRecommendation: (item: CaptureRecommendation) => Promise<void>;
  onApplyFilter: (filter: string) => void;
};

export function CaptureRecommendationsPanel({
  recommendations,
  onOpenRecommendation,
  onApplyFilter,
}: CaptureRecommendationsPanelProps) {
  return (
    <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
      <div className="mb-3 text-sm font-semibold text-slate-900">推荐入口</div>
      <div className="grid gap-3 md:grid-cols-2">
        {recommendations.map((item) => (
          <RecommendationCard
            key={item.key}
            title={item.label}
            summary={item.summary}
            score={item.score}
            icon={iconForRecommendation(item.key)}
            onOpen={() => void onOpenRecommendation(item)}
            onFilter={item.filter ? () => onApplyFilter(item.filter!) : undefined}
          />
        ))}
      </div>
    </div>
  );
}

type CaptureSuspiciousHitsPanelProps = {
  hits: ThreatHit[];
  pendingAction: string;
  onOpenAll: () => void;
  onJumpToPacket: (packetId: number) => Promise<void>;
  onOpenStream: (packetId: number) => Promise<void>;
};

export function CaptureSuspiciousHitsPanel({
  hits,
  pendingAction,
  onOpenAll,
  onJumpToPacket,
  onOpenStream,
}: CaptureSuspiciousHitsPanelProps) {
  return (
    <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-900">优先处理的命中</div>
        <button onClick={onOpenAll} className="text-xs font-medium text-blue-700 hover:text-blue-800">
          打开全部
        </button>
      </div>
      {hits.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-xs leading-5 text-slate-500">
          当前默认规则还没有给出明显命中，可以先从推荐过滤器和协议分布切入，再按需要重跑狩猎。
        </div>
      ) : (
        <div className="space-y-3">
          {hits.map((hit) => (
            <div key={hit.id} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">
                      #{hit.packetId}
                    </span>
                    <span className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-medium text-rose-700">
                      {hit.rule}
                    </span>
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">
                      {hit.level}
                    </span>
                  </div>
                  <div className="mt-2 text-sm font-medium text-slate-900">{hit.preview || hit.match || "可疑命中"}</div>
                  <div className="mt-1 line-clamp-2 font-mono text-[11px] leading-5 text-slate-500">{hit.match}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={() => void onJumpToPacket(hit.packetId)}
                    disabled={pendingAction.length > 0}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {pendingAction === `packet:${hit.packetId}` ? "定位中" : "定位到包"}
                  </button>
                  <button
                    onClick={() => void onOpenStream(hit.packetId)}
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
  );
}

type CapturePayloadShortcutPanelProps = {
  selectedPacket: Packet | null;
  onOpenCurrentStream: () => Promise<void>;
  onOpenMisc: () => void;
};

export function CapturePayloadShortcutPanel({
  selectedPacket,
  onOpenCurrentStream,
  onOpenMisc,
}: CapturePayloadShortcutPanelProps) {
  return (
    <div className="border-t border-slate-200 p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">Payload 快速解码</div>
          <div className="mt-1 text-xs text-slate-500">
            解码与 WebShell 候选识别已收敛到 MISC 工具箱；首屏仅保留当前包上下文和跳转入口，避免工作区过载。
          </div>
        </div>
        {selectedPacket && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] text-slate-600">
              Packet #{selectedPacket.id} / {selectedPacket.displayProtocol || selectedPacket.proto}
            </div>
            {selectedPacket.streamId != null && selectedPacket.streamId >= 0 && (
              <button
                onClick={() => void onOpenCurrentStream()}
                className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
              >
                打开当前关联流
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
            <button
              onClick={onOpenMisc}
              className="inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1.5 text-xs font-medium text-cyan-700 hover:bg-cyan-100"
            >
              打开 MISC 解码工作台
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {selectedPacket ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.82fr)_minmax(0,1.18fr)]">
          <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
            <div className="text-sm font-semibold text-slate-900">当前数据包上下文</div>
            <div className="mt-3 space-y-3 text-xs">
              <InfoRow label="端点" value={`${selectedPacket.src}:${selectedPacket.srcPort} -> ${selectedPacket.dst}:${selectedPacket.dstPort}`} mono />
              <InfoRow label="协议" value={selectedPacket.displayProtocol || selectedPacket.proto} />
              <InfoRow label="长度" value={`${selectedPacket.length} bytes`} />
              <InfoRow label="说明" value={selectedPacket.info || "(no info)"} />
            </div>
          </div>
          <div className="rounded-[24px] border border-cyan-100 bg-cyan-50/60 p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-slate-900">Payload 预览</div>
                <div className="mt-1 text-xs text-slate-500">如需识别候选或尝试解码，请在 MISC 工作台中手动粘贴该 payload。</div>
              </div>
              <button
                onClick={onOpenMisc}
                className="shrink-0 rounded-full border border-cyan-200 bg-white px-3 py-1.5 text-xs font-semibold text-cyan-700 shadow-sm transition hover:border-cyan-300 hover:bg-cyan-50"
              >
                去 MISC
              </button>
            </div>
            <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-xl border border-cyan-100 bg-white/90 px-3 py-2 font-mono text-[11px] leading-5 text-slate-600">
              {selectedPacket.payload || "(empty payload)"}
            </pre>
          </div>
        </div>
      ) : (
        <div className="rounded-[24px] border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center text-xs leading-5 text-slate-500">
          选中一条数据包后，这里会展示 payload 预览；完整解码请前往 MISC 工具箱。
        </div>
      )}
    </div>
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
