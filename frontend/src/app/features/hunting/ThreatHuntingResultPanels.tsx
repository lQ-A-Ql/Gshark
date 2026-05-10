import { CheckCircle2, Crosshair } from "lucide-react";
import { AnalysisBadge, AnalysisDataTable, type AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import { ScrollArea } from "../../components/ui/scroll-area";
import type { ThreatHit } from "../../core/types";

export function ThreatHuntingHitsTable({
  hits,
  selectedHit,
  onSelectHit,
}: {
  hits: ThreatHit[];
  selectedHit: number | null;
  onSelectHit: (id: number) => void;
}) {
  return (
    <>
      <div className="flex shrink-0 items-center justify-between border-b border-slate-200 bg-slate-50/80 px-4 py-3">
        <span className="flex items-center gap-2 text-sm font-medium text-slate-900">
          <CheckCircle2 className="h-4 w-4 text-emerald-600" /> 命中结果 (共 {hits.length} 条)
        </span>
      </div>

      <AnalysisDataTable
        columns={[
          {
            key: "packet",
            header: "No.",
            widthClassName: "w-16",
            headerClassName: "border-r border-slate-200",
            cellClassName: "border-r border-slate-200/80 text-slate-500",
            render: (hit) => hit.packetId,
          },
          {
            key: "category",
            header: "分类",
            widthClassName: "w-28",
            headerClassName: "border-r border-slate-200",
            cellClassName: "border-r border-slate-200/80",
            render: (hit) => hit.category,
          },
          {
            key: "rule",
            header: "规则",
            widthClassName: "w-40",
            headerClassName: "border-r border-slate-200",
            cellClassName: "border-r border-slate-200/80 font-medium text-rose-600",
            render: (hit) => hit.rule,
          },
          {
            key: "level",
            header: "等级",
            widthClassName: "w-24",
            headerClassName: "border-r border-slate-200",
            cellClassName: "border-r border-slate-200/80",
            render: (hit) => <AnalysisBadge tone={toneForThreatLevel(hit.level)}>{hit.level}</AnalysisBadge>,
          },
          {
            key: "preview",
            header: "预览",
            cellClassName: "truncate font-mono text-slate-500",
            render: (hit) => hit.preview,
          },
        ]}
        data={hits}
        rowKey={(hit) => hit.id}
        rowClassName={(hit) =>
          selectedHit === hit.id
            ? "border-l-2 border-l-rose-500 bg-rose-50/80 text-rose-700 hover:bg-rose-50"
            : "text-foreground"
        }
        onRowClick={(hit) => onSelectHit(hit.id)}
        emptyText="暂无威胁命中"
        maxHeightClassName="max-h-none"
        wrapperClassName="min-h-0 flex-1 rounded-none border-0 bg-transparent"
        tableClassName="cursor-default whitespace-nowrap"
        headerClassName="z-10 bg-white/95 backdrop-blur-sm"
      />
    </>
  );
}

export function ThreatHuntingHitDetailPanel({
  actionBusy,
  selected,
  onJumpToPacket,
  onOpenRelatedStream,
}: {
  actionBusy: string;
  selected: ThreatHit;
  onJumpToPacket: (packetId: number) => void | Promise<void>;
  onOpenRelatedStream: (packetId: number) => void | Promise<void>;
}) {
  return (
    <div className="flex h-56 min-h-0 shrink-0 flex-col border-t border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] shadow-[0_-10px_30px_-24px_rgba(15,23,42,0.35)]">
      <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/80 px-4 py-2 text-xs font-semibold text-slate-900">
        <Crosshair className="h-4 w-4 text-blue-600" /> 详细特征提取
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="p-4 font-mono text-sm leading-relaxed text-foreground">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <button
              onClick={() => void onJumpToPacket(selected.packetId)}
              disabled={actionBusy.length > 0}
              className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {actionBusy === `packet:${selected.packetId}` ? "定位中" : `定位到包 #${selected.packetId}`}
            </button>
            <button
              onClick={() => void onOpenRelatedStream(selected.packetId)}
              disabled={actionBusy.length > 0}
              className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {actionBusy === `stream:${selected.packetId}` ? "打开中" : "打开关联流"}
            </button>
          </div>
          <div className="mb-1 font-sans text-xs text-slate-500">命中字符串:</div>
          <div className="break-all rounded-2xl border border-rose-200 bg-rose-50/80 p-3 text-rose-700 select-all">
            {selected.match}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}

function toneForThreatLevel(level: string): AnalysisTone {
  switch (level) {
    case "critical":
    case "high":
      return "rose";
    case "medium":
      return "amber";
    default:
      return "slate";
  }
}
