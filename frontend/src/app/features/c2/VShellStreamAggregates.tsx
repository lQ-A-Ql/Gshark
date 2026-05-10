import { useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2StreamAggregate } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { FilterActions } from "../../misc/FilterActions";
import {
  AggregateExpandButton,
  TagLine,
  VShellStreamAggregateDetailPanel,
  firstNumber,
  formatNumberList,
} from "./C2AggregateDetails";
import { C2_MONO_CELL_CLASS, C2_TABLE_ROW_CLASS, C2_TABLE_WRAPPER_CLASS } from "./C2AggregateTableStyles";

export function VShellStreamAggregates({ items }: { items: C2StreamAggregate[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<number>>(() => new Set());

  const toggleExpanded = (streamId: number) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(streamId)) {
        next.delete(streamId);
      } else {
        next.add(streamId);
      }
      return next;
    });
  };

  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 VShell Stream 聚合。该区域仅代表 stream-level 画像；若上方或候选证据表存在
        candidates，仍应按候选弱信号继续复核。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2StreamAggregate>
      data={items}
      rowKey={(item) => item.streamId}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName="bg-gradient-to-r from-slate-100 to-cyan-50 text-slate-700"
      tableClassName="min-w-[1080px]"
      rowClassName={(item) =>
        cn(C2_TABLE_ROW_CLASS, expandedRows.has(item.streamId) ? "bg-cyan-50/30" : "hover:bg-cyan-50/30")
      }
      expandedRowClassName="border-cyan-100/80 bg-cyan-50/20"
      renderExpandedRow={(item) =>
        expandedRows.has(item.streamId) ? <VShellStreamAggregateDetailPanel item={item} /> : null
      }
      columns={[
        {
          key: "stream",
          header: "Stream",
          widthClassName: "w-20",
          render: (item) => (
            <>
              <div className="font-mono font-semibold text-slate-800">{item.streamId}</div>
              <div className="text-[10px] text-slate-400">{item.protocol || "tcp"}</div>
              <div className="text-[10px] text-slate-400">{item.totalPackets} 包</div>
              <TagLine values={[item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
            </>
          ),
        },
        {
          key: "arch",
          header: "架构标记",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) =>
            (item.archMarkers ?? []).length > 0 ? (
              <div className="space-y-0.5">
                {item.archMarkers!.map((am) => (
                  <div key={am.label}>
                    {am.label} {am.count}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-slate-400">--</div>
            ),
        },
        {
          key: "lengthPrefix",
          header: "长度前缀",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) =>
            item.lengthPrefixCount > 0 ? (
              <div>{item.lengthPrefixCount} 次</div>
            ) : (
              <div className="text-slate-400">--</div>
            ),
        },
        {
          key: "packetShape",
          header: "短/长包",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) =>
            item.shortPackets > 0 || item.longPackets > 0 ? (
              <div>
                <div>短 {item.shortPackets}</div>
                <div>长 {item.longPackets}</div>
                <div className="text-[10px] text-slate-400">transitions={item.transitions}</div>
              </div>
            ) : (
              <div className="text-slate-400">--</div>
            ),
        },
        {
          key: "heartbeat",
          header: "心跳",
          widthClassName: "w-36",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              {item.heartbeatAvg ? (
                <div>
                  <div>{item.heartbeatAvg}</div>
                  <div className="text-[10px] text-slate-400">jitter {item.heartbeatJitter || "--"}</div>
                </div>
              ) : (
                <div className="text-slate-400">--</div>
              )}
              {item.hasWebSocket && <div className="mt-1 text-[10px] text-cyan-600">WebSocket</div>}
            </>
          ),
        },
        {
          key: "evidence",
          header: "摘要 / Packets / 证据",
          cellClassName: "space-y-2",
          render: (item) => {
            const expanded = expandedRows.has(item.streamId);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="break-all text-[11px] text-slate-500">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
                {(item.listenerHints ?? []).length > 0 && (
                  <TagLine values={item.listenerHints!.map((h) => `${h.label}:${h.count}`)} />
                )}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <AggregateExpandButton
                    expanded={expanded}
                    label={`VShell Stream 聚合详情 ${item.streamId}`}
                    onClick={() => toggleExpanded(item.streamId)}
                  />
                  <EvidenceActions packetId={firstNumber(item.packets)} preferredProtocol="TCP" />
                  <FilterActions protocol="tcp" streamId={item.streamId} />
                </div>
              </>
            );
          },
        },
      ]}
    />
  );
}
