import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2HTTPEndpointAggregate } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { FilterActions } from "../../misc/FilterActions";
import { IntervalSparkline, TagLine, firstNumber, formatNumberList } from "./C2AggregateDetails";
import {
  C2_MONO_CELL_CLASS,
  C2_TABLE_HEADER_CLASS,
  C2_TABLE_ROW_CLASS,
  C2_TABLE_WRAPPER_CLASS,
} from "./C2AggregateTableStyles";

export function CSHostURIAggregates({ items }: { items: C2HTTPEndpointAggregate[] }) {
  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 CS Host / URI 聚合。该区域会按 Host + URI 汇总 GET/POST、时间范围、平均间隔、jitter、stream 与 packet
        列表，用于从单包候选升级到 Beacon 会话画像。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2HTTPEndpointAggregate>
      data={items}
      rowKey={(item, index) => `${item.host}-${item.uri}-${index}`}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName={C2_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1080px]"
      rowClassName={cn(C2_TABLE_ROW_CLASS, "hover:bg-rose-50/30")}
      columns={[
        {
          key: "endpoint",
          header: "Host / URI",
          widthClassName: "w-[30%]",
          cellClassName: "space-y-1",
          render: (item) => (
            <>
              <div className="break-all font-semibold text-slate-800">{item.host || "(no-host)"}</div>
              <div className="break-all font-mono text-[11px] text-slate-500">{item.uri || "(no-uri)"}</div>
              <TagLine
                values={[item.channel ?? "", item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)}
              />
            </>
          ),
        },
        {
          key: "methods",
          header: "GET / POST",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>GET {item.getCount.toLocaleString()}</div>
              <div>POST {item.postCount.toLocaleString()}</div>
              <div className="mt-1 text-[10px] text-slate-400">Total {item.total.toLocaleString()}</div>
            </>
          ),
        },
        {
          key: "interval",
          header: "间隔 / Jitter",
          widthClassName: "w-36",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>{item.avgInterval || "--"}</div>
              <div className="text-[10px] text-slate-400">{item.jitter ? `jitter ${item.jitter}` : "jitter --"}</div>
              <IntervalSparkline values={item.intervals} color="stroke-rose-500" compact />
            </>
          ),
        },
        {
          key: "timeRange",
          header: "时间范围",
          widthClassName: "w-44",
          cellClassName: "space-y-1 font-mono text-[11px] text-slate-500",
          render: (item) => (
            <>
              <div>{item.firstTime || "--"}</div>
              <div>{item.lastTime || "--"}</div>
            </>
          ),
        },
        {
          key: "evidence",
          header: "Streams / Packets / 摘要 / 证据",
          cellClassName: "space-y-2",
          render: (item) => (
            <>
              <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
              {(item.scoreFactors ?? []).length > 0 && (
                <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-3 py-2">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-400">
                    Scoring Factors
                  </div>
                  <div className="space-y-1">
                    {(item.scoreFactors ?? []).map((sf) => (
                      <div key={sf.name} className="flex items-start gap-2 text-[11px]">
                        <span
                          className={cn(
                            "mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full",
                            sf.direction === "positive" ? "bg-emerald-500" : "bg-amber-500",
                          )}
                        />
                        <div>
                          <span className="font-semibold text-slate-700">{sf.name}</span>
                          <span className="ml-1 text-slate-400">
                            ({sf.direction === "positive" ? "+" : ""}
                            {sf.weight})
                          </span>
                          {sf.summary && <div className="text-slate-500">{sf.summary}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {(item.signalTags ?? []).length > 0 && (
                <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-3 py-2">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                    Signal Tags
                  </div>
                  <TagLine values={item.signalTags ?? []} />
                </div>
              )}
              <div className="grid gap-1 text-[11px] text-slate-500 md:grid-cols-2">
                <div className="break-all">
                  <span className="font-semibold text-slate-400">Streams </span>
                  {formatNumberList(item.streams)}
                </div>
                <div className="break-all">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
              </div>
              <TagLine values={(item.methods ?? []).map((method) => `${method.label}:${method.count}`)} />
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <EvidenceActions
                  packetId={item.representativePacket || firstNumber(item.packets)}
                  preferredProtocol="HTTP"
                />
                <FilterActions
                  host={item.host === "(no-host)" ? "" : item.host}
                  uri={item.uri === "(no-uri)" ? "" : item.uri}
                />
              </div>
            </>
          ),
        },
      ]}
    />
  );
}
