import { useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2DNSAggregate, C2HTTPEndpointAggregate, C2StreamAggregate } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { FilterActions } from "../../misc/FilterActions";
import {
  AggregateExpandButton,
  CSDNSAggregateDetailPanel,
  IntervalSparkline,
  TagLine,
  VShellStreamAggregateDetailPanel,
  firstNumber,
  formatNumberList,
} from "./C2AggregateDetails";

const C2_TABLE_WRAPPER_CLASS = "border-slate-200 bg-white shadow-sm";
const C2_TABLE_HEADER_CLASS = "bg-gradient-to-r from-slate-100 to-rose-50 text-slate-700";
const C2_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-white even:bg-slate-50/45";
const C2_MONO_CELL_CLASS = "font-mono text-slate-600";

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

export function CSDNSAggregates({ items }: { items: C2DNSAggregate[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(() => new Set());

  const toggleExpanded = (rowKey: string) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(rowKey)) {
        next.delete(rowKey);
      } else {
        next.add(rowKey);
      }
      return next;
    });
  };

  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 CS DNS 聚合。该区域会按 qname 汇总 DNS 查询类型、TXT/NULL/CNAME 分布、请求/响应比例、时间间隔与 packet
        列表，用于 DNS Beacon 画像。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2DNSAggregate>
      data={items}
      rowKey={(item, index) => `${item.qname}-${index}`}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName={C2_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1080px]"
      rowClassName={(item, index) =>
        cn(C2_TABLE_ROW_CLASS, expandedRows.has(`${item.qname}-${index}`) ? "bg-rose-50/25" : "hover:bg-rose-50/30")
      }
      expandedRowClassName="border-rose-100/80 bg-rose-50/20"
      renderExpandedRow={(item, index) =>
        expandedRows.has(`${item.qname}-${index}`) ? <CSDNSAggregateDetailPanel item={item} /> : null
      }
      columns={[
        {
          key: "qname",
          header: "QName",
          widthClassName: "w-[30%]",
          cellClassName: "space-y-1",
          render: (item) => (
            <>
              <div className="break-all font-mono font-semibold text-slate-800">{item.qname}</div>
              <div className="text-[10px] text-slate-400">max_label={item.maxLabelLength}</div>
              <TagLine values={[item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
            </>
          ),
        },
        {
          key: "queryTypes",
          header: "查询类型",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div className="space-y-0.5">
                {(item.queryTypes ?? []).map((qt) => (
                  <div key={qt.label}>
                    {qt.label} {qt.count}
                  </div>
                ))}
              </div>
              <div className="mt-1 text-[10px] text-slate-400">Total {item.total.toLocaleString()}</div>
            </>
          ),
        },
        {
          key: "dnsShape",
          header: "TXT/NULL/CNAME",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              {item.txtCount > 0 && <div>TXT {item.txtCount}</div>}
              {item.nullCount > 0 && <div>NULL {item.nullCount}</div>}
              {item.cnameCount > 0 && <div>CNAME {item.cnameCount}</div>}
              {item.txtCount === 0 && item.nullCount === 0 && item.cnameCount === 0 && (
                <div className="text-slate-400">--</div>
              )}
            </>
          ),
        },
        {
          key: "requestResponse",
          header: "请求/响应",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>req {item.requestCount}</div>
              <div>resp {item.responseCount}</div>
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
              <div className="mt-1 text-[10px] text-slate-400">
                {item.firstTime || "--"} ~ {item.lastTime || "--"}
              </div>
            </>
          ),
        },
        {
          key: "evidence",
          header: "摘要 / Packets / 证据",
          cellClassName: "space-y-2",
          render: (item, index) => {
            const rowKey = `${item.qname}-${index}`;
            const expanded = expandedRows.has(rowKey);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="break-all text-[11px] text-slate-500">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <AggregateExpandButton
                    expanded={expanded}
                    label={`DNS 聚合详情 ${item.qname}`}
                    onClick={() => toggleExpanded(rowKey)}
                  />
                  <EvidenceActions packetId={firstNumber(item.packets)} preferredProtocol="UDP" />
                  <FilterActions
                    protocol="dns"
                    qname={item.qname}
                    dnsQueryType={item.txtCount > 0 ? "TXT" : undefined}
                  />
                </div>
              </>
            );
          },
        },
      ]}
    />
  );
}

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
