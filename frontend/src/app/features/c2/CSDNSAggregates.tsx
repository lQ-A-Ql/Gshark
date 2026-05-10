import { useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2DNSAggregate } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { FilterActions } from "../../misc/FilterActions";
import {
  AggregateExpandButton,
  CSDNSAggregateDetailPanel,
  TagLine,
  firstNumber,
  formatNumberList,
} from "./C2AggregateDetails";
import {
  C2_MONO_CELL_CLASS,
  C2_TABLE_HEADER_CLASS,
  C2_TABLE_ROW_CLASS,
  C2_TABLE_WRAPPER_CLASS,
} from "./C2AggregateTableStyles";

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
