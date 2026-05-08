import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2IndicatorRecord } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { FilterActions } from "../../misc/FilterActions";

const C2_CANDIDATE_TABLE_WRAPPER_CLASS = "border-slate-200 bg-white shadow-sm";
const C2_CANDIDATE_TABLE_HEADER_CLASS = "bg-gradient-to-r from-slate-100 to-rose-50 text-slate-700";
const C2_CANDIDATE_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-white even:bg-slate-50/45";
const C2_CANDIDATE_MONO_CELL_CLASS = "font-mono text-slate-600";

export function C2CandidateTable({ candidates }: { candidates: C2IndicatorRecord[] }) {
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

  if (candidates.length === 0) {
    return (
      <EmptyState className="py-8">
        当前抓包未形成候选证据。命中后会展示 family、channel、indicator、confidence、actorHints 与
        tags，并支持定位包或打开关联流。
      </EmptyState>
    );
  }

  return (
    <DataTable<C2IndicatorRecord>
      data={candidates}
      rowKey={(item, index) => candidateRowKey(item, index)}
      maxHeightClassName="max-h-[440px]"
      wrapperClassName={C2_CANDIDATE_TABLE_WRAPPER_CLASS}
      headerClassName={C2_CANDIDATE_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1120px]"
      rowClassName={(item, index) =>
        cn(
          C2_CANDIDATE_TABLE_ROW_CLASS,
          expandedRows.has(candidateRowKey(item, index)) ? "bg-rose-50/25" : "hover:bg-slate-50/70",
        )
      }
      expandedRowClassName="border-rose-100/80 bg-rose-50/20"
      renderExpandedRow={(item, index) => {
        const tags = candidateTagValues(item);
        return expandedRows.has(candidateRowKey(item, index)) ? <CandidateDetailPanel item={item} tags={tags} /> : null;
      }}
      columns={[
        {
          key: "packet",
          header: "包号",
          widthClassName: "w-16",
          cellClassName: "font-mono text-slate-500",
          render: (item) => item.packetId || "--",
        },
        {
          key: "family",
          header: "Family",
          widthClassName: "w-20",
          cellClassName: "font-semibold text-slate-800",
          render: (item) => item.family,
        },
        { key: "channel", header: "Channel", widthClassName: "w-24", render: (item) => item.channel || "--" },
        { key: "type", header: "类型", widthClassName: "w-32", render: (item) => item.indicatorType || "--" },
        {
          key: "value",
          header: "值",
          widthClassName: "w-44",
          cellClassName: "break-all font-mono text-[11px] text-slate-600",
          render: (item) => item.indicatorValue || item.uri || item.host || "--",
        },
        {
          key: "confidence",
          header: "置信度",
          widthClassName: "w-20",
          cellClassName: C2_CANDIDATE_MONO_CELL_CLASS,
          render: (item) => item.confidence ?? "--",
        },
        {
          key: "summary",
          header: "摘要 / 标签",
          cellClassName: "space-y-2",
          render: (item, index) => {
            const rowKey = candidateRowKey(item, index);
            const expanded = expandedRows.has(rowKey);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    aria-label={`${expanded ? "收起" : "展开"} C2 候选详情 #${item.packetId || index + 1}`}
                    onClick={() => toggleExpanded(rowKey)}
                    className={cn(
                      "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold transition-all duration-200",
                      expanded
                        ? "border-rose-200 bg-rose-50 text-rose-700 shadow-[0_12px_28px_-22px_rgba(225,29,72,0.75)]"
                        : "border-slate-200 bg-white text-slate-600 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700",
                    )}
                  >
                    {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    {expanded ? "收起详情" : "展开详情"}
                  </button>
                  <CandidateTagLine values={compactCandidateTags(candidateTagValues(item))} />
                </div>
              </>
            );
          },
        },
        {
          key: "actions",
          header: "证据联动",
          widthClassName: "w-44",
          render: (item) => (
            <div className="flex flex-col items-start gap-2">
              <EvidenceActions
                packetId={item.packetId}
                preferredProtocol={preferredProtocolForCandidate(item)}
                className="flex-col items-start"
              />
              <CandidateFilterActions item={item} />
            </div>
          ),
        },
      ]}
    />
  );
}

function CandidateFilterActions({ item }: { item: C2IndicatorRecord }) {
  const channel = (item.channel ?? "").toLowerCase();
  const indicatorType = (item.indicatorType ?? "").toLowerCase();
  const indicatorValue = item.indicatorValue?.trim() ?? "";
  const isDns = channel === "dns" || indicatorType.includes("dns");
  const isTcpLike = channel === "tcp" || channel === "smb" || channel === "dot" || item.family === "vshell";

  if (isDns) {
    const qname = item.host || indicatorValue;
    return qname ? (
      <FilterActions
        protocol="dns"
        qname={qname}
        dnsQueryType={indicatorValue.toUpperCase().includes("TXT") ? "TXT" : undefined}
      />
    ) : null;
  }
  if (isTcpLike && typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  if (item.host || item.uri) {
    return <FilterActions protocol="http" host={item.host} uri={item.uri} />;
  }
  if (typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  return null;
}

function CandidateDetailPanel({ item, tags }: { item: C2IndicatorRecord; tags: string[] }) {
  return (
    <div className="overflow-hidden rounded-[24px] border border-rose-100 bg-white/95 p-4 shadow-[0_20px_60px_-48px_rgba(15,23,42,0.55)] transition-all duration-200">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Evidence Context</div>
          <CandidateContext item={item} />
          <div className="mt-3">
            <CandidateTagLine values={tags} />
          </div>
        </div>
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">
            Typed Record Preview
          </div>
          <pre className="max-h-60 overflow-auto rounded-2xl border border-slate-100 bg-slate-950 p-3 text-[11px] leading-5 text-slate-100">
            {JSON.stringify(candidatePreviewRecord(item), null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

function CandidateContext({ item }: { item: C2IndicatorRecord }) {
  const endpoint = item.source || item.destination ? `${item.source || "?"} → ${item.destination || "?"}` : "";
  const rows = [
    { label: "时间", value: item.time },
    { label: "Stream", value: typeof item.streamId === "number" ? String(item.streamId) : "" },
    { label: "端点", value: endpoint },
    { label: "Host", value: item.host },
    { label: "URI", value: item.uri },
    { label: "Method", value: item.method },
    { label: "Evidence", value: item.evidence },
  ].filter((row) => row.value && String(row.value).trim() !== "");

  if (rows.length === 0) return null;

  return (
    <div className="mt-2 grid gap-1.5 rounded-2xl border border-slate-100 bg-slate-50/70 p-2">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2 text-[11px] leading-5">
          <span className="font-semibold text-slate-400">{row.label}</span>
          <span className="break-all font-mono text-slate-600">{row.value}</span>
        </div>
      ))}
    </div>
  );
}

function candidateRowKey(item: C2IndicatorRecord, index: number) {
  return `${item.family}-${item.packetId}-${item.streamId ?? "no-stream"}-${index}`;
}

function candidateTagValues(item: C2IndicatorRecord) {
  return uniqueValues([
    ...(item.tags ?? []),
    ...(item.actorHints ?? []),
    item.sampleFamily ?? "",
    item.campaignStage ?? "",
    ...(item.transportTraits ?? []),
    ...(item.infrastructureHints ?? []),
    ...(item.ttpTags ?? []),
  ]);
}

function compactCandidateTags(tags: string[]) {
  if (tags.length <= 5) return tags;
  return [...tags.slice(0, 5), `+${tags.length - 5} more`];
}

function uniqueValues(values: string[]) {
  const seen = new Set<string>();
  const next: string[] = [];
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    next.push(normalized);
  }
  return next;
}

function candidatePreviewRecord(item: C2IndicatorRecord) {
  return {
    packetId: item.packetId,
    streamId: item.streamId,
    time: item.time,
    family: item.family,
    channel: item.channel,
    source: item.source,
    destination: item.destination,
    host: item.host,
    uri: item.uri,
    method: item.method,
    indicatorType: item.indicatorType,
    indicatorValue: item.indicatorValue,
    confidence: item.confidence,
    evidence: item.evidence,
    actorHints: item.actorHints,
    sampleFamily: item.sampleFamily,
    campaignStage: item.campaignStage,
    transportTraits: item.transportTraits,
    infrastructureHints: item.infrastructureHints,
    ttpTags: item.ttpTags,
  };
}

function preferredProtocolForCandidate(item: C2IndicatorRecord): "HTTP" | "TCP" | "UDP" | undefined {
  const channel = (item.channel ?? "").toLowerCase();
  if (item.method || channel === "http" || channel === "websocket" || channel === "doh") {
    return "HTTP";
  }
  if (channel === "dns" || channel === "kcp_udp" || channel === "udp") {
    return "UDP";
  }
  if (channel === "tcp" || channel === "smb" || channel === "dot") {
    return "TCP";
  }
  return undefined;
}

function CandidateTagLine({ values }: { values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span
          key={value}
          className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold text-slate-500"
        >
          {value}
        </span>
      ))}
    </div>
  );
}
