import { ChevronDown, ChevronRight } from "lucide-react";
import { Sparkline } from "../../components/Sparkline";
import { cn } from "../../components/ui/utils";
import type { C2DNSAggregate, C2StreamAggregate } from "../../core/types";

export function formatNumberList(values?: number[]) {
  if (!values || values.length === 0) return "--";
  return values.slice(0, 10).join(", ") + (values.length > 10 ? `, +${values.length - 10}` : "");
}

export function firstNumber(values?: number[]) {
  const value = values?.find((item) => Number.isFinite(item) && item > 0);
  return value ?? 0;
}

export function IntervalSparkline({
  values,
  color = "stroke-rose-500",
  compact = false,
}: {
  values?: number[];
  color?: string;
  compact?: boolean;
}) {
  const cleanValues = (values ?? []).filter((value) => Number.isFinite(value) && value > 0);
  if (cleanValues.length < 2) return null;
  const preview = cleanValues
    .slice(0, 6)
    .map((value) => `${value.toFixed(value >= 10 ? 0 : 1)}s`)
    .join(" / ");
  return (
    <div className={cn("gshark-tile border-slate-100 px-3 py-2", compact ? "mt-2 px-2 py-1" : "mt-3")}>
      <div className="mb-1 flex items-center justify-between gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-400">
        <span>Interval Sparkline</span>
        <span className="font-mono normal-case tracking-normal text-slate-500">
          {preview}
          {cleanValues.length > 6 ? " ..." : ""}
        </span>
      </div>
      <Sparkline values={cleanValues} color={color} width={compact ? 96 : 180} height={compact ? 20 : 28} />
    </div>
  );
}

export function AggregateExpandButton({
  expanded,
  label,
  onClick,
}: {
  expanded: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={`${expanded ? "收起" : "展开"} ${label}`}
      onClick={onClick}
      className={cn(
        "gshark-control inline-flex h-7 items-center gap-1.5 px-2.5 text-[11px] font-semibold transition-all duration-200",
        expanded ? "gshark-evidence-accent text-cyan-700" : "text-slate-600 hover:text-cyan-700",
      )}
    >
      {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
      {expanded ? "收起详情" : "展开详情"}
    </button>
  );
}

export function CSDNSAggregateDetailPanel({ item }: { item: C2DNSAggregate }) {
  const metrics = [
    { label: "QName", value: item.qname },
    {
      label: "时间范围",
      value: item.firstTime || item.lastTime ? `${item.firstTime || "--"} ~ ${item.lastTime || "--"}` : "",
    },
    { label: "平均间隔", value: item.avgInterval },
    { label: "Jitter", value: item.jitter },
    { label: "最大 Label", value: item.maxLabelLength ? String(item.maxLabelLength) : "" },
    { label: "请求/响应", value: `${item.requestCount} / ${item.responseCount}` },
    { label: "Packet 时间序列", value: formatNumberList(item.packets) },
  ];
  const queryTypeTags = (item.queryTypes ?? []).map((qt) => `${qt.label}:${qt.count}`);
  const dnsShapeTags = [
    item.txtCount > 0 ? `TXT:${item.txtCount}` : "",
    item.nullCount > 0 ? `NULL:${item.nullCount}` : "",
    item.cnameCount > 0 ? `CNAME:${item.cnameCount}` : "",
  ].filter(Boolean);

  return (
    <div className="gshark-tile overflow-hidden border-rose-100 p-3.5 transition-all duration-200">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">DNS Aggregate Detail</div>
          <div className="mt-1 break-all font-mono text-xs text-slate-700">{item.summary || item.qname}</div>
        </div>
        <TagLine
          values={["dns-beacon-review", item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)}
        />
      </div>
      <DetailMetricGrid rows={metrics} />
      <IntervalSparkline values={item.intervals} color="stroke-rose-500" />
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="gshark-soft-fill p-2.5">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">Query Type 分布</div>
          <TagLine values={queryTypeTags.length > 0 ? queryTypeTags : ["--"]} />
        </div>
        <div className="gshark-soft-fill p-2.5">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">TXT / NULL / CNAME 形态</div>
          <TagLine values={dnsShapeTags.length > 0 ? dnsShapeTags : ["no-txt-null-cname"]} />
        </div>
      </div>
    </div>
  );
}

export function VShellStreamAggregateDetailPanel({ item }: { item: C2StreamAggregate }) {
  const metrics = [
    { label: "Stream", value: String(item.streamId) },
    { label: "协议", value: item.protocol || "TCP" },
    { label: "总包数", value: String(item.totalPackets) },
    { label: "长度前缀", value: item.lengthPrefixCount > 0 ? `${item.lengthPrefixCount} 次` : "" },
    { label: "短/长包", value: `${item.shortPackets} / ${item.longPackets}` },
    { label: "状态转移", value: typeof item.transitions === "number" ? String(item.transitions) : "" },
    { label: "心跳", value: item.heartbeatAvg ? `${item.heartbeatAvg} · jitter ${item.heartbeatJitter || "--"}` : "" },
    { label: "Packet 时间序列", value: formatNumberList(item.packets) },
  ];
  const archTags = (item.archMarkers ?? []).map((marker) => `${marker.label}:${marker.count}`);
  const listenerTags = (item.listenerHints ?? []).map((hint) => `${hint.label}:${hint.count}`);

  return (
    <div className="gshark-tile overflow-hidden border-cyan-100 p-3.5 transition-all duration-200">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">VShell Stream Detail</div>
          <div className="mt-1 break-all font-mono text-xs text-slate-700">
            {item.summary || `tcp.stream == ${item.streamId}`}
          </div>
        </div>
        <TagLine
          values={[
            "stream-level-review",
            item.hasWebSocket ? "websocket" : "",
            item.confidence ? `confidence:${item.confidence}` : "",
          ].filter(Boolean)}
        />
      </div>
      <DetailMetricGrid rows={metrics} />
      <IntervalSparkline values={item.intervals} color="stroke-cyan-500" />
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="gshark-soft-fill p-2.5">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">架构标记 / Payload 形态</div>
          <TagLine values={archTags.length > 0 ? archTags : ["no-arch-marker"]} />
        </div>
        <div className="gshark-soft-fill p-2.5">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">Listener / 管理面提示</div>
          <TagLine values={listenerTags.length > 0 ? listenerTags : ["no-listener-hint"]} />
        </div>
      </div>
    </div>
  );
}

function DetailMetricGrid({ rows }: { rows: Array<{ label: string; value?: string }> }) {
  const visibleRows = rows.filter((row) => row.value && row.value.trim() !== "");
  if (visibleRows.length === 0) return null;
  return (
    <div className="gshark-soft-fill grid gap-1.5 p-2 md:grid-cols-2">
      {visibleRows.map((row) => (
        <div key={row.label} className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-2 text-[11px] leading-5">
          <span className="font-semibold text-slate-400">{row.label}</span>
          <span className="break-all font-mono text-slate-600">{row.value}</span>
        </div>
      ))}
    </div>
  );
}

export function TagLine({ values }: { values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="gshark-diffuse-chip px-2 py-0.5 text-[10px] font-semibold text-slate-500">
          {value}
        </span>
      ))}
    </div>
  );
}
