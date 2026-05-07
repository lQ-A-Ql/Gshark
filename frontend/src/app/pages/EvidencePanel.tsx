import { useMemo, useState } from "react";
import { Shield, Search, Filter, Download } from "lucide-react";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBadge,
  AnalysisDataTable,
  type AnalysisTone,
} from "../components/analysis/AnalysisPrimitives";
import { useSentinel } from "../state/SentinelContext";
import { useEvidence } from "../features/evidence/useEvidence";
import type { UnifiedEvidenceRecord, EvidenceSeverity } from "../features/evidence/evidenceSchema";
import { downloadText } from "../utils/browserFile";
import { cn } from "../components/ui/utils";
import { EvidenceActions } from "../misc/EvidenceActions";

const MODULE_OPTIONS = [
  { value: "hunting", label: "威胁狩猎" },
  { value: "c2", label: "C2 分析" },
  { value: "apt", label: "APT 画像" },
  { value: "industrial", label: "工控分析" },
  { value: "object", label: "对象导出" },
  { value: "vehicle", label: "车机分析" },
  { value: "usb", label: "USB 分析" },
] as const;

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function EvidencePanel() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<EvidenceSeverity | "all">("all");

  const { evidence, loading, error } = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: selectedModules.length > 0 ? selectedModules : undefined,
  });

  const filtered = useMemo(() => {
    return evidence.filter((item) => {
      const matchesSeverity = severityFilter === "all" || item.severity === severityFilter;
      const matchesQuery = !query.trim() || matchesSearch(item, query);
      return matchesSeverity && matchesQuery;
    });
  }, [evidence, query, severityFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity] ?? 5;
      const sb = SEVERITY_ORDER[b.severity] ?? 5;
      if (sa !== sb) return sa - sb;
      return (b.confidence ?? 0) - (a.confidence ?? 0);
    });
  }, [filtered]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const item of evidence) {
      counts[item.severity] = (counts[item.severity] ?? 0) + 1;
    }
    return counts;
  }, [evidence]);

  const handleExportJSON = () => {
    const payload = JSON.stringify(sorted, null, 2);
    downloadText("evidence-export.json", payload, "application/json;charset=utf-8");
  };

  const handleExportCSV = () => {
    const headers = ["module", "severity", "confidence", "sourceType", "summary", "packetId", "tags"];
    const rows = sorted.map((item) => [
      item.module,
      item.severity,
      String(item.confidence ?? ""),
      item.sourceType,
      `"${(item.summary || "").replace(/"/g, '""')}"`,
      String(item.packetId ?? ""),
      item.tags.join("; "),
    ]);
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    downloadText("evidence-export.csv", csv, "text/csv;charset=utf-8");
  };

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(99,102,241,0.26),transparent_36%),linear-gradient(180deg,#eef2ff_0%,#f5f3ff_44%,#f8fafc_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1200px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(99,102,241,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
        {/* Hero */}
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-700 shadow-sm">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="flex flex-wrap items-baseline gap-2">
                  <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">证据链总览</h1>
                  <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">UNIFIED EVIDENCE</span>
                </div>
              </div>
            </div>
            <p className="max-w-2xl text-[13px] leading-7 text-slate-500">
              跨模块统一查看威胁狩猎、C2 分析、APT 画像、工控分析、车机分析、USB 分析和对象导出的证据记录，支持搜索、过滤和导出。
            </p>
            <div className="flex flex-wrap gap-2 text-[11px]">
              {["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"].map((tag) => (
                <span key={tag} className="rounded-full border border-indigo-100 bg-indigo-50/60 px-3 py-1 text-indigo-700 shadow-sm">{tag}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Severity summary */}
        <div className="mb-4 flex flex-wrap gap-2">
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(severityFilter === sev ? "all" : sev)}
              className={cn(
                "rounded-full border px-3 py-1 text-[11px] font-medium transition-all",
                severityFilter === sev
                  ? severityActiveStyle(sev)
                  : "border-slate-200 bg-white/80 text-slate-600 hover:border-indigo-200",
              )}
            >
              {severityLabel(sev)} · {severityCounts[sev] ?? 0}
            </button>
          ))}
        </div>

        {/* Toolbar */}
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
          <div className="flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1 shadow-sm focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索摘要、值、标签..."
              className="border-none bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            {MODULE_OPTIONS.map((mod) => {
              const active = selectedModules.includes(mod.value);
              return (
                <button
                  key={mod.value}
                  type="button"
                  onClick={() => {
                    setSelectedModules((prev) =>
                      active ? prev.filter((m) => m !== mod.value) : [...prev, mod.value],
                    );
                  }}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-all",
                    active
                      ? "border-indigo-200 bg-indigo-100 text-indigo-700 shadow-sm"
                      : "border-slate-200 bg-white/80 text-slate-500 hover:border-indigo-200 hover:text-indigo-700",
                  )}
                >
                  {mod.label}
                </button>
              );
            })}
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-muted-foreground">{sorted.length} / {evidence.length} 条</span>
            <button type="button" onClick={handleExportJSON} className="flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-foreground shadow-sm transition-colors hover:bg-accent">
              <Download className="h-3 w-3" /> JSON
            </button>
            <button type="button" onClick={handleExportCSV} className="flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-foreground shadow-sm transition-colors hover:bg-accent">
              <Download className="h-3 w-3" /> CSV
            </button>
          </div>
        </div>

        {loading && (
          <div className="mb-4 rounded-2xl border border-indigo-100 bg-white/80 px-4 py-3 text-xs font-medium text-slate-500 shadow-sm">
            正在聚合跨模块证据...
          </div>
        )}

        {!loading && error && (
          <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-xs text-amber-700 shadow-sm">
            {error}
          </div>
        )}

        {/* Evidence table */}
        <AnalysisDataTable
          columns={[
            {
              key: "severity",
              header: "等级",
              widthClassName: "w-16",
              render: (item) => <AnalysisBadge tone={severityTone(item.severity)}>{item.severity}</AnalysisBadge>,
            },
            {
              key: "module",
              header: "模块",
              widthClassName: "w-24",
              render: (item) => <span className="text-[11px] font-medium text-slate-600">{moduleLabel(item.module)}</span>,
            },
            {
              key: "sourceType",
              header: "类型",
              widthClassName: "w-28",
              cellClassName: "font-mono text-slate-600 text-[11px]",
              render: (item) => item.sourceType || "--",
            },
            {
              key: "summary",
              header: "摘要",
              render: (item) => (
                <div className="min-w-0">
                  <div className="truncate text-[13px]">{item.summary || "--"}</div>
                  {item.value && <div className="mt-0.5 truncate text-[11px] text-slate-500">{item.value}</div>}
                </div>
              ),
            },
            {
              key: "confidence",
              header: "置信",
              widthClassName: "w-16",
              render: (item) => item.confidence != null ? (
                <span className={cn("text-[11px] font-medium", confidenceColor(item.confidence))}>
                  {item.confidence}
                </span>
              ) : <span className="text-[11px] text-slate-400">--</span>,
            },
            {
              key: "packetId",
              header: "包号",
              widthClassName: "w-20",
              cellClassName: "font-mono text-slate-500 text-[11px]",
              render: (item) => item.packetId ? (
                <EvidenceActions packetId={item.packetId} className="inline-flex" />
              ) : "--",
            },
            {
              key: "tags",
              header: "标签",
              widthClassName: "w-40",
              render: (item) => (
                <div className="flex flex-wrap gap-1">
                  {item.tags.slice(0, 3).map((tag) => (
                    <span key={tag} className="rounded-full border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-600">{tag}</span>
                  ))}
                  {item.tags.length > 3 && <span className="text-[10px] text-slate-400">+{item.tags.length - 3}</span>}
                </div>
              ),
            },
          ]}
          data={sorted}
          rowKey={(item) => item.id}
          maxHeightClassName="max-h-[600px]"
          tableClassName="min-w-[900px]"
          emptyText={loading ? "正在加载..." : "当前抓包未产生证据记录"}
        />

        {/* Caveats */}
        {sorted.some((item) => item.caveats.length > 0) && (
          <div className="mt-4 rounded-2xl border border-amber-100 bg-amber-50/60 px-4 py-3 text-[11px] text-amber-700">
            <div className="mb-1 font-semibold">证据使用提示</div>
            <ul className="list-inside list-disc space-y-0.5">
              {Array.from(new Set(sorted.flatMap((item) => item.caveats))).slice(0, 5).map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </PageShell>
  );
}

function matchesSearch(item: UnifiedEvidenceRecord, query: string): boolean {
  const lower = query.toLowerCase();
  return (
    item.summary.toLowerCase().includes(lower) ||
    (item.value ?? "").toLowerCase().includes(lower) ||
    item.sourceType.toLowerCase().includes(lower) ||
    item.tags.some((tag) => tag.toLowerCase().includes(lower)) ||
    (item.host ?? "").toLowerCase().includes(lower) ||
    (item.uri ?? "").toLowerCase().includes(lower)
  );
}

function severityLabel(sev: EvidenceSeverity): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[sev] ?? sev;
}

function severityTone(sev: EvidenceSeverity): AnalysisTone {
  const map: Record<string, AnalysisTone> = { critical: "rose", high: "rose", medium: "amber", low: "blue", info: "slate" };
  return map[sev] ?? "slate";
}

function severityActiveStyle(sev: EvidenceSeverity): string {
  return {
    critical: "border-rose-300 bg-rose-100 text-rose-700 shadow-sm",
    high: "border-rose-200 bg-rose-50 text-rose-700 shadow-sm",
    medium: "border-amber-200 bg-amber-100 text-amber-700 shadow-sm",
    low: "border-blue-200 bg-blue-50 text-blue-700 shadow-sm",
    info: "border-slate-300 bg-slate-100 text-slate-700 shadow-sm",
  }[sev] ?? "border-slate-200 bg-white text-slate-600";
}

function confidenceColor(confidence: number): string {
  if (confidence >= 75) return "text-emerald-600";
  if (confidence >= 45) return "text-amber-600";
  return "text-rose-600";
}

function moduleLabel(module: string): string {
  return {
    "hunting": "狩猎",
    "c2": "C2",
    "apt": "APT",
    "industrial": "工控",
    "vehicle": "车机",
    "usb": "USB",
    "object": "对象",
    "misc": "MISC",
    "stream": "流",
  }[module] ?? module;
}
