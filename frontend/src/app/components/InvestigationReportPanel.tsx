import type { InvestigationReport, InvestigationReportItem } from "../core/types";
import { EvidenceActions } from "../misc/EvidenceActions";

interface InvestigationReportPanelProps {
  title?: string;
  report?: InvestigationReport;
  preferredProtocol?: "HTTP" | "TCP" | "UDP";
  className?: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-rose-300 bg-rose-50 text-rose-700",
  high: "border-amber-300 bg-amber-50 text-amber-700",
  medium: "border-sky-300 bg-sky-50 text-sky-700",
  low: "border-slate-300 bg-slate-50 text-slate-700",
  info: "border-emerald-300 bg-emerald-50 text-emerald-700",
};

export function InvestigationReportPanel({
  title = "结构化调查报告",
  report,
  preferredProtocol,
  className = "",
}: InvestigationReportPanelProps) {
  if (!report) {
    return null;
  }
  const hasContent =
    report.summary.length > 0 ||
    report.evidence.length > 0 ||
    report.details.length > 0 ||
    report.recommendations.length > 0;
  if (!hasContent) {
    return null;
  }

  return (
    <section className={`rounded-2xl border border-slate-200 bg-white/90 p-5 shadow-sm ${className}`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">report schema</div>
          <h3 className="mt-1 text-base font-semibold text-slate-800">{title}</h3>
        </div>
        <div className="text-[11px] text-slate-500">摘要 / 证据 / 明细 / 建议</div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ReportSection title="摘要" items={report.summary} preferredProtocol={preferredProtocol} />
        <ReportSection title="证据" items={report.evidence} preferredProtocol={preferredProtocol} />
        <ReportSection title="明细" items={report.details} preferredProtocol={preferredProtocol} />
        <RecommendationSection items={report.recommendations} />
      </div>
    </section>
  );
}

function ReportSection({
  title,
  items,
  preferredProtocol,
}: {
  title: string;
  items: InvestigationReportItem[];
  preferredProtocol?: "HTTP" | "TCP" | "UDP";
}) {
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
      <div className="mb-3 text-sm font-semibold text-slate-800">{title}</div>
      {items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-3 text-xs text-slate-500">
          当前分段暂无条目。
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item, index) => (
            <div
              key={`${title}-${item.title}-${item.packetId ?? item.streamId ?? index}`}
              className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-slate-800">{item.title}</div>
                  {item.summary && <div className="mt-1 text-xs leading-5 text-slate-600">{item.summary}</div>}
                </div>
                {item.severity && (
                  <span
                    className={`inline-flex rounded-full border px-2 py-1 text-[11px] font-semibold ${SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.info}`}
                  >
                    {item.severity}
                  </span>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                {item.packetId ? <span>packet #{item.packetId}</span> : null}
                {item.streamId ? <span>stream #{item.streamId}</span> : null}
                {item.tags?.map((tag) => (
                  <span
                    key={tag}
                    className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] text-slate-600"
                  >
                    {tag}
                  </span>
                ))}
              </div>
              {item.packetId ? (
                <EvidenceActions className="mt-3" packetId={item.packetId} preferredProtocol={preferredProtocol} />
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RecommendationSection({ items }: { items: string[] }) {
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
      <div className="mb-3 text-sm font-semibold text-slate-800">建议</div>
      {items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-3 text-xs text-slate-500">
          当前暂无额外建议。
        </div>
      ) : (
        <div className="space-y-2">
          {items.map((item, index) => (
            <div
              key={`${index}-${item}`}
              className="rounded-lg border border-emerald-100 bg-white px-3 py-3 text-xs leading-5 text-slate-700 shadow-sm"
            >
              {item}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
