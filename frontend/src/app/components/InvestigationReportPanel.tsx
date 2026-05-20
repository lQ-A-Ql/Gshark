import type { InvestigationReport, InvestigationReportItem } from "../core/types";
import { EvidenceActions } from "../misc/EvidenceActions";

interface InvestigationReportPanelProps {
  title?: string;
  report?: InvestigationReport;
  preferredProtocol?: "HTTP" | "TCP" | "UDP";
  className?: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-rose-200/30 bg-rose-50/20 text-rose-700",
  high: "border-amber-200/30 bg-amber-50/20 text-amber-700",
  medium: "border-sky-200/30 bg-sky-50/20 text-sky-700",
  low: "border-slate-200/26 bg-slate-50/16 text-slate-700",
  info: "border-emerald-200/30 bg-emerald-50/20 text-emerald-700",
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
    <section className={`gshark-tile gshark-tile-strong gshark-diffuse-edge p-4 ${className}`}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">report schema</div>
          <h3 className="mt-1 text-base font-semibold text-slate-800">{title}</h3>
        </div>
        <div className="text-[11px] text-slate-500">摘要 / 证据 / 明细 / 建议</div>
      </div>

      <div className="grid gap-0 xl:grid-cols-2">
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
    <div className="gshark-tile bg-transparent p-3.5">
      <div className="mb-3 text-sm font-semibold text-slate-800">{title}</div>
      {items.length === 0 ? (
        <div className="px-3 py-3 text-xs text-slate-500">当前分段暂无条目。</div>
      ) : (
        <div className="space-y-3">
          {items.map((item, index) => (
            <div
              key={`${title}-${item.title}-${item.packetId ?? item.streamId ?? index}`}
              className="gshark-soft-fill p-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-slate-800">{item.title}</div>
                  {item.summary && <div className="mt-1 text-xs leading-5 text-slate-600">{item.summary}</div>}
                </div>
                {item.severity && (
                  <span
                    className={`inline-flex rounded-sm border px-2 py-1 text-[11px] font-semibold ${SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.info}`}
                  >
                    {item.severity}
                  </span>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                {item.ruleId ? (
                  <span className="gshark-diffuse-chip border-indigo-200/24 bg-indigo-50/18 px-2 py-0.5 font-mono text-[10px] text-indigo-700">
                    {item.ruleId}
                  </span>
                ) : null}
                {typeof item.confidence === "number" && item.confidence > 0 ? (
                  <span className="gshark-diffuse-chip border-emerald-200/24 bg-emerald-50/18 px-2 py-0.5 text-[10px] font-semibold text-emerald-700">
                    conf {item.confidence}%
                  </span>
                ) : null}
                {item.packetId ? <span>packet #{item.packetId}</span> : null}
                {item.streamId ? <span>stream #{item.streamId}</span> : null}
                {item.tags?.map((tag) => (
                  <span
                    key={tag}
                    className="gshark-diffuse-chip border-slate-200/18 bg-slate-50/12 px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] text-slate-600"
                  >
                    {tag}
                  </span>
                ))}
              </div>
              {item.reason ? <div className="mt-2 text-[11px] leading-5 text-slate-600">{item.reason}</div> : null}
              {item.caveats && item.caveats.length > 0 ? (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {item.caveats.map((caveat) => (
                    <span
                      key={caveat}
                      className="gshark-diffuse-chip border-amber-200/24 bg-amber-50/18 px-2 py-1 text-[10px] leading-4 text-amber-800"
                    >
                      {caveat}
                    </span>
                  ))}
                </div>
              ) : null}
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
    <div className="gshark-tile bg-transparent p-3.5">
      <div className="mb-3 text-sm font-semibold text-slate-800">建议</div>
      {items.length === 0 ? (
        <div className="px-3 py-3 text-xs text-slate-500">当前暂无额外建议。</div>
      ) : (
        <div className="space-y-2">
          {items.map((item, index) => (
            <div key={`${index}-${item}`} className="gshark-soft-fill px-3 py-3 text-xs leading-5 text-slate-700">
              {item}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
