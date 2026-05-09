import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { APTEvidenceRecord } from "../../core/types";
import { confidenceLabelText, fromAPTEvidence } from "../evidence/evidenceSchema";
import { EvidenceActions } from "../../misc/EvidenceActions";
import type { APTDisplayProfile } from "./actorRegistry";

export type EvidenceSourceTab = "all" | "c2" | "delivery" | "hunting" | "credential";

export function EvidenceSourceTabs({
  tabs,
  active,
  onChange,
}: {
  tabs: Array<{ id: EvidenceSourceTab; label: string; count: number }>;
  active: EvidenceSourceTab;
  onChange: (tab: EvidenceSourceTab) => void;
}) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={cn(
            "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition",
            active === tab.id
              ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm"
              : "border-slate-200 bg-white text-slate-600 hover:border-indigo-100 hover:bg-indigo-50/50",
          )}
        >
          <span>{tab.label}</span>
          <span className="rounded-full bg-white/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">{tab.count}</span>
        </button>
      ))}
    </div>
  );
}

export function EvidenceTable({ profile, evidence }: { profile?: APTDisplayProfile; evidence: APTEvidenceRecord[] }) {
  if (!evidence.length) {
    return (
      <EmptyState className="py-8">
        {profile?.frameworkOnly
          ? `${profile.name} 当前为${profile.registry.statusLabel}画像，不参与本轮评分；请补充样本、投递链、C2 和对象证据后再进入归因复核。`
          : "暂无 APT 归因证据。当前抓包未形成该组织候选；后续由 C2 样本分析、对象提取、威胁狩猎和样本解析模块共同填充。"}
      </EmptyState>
    );
  }
  return (
    <AnalysisDataTable
      data={evidence}
      rowKey={(item, index) => `${item.packetId}-${item.actorId}-${index}`}
      maxHeightClassName="max-h-[460px]"
      tableClassName="min-w-[980px]"
      rowClassName="hover:bg-indigo-50/20"
      columns={[
        {
          key: "actor",
          header: "Actor / Type",
          widthClassName: "w-[210px]",
          cellClassName: "space-y-1",
          render: (item, index) => {
            const normalized = fromAPTEvidence(item, index);
            return (
              <>
                <div className="font-semibold text-slate-800">{item.actorName || "--"}</div>
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-slate-500">
                  <span>
                    {normalized.sourceModule || "--"} · {normalized.sourceType || "--"}
                  </span>
                  <span className={cn("rounded-full border px-2 py-0.5 font-sans text-[10px] font-semibold", confidenceToneClass(normalized.confidenceLabel))}>
                    {confidenceLabelText(normalized.confidenceLabel)}
                    {normalized.confidence !== undefined ? ` ${normalized.confidence}` : ""}
                  </span>
                </div>
              </>
            );
          },
        },
        {
          key: "evidence",
          header: "Evidence",
          cellClassName: "space-y-1",
          render: (item) => (
            <>
              <div className="text-slate-700">{item.summary}</div>
              <div className="font-mono text-[11px] text-slate-500">{item.evidenceValue || item.evidence || "--"}</div>
            </>
          ),
        },
        {
          key: "network",
          header: "Network",
          widthClassName: "w-[220px]",
          cellClassName: "space-y-1 font-mono text-[11px] text-slate-500",
          render: (item) => (
            <>
              <div>
                {item.source || "--"} → {item.destination || "--"}
              </div>
              <div>
                {item.host || ""}
                {item.uri || ""}
              </div>
            </>
          ),
        },
        {
          key: "traits",
          header: "Traits",
          widthClassName: "w-[260px]",
          render: (item, index) => {
            const normalized = fromAPTEvidence(item, index);
            return (
              <div className="space-y-2">
                <TagLine values={normalized.tags.length > 0 ? normalized.tags : [item.sampleFamily ?? "", item.campaignStage ?? ""].filter(Boolean)} />
                {normalized.caveats.length > 0 ? <CaveatLine values={normalized.caveats} /> : null}
              </div>
            );
          },
        },
        {
          key: "actions",
          header: "Actions",
          widthClassName: "w-[140px]",
          render: (item) => <EvidenceActions packetId={item.packetId} preferredProtocol={protocolForEvidence(item.family)} />,
        },
      ]}
    />
  );
}

export function buildEvidenceSourceTabs(evidence: APTEvidenceRecord[]): Array<{ id: EvidenceSourceTab; label: string; count: number }> {
  return [
    { id: "all", label: "全部证据", count: evidence.length },
    { id: "c2", label: "C2 Evidence", count: evidence.filter((item) => evidenceMatchesTab(item, "c2")).length },
    { id: "delivery", label: "Delivery / Object", count: evidence.filter((item) => evidenceMatchesTab(item, "delivery")).length },
    { id: "hunting", label: "Threat Hunting", count: evidence.filter((item) => evidenceMatchesTab(item, "hunting")).length },
    { id: "credential", label: "Credential / Auth", count: evidence.filter((item) => evidenceMatchesTab(item, "credential")).length },
  ];
}

export function evidenceMatchesTab(item: APTEvidenceRecord, tab: EvidenceSourceTab) {
  if (tab === "all") return true;
  const source = String(item.sourceModule ?? "").toLowerCase();
  const family = String(item.family ?? "").toLowerCase();
  const campaignStage = String(item.campaignStage ?? "").toLowerCase();
  const evidenceType = String(item.evidenceType ?? "").toLowerCase();
  const tags = [...(item.tags ?? []), ...(item.infrastructureHints ?? []), ...(item.ttpTags ?? []), ...(item.transportTraits ?? [])]
    .join(" ")
    .toLowerCase();
  if (tab === "c2") {
    return source.includes("c2") || family === "cs" || family === "vshell";
  }
  if (tab === "delivery") {
    return campaignStage.includes("deliver") || campaignStage.includes("download") || tags.includes("hfs") || tags.includes("delivery");
  }
  if (tab === "hunting") {
    return source.includes("hunting") || tags.includes("yara") || tags.includes("threat");
  }
  if (tab === "credential") {
    return source.includes("credential") || source.includes("auth") || evidenceType.includes("login") || evidenceType.includes("ntlm") || tags.includes("credential");
  }
  return true;
}

function confidenceToneClass(label: ReturnType<typeof fromAPTEvidence>["confidenceLabel"]) {
  return {
    high: "border-emerald-200 bg-emerald-50 text-emerald-700",
    medium: "border-amber-200 bg-amber-50 text-amber-700",
    low: "border-rose-200 bg-rose-50 text-rose-700",
    unknown: "border-slate-200 bg-slate-50 text-slate-600",
  }[label];
}

function TagLine({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-[11px] text-slate-400">--</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600">
          {value}
        </span>
      ))}
    </div>
  );
}

function CaveatLine({ values }: { values: string[] }) {
  return (
    <div className="space-y-1">
      {values.slice(0, 2).map((value) => (
        <div key={value} className="rounded-xl border border-amber-100 bg-amber-50/50 px-2 py-1 text-[10px] leading-4 text-amber-700">
          {value}
        </div>
      ))}
    </div>
  );
}

function protocolForEvidence(family?: string): "HTTP" | "TCP" | "UDP" {
  if (String(family ?? "").toLowerCase().includes("dns")) return "UDP";
  return "HTTP";
}
