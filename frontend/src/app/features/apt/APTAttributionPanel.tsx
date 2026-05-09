import { EmptyState } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { APTEvidenceRecord, APTScoreFactor } from "../../core/types";
import type { APTDisplayProfile } from "./actorRegistry";

export function NotesPanel({ notes, emptyText }: { notes: string[]; emptyText: string }) {
  if (!notes.length) {
    return <EmptyState>{emptyText}</EmptyState>;
  }
  return (
    <div className="space-y-2">
      {notes.map((note, index) => (
        <div
          key={`${note}-${index}`}
          className="rounded-2xl border border-indigo-100 bg-indigo-50/60 px-3 py-2 text-xs leading-5 text-indigo-800"
        >
          {note}
        </div>
      ))}
    </div>
  );
}

export function AttributionExplainer({
  profile,
  evidence,
}: {
  profile?: APTDisplayProfile;
  evidence: APTEvidenceRecord[];
}) {
  if (!profile) {
    return <EmptyState>暂无活跃 actor profile，无法生成归因解释。</EmptyState>;
  }

  const profileFactors = profile.frameworkOnly ? [] : (profile.scoreFactors ?? []);
  const hasStructuredFactors = profileFactors.length > 0;
  const supportingFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight >= 5);
  const weakFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight < 5);
  const negativeFactors = profileFactors.filter((factor) => factor.direction === "negative");
  const missingFactors = profileFactors.filter((factor) => factor.direction === "missing");
  const supporting = hasStructuredFactors ? supportingFactors : evidence.filter((e) => (e.confidence ?? 0) >= 60);
  const weak = hasStructuredFactors
    ? weakFactors
    : evidence.filter((e) => (e.confidence ?? 0) >= 30 && (e.confidence ?? 0) < 60);
  const missing = profile.frameworkOnly
    ? profile.registry.evidenceNeeds.map((summary) => ({ name: summary, summary }))
    : hasStructuredFactors
      ? missingFactors.map(formatAPTScoreFactor)
      : buildMissingEvidence(profile, evidence).map((summary) => ({ name: summary, summary }));
  const caveatCount = profile.frameworkOnly ? profile.registry.caveats.length : negativeFactors.length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <div className="rounded-2xl border border-emerald-100 bg-emerald-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-600">
            Supporting Evidence
          </div>
          <div className="mt-1 text-lg font-semibold text-emerald-900">{supporting.length}</div>
          <div className="mt-1 text-[11px] text-emerald-700">
            {hasStructuredFactors ? "结构化正向评分因子" : "置信度 ≥ 60 的正向证据"}
          </div>
        </div>
        <div className="rounded-2xl border border-amber-100 bg-amber-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-600">Weak Observations</div>
          <div className="mt-1 text-lg font-semibold text-amber-900">{weak.length}</div>
          <div className="mt-1 text-[11px] text-amber-700">中弱权重或弱观察因子</div>
        </div>
        <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">Missing Evidence</div>
          <div className="mt-1 text-lg font-semibold text-slate-900">{missing.length}</div>
          <div className="mt-1 text-[11px] text-slate-700">基于真实证据动态判断</div>
        </div>
        <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-600">
            Suppression / Caveat
          </div>
          <div className="mt-1 text-lg font-semibold text-rose-900">{caveatCount}</div>
          <div className="mt-1 text-[11px] text-rose-700">
            {profile.frameworkOnly ? "registry caveat 与人工复核提示" : "负向抑制或归因注意事项"}
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-indigo-100 bg-indigo-50/30 px-4 py-3">
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-indigo-600">
          Confidence Rationale
        </div>
        <div className="mt-2 text-xs leading-5 text-indigo-800">
          {profile.frameworkOnly ? (
            <span>
              {profile.name} 当前为 <strong>{profile.registry.statusLabel}</strong>，只展示画像、证据需求和
              caveat，不参与本轮强归因评分；需要补充样本、投递链、C2 与对象证据后再进入评分链路。
            </span>
          ) : profile.confidence && profile.confidence > 0 ? (
            <span>
              当前置信度 <strong>{profile.confidence}%</strong>，基于 {supporting.length} 个正向因子、{weak.length}{" "}
              个弱观察、{negativeFactors.length} 个 caveat 与 {missing.length} 个缺失项。
            </span>
          ) : (
            <span>当前置信度待计算：需要更多 C2 / Threat Hunting / Object 证据流入。</span>
          )}
        </div>
      </div>

      {hasStructuredFactors &&
        (supportingFactors.length > 0 || weakFactors.length > 0 || negativeFactors.length > 0) && (
          <div className="grid gap-3 lg:grid-cols-3">
            <ScoreFactorColumn title="Supporting Evidence" factors={supportingFactors} tone="emerald" />
            <ScoreFactorColumn title="Weak Observations" factors={weakFactors} tone="amber" />
            <ScoreFactorColumn title="Suppression / Caveat" factors={negativeFactors} tone="rose" />
          </div>
        )}

      {missing.length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
            Missing Evidence Details
          </div>
          <div className="mt-2 space-y-1">
            {missing.map((item) => (
              <div key={item.name} className="flex items-start gap-2 text-[11px] text-slate-600">
                <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-slate-400" />
                <span>{item.summary || item.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {profile.frameworkOnly && profile.registry.caveats.length > 0 && (
        <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-600">Framework Caveat</div>
          <div className="mt-2 space-y-1">
            {profile.registry.caveats.map((item) => (
              <div key={item} className="flex items-start gap-2 text-[11px] leading-5 text-rose-700">
                <span className="mt-1 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-rose-400" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ScoreFactorColumn({
  title,
  factors,
  tone,
}: {
  title: string;
  factors: APTScoreFactor[];
  tone: "emerald" | "amber" | "rose";
}) {
  const toneClass = {
    emerald: "border-emerald-100 bg-emerald-50/40 text-emerald-800",
    amber: "border-amber-100 bg-amber-50/40 text-amber-800",
    rose: "border-rose-100 bg-rose-50/40 text-rose-800",
  }[tone];
  return (
    <div className={cn("rounded-2xl border px-4 py-3", toneClass)}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] opacity-80">{title}</div>
      <div className="mt-2 space-y-2">
        {factors.length === 0 ? (
          <div className="text-[11px] opacity-70">--</div>
        ) : (
          factors.map((factor) => (
            <div key={`${factor.sourceModule}-${factor.name}`} className="text-[11px] leading-5">
              <div className="font-semibold">
                {factor.name}{" "}
                <span className="font-mono opacity-70">
                  {factor.weight > 0 ? "+" : ""}
                  {factor.weight}
                </span>
              </div>
              <div className="opacity-80">{factor.summary || factor.sourceModule || "structured factor"}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function buildMissingEvidence(profile: APTDisplayProfile, evidence: APTEvidenceRecord[]): string[] {
  const missing: string[] = [];
  const joinedEvidence = evidence
    .map((item) =>
      [
        item.sourceModule,
        item.evidenceType,
        item.sampleFamily,
        item.campaignStage,
        ...(item.tags ?? []),
        ...(item.transportTraits ?? []),
        ...(item.infrastructureHints ?? []),
        ...(item.ttpTags ?? []),
        ...(item.scoreFactors ?? []).map((factor) => factor.name),
      ]
        .join(" ")
        .toLowerCase(),
    )
    .join(" ");
  const profileBuckets = [
    ...(profile.sampleFamilies ?? []).map((b) => b.label),
    ...(profile.campaignStages ?? []).map((b) => b.label),
    ...(profile.transportTraits ?? []).map((b) => b.label),
    ...(profile.infrastructureHints ?? []).map((b) => b.label),
  ]
    .join(" ")
    .toLowerCase();
  const corpus = `${joinedEvidence} ${profileBuckets}`;

  if (!/valleyrat|winos|gh0st/.test(corpus)) {
    missing.push("样本家族证据：缺失 ValleyRAT / Winos 4.0 / Gh0st 任一命中");
  }
  if (!/delivery|downloader|hfs-download-chain|rejetto/.test(corpus)) {
    missing.push("投递链证据：缺失 delivery / downloader / HFS 下载链");
  }
  if (!evidence.some((item) => item.sourceModule === "c2-analysis")) {
    missing.push("C2 通信证据：缺失 C2 样本分析来源证据");
  }
  if (!evidence.some((item) => item.sourceModule === "threat-hunting")) {
    missing.push("威胁狩猎证据：缺失 YARA / rule match / anomaly 来源证据");
  }
  if (!evidence.some((item) => item.sourceModule === "object-export")) {
    missing.push("对象 / 文件证据：缺失 Object Export 来源证据");
  }
  const allFactors = evidence.flatMap((item) => item.scoreFactors ?? []);
  if (allFactors.length > 0 && allFactors.every((factor) => factor.name === "silverfox-case-port-weak")) {
    missing.push("归因 caveat：当前仅有端口类弱观察，不能强归因");
  }
  return missing;
}

function formatAPTScoreFactor(factor: APTScoreFactor): { name: string; summary?: string } {
  const prefix = factor.weight ? `${factor.name} (${factor.weight > 0 ? "+" : ""}${factor.weight})` : factor.name;
  return { name: factor.name, summary: factor.summary ? `${prefix}: ${factor.summary}` : prefix };
}
