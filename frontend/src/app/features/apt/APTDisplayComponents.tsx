import { ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { AnalysisBadge } from "../../components/analysis/AnalysisPrimitives";
import { SurfacePanel } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { APTActorStatusTone, APTDisplayProfile } from "./actorRegistry";

export function ActorTab({
  profile,
  active,
  onClick,
}: {
  profile: APTDisplayProfile;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "gshark-tile px-4 py-3 text-left transition-all",
        active
          ? "border-indigo-200 bg-indigo-50/30 text-indigo-900"
          : "border-transparent bg-transparent text-slate-700 hover:border-indigo-100/35 hover:bg-indigo-50/20",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-semibold">{profile.name}</div>
          <div className="mt-1 truncate text-xs text-slate-500">{profile.aliases?.join(" / ") || "actor profile"}</div>
        </div>
        <AnalysisBadge tone={profile.registry.statusTone} className="shrink-0">
          {profile.registry.statusLabel}
        </AnalysisBadge>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
        <span className="gshark-diffuse-chip px-2 py-0.5 font-mono">
          {profile.frameworkOnly ? "不评分" : profile.evidenceCount}
        </span>
        {profile.frameworkOnly ? <span>需要人工补样本验证</span> : <span>证据计入当前评分</span>}
      </div>
    </button>
  );
}

export function RegistryTagSection({ profile }: { profile: APTDisplayProfile }) {
  const registry = profile.registry;
  return (
    <div className="grid gap-3 lg:grid-cols-3">
      <RegistryTagBlock title="Regions" values={registry.regions} />
      <RegistryTagBlock title="Families" values={registry.families} />
      <RegistryTagBlock title="TTP Tags" values={registry.ttpTags} />
    </div>
  );
}

export function ActorEvidenceNeeds({ profile }: { profile: APTDisplayProfile }) {
  return (
    <div className="space-y-3">
      <div className="gshark-soft-fill border-amber-100/70 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge label={profile.registry.statusLabel} tone={profile.registry.statusTone} />
          {profile.frameworkOnly && <StatusBadge label="不参与本轮评分" tone="rose" />}
        </div>
        <p className="mt-2 text-xs leading-5 text-amber-800">
          {profile.frameworkOnly
            ? "该画像当前只作为识别框架和证据清单展示，不会生成强归因分数。"
            : profile.evidenceCount > 0
              ? "该画像已接入真实证据流，仍需要结合缺失项和 caveat 人工复核。"
              : "检测能力已接入，但当前抓包没有形成候选证据。"}
        </p>
      </div>
      <ListCallout title="需要补充的证据类型" values={profile.registry.evidenceNeeds} tone="amber" />
      <ListCallout title="Suppression / Caveat" values={profile.registry.caveats} tone="rose" />
    </div>
  );
}

export function StatusBadge({ label, tone }: { label: string; tone: APTActorStatusTone }) {
  return (
    <AnalysisBadge tone={tone} className="px-2.5 py-1">
      {label}
    </AnalysisBadge>
  );
}

export function AptPanel({
  title,
  children,
  icon,
  className,
}: {
  title: string;
  children: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <SurfacePanel
      title={title}
      icon={icon ?? <ShieldAlert className="h-4 w-4 text-indigo-600" />}
      className={cn("gshark-tile", className)}
    >
      {children}
    </SurfacePanel>
  );
}

function RegistryTagBlock({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="gshark-soft-fill border-slate-100 px-3 py-2">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <TagLine values={values.length > 0 ? values : ["待补充"]} />
    </div>
  );
}

function ListCallout({ title, values, tone }: { title: string; values: string[]; tone: "amber" | "rose" }) {
  const toneClass =
    tone === "amber" ? "border-amber-100 bg-amber-50/50 text-amber-800" : "border-rose-100 bg-rose-50/50 text-rose-800";
  return (
    <div className={cn("gshark-tile px-4 py-3", toneClass)}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] opacity-80">{title}</div>
      <div className="mt-2 space-y-1">
        {values.length === 0 ? (
          <div className="text-[11px] opacity-70">暂无条目</div>
        ) : (
          values.map((value) => (
            <div key={value} className="flex items-start gap-2 text-[11px] leading-5">
              <span className="mt-1 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-60" />
              <span>{value}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function TagLine({ values }: { values: string[] }) {
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
