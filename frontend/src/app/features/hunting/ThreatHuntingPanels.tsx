import { type ReactNode } from "react";
import { BarChart2, CheckCircle2, Crosshair, Flag, FolderCog, Shield } from "lucide-react";
import { AnalysisBadge, AnalysisDataTable, type AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import { Progress } from "../../components/ui/progress";
import { ScrollArea } from "../../components/ui/scroll-area";
import { cn } from "../../components/ui/utils";
import type { ThreatHit } from "../../core/types";

export interface ThreatHuntingStats {
  ctf: number;
  owasp: number;
  anomaly: number;
}

export interface ThreatHuntingProgressView {
  title: string;
  detail: string;
  value: number;
  phaseLabel: string;
  current: number;
  total: number;
}

interface ThreatHuntingCategoryPanelProps {
  stats: ThreatHuntingStats;
}

interface ThreatHuntingProgressPanelProps {
  progress: ThreatHuntingProgressView;
}

interface ThreatHuntingWorkbenchPanelProps {
  actionBusy: string;
  backendConnected: boolean;
  configBusy: boolean;
  hits: ThreatHit[];
  huntBusy: boolean;
  prefixText: string;
  selected: ThreatHit | null;
  selectedHit: number | null;
  statusText: string;
  yaraBin: string;
  yaraEnabled: boolean;
  yaraRules: string;
  yaraTimeoutMs: number;
  onApplyConfigAndRun: () => void | Promise<void>;
  onJumpToPacket: (packetId: number) => void | Promise<void>;
  onLoadConfig: () => void | Promise<void>;
  onOpenRelatedStream: (packetId: number) => void | Promise<void>;
  onPrefixTextChange: (value: string) => void;
  onRunWithoutSave: () => void | Promise<void>;
  onSelectHit: (id: number) => void;
  onYaraBinChange: (value: string) => void;
  onYaraEnabledChange: (value: boolean) => void;
  onYaraRulesChange: (value: string) => void;
  onYaraTimeoutMsChange: (value: number) => void;
}

export function ThreatHuntingProgressPanel({ progress }: ThreatHuntingProgressPanelProps) {
  return (
    <div className="mb-4 rounded-[24px] border border-blue-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.96),rgba(255,255,255,0.98))] p-4 shadow-[0_20px_48px_-32px_rgba(37,99,235,0.35)]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">{progress.title}</div>
          <div className="mt-1 text-xs leading-5 text-slate-500">{progress.detail}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <AnalysisBadge tone="blue" className="bg-white/90 px-2.5 py-1">
            {progress.phaseLabel}
          </AnalysisBadge>
          <span className="text-[11px] font-medium text-slate-500">{Math.round(progress.value)}%</span>
        </div>
      </div>
      <div className="mt-3">
        <Progress value={progress.value} className="h-2.5 bg-blue-100 [&_[data-slot=progress-indicator]]:bg-blue-600" />
      </div>
      <div className="mt-2 text-[11px] text-slate-500">
        {progress.total > 0
          ? `${progress.current.toLocaleString()} / ${progress.total.toLocaleString()}`
          : `${progress.current.toLocaleString()}`}
      </div>
    </div>
  );
}

export function ThreatHuntingCategoryPanel({ stats }: ThreatHuntingCategoryPanelProps) {
  return (
    <div className="flex min-h-0 flex-col overflow-hidden rounded-[28px] border border-slate-200 bg-white/92 shadow-[0_24px_80px_-48px_rgba(15,23,42,0.45)] backdrop-blur">
      <div className="border-b border-slate-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.9),rgba(255,255,255,0.98))] px-4 py-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
          <FolderCog className="h-4 w-4 text-blue-600" />
          规则分类
        </div>
        <div className="mt-1 text-xs leading-5 text-slate-500">
          这里把命中结果按常见分析语义收在一起看，左侧能快速判断当前更偏 CTF、OWASP 还是异常流量。
        </div>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-3 p-3">
          <CategoryCard title="CTF Flags" count={stats.ctf} icon={<Flag className="h-4 w-4 text-blue-600" />} accent="blue" />
          <CategoryCard title="OWASP" count={stats.owasp} icon={<Shield className="h-4 w-4 text-rose-600" />} accent="rose" />
          <CategoryCard title="异常统计" count={stats.anomaly} icon={<BarChart2 className="h-4 w-4 text-amber-600" />} accent="amber" />
        </div>
      </ScrollArea>
    </div>
  );
}

export function ThreatHuntingWorkbenchPanel({
  actionBusy,
  backendConnected,
  configBusy,
  hits,
  huntBusy,
  prefixText,
  selected,
  selectedHit,
  statusText,
  yaraBin,
  yaraEnabled,
  yaraRules,
  yaraTimeoutMs,
  onApplyConfigAndRun,
  onJumpToPacket,
  onLoadConfig,
  onOpenRelatedStream,
  onPrefixTextChange,
  onRunWithoutSave,
  onSelectHit,
  onYaraBinChange,
  onYaraEnabledChange,
  onYaraRulesChange,
  onYaraTimeoutMsChange,
}: ThreatHuntingWorkbenchPanelProps) {
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-[28px] border border-slate-200 bg-white/92 shadow-[0_24px_80px_-48px_rgba(15,23,42,0.45)] backdrop-blur">
      <div className="shrink-0 border-b border-slate-200 bg-[linear-gradient(180deg,rgba(248,250,252,0.88),rgba(255,255,255,0.98))] p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-slate-900">运行参数与命中结果</div>
            <div className="mt-1 text-xs text-slate-500">
              YARA 相关路径更推荐在右侧设置栏统一维护；这里保留的是当前狩猎任务的快速参数入口。
            </div>
          </div>
          <AnalysisBadge tone={backendConnected ? "blue" : "slate"} className="px-2.5 py-1">
            {statusText || (backendConnected ? "可以直接重跑当前狩猎任务" : "后端未连接")}
          </AnalysisBadge>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">Flag Prefixes（逗号分隔）</span>
            <input
              value={prefixText}
              onChange={(event) => onPrefixTextChange(event.target.value)}
              className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
              placeholder="flag{,ctf{"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">YARA 可执行（留空自动探测）</span>
            <input
              value={yaraBin}
              onChange={(event) => onYaraBinChange(event.target.value)}
              className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
              placeholder="C:/tools/yara64.exe"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">规则文件（留空默认）</span>
            <input
              value={yaraRules}
              onChange={(event) => onYaraRulesChange(event.target.value)}
              className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
              placeholder="C:/rules/default.yar"
            />
          </label>

          <div className="flex items-end gap-2">
            <label className="flex min-w-0 flex-1 flex-col gap-1 text-xs">
              <span className="text-muted-foreground">超时(ms)</span>
              <input
                value={yaraTimeoutMs}
                onChange={(event) => onYaraTimeoutMsChange(Number(event.target.value) || 0)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
                type="number"
                min={1000}
                step={1000}
              />
            </label>
            <label className="mb-1 inline-flex items-center gap-1 text-xs text-foreground">
              <input type="checkbox" checked={yaraEnabled} onChange={(event) => onYaraEnabledChange(event.target.checked)} />
              启用YARA
            </label>
          </div>

          <div className="col-span-1 flex flex-wrap items-center gap-2 md:col-span-2 xl:col-span-4">
            <button
              onClick={() => void onLoadConfig()}
              disabled={!backendConnected || configBusy || huntBusy}
              className="h-9 rounded-xl border border-slate-200 bg-white px-3.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
            >
              重新读取参数
            </button>
            <button
              onClick={() => void onApplyConfigAndRun()}
              disabled={!backendConnected || configBusy || huntBusy}
              className="h-9 rounded-xl border border-blue-200 bg-blue-50 px-3.5 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              保存并重跑狩猎
            </button>
            <button
              onClick={() => void onRunWithoutSave()}
              disabled={!backendConnected || configBusy || huntBusy}
              className="h-9 rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              仅重跑（不保存）
            </button>
            <span className="truncate text-xs text-slate-500">{backendConnected ? "支持边调规则边重跑，适合做快速验证。" : "后端未连接"}</span>
          </div>
        </div>
      </div>

      <div className="flex shrink-0 items-center justify-between border-b border-slate-200 bg-slate-50/80 px-4 py-3">
        <span className="flex items-center gap-2 text-sm font-medium text-slate-900">
          <CheckCircle2 className="h-4 w-4 text-emerald-600" /> 命中结果 (共 {hits.length} 条)
        </span>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        <AnalysisDataTable
          columns={[
            {
              key: "packet",
              header: "No.",
              widthClassName: "w-16",
              headerClassName: "border-r border-slate-200",
              cellClassName: "border-r border-slate-200/80 text-slate-500",
              render: (hit) => hit.packetId,
            },
            {
              key: "category",
              header: "分类",
              widthClassName: "w-28",
              headerClassName: "border-r border-slate-200",
              cellClassName: "border-r border-slate-200/80",
              render: (hit) => hit.category,
            },
            {
              key: "rule",
              header: "规则",
              widthClassName: "w-40",
              headerClassName: "border-r border-slate-200",
              cellClassName: "border-r border-slate-200/80 font-medium text-rose-600",
              render: (hit) => hit.rule,
            },
            {
              key: "level",
              header: "等级",
              widthClassName: "w-24",
              headerClassName: "border-r border-slate-200",
              cellClassName: "border-r border-slate-200/80",
              render: (hit) => <AnalysisBadge tone={toneForThreatLevel(hit.level)}>{hit.level}</AnalysisBadge>,
            },
            {
              key: "preview",
              header: "预览",
              cellClassName: "truncate font-mono text-slate-500",
              render: (hit) => hit.preview,
            },
          ]}
          data={hits}
          rowKey={(hit) => hit.id}
          rowClassName={(hit) =>
            selectedHit === hit.id
              ? "border-l-2 border-l-rose-500 bg-rose-50/80 text-rose-700 hover:bg-rose-50"
              : "text-foreground"
          }
          onRowClick={(hit) => onSelectHit(hit.id)}
          emptyText="暂无威胁命中"
          maxHeightClassName="max-h-none"
          wrapperClassName="min-h-0 flex-1 rounded-none border-0 bg-transparent"
          tableClassName="cursor-default whitespace-nowrap"
          headerClassName="z-10 bg-white/95 backdrop-blur-sm"
        />

        {selected && (
          <div className="flex h-56 min-h-0 shrink-0 flex-col border-t border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] shadow-[0_-10px_30px_-24px_rgba(15,23,42,0.35)]">
            <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/80 px-4 py-2 text-xs font-semibold text-slate-900">
              <Crosshair className="h-4 w-4 text-blue-600" /> 详细特征提取
            </div>
            <ScrollArea className="min-h-0 flex-1">
              <div className="p-4 font-mono text-sm leading-relaxed text-foreground">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => void onJumpToPacket(selected.packetId)}
                    disabled={actionBusy.length > 0}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {actionBusy === `packet:${selected.packetId}` ? "定位中" : `定位到包 #${selected.packetId}`}
                  </button>
                  <button
                    onClick={() => void onOpenRelatedStream(selected.packetId)}
                    disabled={actionBusy.length > 0}
                    className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {actionBusy === `stream:${selected.packetId}` ? "打开中" : "打开关联流"}
                  </button>
                </div>
                <div className="mb-1 font-sans text-xs text-slate-500">命中字符串:</div>
                <div className="break-all rounded-2xl border border-rose-200 bg-rose-50/80 p-3 text-rose-700 select-all">{selected.match}</div>
              </div>
            </ScrollArea>
          </div>
        )}
      </div>
    </div>
  );
}

function CategoryCard({ title, count, icon, accent }: { title: string; count: number; icon: ReactNode; accent: "blue" | "rose" | "amber" }) {
  const accentClass =
    accent === "blue" ? "border-blue-200 bg-blue-50/70" : accent === "rose" ? "border-rose-200 bg-rose-50/70" : "border-amber-200 bg-amber-50/70";

  return (
    <div className={cn("rounded-2xl border px-3 py-3", accentClass)}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-800">
          {icon}
          {title}
        </div>
        <AnalysisBadge tone={accent} className="border-white/70 bg-white/80 px-2 text-xs text-slate-600 shadow-sm">
          {count}
        </AnalysisBadge>
      </div>
    </div>
  );
}

function toneForThreatLevel(level: string): AnalysisTone {
  switch (level) {
    case "critical":
    case "high":
      return "rose";
    case "medium":
      return "amber";
    default:
      return "slate";
  }
}
