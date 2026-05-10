import { AnalysisBadge } from "../../components/analysis/AnalysisPrimitives";

export interface ThreatHuntingConfigPanelProps {
  backendConnected: boolean;
  configBusy: boolean;
  huntBusy: boolean;
  prefixText: string;
  statusText: string;
  yaraBin: string;
  yaraEnabled: boolean;
  yaraRules: string;
  yaraTimeoutMs: number;
  onApplyConfigAndRun: () => void | Promise<void>;
  onLoadConfig: () => void | Promise<void>;
  onPrefixTextChange: (value: string) => void;
  onRunWithoutSave: () => void | Promise<void>;
  onYaraBinChange: (value: string) => void;
  onYaraEnabledChange: (value: boolean) => void;
  onYaraRulesChange: (value: string) => void;
  onYaraTimeoutMsChange: (value: number) => void;
}

export function ThreatHuntingConfigPanel({
  backendConnected,
  configBusy,
  huntBusy,
  prefixText,
  statusText,
  yaraBin,
  yaraEnabled,
  yaraRules,
  yaraTimeoutMs,
  onApplyConfigAndRun,
  onLoadConfig,
  onPrefixTextChange,
  onRunWithoutSave,
  onYaraBinChange,
  onYaraEnabledChange,
  onYaraRulesChange,
  onYaraTimeoutMsChange,
}: ThreatHuntingConfigPanelProps) {
  return (
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
            <input
              type="checkbox"
              checked={yaraEnabled}
              onChange={(event) => onYaraEnabledChange(event.target.checked)}
            />
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
          <span className="truncate text-xs text-slate-500">
            {backendConnected ? "支持边调规则边重跑，适合做快速验证。" : "后端未连接"}
          </span>
        </div>
      </div>
    </div>
  );
}
