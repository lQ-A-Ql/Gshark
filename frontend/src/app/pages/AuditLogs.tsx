import { ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import type { AuditEntry } from "../core/types";
import { bridge } from "../integrations/wailsBridge";

type RiskFilter = "all" | "high" | "medium" | "low";

function riskClassName(risk: string) {
  switch (risk) {
    case "high":
      return "border-rose-200 bg-rose-50 text-rose-700";
    case "medium":
      return "border-amber-200 bg-amber-50 text-amber-700";
    default:
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
}

function formatAuditTime(value: string) {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString("zh-CN", { hour12: false });
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");

  const loadLogs = async (silent = false) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const items = await bridge.listAuditLogs();
      setLogs(items);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "审计日志加载失败");
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    void loadLogs();

    const timer = window.setInterval(() => {
      void loadLogs(true);
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const filteredLogs = useMemo(() => {
    const items = riskFilter === "all" ? logs : logs.filter((entry) => entry.risk === riskFilter);
    return [...items].reverse();
  }, [logs, riskFilter]);

  const counts = useMemo(() => {
    return logs.reduce(
      (acc, entry) => {
        if (entry.risk === "high") acc.high += 1;
        else if (entry.risk === "medium") acc.medium += 1;
        else acc.low += 1;
        return acc;
      },
      { high: 0, medium: 0, low: 0 },
    );
  }, [logs]);

  return (
    <PageShell>
      <AnalysisHero
        icon={<ShieldAlert className="h-5 w-5" />}
        title="本地审计日志"
        subtitle="SECURITY AUDIT"
        description="统一回看高风险接口、TLS 配置、抓包控制和其他敏感操作的最近访问记录。"
        tags={["安全审计", "高风险接口", "TLS 配置", "抓包控制"]}
        tagsLabel="审计域"
        theme="blue"
        onRefresh={() => void loadLogs()}
      />

      <div className="flex flex-wrap gap-3">
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          高风险 {counts.high}
        </div>
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
          中风险 {counts.medium}
        </div>
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          低风险 {counts.low}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {(["all", "high", "medium", "low"] as const).map((risk) => (
          <button
            key={risk}
            className={`rounded-full border px-3 py-1.5 font-medium ${
              riskFilter === risk
                ? "border-blue-300 bg-blue-50 text-blue-700"
                : "border-border bg-background text-muted-foreground hover:bg-accent"
            }`}
            onClick={() => setRiskFilter(risk)}
          >
            {risk === "all" ? "全部" : risk}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto">
        {error && (
          <div className="mb-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        )}

        {filteredLogs.length === 0 ? (
          <div className="flex h-full min-h-[320px] items-center justify-center rounded-2xl border border-dashed border-border bg-card text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-blue-500" />
              {loading ? "正在加载审计日志..." : "当前没有符合筛选条件的审计记录"}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredLogs.map((entry, index) => (
              <div key={`${entry.time}-${entry.path}-${index}`} className="rounded-2xl border border-border bg-card p-4 shadow-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide ${riskClassName(entry.risk)}`}>
                    {entry.risk}
                  </span>
                  <span className="rounded-full border border-border bg-accent px-2.5 py-1 text-[11px] font-semibold text-muted-foreground">
                    {entry.method}
                  </span>
                  <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600">
                    {entry.status}
                  </span>
                  <span className="text-xs text-muted-foreground">{formatAuditTime(entry.time)}</span>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
                  <div className="font-semibold text-foreground">{entry.action}</div>
                  <div className="font-mono text-xs text-muted-foreground">{entry.path}</div>
                </div>

                <div className="mt-2 flex flex-wrap gap-4 text-xs text-muted-foreground">
                  <span>来源: {entry.origin || "direct"}</span>
                  <span>地址: {entry.remoteAddr || "-"}</span>
                  <span>鉴权: {entry.authenticated ? "passed" : "public"}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  );
}
