import { useEffect, useMemo, useState, type ReactNode } from "react";
import { ShieldAlert, Crosshair, CheckCircle2, Flag, Shield, BarChart2, FolderCog, SearchCode, Sparkles } from "lucide-react";
import { useNavigate } from "react-router";
import { useSentinel } from "../state/SentinelContext";
import { cn } from "../components/ui/utils";
import { bridge } from "../integrations/wailsBridge";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { ScrollArea } from "../components/ui/scroll-area";
import { Progress } from "../components/ui/progress";

function levelColor(level: string) {
  if (level === "critical") return "text-rose-700 bg-rose-50 border-rose-200";
  if (level === "high") return "text-orange-700 bg-orange-50 border-orange-200";
  if (level === "medium") return "text-amber-700 bg-amber-50 border-amber-200";
  return "text-foreground bg-accent border-border";
}

export default function ThreatHunting() {
  const navigate = useNavigate();
  const { threatHits, backendConnected, locatePacketById, preparePacketStream, isThreatAnalysisLoading, threatAnalysisProgress } = useSentinel();
  const [hits, setHits] = useState(threatHits);
  const [selectedHit, setSelectedHit] = useState<number | null>(threatHits[0]?.id ?? null);
  const [prefixText, setPrefixText] = useState("flag{,ctf{");
  const [yaraEnabled, setYaraEnabled] = useState(true);
  const [yaraBin, setYaraBin] = useState("");
  const [yaraRules, setYaraRules] = useState("");
  const [yaraTimeoutMs, setYaraTimeoutMs] = useState(25000);
  const [configBusy, setConfigBusy] = useState(false);
  const [huntBusy, setHuntBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const [statusText, setStatusText] = useState("");

  const parsePrefixes = (value: string) =>
    value
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);

  const runHunt = async (prefixes: string[]) => {
    if (!backendConnected) return;
    setHuntBusy(true);
    try {
      const nextHits = await bridge.listThreatHits(prefixes);
      setHits(nextHits);
      setSelectedHit(nextHits[0]?.id ?? null);
      setStatusText(`狩猎完成: ${nextHits.length} 条命中`);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "狩猎执行失败");
    } finally {
      setHuntBusy(false);
    }
  };

  const loadConfig = async () => {
    if (!backendConnected) return;
    setConfigBusy(true);
    try {
      const cfg = await bridge.getHuntingRuntimeConfig();
      setPrefixText((cfg.prefixes.length > 0 ? cfg.prefixes : ["flag{", "ctf{"]).join(","));
      setYaraEnabled(cfg.yaraEnabled);
      setYaraBin(cfg.yaraBin);
      setYaraRules(cfg.yaraRules);
      setYaraTimeoutMs(cfg.yaraTimeoutMs > 0 ? cfg.yaraTimeoutMs : 25000);
      setStatusText("已加载狩猎运行参数");
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "加载狩猎参数失败");
    } finally {
      setConfigBusy(false);
    }
  };

  const applyConfigAndRun = async () => {
    if (!backendConnected) return;
    const prefixes = parsePrefixes(prefixText);
    if (prefixes.length === 0) {
      setStatusText("至少需要一个 Prefix（例如 flag{）");
      return;
    }

    setConfigBusy(true);
    try {
      const saved = await bridge.updateHuntingRuntimeConfig({
        prefixes,
        yaraEnabled,
        yaraBin: yaraBin.trim(),
        yaraRules: yaraRules.trim(),
        yaraTimeoutMs: Number.isFinite(yaraTimeoutMs) && yaraTimeoutMs > 0 ? Math.floor(yaraTimeoutMs) : 25000,
      });

      setPrefixText(saved.prefixes.join(","));
      setYaraEnabled(saved.yaraEnabled);
      setYaraBin(saved.yaraBin);
      setYaraRules(saved.yaraRules);
      setYaraTimeoutMs(saved.yaraTimeoutMs > 0 ? saved.yaraTimeoutMs : 25000);
      setStatusText("参数已保存，开始重跑狩猎...");
      await runHunt(saved.prefixes);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "保存参数失败");
    } finally {
      setConfigBusy(false);
    }
  };

  useEffect(() => {
    setHits(threatHits);
    setSelectedHit((prev) => prev ?? threatHits[0]?.id ?? null);
  }, [threatHits]);

  useEffect(() => {
    void loadConfig();
  }, [backendConnected]);

  const stats = useMemo(() => {
    const ctf = hits.filter((h) => h.category === "CTF").length;
    const owasp = hits.filter((h) => h.category === "OWASP").length;
    const anomaly = hits.filter((h) => h.category === "Anomaly").length;
    return { ctf, owasp, anomaly };
  }, [hits]);

  const threatProgress = useMemo(() => {
    if (threatAnalysisProgress.active) {
      return {
        title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
        detail: threatAnalysisProgress.label || "正在整理对象、重组流并执行 YARA 扫描。",
        value: Math.max(4, threatAnalysisProgress.percent || 4),
        phaseLabel: threatAnalysisProgress.phaseLabel || "处理中",
        current: threatAnalysisProgress.current,
        total: threatAnalysisProgress.total,
      };
    }
    if (huntBusy || isThreatAnalysisLoading) {
      return {
        title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
        detail: "正在准备威胁分析任务...",
        value: 12,
        phaseLabel: "准备",
        current: 0,
        total: 5,
      };
    }
    return null;
  }, [huntBusy, isThreatAnalysisLoading, threatAnalysisProgress]);

  const selected = hits.find((h) => h.id === selectedHit) ?? null;

  const jumpToPacket = async (packetId: number) => {
    setActionBusy(`packet:${packetId}`);
    try {
      await locatePacketById(packetId);
      navigate("/");
    } finally {
      setActionBusy("");
    }
  };

  const openRelatedStream = async (packetId: number) => {
    setActionBusy(`stream:${packetId}`);
    try {
      const prepared = await preparePacketStream(packetId);
      if (!prepared.protocol || prepared.streamId == null) {
        navigate("/");
        return;
      }
      if (prepared.protocol === "HTTP") {
        navigate("/http-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      if (prepared.protocol === "UDP") {
        navigate("/udp-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      navigate("/tcp-stream", { state: { streamId: prepared.streamId } });
    } finally {
      setActionBusy("");
    }
  };

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
      <AnalysisHero
        icon={<ShieldAlert className="h-5 w-5" />}
        title="威胁狩猎中心"
        subtitle="THREAT HUNTING WORKBENCH"
        description="把 YARA、OWASP、CTF 命中与异常流量汇总到同一工作台，在统一布局中完成规则调参、定位数据包和关联流追踪。"
        tags={["YARA", "OWASP", "CTF", "异常流量"]}
        tagsLabel="狩猎域"
        theme="blue"
        onRefresh={() => void runHunt(parsePrefixes(prefixText))}
        refreshLabel="重新狩猎"
      />

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <GlassStatCard title="总命中" value={hits.length} icon={<SearchCode className="h-4 w-4" />} tone="blue" />
        <GlassStatCard title="高风险" value={hits.filter((item) => item.level === "critical" || item.level === "high").length} icon={<Shield className="h-4 w-4" />} tone="rose" />
        <GlassStatCard title="CTF / 异常" value={`${stats.ctf} / ${stats.anomaly}`} icon={<Sparkles className="h-4 w-4" />} tone="amber" />
      </div>

      {threatProgress && (
        <div className="mb-4 rounded-[24px] border border-blue-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.96),rgba(255,255,255,0.98))] p-4 shadow-[0_20px_48px_-32px_rgba(37,99,235,0.35)]">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">{threatProgress.title}</div>
              <div className="mt-1 text-xs leading-5 text-slate-500">{threatProgress.detail}</div>
            </div>
            <div className="flex flex-col items-end gap-1">
              <span className="rounded-full border border-blue-200 bg-white/90 px-2.5 py-1 text-[11px] font-medium text-blue-700">
                {threatProgress.phaseLabel}
              </span>
              <span className="text-[11px] font-medium text-slate-500">
                {Math.round(threatProgress.value)}%
              </span>
            </div>
          </div>
          <div className="mt-3">
            <Progress value={threatProgress.value} className="h-2.5 bg-blue-100 [&_[data-slot=progress-indicator]]:bg-blue-600" />
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            {threatProgress.total > 0
              ? `${threatProgress.current.toLocaleString()} / ${threatProgress.total.toLocaleString()}`
              : `${threatProgress.current.toLocaleString()}`}
          </div>
        </div>
      )}

      <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
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

        <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-[28px] border border-slate-200 bg-white/92 shadow-[0_24px_80px_-48px_rgba(15,23,42,0.45)] backdrop-blur">
          <div className="shrink-0 border-b border-slate-200 bg-[linear-gradient(180deg,rgba(248,250,252,0.88),rgba(255,255,255,0.98))] p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-slate-900">运行参数与命中结果</div>
                <div className="mt-1 text-xs text-slate-500">
                  YARA 相关路径更推荐在右侧设置栏统一维护；这里保留的是当前狩猎任务的快速参数入口。
                </div>
              </div>
              <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600">
                {statusText || (backendConnected ? "可以直接重跑当前狩猎任务" : "后端未连接")}
              </span>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">Flag Prefixes（逗号分隔）</span>
              <input
                value={prefixText}
                onChange={(e) => setPrefixText(e.target.value)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
                placeholder="flag{,ctf{"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">YARA 可执行（留空自动探测）</span>
              <input
                value={yaraBin}
                onChange={(e) => setYaraBin(e.target.value)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
                placeholder="C:/tools/yara64.exe"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">规则文件（留空默认）</span>
              <input
                value={yaraRules}
                onChange={(e) => setYaraRules(e.target.value)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-foreground outline-none ring-0 transition focus:border-blue-400"
                placeholder="C:/rules/default.yar"
              />
            </label>

            <div className="flex items-end gap-2">
              <label className="flex min-w-0 flex-1 flex-col gap-1 text-xs">
                <span className="text-muted-foreground">超时(ms)</span>
                <input
                  value={yaraTimeoutMs}
                  onChange={(e) => setYaraTimeoutMs(Number(e.target.value) || 0)}
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
                  onChange={(e) => setYaraEnabled(e.target.checked)}
                />
                启用YARA
              </label>
            </div>

              <div className="col-span-1 flex flex-wrap items-center gap-2 md:col-span-2 xl:col-span-4">
              <button
                onClick={() => void loadConfig()}
                disabled={!backendConnected || configBusy || huntBusy}
                className="h-9 rounded-xl border border-slate-200 bg-white px-3.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
              >
                重新读取参数
              </button>
              <button
                onClick={() => void applyConfigAndRun()}
                disabled={!backendConnected || configBusy || huntBusy}
                className="h-9 rounded-xl border border-blue-200 bg-blue-50 px-3.5 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
              >
                保存并重跑狩猎
              </button>
              <button
                onClick={() => void runHunt(parsePrefixes(prefixText))}
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
            <ScrollArea className="min-h-0 flex-1">
              <table className="w-full table-fixed cursor-default whitespace-nowrap border-collapse text-left text-xs">
                <thead className="sticky top-0 z-10 bg-white/95 text-slate-500 shadow-[0_1px_0_0_var(--color-border)] backdrop-blur-sm">
                  <tr>
                    <th className="w-16 border-r border-slate-200 px-3 py-2 font-medium">No.</th>
                    <th className="w-28 border-r border-slate-200 px-3 py-2 font-medium">分类</th>
                    <th className="w-40 border-r border-slate-200 px-3 py-2 font-medium">规则</th>
                    <th className="w-24 border-r border-slate-200 px-3 py-2 font-medium">等级</th>
                    <th className="px-3 py-2 font-medium">预览</th>
                  </tr>
                </thead>
                <tbody>
                  {hits.map((hit) => {
                    const isSelected = selectedHit === hit.id;
                    return (
                      <tr
                        key={hit.id}
                        onClick={() => setSelectedHit(hit.id)}
                        className={cn(
                          "border-b border-slate-200/80 transition-colors",
                          isSelected ? "border-l-2 border-l-rose-500 bg-rose-50/80 text-rose-700" : "text-foreground hover:bg-slate-50",
                        )}
                      >
                        <td className="border-r border-slate-200/80 px-3 py-2 text-slate-500">{hit.packetId}</td>
                        <td className="border-r border-slate-200/80 px-3 py-2">{hit.category}</td>
                        <td className="border-r border-slate-200/80 px-3 py-2 font-medium text-rose-600">{hit.rule}</td>
                        <td className="border-r border-slate-200/80 px-3 py-2">
                          <span className={`rounded border px-2 py-0.5 ${levelColor(hit.level)}`}>{hit.level}</span>
                        </td>
                        <td className="truncate px-3 py-2 font-mono text-slate-500">{hit.preview}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollArea>

            {selected && (
              <div className="flex h-56 min-h-0 shrink-0 flex-col border-t border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] shadow-[0_-10px_30px_-24px_rgba(15,23,42,0.35)]">
                <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/80 px-4 py-2 text-xs font-semibold text-slate-900">
                  <Crosshair className="h-4 w-4 text-blue-600" /> 详细特征提取
                </div>
                <ScrollArea className="min-h-0 flex-1">
                <div className="p-4 font-mono text-sm leading-relaxed text-foreground">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => void jumpToPacket(selected.packetId)}
                      disabled={actionBusy.length > 0}
                      className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {actionBusy === `packet:${selected.packetId}` ? "定位中" : `定位到包 #${selected.packetId}`}
                    </button>
                    <button
                      onClick={() => void openRelatedStream(selected.packetId)}
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
      </div>
    </PageShell>
  );
}

function GlassStatCard({ title, value, icon, tone }: { title: string; value: string | number; icon: ReactNode; tone: "blue" | "rose" | "amber" }) {
  const toneClass = tone === "blue"
    ? "border-blue-200 bg-gradient-to-br from-white via-blue-50 to-cyan-50 text-blue-700"
    : tone === "rose"
      ? "border-rose-200 bg-gradient-to-br from-white via-rose-50 to-orange-50 text-rose-700"
      : "border-amber-200 bg-gradient-to-br from-white via-amber-50 to-yellow-50 text-amber-700";
  return (
    <div className={cn("rounded-2xl border p-4 shadow-sm", toneClass)}>
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-medium text-slate-500">{title}</div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">{value}</div>
        </div>
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-white/80 shadow-sm">
          {icon}
        </div>
      </div>
    </div>
  );
}

function CategoryCard({ title, count, icon, accent }: { title: string; count: number; icon: ReactNode; accent: "blue" | "rose" | "amber" }) {
  const accentClass = accent === "blue"
    ? "border-blue-200 bg-blue-50/70"
    : accent === "rose"
      ? "border-rose-200 bg-rose-50/70"
      : "border-amber-200 bg-amber-50/70";
  return (
    <div className={cn("rounded-2xl border px-3 py-3", accentClass)}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-800">
          {icon}
          {title}
        </div>
        <span className="rounded-full border border-white/70 bg-white/80 px-2 py-0.5 text-xs font-semibold text-slate-600 shadow-sm">
          {count}
        </span>
      </div>
    </div>
  );
}
