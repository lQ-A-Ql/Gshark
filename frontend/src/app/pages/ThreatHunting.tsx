import { useEffect, useMemo, useState } from "react";
import { ShieldAlert, Crosshair, CheckCircle2, Flag, Shield, BarChart2 } from "lucide-react";
import { useNavigate } from "react-router";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useSentinel } from "../state/SentinelContext";
import { bridge } from "../integrations/wailsBridge";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

function levelColor(level: string) {
  if (level === "critical") return "text-rose-700 bg-rose-50 border-rose-200";
  if (level === "high") return "text-orange-700 bg-orange-50 border-orange-200";
  if (level === "medium") return "text-amber-700 bg-amber-50 border-amber-200";
  return "text-foreground bg-accent border-border";
}

export default function ThreatHunting() {
  const navigate = useNavigate();
  const { threatHits, backendConnected, locatePacketById, preparePacketStream } = useSentinel();
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
    <div className="relative flex h-full flex-col overflow-hidden bg-background text-sm text-foreground">
      <div className="z-10 flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-4 py-2 shadow-sm">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-4 w-4 text-rose-600" />
          <h1 className="flex items-center gap-2 font-semibold text-foreground">深度狩猎与审计中心</h1>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="z-10 flex w-64 shrink-0 flex-col border-r border-border bg-card shadow-sm">
          <div className="border-b border-border bg-accent/40 p-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            规则分类
          </div>
          <div className="flex-1 space-y-2 overflow-auto p-2">
            <div className="rounded-md border border-border px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-foreground">
                  <Flag className="h-4 w-4 text-blue-600" /> CTF Flags
                </div>
                <span className="rounded-full border border-border bg-accent px-1.5 text-xs text-muted-foreground">{stats.ctf}</span>
              </div>
            </div>
            <div className="rounded-md border border-border px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-foreground">
                  <Shield className="h-4 w-4 text-rose-600" /> OWASP
                </div>
                <span className="rounded-full border border-border bg-accent px-1.5 text-xs text-muted-foreground">{stats.owasp}</span>
              </div>
            </div>
            <div className="rounded-md border border-border px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-foreground">
                  <BarChart2 className="h-4 w-4 text-amber-600" /> 异常统计
                </div>
                <span className="rounded-full border border-border bg-accent px-1.5 text-xs text-muted-foreground">{stats.anomaly}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex min-w-0 flex-1 flex-col bg-card">
          <div className="grid shrink-0 grid-cols-1 gap-2 border-b border-border bg-accent/30 p-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">Flag Prefixes（逗号分隔）</span>
              <input
                value={prefixText}
                onChange={(e) => setPrefixText(e.target.value)}
                className="h-8 rounded border border-border bg-background px-2 text-foreground outline-none ring-0 focus:border-blue-400"
                placeholder="flag{,ctf{"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">YARA 可执行（留空自动探测）</span>
              <input
                value={yaraBin}
                onChange={(e) => setYaraBin(e.target.value)}
                className="h-8 rounded border border-border bg-background px-2 text-foreground outline-none ring-0 focus:border-blue-400"
                placeholder="C:/tools/yara64.exe"
              />
            </label>

            <label className="flex flex-col gap-1 text-xs">
              <span className="text-muted-foreground">规则文件（留空默认）</span>
              <input
                value={yaraRules}
                onChange={(e) => setYaraRules(e.target.value)}
                className="h-8 rounded border border-border bg-background px-2 text-foreground outline-none ring-0 focus:border-blue-400"
                placeholder="C:/rules/default.yar"
              />
            </label>

            <div className="flex items-end gap-2">
              <label className="flex min-w-0 flex-1 flex-col gap-1 text-xs">
                <span className="text-muted-foreground">超时(ms)</span>
                <input
                  value={yaraTimeoutMs}
                  onChange={(e) => setYaraTimeoutMs(Number(e.target.value) || 0)}
                  className="h-8 rounded border border-border bg-background px-2 text-foreground outline-none ring-0 focus:border-blue-400"
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

            <div className="col-span-1 flex items-center gap-2 md:col-span-2 xl:col-span-4">
              <button
                onClick={() => void loadConfig()}
                disabled={!backendConnected || configBusy || huntBusy}
                className="h-8 rounded border border-border bg-background px-3 text-xs text-foreground disabled:cursor-not-allowed disabled:opacity-50"
              >
                重新读取参数
              </button>
              <button
                onClick={() => void applyConfigAndRun()}
                disabled={!backendConnected || configBusy || huntBusy}
                className="h-8 rounded border border-blue-200 bg-blue-50 px-3 text-xs text-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                保存并重跑狩猎
              </button>
              <button
                onClick={() => void runHunt(parsePrefixes(prefixText))}
                disabled={!backendConnected || configBusy || huntBusy}
                className="h-8 rounded border border-emerald-200 bg-emerald-50 px-3 text-xs text-emerald-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                仅重跑（不保存）
              </button>
              <span className="truncate text-xs text-muted-foreground">{statusText || (backendConnected ? "可在此调整狩猎参数并重跑" : "后端未连接")}</span>
            </div>
          </div>

          <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 p-3">
            <span className="flex items-center gap-2 text-sm font-medium text-foreground">
              <CheckCircle2 className="h-4 w-4 text-emerald-600" /> 命中结果 (共 {hits.length} 条)
            </span>
          </div>

          <div className="flex flex-1 flex-col">
            <div className="flex-1 overflow-auto">
              <table className="w-full table-fixed cursor-default whitespace-nowrap border-collapse text-left text-xs">
                <thead className="sticky top-0 z-10 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)] backdrop-blur-sm">
                  <tr>
                    <th className="w-16 border-r border-border px-3 py-2 font-medium">No.</th>
                    <th className="w-28 border-r border-border px-3 py-2 font-medium">分类</th>
                    <th className="w-32 border-r border-border px-3 py-2 font-medium">规则</th>
                    <th className="w-24 border-r border-border px-3 py-2 font-medium">等级</th>
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
                          "border-b border-border/70 transition-colors",
                          isSelected ? "border-l-2 border-l-rose-500 bg-rose-500/10 text-rose-600 dark:text-rose-400" : "text-foreground hover:bg-accent/50",
                        )}
                      >
                        <td className="border-r border-border/70 px-3 py-2 text-muted-foreground">{hit.packetId}</td>
                        <td className="border-r border-border/70 px-3 py-2">{hit.category}</td>
                        <td className="border-r border-border/70 px-3 py-2 font-medium text-rose-600">{hit.rule}</td>
                        <td className="border-r border-border/70 px-3 py-2">
                          <span className={`rounded border px-2 py-0.5 ${levelColor(hit.level)}`}>{hit.level}</span>
                        </td>
                        <td className="truncate px-3 py-2 font-mono text-muted-foreground">{hit.preview}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {selected && (
              <div className="flex h-48 shrink-0 flex-col border-t border-border bg-card shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)]">
                <div className="flex items-center gap-2 border-b border-border bg-accent/40 px-3 py-1.5 text-xs font-semibold text-foreground">
                  <Crosshair className="h-4 w-4 text-blue-600" /> 详细特征提取
                </div>
                <div className="flex-1 overflow-auto p-4 font-mono text-sm leading-relaxed text-foreground">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => void jumpToPacket(selected.packetId)}
                      disabled={actionBusy.length > 0}
                      className="rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {actionBusy === `packet:${selected.packetId}` ? "定位中" : `定位到包 #${selected.packetId}`}
                    </button>
                    <button
                      onClick={() => void openRelatedStream(selected.packetId)}
                      disabled={actionBusy.length > 0}
                      className="rounded-md border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {actionBusy === `stream:${selected.packetId}` ? "打开中" : "打开关联流"}
                    </button>
                  </div>
                  <div className="mb-1 font-sans text-xs text-muted-foreground">命中字符串:</div>
                  <div className="break-all rounded-md border border-border bg-accent p-3 text-rose-700 select-all">{selected.match}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
