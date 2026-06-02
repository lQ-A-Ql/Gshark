import { ShieldAlert, RefreshCw } from "lucide-react";
import { useCallback, useState } from "react";
import type { BruteforceAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Button } from "../../components/ui/button";
import { cn } from "../../components/ui/utils";
import { ErrorBlock, NotesList } from "../ui";
import { MiscModuleSurface } from "./MiscModuleSurface";

const EMPTY: BruteforceAnalysis = { totalSuspicious: 0, portScanHits: [], dirBruteforceHits: [], notes: [] };

function ConfidenceBadge({ value }: { value: number }) {
  const color = value > 80 ? "bg-rose-100 text-rose-700" : value > 60 ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-600";
  return <span className={cn("inline-block rounded px-1.5 py-0.5 text-[11px] font-semibold", color)}>{value}%</span>;
}

export function BruteforceModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [result, setResult] = useState<BruteforceAnalysis>(EMPTY);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const embedded = surfaceVariant === "embedded";

  const run = useCallback(async () => {
    if (!hasCapture) { setError("请先导入抓包文件"); return; }
    setLoading(true);
    setError("");
    try {
      const data = await backendClients.analysis.getBruteforceAnalysis();
      setResult(data);
    } catch (err) {
      setResult(EMPTY);
      setError(err instanceof Error ? err.message : "爆破检测失败");
    } finally { setLoading(false); }
  }, [hasCapture]);

  return (
    <MiscModuleSurface module={module} embedded={embedded} icon={<ShieldAlert className="h-4 w-4" />} tone="amber">
      <div className="flex items-center gap-3">
        <Button variant="outline" disabled={!hasCapture || loading} onClick={() => void run()} className="gap-2 bg-amber-50 text-amber-700">
          <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          {loading ? "检测中..." : "开始检测"}
        </Button>
        {result.totalSuspicious > 0 && (
          <span className="text-[13px] font-semibold text-amber-700">可疑项: {result.totalSuspicious}</span>
        )}
      </div>

      {error && <ErrorBlock message={error} />}

      {result.portScanHits.length > 0 && (
        <div className="space-y-2">
          <div className="text-[13px] font-semibold text-slate-700">端口扫描</div>
          <div className="overflow-x-auto">
            <table className="meow-soft-fill w-full text-[12px]">
              <thead><tr className="border-b text-left text-slate-500">
                <th className="px-2 py-1">源→目标</th><th className="px-2 py-1">端口数</th>
                <th className="px-2 py-1">SYN/RST</th><th className="px-2 py-1">开放端口</th>
                <th className="px-2 py-1">类型</th><th className="px-2 py-1">置信度</th>
              </tr></thead>
              <tbody>
                {result.portScanHits.map((h, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    <td className="px-2 py-1 font-mono">{h.sourceIp}→{h.targetIp}</td>
                    <td className="px-2 py-1">{h.uniquePortsHit}</td>
                    <td className="px-2 py-1">{h.synCount}/{h.rstCount}</td>
                    <td className="max-w-[120px] truncate px-2 py-1 font-mono text-[11px]">{h.openPorts.join(", ")}</td>
                    <td className="px-2 py-1">{h.scanType}</td>
                    <td className="px-2 py-1"><ConfidenceBadge value={h.confidence} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {result.dirBruteforceHits.length > 0 && (
        <div className="space-y-2">
          <div className="text-[13px] font-semibold text-slate-700">目录爆破</div>
          <div className="overflow-x-auto">
            <table className="meow-soft-fill w-full text-[12px]">
              <thead><tr className="border-b text-left text-slate-500">
                <th className="px-2 py-1">源→主机</th><th className="px-2 py-1">请求数</th>
                <th className="px-2 py-1">404/403/200</th><th className="px-2 py-1">req/s</th>
                <th className="px-2 py-1">示例路径</th><th className="px-2 py-1">置信度</th>
              </tr></thead>
              <tbody>
                {result.dirBruteforceHits.map((h, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    <td className="px-2 py-1 font-mono">{h.sourceIp}→{h.targetHost}</td>
                    <td className="px-2 py-1">{h.totalRequests}</td>
                    <td className="px-2 py-1">{h.status404Count}/{h.status403Count}/{h.status200Count}</td>
                    <td className="px-2 py-1">{h.requestsPerSec.toFixed(1)}</td>
                    <td className="max-w-[160px] truncate px-2 py-1 font-mono text-[11px]">{h.samplePaths.slice(0, 3).join(", ")}</td>
                    <td className="px-2 py-1"><ConfidenceBadge value={h.confidence} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <NotesList notes={result.notes} />
    </MiscModuleSurface>
  );
}
