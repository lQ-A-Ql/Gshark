import { RefreshCw, Usb, Waypoints, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { TrafficBucket, USBAnalysis as USBAnalysisData } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

const EMPTY_ANALYSIS: USBAnalysisData = {
  totalUSBPackets: 0,
  protocols: [],
  transferTypes: [],
  directions: [],
  devices: [],
  endpoints: [],
  setupRequests: [],
  records: [],
  notes: [],
};

const usbAnalysisCache = new Map<string, USBAnalysisData>();

export default function UsbAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets } = useSentinel();
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${fileMeta.path}::${totalPackets}`;
  }, [fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<USBAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_ANALYSIS);
      return;
    }
    if (!force && cacheKey && usbAnalysisCache.has(cacheKey)) {
      setAnalysis(usbAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    void bridge
      .getUSBAnalysis()
      .then((payload) => {
        if (cacheKey) {
          usbAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "USB 分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [backendConnected, cacheKey]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-lg font-semibold">
        <Usb className="h-5 w-5 text-blue-600" />
        USB 流量分析
        <span className="rounded border border-border bg-accent px-2 py-0.5 text-xs font-medium text-muted-foreground">
          USB URB / Control / Bulk / Interrupt / Isochronous
        </span>
        <button
          className="ml-2 inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => refreshAnalysis(true)}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </button>
      </div>

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          正在调用 tshark 生成 USB 分析结果...
        </div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="USB 包总数" value={analysis.totalUSBPackets.toLocaleString()} />
        <StatCard title="设备数" value={String(analysis.devices.length)} />
        <StatCard title="端点数" value={String(analysis.endpoints.length)} />
        <StatCard title="Setup 请求类型" value={String(analysis.setupRequests.length)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} color="bg-blue-500" />
        </Panel>
        <Panel title="传输类型">
          <BucketChart data={analysis.transferTypes} color="bg-emerald-500" />
        </Panel>
        <Panel title="方向分布">
          <BucketChart data={analysis.directions} color="bg-amber-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="设备热度">
          <BucketChart data={analysis.devices} color="bg-cyan-500" />
        </Panel>
        <Panel title="端点热度">
          <BucketChart data={analysis.endpoints} color="bg-indigo-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Setup Request 分布">
          <BucketChart data={analysis.setupRequests} color="bg-rose-500" />
        </Panel>
        <Panel title="分析提示">
          <div className="space-y-2 text-sm">
            {analysis.notes.length === 0 ? (
              <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到明显的 USB 解析特征。</div>
            ) : (
              analysis.notes.map((note, index) => (
                <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
                  <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                  <span>{note}</span>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      <Panel title={`USB 数据明细 (${analysis.records.length})`} className="mt-4">
        <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
          <Waypoints className="h-3.5 w-3.5" />
          保留重点记录，便于快速判断设备、端点、方向与 payload 特征。
        </div>
        <div className="max-h-[560px] overflow-auto">
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
              <tr>
                <th className="w-20 px-3 py-2">包号</th>
                <th className="w-28 px-3 py-2">时间</th>
                <th className="w-24 px-3 py-2">协议</th>
                <th className="w-28 px-3 py-2">设备</th>
                <th className="w-28 px-3 py-2">端点</th>
                <th className="w-20 px-3 py-2">方向</th>
                <th className="w-24 px-3 py-2">传输</th>
                <th className="w-24 px-3 py-2">URB</th>
                <th className="w-24 px-3 py-2">状态</th>
                <th className="w-20 px-3 py-2">长度</th>
                <th className="w-28 px-3 py-2">Setup</th>
                <th className="px-3 py-2">摘要</th>
              </tr>
            </thead>
            <tbody>
              {analysis.records.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-3 py-6 text-center text-muted-foreground">暂无 USB 记录</td>
                </tr>
              ) : (
                analysis.records.map((item) => (
                  <tr key={`${item.packetId}-${item.endpoint}-${item.summary}`} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2 font-mono text-muted-foreground">{item.packetId}</td>
                    <td className="px-3 py-2 font-mono">{item.time || "--"}</td>
                    <td className="px-3 py-2">{item.protocol || "--"}</td>
                    <td className="px-3 py-2">{joinParts(item.busId, item.deviceAddress)}</td>
                    <td className="px-3 py-2 font-mono">{item.endpoint || "--"}</td>
                    <td className="px-3 py-2">{item.direction || "--"}</td>
                    <td className="px-3 py-2">{item.transferType || "--"}</td>
                    <td className="px-3 py-2">{item.urbType || "--"}</td>
                    <td className="px-3 py-2">{item.status || "--"}</td>
                    <td className="px-3 py-2 font-mono">{item.dataLength}</td>
                    <td className="px-3 py-2">{item.setupRequest || "--"}</td>
                    <td className="px-3 py-2">
                      <div>{item.summary || "--"}</div>
                      {item.payloadPreview && (
                        <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.payloadPreview}</div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function joinParts(busId: string, deviceAddress: string) {
  const parts = [busId && `bus ${busId}`, deviceAddress && `dev ${deviceAddress}`].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "--";
}

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-2 text-xs text-muted-foreground">{title}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-border bg-card p-4 shadow-sm ${className}`.trim()}>
      <div className="mb-3 text-sm font-semibold">{title}</div>
      {children}
    </div>
  );
}

function BucketChart({ data, color }: { data: TrafficBucket[]; color: string }) {
  const max = Math.max(1, ...data.map((item) => item.count));
  if (data.length === 0) {
    return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">暂无数据</div>;
  }
  return (
    <div className="max-h-[420px] overflow-auto pr-1">
      <div className="space-y-2">
        {data.map((row) => (
          <div key={row.label} className="grid grid-cols-[220px_1fr_72px] items-center gap-2 text-xs">
            <div className="truncate text-muted-foreground" title={row.label}>{row.label}</div>
            <div className="h-2 rounded bg-accent">
              <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono">{row.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
