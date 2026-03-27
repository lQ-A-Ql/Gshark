import { Clapperboard, Download, RefreshCw, Video } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { MediaAnalysis as MediaAnalysisData, MediaSession, TrafficBucket } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { formatBytes, useSentinel } from "../state/SentinelContext";

const EMPTY_ANALYSIS: MediaAnalysisData = {
  totalMediaPackets: 0,
  protocols: [],
  applications: [],
  sessions: [],
  notes: [],
};

const mediaAnalysisCache = new Map<string, MediaAnalysisData>();

export default function MediaAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets } = useSentinel();
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${fileMeta.path}::${totalPackets}`;
  }, [fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<MediaAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_ANALYSIS);
      return;
    }
    if (!force && cacheKey && mediaAnalysisCache.has(cacheKey)) {
      setAnalysis(mediaAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    void bridge
      .getMediaAnalysis()
      .then((payload) => {
        if (cacheKey) {
          mediaAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "媒体分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [backendConnected, cacheKey]);

  const downloadArtifact = useCallback(async (session: MediaSession) => {
    if (!session.artifact) return;
    try {
      await bridge.downloadMediaArtifact(session.artifact.token, session.artifact.name);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "媒体文件下载失败");
    }
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-lg font-semibold">
        <Clapperboard className="h-5 w-5 text-blue-600" />
        视频流还原
        <span className="rounded border border-border bg-accent px-2 py-0.5 text-xs font-medium text-muted-foreground">RTP / RTSP / Moonlight / GameStream</span>
        <button
          className="ml-2 inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => refreshAnalysis(true)}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </button>
      </div>

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在识别 RTP / RTSP / Moonlight / GameStream 并尝试还原视频流...</div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="相关流量包" value={analysis.totalMediaPackets.toLocaleString()} />
        <StatCard title="协议标签" value={String(analysis.protocols.length)} />
        <StatCard title="会话数" value={analysis.sessions.length.toLocaleString()} />
        <StatCard title="已导出视频流" value={analysis.sessions.filter((item) => item.artifact).length.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} color="bg-blue-500" />
        </Panel>
        <Panel title="应用分布">
          <BucketChart data={analysis.applications} color="bg-violet-500" />
        </Panel>
      </div>

      <Panel title="分析提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.notes.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到视频流。</div>
          ) : (
            analysis.notes.map((note, index) => (
              <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
                <Video className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                <span>{note}</span>
              </div>
            ))
          )}
        </div>
      </Panel>

      <Panel title={`媒体会话 (${analysis.sessions.length})`} className="mt-4">
        <div className="max-h-[560px] overflow-auto">
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
              <tr>
                <th className="px-3 py-2">族类</th>
                <th className="px-3 py-2">应用</th>
                <th className="px-3 py-2">端点</th>
                <th className="px-3 py-2">RTP</th>
                <th className="px-3 py-2">时间</th>
                <th className="px-3 py-2">统计</th>
                <th className="px-3 py-2">控制面</th>
                <th className="px-3 py-2">导出</th>
              </tr>
            </thead>
            <tbody>
              {analysis.sessions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">暂无可还原的视频会话</td>
                </tr>
              ) : (
                analysis.sessions.map((session) => (
                  <tr key={session.id} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2">
                      <div className="font-medium">{session.family || "--"}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">{session.tags.join(" / ") || "--"}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div>{session.application || "--"}</div>
                      <div className="mt-1 font-mono text-[11px] text-muted-foreground">{session.transport || "--"}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-mono">{session.source || "--"}:{session.sourcePort || 0}</div>
                      <div className="font-mono text-muted-foreground">{session.destination || "--"}:{session.destinationPort || 0}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div>{session.codec || "--"}</div>
                      <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                        SSRC {session.ssrc || "--"} / PT {session.payloadType || "--"}{session.clockRate ? ` / ${session.clockRate}` : ""}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-mono">{session.startTime || "--"}</div>
                      <div className="font-mono text-muted-foreground">{session.endTime || "--"}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div>包数 {session.packetCount.toLocaleString()}</div>
                      <div className="text-muted-foreground">丢序 {session.gapCount.toLocaleString()}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div>{session.controlSummary || "--"}</div>
                      {session.notes.length > 0 && (
                        <div className="mt-1 text-[11px] text-muted-foreground">{session.notes.join(" / ")}</div>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {session.artifact ? (
                        <button
                          className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
                          onClick={() => void downloadArtifact(session)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          {session.artifact.name}
                          <span className="text-muted-foreground">({formatBytes(session.artifact.sizeBytes)})</span>
                        </button>
                      ) : (
                        <span className="text-muted-foreground">未生成</span>
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
    <div className="max-h-[320px] overflow-auto pr-1">
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
