import { Clapperboard, Download, Headphones, Loader2, Play, Video } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../components/ui/alert-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../components/ui/dialog";
import type { MediaAnalysis as MediaAnalysisData, MediaSession, TrafficBucket } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { formatBytes, useSentinel } from "../state/SentinelContext";

type MediaTab = "all" | "video" | "audio";

const EMPTY_ANALYSIS: MediaAnalysisData = {
  totalMediaPackets: 0,
  protocols: [],
  applications: [],
  sessions: [],
  notes: [],
};

const mediaAnalysisCache = new Map<string, MediaAnalysisData>();
const MEDIA_PROTOCOL_TAGS = ["RTP", "RTSP", "Moonlight", "GameStream"];

function canPlayArtifact(session: MediaSession): boolean {
  if (!session.artifact) return false;
  const mediaType = (session.mediaType || "").toLowerCase();
  const format = (session.artifact.format || "").toLowerCase();
  if (mediaType === "video") {
    return format === "h264" || format === "264" || format === "h265" || format === "265" || format === "hevc";
  }
  if (mediaType === "audio") {
    return format === "ulaw" || format === "alaw" || format === "g722" || format === "l16" || format === "aac" || format === "opus" || format === "mpa" || format === "mp3";
  }
  return false;
}

export default function MediaAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, mediaAnalysisProgress, captureRevision } = useSentinel();
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${captureRevision}::${fileMeta.path}::${totalPackets}`;
  }, [captureRevision, fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<MediaAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<MediaTab>("all");
  const [playbackSession, setPlaybackSession] = useState<MediaSession | null>(null);
  const [playbackUrl, setPlaybackUrl] = useState("");
  const [playbackLoadingToken, setPlaybackLoadingToken] = useState("");
  const [ffmpegDialogMessage, setFfmpegDialogMessage] = useState("");

  const filteredSessions = useMemo(() => {
    if (activeTab === "all") return analysis.sessions;
    return analysis.sessions.filter((s) => (s.mediaType || "video") === activeTab);
  }, [analysis.sessions, activeTab]);

  const videoCount = useMemo(() => analysis.sessions.filter((s) => (s.mediaType || "video") === "video").length, [analysis.sessions]);
  const audioCount = useMemo(() => analysis.sessions.filter((s) => s.mediaType === "audio").length, [analysis.sessions]);

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
    if (force && cacheKey) {
      mediaAnalysisCache.delete(cacheKey);
    }
    void bridge
      .getMediaAnalysis(force)
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

  const closePlayback = useCallback(() => {
    setPlaybackSession(null);
    setPlaybackUrl((current) => {
      if (current) {
        URL.revokeObjectURL(current);
      }
      return "";
    });
  }, []);

  const openPlayback = useCallback(async (session: MediaSession) => {
    if (!session.artifact) return;
    setPlaybackLoadingToken(session.artifact.token);
    setError("");
    try {
      const ffmpeg = await bridge.checkFFmpeg();
      if (!ffmpeg.available) {
        setFFmpegDialogMessage(ffmpeg.message || "未检测到 ffmpeg，请先将 ffmpeg 加入环境变量 PATH。");
        return;
      }
      const blob = await bridge.getMediaPlaybackBlob(session.artifact.token);
      const nextUrl = URL.createObjectURL(blob);
      setPlaybackUrl((current) => {
        if (current) {
          URL.revokeObjectURL(current);
        }
        return nextUrl;
      });
      setPlaybackSession(session);
    } catch (err) {
      const message = err instanceof Error ? err.message : "媒体播放初始化失败";
      if (message.toLowerCase().includes("ffmpeg")) {
        setFFmpegDialogMessage(message);
      } else {
        setError(message);
      }
    } finally {
      setPlaybackLoadingToken("");
    }
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  useEffect(() => (
    () => {
      if (playbackUrl) {
        URL.revokeObjectURL(playbackUrl);
      }
    }
  ), [playbackUrl]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <AnalysisHero
        icon={<Clapperboard className="h-5 w-5" />}
        title="媒体流还原"
        subtitle="MEDIA STREAM RECONSTRUCTION"
        tags={MEDIA_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在识别 RTP / RTSP / Moonlight / GameStream 并尝试还原媒体流...</div>
      )}

      {mediaAnalysisProgress.active && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-3">
          <div className="mb-2 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="inline-flex rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 font-medium text-rose-700">
                  {mediaAnalysisProgress.phaseLabel || "处理中"}
                </span>
                <span>{Math.round(mediaAnalysisProgress.percent)}%</span>
              </div>
              <div className="mt-1 text-sm font-medium text-foreground">
                {mediaAnalysisProgress.label || "正在分析媒体流..."}
              </div>
            </div>
            <div className="shrink-0 text-right text-xs text-muted-foreground">
              {mediaAnalysisProgress.total > 0
                ? `${mediaAnalysisProgress.current.toLocaleString()} / ${mediaAnalysisProgress.total.toLocaleString()}`
                : `${mediaAnalysisProgress.current.toLocaleString()}`}
            </div>
          </div>
          <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
            <div
              className="h-full bg-rose-600 transition-all"
              style={{
                width: `${Math.max(4, Math.min(100, mediaAnalysisProgress.percent || 4))}%`,
              }}
            />
          </div>
          <div className="mb-2 grid grid-cols-4 gap-2 text-[11px] text-muted-foreground">
            {[
              { key: "prepare", label: "准备" },
              { key: "scan", label: "扫描" },
              { key: "organize", label: "整理" },
              { key: "rebuild", label: "重建" },
            ].map((item) => {
              const active = mediaAnalysisProgress.phase === item.key;
              const completed = ["prepare", "scan", "organize", "rebuild", "complete"].indexOf(mediaAnalysisProgress.phase) >= ["prepare", "scan", "organize", "rebuild"].indexOf(item.key as typeof mediaAnalysisProgress.phase);
              return (
                <div
                  key={item.key}
                  className={`rounded border px-2 py-1 text-center transition-colors ${active
                    ? "border-rose-300 bg-rose-50 text-rose-700"
                    : completed
                      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                      : "border-border bg-background"
                    }`}
                >
                  {item.label}
                </div>
              );
            })}
          </div>
          {mediaAnalysisProgress.recent.length > 1 && (
            <div className="space-y-1 text-[11px] text-muted-foreground">
              {mediaAnalysisProgress.recent.slice(0, 3).map((item, index) => (
                <div key={`${item}-${index}`} className="truncate">
                  {index === 0 ? "当前" : "最近"}: {item}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="相关流量包" value={analysis.totalMediaPackets.toLocaleString()} />
        <StatCard title="协议标签" value={String(analysis.protocols.length)} />
        <StatCard title="会话数" value={analysis.sessions.length.toLocaleString()} />
        <StatCard title="已导出媒体流" value={analysis.sessions.filter((item) => item.artifact).length.toLocaleString()} />
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
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到媒体流。</div>
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
        {/* Tab 切换：全部 / 视频 / 音频 */}
        <div className="mb-3 flex items-center gap-1 border-b border-border pb-2">
          {([
            { key: "all" as MediaTab, label: "全部", count: analysis.sessions.length, icon: <Clapperboard className="h-3.5 w-3.5" /> },
            { key: "video" as MediaTab, label: "视频", count: videoCount, icon: <Video className="h-3.5 w-3.5" /> },
            { key: "audio" as MediaTab, label: "音频", count: audioCount, icon: <Headphones className="h-3.5 w-3.5" /> },
          ]).map((tab) => (
            <button
              key={tab.key}
              className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-xs font-medium transition-colors ${activeTab === tab.key
                ? "bg-blue-600 text-white"
                : "bg-accent text-muted-foreground hover:bg-accent/80 hover:text-foreground"
                }`}
              onClick={() => setActiveTab(tab.key)}
            >
              {tab.icon}
              {tab.label}
              <span className="ml-0.5 opacity-70">({tab.count})</span>
            </button>
          ))}
        </div>
        <div className="max-h-[560px] overflow-auto">
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead className="sticky top-0 z-10 bg-card text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
              <tr>
                <th className="px-3 py-2">类型</th>
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
              {filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-3 py-6 text-center text-muted-foreground">暂无可还原的媒体会话</td>
                </tr>
              ) : (
                filteredSessions.map((session) => (
                  <tr key={session.id} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${(session.mediaType || "video") === "audio"
                        ? "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300"
                        : "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300"
                        }`}>
                        {(session.mediaType || "video") === "audio"
                          ? <><Headphones className="h-3 w-3" /> 音频</>
                          : <><Video className="h-3 w-3" /> 视频</>}
                      </span>
                    </td>
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
                        <div className="flex flex-wrap items-center gap-2">
                          <button
                            className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
                            onClick={() => void downloadArtifact(session)}
                          >
                            <Download className="h-3.5 w-3.5" />
                            {(session.mediaType || "").toLowerCase() === "audio" ? "下载音频流" : "下载裸流"}
                            <span className="text-muted-foreground">({formatBytes(session.artifact.sizeBytes)})</span>
                          </button>
                          {canPlayArtifact(session) && (
                            <button
                              className="inline-flex items-center gap-1 rounded border border-blue-200 bg-blue-50 px-2 py-1 text-xs text-blue-700 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                              onClick={() => void openPlayback(session)}
                              disabled={playbackLoadingToken === session.artifact.token}
                            >
                              {playbackLoadingToken === session.artifact.token ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <Play className="h-3.5 w-3.5" />
                              )}
                              播放
                            </button>
                          )}
                          <div className="text-[11px] text-muted-foreground">{session.artifact.name}</div>
                        </div>
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

      <Dialog open={Boolean(playbackSession)} onOpenChange={(open) => { if (!open) closePlayback(); }}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>媒体播放</DialogTitle>
            <DialogDescription>
              {playbackSession
                ? `${playbackSession.application || "媒体流"} · ${playbackSession.codec || "未知编码"} · ${playbackSession.source}:${playbackSession.sourcePort} -> ${playbackSession.destination}:${playbackSession.destinationPort}`
                : "使用 ffmpeg 将裸流转为浏览器可播放的音视频文件。"}
            </DialogDescription>
          </DialogHeader>
          <div className={`overflow-hidden rounded-lg border border-border ${playbackSession?.mediaType === "audio" ? "bg-gradient-to-br from-slate-50 via-rose-50 to-orange-50 p-6" : "bg-black"}`}>
            {playbackUrl ? (
              playbackSession?.mediaType === "audio" ? (
                <div className="flex min-h-48 flex-col items-center justify-center gap-4 text-center">
                  <div className="inline-flex h-16 w-16 items-center justify-center rounded-full bg-white/80 text-rose-600 shadow-sm">
                    <Headphones className="h-8 w-8" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-foreground">{playbackSession.codec || "音频流"}</div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      {playbackSession.source}:{playbackSession.sourcePort} {"->"} {playbackSession.destination}:{playbackSession.destinationPort}
                    </div>
                  </div>
                  <audio key={playbackUrl} className="w-full max-w-2xl" controls autoPlay src={playbackUrl}>
                    当前环境不支持音频播放。
                  </audio>
                </div>
              ) : (
              <video key={playbackUrl} className="aspect-video w-full bg-black" controls autoPlay src={playbackUrl}>
                当前环境不支持视频播放。
              </video>
              )
            ) : (
              <div className={`flex items-center justify-center text-sm ${playbackSession?.mediaType === "audio" ? "min-h-48 text-muted-foreground" : "aspect-video text-white/70"}`}>
                正在准备媒体播放...
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={Boolean(ffmpegDialogMessage)} onOpenChange={(open) => { if (!open) setFfmpegDialogMessage(""); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>缺少 ffmpeg</AlertDialogTitle>
            <AlertDialogDescription>
              {ffmpegDialogMessage || "未在环境变量 PATH 中找到 ffmpeg，请先安装 ffmpeg 并将其加入 PATH。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => setFfmpegDialogMessage("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
