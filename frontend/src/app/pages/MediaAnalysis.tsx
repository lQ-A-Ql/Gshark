import { Clapperboard, Copy, Download, FileText, Headphones, Loader2, Play, Square, Video } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../components/analysis/AnalysisPrimitives";
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
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus, SpeechToTextStatus } from "../core/types";
import { EMPTY_BATCH_STATUS, useMediaAnalysis } from "../features/media/useMediaAnalysis";
import { bridge } from "../integrations/wailsBridge";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import { copyTextToClipboard } from "../utils/browserFile";

type MediaTab = "all" | "video" | "audio";

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

function transcriptionStatusOf(session: MediaSession, batchStatus: SpeechBatchTaskStatus, transcriptions: Record<string, MediaTranscription>) {
  const token = session.artifact?.token;
  if (!token) return { status: "missing", label: "未生成", className: "bg-muted text-muted-foreground" };
  const batchItem = batchStatus.items.find((item) => item.token === token);
  if (batchItem) {
    switch (batchItem.status) {
      case "queued":
        return { status: "queued", label: "排队中", className: "bg-slate-100 text-slate-700" };
      case "running":
        return { status: "running", label: "转写中", className: "bg-blue-100 text-blue-700" };
      case "completed":
        return { status: "completed", label: "已完成", className: "bg-emerald-100 text-emerald-700" };
      case "failed":
        return { status: "failed", label: "失败", className: "bg-rose-100 text-rose-700" };
      case "skipped":
        return { status: "skipped", label: "已跳过（缓存）", className: "bg-amber-100 text-amber-700" };
    }
  }
  if (transcriptions[token]) {
    return { status: "completed", label: "已完成", className: "bg-emerald-100 text-emerald-700" };
  }
  return { status: "idle", label: "未转写", className: "bg-muted text-muted-foreground" };
}

function transcriptionRecordOf(session: MediaSession, batchStatus: SpeechBatchTaskStatus, transcriptions: Record<string, MediaTranscription>) {
  const token = session.artifact?.token;
  if (!token) return null;
  const cached = transcriptions[token];
  if (cached) {
    return {
      text: cached.text || "",
      error: cached.error || "",
      status: cached.status || "completed",
      cached: cached.cached,
    };
  }
  const batchItem = batchStatus.items.find((item) => item.token === token);
  if (!batchItem) return null;
  return {
    text: batchItem.text || "",
    error: batchItem.error || "",
    status: batchItem.status || "idle",
    cached: batchItem.cached,
  };
}

function estimateTranscriptionProgress(elapsedMs: number) {
  if (elapsedMs < 800) {
    return { percent: 14, label: "正在准备音频", tone: "rose" as const };
  }
  if (elapsedMs < 2600) {
    return { percent: 38, label: "正在转码为识别输入", tone: "amber" as const };
  }
  if (elapsedMs < 9000) {
    return { percent: 76, label: "正在进行离线转写", tone: "blue" as const };
  }
  return { percent: 92, label: "正在整理转写结果", tone: "emerald" as const };
}

function progressToneClass(tone: "rose" | "amber" | "blue" | "emerald") {
  switch (tone) {
    case "rose":
      return "bg-rose-500";
    case "amber":
      return "bg-amber-500";
    case "blue":
      return "bg-blue-500";
    case "emerald":
      return "bg-emerald-500";
  }
}

function collectBatchSummaryItems(batchStatus: SpeechBatchTaskStatus, transcriptions: Record<string, MediaTranscription>) {
  const byToken = new Map<string, {
    token: string;
    title: string;
    text: string;
    status: string;
    cached: boolean;
  }>();
  for (const item of batchStatus.items) {
    const text = (item.text || transcriptions[item.token]?.text || "").trim();
    if (!text) continue;
    byToken.set(item.token, {
      token: item.token,
      title: item.title || transcriptions[item.token]?.title || item.mediaLabel,
      text,
      status: item.status,
      cached: item.cached,
    });
  }
  for (const [token, item] of Object.entries(transcriptions)) {
    if (!item.text.trim() || byToken.has(token)) continue;
    byToken.set(token, {
      token,
      title: item.title,
      text: item.text,
      status: item.status,
      cached: item.cached,
    });
  }
  return Array.from(byToken.values());
}

export default function MediaAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, mediaAnalysisProgress, captureRevision } = useSentinel();
  const { analysis, loading, error: analysisError, refreshAnalysis, batchStatus, setBatchStatus, transcriptions, setTranscriptions } = useMediaAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });
  const [pageError, setPageError] = useState("");
  const error = analysisError || pageError;
  const [activeTab, setActiveTab] = useState<MediaTab>("all");
  const [playbackSession, setPlaybackSession] = useState<MediaSession | null>(null);
  const [playbackUrl, setPlaybackUrl] = useState("");
  const [playbackLoadingToken, setPlaybackLoadingToken] = useState("");
  const [ffmpegDialogMessage, setFfmpegDialogMessage] = useState("");
  const [speechDialogMessage, setSpeechDialogMessage] = useState("");
  const [speechStatus, setSpeechStatus] = useState<SpeechToTextStatus | null>(null);
  const [transcriptionLoadingToken, setTranscriptionLoadingToken] = useState("");
  const [transcriptionStartedAt, setTranscriptionStartedAt] = useState<number | null>(null);
  const [batchStarting, setBatchStarting] = useState(false);
  const [batchTokenStartedAt, setBatchTokenStartedAt] = useState<number | null>(null);
  const [progressClock, setProgressClock] = useState(() => Date.now());

  const filteredSessions = useMemo(() => {
    if (activeTab === "all") return analysis.sessions;
    return analysis.sessions.filter((s) => (s.mediaType || "video") === activeTab);
  }, [analysis.sessions, activeTab]);

  const videoCount = useMemo(() => analysis.sessions.filter((s) => (s.mediaType || "video") === "video").length, [analysis.sessions]);
  const audioCount = useMemo(() => analysis.sessions.filter((s) => s.mediaType === "audio").length, [analysis.sessions]);
  const audioArtifactSessions = useMemo(
    () => analysis.sessions.filter((s) => s.mediaType === "audio" && s.artifact),
    [analysis.sessions],
  );
  const batchSummaryItems = useMemo(
    () => collectBatchSummaryItems(batchStatus, transcriptions),
    [batchStatus, transcriptions],
  );

  const ensureSpeechReady = useCallback(async () => {
    const nextStatus = await bridge.checkSpeechToText();
    setSpeechStatus(nextStatus);
    if (!nextStatus.available) {
      setSpeechDialogMessage(nextStatus.message || "语音转写依赖未就绪。");
      throw new Error(nextStatus.message || "语音转写依赖未就绪。");
    }
    return nextStatus;
  }, []);

  const loadBatchStatus = useCallback(async () => {
    if (!backendConnected) {
      setBatchStatus(EMPTY_BATCH_STATUS);
      return;
    }
    try {
      const status = await bridge.getMediaBatchTranscriptionStatus();
      setBatchStatus(status);
      if (status.items.length > 0) {
        setTranscriptions((prev) => {
          const next = { ...prev };
          for (const item of status.items) {
            if (!item.text?.trim()) continue;
            next[item.token] = {
              token: item.token,
              sessionId: item.sessionId,
              title: item.title,
              text: item.text,
              language: speechStatus?.language || "zh-CN",
              engine: speechStatus?.engine || "vosk",
              status: item.status,
              cached: item.cached,
              durationSeconds: prev[item.token]?.durationSeconds ?? 0,
              segments: prev[item.token]?.segments ?? [],
            };
          }
          return next;
        });
      }
    } catch {
      setBatchStatus(EMPTY_BATCH_STATUS);
    }
  }, [backendConnected, speechStatus?.engine, speechStatus?.language]);

  const runTranscription = useCallback(async (session: MediaSession, force = false) => {
    if (!session.artifact) return;
    setTranscriptionLoadingToken(session.artifact.token);
    setTranscriptionStartedAt(Date.now());
    setPageError("");
    try {
      await ensureSpeechReady();
      const result = await bridge.transcribeMediaArtifact(session.artifact.token, force);
      setTranscriptions((prev) => ({ ...prev, [result.token]: result }));
      await loadBatchStatus();
    } catch (err) {
      const message = err instanceof Error ? err.message : "音频转写失败";
      if (message.toLowerCase().includes("vosk") || message.toLowerCase().includes("python") || message.toLowerCase().includes("ffmpeg") || message.includes("模型")) {
        setSpeechDialogMessage(message);
      } else {
        setPageError(message);
      }
    } finally {
      setTranscriptionLoadingToken("");
      setTranscriptionStartedAt(null);
    }
  }, [ensureSpeechReady, loadBatchStatus]);

  const startBatchTranscription = useCallback(async (force = false) => {
    setBatchStarting(true);
    setPageError("");
    try {
      await ensureSpeechReady();
      const status = await bridge.startMediaBatchTranscription(force);
      setBatchStatus(status);
    } catch (err) {
      const message = err instanceof Error ? err.message : "批量转写启动失败";
      if (message.toLowerCase().includes("vosk") || message.toLowerCase().includes("python") || message.toLowerCase().includes("ffmpeg") || message.includes("模型")) {
        setSpeechDialogMessage(message);
      } else {
        setPageError(message);
      }
    } finally {
      setBatchStarting(false);
    }
  }, [ensureSpeechReady]);

  const cancelBatchTranscription = useCallback(async () => {
    try {
      const status = await bridge.cancelMediaBatchTranscription();
      setBatchStatus(status);
    } catch (err) {
      setPageError(err instanceof Error ? err.message : "取消批量转写失败");
    }
  }, []);

  const copyText = useCallback(async (text: string) => {
    if (await copyTextToClipboard(text)) {
      setPageError("");
    } else {
      setPageError("复制文本失败");
    }
  }, []);

  const copyAllText = useCallback(async () => {
    const text = batchSummaryItems.map((item) => `${item.title}\n${item.text}`).join("\n\n");
    if (!text.trim()) return;
    await copyText(text);
  }, [batchSummaryItems, copyText]);

  const exportBatchTranscription = useCallback(async (format: "txt" | "json") => {
    try {
      await bridge.exportMediaBatchTranscription(format);
      setPageError("");
    } catch (err) {
      setPageError(err instanceof Error ? err.message : "批量转写导出失败");
    }
  }, []);

  const downloadArtifact = useCallback(async (session: MediaSession) => {
    if (!session.artifact) return;
    try {
      await bridge.downloadMediaArtifact(session.artifact.token, session.artifact.name);
      setPageError("");
    } catch (err) {
      setPageError(err instanceof Error ? err.message : "媒体文件下载失败");
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
    setPageError("");
    try {
      const ffmpeg = await bridge.checkFFmpeg();
      if (!ffmpeg.available) {
        setFfmpegDialogMessage(ffmpeg.message || "未检测到 ffmpeg，请先将 ffmpeg 加入环境变量 PATH。");
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
        setFfmpegDialogMessage(message);
      } else {
        setPageError(message);
      }
    } finally {
      setPlaybackLoadingToken("");
    }
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  useEffect(() => {
    setTranscriptions({});
    setBatchStatus(EMPTY_BATCH_STATUS);
    setSpeechStatus(null);
    if (!isPreloadingCapture) {
      void loadBatchStatus();
    }
  }, [captureRevision, isPreloadingCapture, loadBatchStatus]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    void loadBatchStatus();
  }, [isPreloadingCapture, loadBatchStatus]);

  useEffect(() => {
    if (!batchStatus.taskId || batchStatus.done) return;
    const timer = window.setInterval(() => {
      void loadBatchStatus();
    }, 900);
    return () => window.clearInterval(timer);
  }, [batchStatus.done, batchStatus.taskId, loadBatchStatus]);

  useEffect(() => {
    if (!batchStatus.currentToken) {
      setBatchTokenStartedAt(null);
      return;
    }
    setBatchTokenStartedAt(Date.now());
  }, [batchStatus.currentToken]);

  useEffect(() => {
    if (!transcriptionLoadingToken && !batchStatus.currentToken) {
      return;
    }
    const timer = window.setInterval(() => {
      setProgressClock(Date.now());
    }, 280);
    return () => window.clearInterval(timer);
  }, [batchStatus.currentToken, transcriptionLoadingToken]);

  useEffect(() => (
    () => {
      if (playbackUrl) {
        URL.revokeObjectURL(playbackUrl);
      }
    }
  ), [playbackUrl]);

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(251,113,133,0.26),transparent_36%),linear-gradient(180deg,#fff7f8_0%,#fbfbff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Clapperboard className="h-5 w-5" />}
        title="媒体流还原"
        subtitle="MEDIA STREAM RECONSTRUCTION"
        description="统一串起媒体流识别、播放、导出与语音转写，让 RTP、RTSP、Moonlight 和音频流分析保持同一套工作台结构。"
        tags={MEDIA_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      {audioArtifactSessions.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <button
            className="inline-flex items-center gap-1 rounded border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
            onClick={() => void startBatchTranscription(false)}
            disabled={batchStarting || (!!batchStatus.taskId && !batchStatus.done)}
          >
            {batchStarting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileText className="h-3.5 w-3.5" />}
            批量转写音频
          </button>
          <button
            className="inline-flex items-center gap-1 rounded border border-border bg-card px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
            onClick={() => void startBatchTranscription(true)}
            disabled={batchStarting || (!!batchStatus.taskId && !batchStatus.done)}
          >
            强制重新转写
          </button>
          {batchStatus.taskId && !batchStatus.done && (
            <button
              className="inline-flex items-center gap-1 rounded border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-100"
              onClick={() => void cancelBatchTranscription()}
            >
              <Square className="h-3.5 w-3.5" />
              取消
            </button>
          )}
        </div>
      )}

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

      {batchStatus.taskId && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-foreground">批量音频转写</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {batchStatus.done
                  ? (batchStatus.cancelled ? "任务已取消" : "任务已完成")
                  : (batchStatus.currentLabel ? `当前处理：${batchStatus.currentLabel}` : "正在准备队列...")}
              </div>
            </div>
            <div className="text-right text-xs text-muted-foreground">
              <div>{batchStatus.completed + batchStatus.skipped} / {batchStatus.total}</div>
              <div>失败 {batchStatus.failed} · 排队 {batchStatus.queued}</div>
            </div>
          </div>
          <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
            <div
              className="h-full bg-rose-600 transition-all"
              style={{ width: `${Math.max(0, Math.min(100, batchStatus.total > 0 ? ((batchStatus.completed + batchStatus.failed + batchStatus.skipped) / batchStatus.total) * 100 : 0))}%` }}
            />
          </div>
          <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
            <span className="rounded bg-muted px-2 py-1">完成 {batchStatus.completed}</span>
            <span className="rounded bg-muted px-2 py-1">跳过 {batchStatus.skipped}</span>
            <span className="rounded bg-muted px-2 py-1">运行中 {batchStatus.running}</span>
            <span className="rounded bg-muted px-2 py-1">失败 {batchStatus.failed}</span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="相关流量包" value={analysis.totalMediaPackets.toLocaleString()} />
        <StatCard title="协议标签" value={String(analysis.protocols.length)} />
        <StatCard title="会话数" value={analysis.sessions.length.toLocaleString()} />
        <StatCard title="已导出媒体流" value={analysis.sessions.filter((item) => item.artifact).length.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" maxHeightClassName="max-h-[320px]" />
        </Panel>
        <Panel title="应用分布">
          <BucketChart data={analysis.applications} barClassName="bg-violet-500" maxHeightClassName="max-h-[320px]" />
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
        <DataTable
          data={filteredSessions}
          rowKey={(session) => session.id}
          maxHeightClassName="max-h-[560px]"
          tableClassName="min-w-[1380px]"
          emptyText="暂无可还原的媒体会话"
          columns={[
            {
              key: "type",
              header: "类型",
              widthClassName: "w-[90px]",
              render: (session) => (
                <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${(session.mediaType || "video") === "audio"
                  ? "bg-purple-100 text-purple-700"
                  : "bg-blue-100 text-blue-700"
                  }`}>
                  {(session.mediaType || "video") === "audio"
                    ? <><Headphones className="h-3 w-3" /> 音频</>
                    : <><Video className="h-3 w-3" /> 视频</>}
                </span>
              ),
            },
            {
              key: "family",
              header: "族类",
              widthClassName: "w-[140px]",
              render: (session) => (
                <>
                  <div className="font-medium">{session.family || "--"}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{session.tags.join(" / ") || "--"}</div>
                </>
              ),
            },
            {
              key: "application",
              header: "应用",
              widthClassName: "w-[120px]",
              render: (session) => (
                <>
                  <div>{session.application || "--"}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{session.transport || "--"}</div>
                </>
              ),
            },
            {
              key: "endpoint",
              header: "端点",
              widthClassName: "w-[180px]",
              render: (session) => (
                <>
                  <div className="font-mono">{session.source || "--"}:{session.sourcePort || 0}</div>
                  <div className="font-mono text-muted-foreground">{session.destination || "--"}:{session.destinationPort || 0}</div>
                </>
              ),
            },
            {
              key: "rtp",
              header: "RTP",
              widthClassName: "w-[190px]",
              render: (session) => (
                <>
                  <div>{session.codec || "--"}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                    SSRC {session.ssrc || "--"} / PT {session.payloadType || "--"}{session.clockRate ? ` / ${session.clockRate}` : ""}
                  </div>
                </>
              ),
            },
            {
              key: "time",
              header: "时间",
              widthClassName: "w-[160px]",
              render: (session) => (
                <>
                  <div className="font-mono">{session.startTime || "--"}</div>
                  <div className="font-mono text-muted-foreground">{session.endTime || "--"}</div>
                </>
              ),
            },
            {
              key: "stats",
              header: "统计",
              widthClassName: "w-[110px]",
              render: (session) => (
                <>
                  <div>包数 {session.packetCount.toLocaleString()}</div>
                  <div className="text-muted-foreground">丢序 {session.gapCount.toLocaleString()}</div>
                </>
              ),
            },
            {
              key: "control",
              header: "控制面",
              widthClassName: "w-[190px]",
              render: (session) => (
                <>
                  <div>{session.controlSummary || "--"}</div>
                  {session.notes.length > 0 && (
                    <div className="mt-1 text-[11px] text-muted-foreground">{session.notes.join(" / ")}</div>
                  )}
                </>
              ),
            },
            {
              key: "transcription",
              header: "转写",
              widthClassName: "w-[360px]",
              render: (session) => {
                const mediaType = (session.mediaType || "").toLowerCase();
                if (mediaType !== "audio") {
                  return <span className="text-muted-foreground">仅音频支持</span>;
                }
                if (!session.artifact) {
                  return <span className="text-muted-foreground">音频流未导出</span>;
                }
                const transcriptionStatus = transcriptionStatusOf(session, batchStatus, transcriptions);
                const record = transcriptionRecordOf(session, batchStatus, transcriptions);
                const text = (record?.text || "").trim();
                const errorText = (record?.error || "").trim();
                const singleRunning = transcriptionLoadingToken === session.artifact.token;
                const batchRunning = !!batchStatus.currentToken && batchStatus.currentToken === session.artifact.token && !batchStatus.done;
                const running = singleRunning || batchRunning;
                const startedAt = singleRunning ? transcriptionStartedAt : batchRunning ? batchTokenStartedAt : null;
                const progress = running && startedAt
                  ? estimateTranscriptionProgress(Math.max(0, progressClock - startedAt))
                  : null;
                return (
                  <div className="min-w-0 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${transcriptionStatus.className}`}>
                        {transcriptionStatus.label}
                      </span>
                      {record?.cached && transcriptionStatus.status === "completed" && (
                        <span className="inline-flex items-center rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-700">
                          缓存
                        </span>
                      )}
                      {text && (
                        <button
                          className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-0.5 text-[11px] hover:bg-accent"
                          onClick={() => void copyText(text)}
                        >
                          <Copy className="h-3 w-3" />
                          复制
                        </button>
                      )}
                    </div>
                    {text ? (
                      <div className="max-w-[28rem] rounded border border-emerald-200 bg-emerald-50 px-2.5 py-2 text-[11px] leading-5 text-emerald-950">
                        <div className="line-clamp-4 whitespace-pre-wrap break-words">{text}</div>
                      </div>
                    ) : progress ? (
                      <div className="max-w-[22rem] rounded border border-slate-200 bg-slate-50 px-2.5 py-2">
                        <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px] text-slate-600">
                          <span>{progress.label}</span>
                          <span>{progress.percent}%</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-slate-200">
                          <div
                            className={`h-full transition-all ${progressToneClass(progress.tone)}`}
                            style={{ width: `${progress.percent}%` }}
                          />
                        </div>
                      </div>
                    ) : errorText ? (
                      <div className="max-w-[22rem] rounded border border-rose-200 bg-rose-50 px-2.5 py-2 text-[11px] leading-5 text-rose-700">
                        {errorText}
                      </div>
                    ) : (
                      <div className="text-[11px] text-muted-foreground">
                        {transcriptionStatus.status === "idle"
                          ? "点右侧“转写”后，结果会直接显示在这里。"
                          : transcriptionStatus.status === "completed"
                            ? "转写已完成，但这段音频暂时没有识别出可显示的文字。"
                            : "正在等待转写任务进入这一条音频。"}
                      </div>
                    )}
                  </div>
                );
              },
            },
            {
              key: "export",
              header: "导出",
              widthClassName: "w-[230px]",
              render: (session) => session.artifact ? (
                <div className="w-full max-w-[13rem] rounded-2xl border border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.98))] p-2 shadow-sm">
                  <div className="flex flex-col gap-2">
                    <button
                      className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-slate-200 bg-white px-2.5 py-2 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50"
                      onClick={() => void downloadArtifact(session)}
                    >
                      <Download className="h-3.5 w-3.5" />
                      {(session.mediaType || "").toLowerCase() === "audio" ? "下载音频流" : "下载裸流"}
                      <span className="text-muted-foreground">({formatBytes(session.artifact.sizeBytes)})</span>
                    </button>
                    {canPlayArtifact(session) && (
                      <button
                        className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-blue-200 bg-blue-50 px-2.5 py-2 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
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
                    {(session.mediaType || "").toLowerCase() === "audio" && (
                      <button
                        className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-emerald-200 bg-emerald-50 px-2.5 py-2 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
                        onClick={() => void runTranscription(session, false)}
                        disabled={transcriptionLoadingToken === session.artifact.token || (!!batchStatus.taskId && !batchStatus.done && batchStatus.currentToken === session.artifact.token)}
                      >
                        {transcriptionLoadingToken === session.artifact.token || (!!batchStatus.taskId && !batchStatus.done && batchStatus.currentToken === session.artifact.token) ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <FileText className="h-3.5 w-3.5" />
                        )}
                        转写
                      </button>
                    )}
                    <div className="rounded-xl bg-slate-50 px-2.5 py-2 text-[11px] text-slate-500">
                      <div className="truncate font-medium text-slate-700">{session.artifact.name}</div>
                      <div className="mt-1">
                        {(session.mediaType || "").toLowerCase() === "audio" ? "音频文件已准备好，可下载、播放或直接转写。" : "视频裸流已导出，可继续下载或转为可播放格式。"}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <span className="text-muted-foreground">未生成</span>
              ),
            },
          ]}
        />
      </Panel>

      {(batchSummaryItems.length > 0 || (batchStatus.taskId && batchStatus.total > 0)) && (
        <Panel title={`转写汇总 (${batchSummaryItems.length})`} className="mt-4">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <button
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
              onClick={() => void copyAllText()}
              disabled={batchSummaryItems.length === 0}
            >
              <Copy className="h-3.5 w-3.5" />
              复制全部
            </button>
            <button
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
              onClick={() => void exportBatchTranscription("txt")}
              disabled={batchSummaryItems.length === 0}
            >
              <Download className="h-3.5 w-3.5" />
              导出 TXT
            </button>
            <button
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
              onClick={() => void exportBatchTranscription("json")}
              disabled={batchSummaryItems.length === 0}
            >
              <Download className="h-3.5 w-3.5" />
              导出 JSON
            </button>
          </div>
          {batchSummaryItems.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
              批量转写结果会在这里汇总展示。
            </div>
          ) : (
            <div className="space-y-3">
              {batchSummaryItems.map((item) => (
                <details key={item.token} className="rounded border border-border bg-background" open>
                  <summary className="cursor-pointer list-none px-3 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-sm font-medium">{item.title}</div>
                      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                        <span className="rounded bg-muted px-2 py-0.5">{item.cached ? "缓存" : "新转写"}</span>
                        <span>{item.status}</span>
                      </div>
                    </div>
                  </summary>
                  <div className="border-t border-border px-3 py-3">
                    <div className="whitespace-pre-wrap text-sm text-foreground">{item.text}</div>
                    <div className="mt-3">
                      <button
                        className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs hover:bg-accent"
                        onClick={() => void copyText(item.text)}
                      >
                        <Copy className="h-3.5 w-3.5" />
                        复制
                      </button>
                    </div>
                  </div>
                </details>
              ))}
            </div>
          )}
        </Panel>
      )}

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

      <AlertDialog open={Boolean(speechDialogMessage)} onOpenChange={(open) => { if (!open) setSpeechDialogMessage(""); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>语音转写不可用</AlertDialogTitle>
            <AlertDialogDescription>
              {speechDialogMessage || "本地语音转写依赖未就绪，请检查 Python、vosk 模块、模型目录与 ffmpeg。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => setSpeechDialogMessage("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageShell>
  );
}
