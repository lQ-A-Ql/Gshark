import { Clapperboard, FileText, Loader2, Square, Video } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../components/analysis/AnalysisPrimitives";
import type { MediaSession, SpeechToTextStatus } from "../core/types";
import {
  BatchTranscriptionStatusPanel,
  MediaAnalysisProgressPanel,
  MediaDependencyDialogs,
  MediaPlaybackDialog,
} from "../features/media/MediaDisplayPanels";
import { MediaSessionTable } from "../features/media/MediaSessionTable";
import { MediaTranscriptionSummaryPanel } from "../features/media/MediaTranscriptionSummaryPanel";
import { EMPTY_BATCH_STATUS, useMediaAnalysis } from "../features/media/useMediaAnalysis";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";
import { copyTextToClipboard } from "../utils/browserFile";

const MEDIA_PROTOCOL_TAGS = ["RTP", "RTSP", "Moonlight", "GameStream"];

export default function MediaAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, mediaAnalysisProgress, captureRevision } =
    useSentinel();
  const {
    analysis,
    loading,
    error: analysisError,
    refreshAnalysis,
    batchStatus,
    setBatchStatus,
    transcriptions,
    setTranscriptions,
  } = useMediaAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });
  const [pageError, setPageError] = useState("");
  const error = analysisError || pageError;
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

  const audioArtifactSessions = useMemo(
    () => analysis.sessions.filter((s) => s.mediaType === "audio" && s.artifact),
    [analysis.sessions],
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

  const runTranscription = useCallback(
    async (session: MediaSession, force = false) => {
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
        if (
          message.toLowerCase().includes("vosk") ||
          message.toLowerCase().includes("python") ||
          message.toLowerCase().includes("ffmpeg") ||
          message.includes("模型")
        ) {
          setSpeechDialogMessage(message);
        } else {
          setPageError(message);
        }
      } finally {
        setTranscriptionLoadingToken("");
        setTranscriptionStartedAt(null);
      }
    },
    [ensureSpeechReady, loadBatchStatus],
  );

  const startBatchTranscription = useCallback(
    async (force = false) => {
      setBatchStarting(true);
      setPageError("");
      try {
        await ensureSpeechReady();
        const status = await bridge.startMediaBatchTranscription(force);
        setBatchStatus(status);
      } catch (err) {
        const message = err instanceof Error ? err.message : "批量转写启动失败";
        if (
          message.toLowerCase().includes("vosk") ||
          message.toLowerCase().includes("python") ||
          message.toLowerCase().includes("ffmpeg") ||
          message.includes("模型")
        ) {
          setSpeechDialogMessage(message);
        } else {
          setPageError(message);
        }
      } finally {
        setBatchStarting(false);
      }
    },
    [ensureSpeechReady],
  );

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

  useEffect(
    () => () => {
      if (playbackUrl) {
        URL.revokeObjectURL(playbackUrl);
      }
    },
    [playbackUrl],
  );

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
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          正在识别 RTP / RTSP / Moonlight / GameStream 并尝试还原媒体流...
        </div>
      )}

      <MediaAnalysisProgressPanel progress={mediaAnalysisProgress} />

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <BatchTranscriptionStatusPanel batchStatus={batchStatus} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="相关流量包" value={analysis.totalMediaPackets.toLocaleString()} />
        <StatCard title="协议标签" value={String(analysis.protocols.length)} />
        <StatCard title="会话数" value={analysis.sessions.length.toLocaleString()} />
        <StatCard
          title="已导出媒体流"
          value={analysis.sessions.filter((item) => item.artifact).length.toLocaleString()}
        />
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
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">
              当前抓包未识别到媒体流。
            </div>
          ) : (
            analysis.notes.map((note, index) => (
              <div
                key={`${note}-${index}`}
                className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2"
              >
                <Video className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                <span>{note}</span>
              </div>
            ))
          )}
        </div>
      </Panel>

      <MediaSessionTable
        sessions={analysis.sessions}
        batchStatus={batchStatus}
        transcriptions={transcriptions}
        transcriptionLoadingToken={transcriptionLoadingToken}
        transcriptionStartedAt={transcriptionStartedAt}
        batchTokenStartedAt={batchTokenStartedAt}
        progressClock={progressClock}
        playbackLoadingToken={playbackLoadingToken}
        onCopyText={copyText}
        onDownloadArtifact={downloadArtifact}
        onOpenPlayback={openPlayback}
        onRunTranscription={runTranscription}
      />

      <MediaTranscriptionSummaryPanel
        batchStatus={batchStatus}
        transcriptions={transcriptions}
        onCopyText={copyText}
        onExportBatchTranscription={exportBatchTranscription}
      />

      <MediaPlaybackDialog playbackSession={playbackSession} playbackUrl={playbackUrl} onClose={closePlayback} />

      <MediaDependencyDialogs
        ffmpegDialogMessage={ffmpegDialogMessage}
        speechDialogMessage={speechDialogMessage}
        onFfmpegDialogMessageChange={setFfmpegDialogMessage}
        onSpeechDialogMessageChange={setSpeechDialogMessage}
      />
    </PageShell>
  );
}
