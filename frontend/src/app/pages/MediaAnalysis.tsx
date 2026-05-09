import { Clapperboard } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import type { MediaSession, SpeechToTextStatus } from "../core/types";
import {
  BatchTranscriptionStatusPanel,
  MediaAnalysisProgressPanel,
  MediaDependencyDialogs,
  MediaPlaybackDialog,
} from "../features/media/MediaDisplayPanels";
import {
  MediaBatchActions,
  MediaDistributionPanels,
  MediaLoadingNotice,
  MediaNotesPanel,
  MediaOverviewStats,
} from "../features/media/MediaOverviewPanels";
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

  const hasAudioArtifacts = useMemo(
    () => analysis.sessions.some((s) => s.mediaType === "audio" && s.artifact),
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

      <MediaBatchActions
        hasAudioArtifacts={hasAudioArtifacts}
        batchStarting={batchStarting}
        batchStatus={batchStatus}
        onStartBatchTranscription={(force) => void startBatchTranscription(force)}
        onCancelBatchTranscription={() => void cancelBatchTranscription()}
      />

      <MediaLoadingNotice loading={loading} />

      <MediaAnalysisProgressPanel progress={mediaAnalysisProgress} />

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <BatchTranscriptionStatusPanel batchStatus={batchStatus} />

      <MediaOverviewStats analysis={analysis} />
      <MediaDistributionPanels analysis={analysis} />
      <MediaNotesPanel notes={analysis.notes} />

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
