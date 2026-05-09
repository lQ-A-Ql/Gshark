import { useCallback, useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus, SpeechToTextStatus } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { copyTextToClipboard } from "../../utils/browserFile";
import { EMPTY_BATCH_STATUS } from "./useMediaAnalysis";

interface UseMediaTranscriptionWorkflowOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  captureRevision: number;
  sessions: MediaSession[];
  batchStatus: SpeechBatchTaskStatus;
  setBatchStatus: Dispatch<SetStateAction<SpeechBatchTaskStatus>>;
  setTranscriptions: Dispatch<SetStateAction<Record<string, MediaTranscription>>>;
}

export function useMediaTranscriptionWorkflow({
  backendConnected,
  isPreloadingCapture,
  captureRevision,
  sessions,
  batchStatus,
  setBatchStatus,
  setTranscriptions,
}: UseMediaTranscriptionWorkflowOptions) {
  const [error, setError] = useState("");
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
    () => sessions.some((session) => session.mediaType === "audio" && session.artifact),
    [sessions],
  );

  const loadBatchStatus = useCallback(async () => {
    if (!backendConnected) {
      setBatchStatus(EMPTY_BATCH_STATUS);
      return;
    }
    try {
      const status = await bridge.getMediaBatchTranscriptionStatus();
      setBatchStatus(status);
      if (status.items.length > 0) {
        setTranscriptions((prev) => mergeBatchTranscriptions(prev, status, speechStatus));
      }
    } catch {
      setBatchStatus(EMPTY_BATCH_STATUS);
    }
  }, [backendConnected, setBatchStatus, setTranscriptions, speechStatus]);

  const ensureSpeechReady = useCallback(async () => {
    const nextStatus = await bridge.checkSpeechToText();
    setSpeechStatus(nextStatus);
    if (!nextStatus.available) {
      const message = nextStatus.message || "语音转写依赖未就绪。";
      setSpeechDialogMessage(message);
      throw new Error(message);
    }
    return nextStatus;
  }, []);

  const runTranscription = useCallback(
    async (session: MediaSession, force = false) => {
      if (!session.artifact) return;
      setTranscriptionLoadingToken(session.artifact.token);
      setTranscriptionStartedAt(Date.now());
      setError("");
      try {
        await ensureSpeechReady();
        const result = await bridge.transcribeMediaArtifact(session.artifact.token, force);
        setTranscriptions((prev) => ({ ...prev, [result.token]: result }));
        await loadBatchStatus();
      } catch (err) {
        routeMediaWorkflowError(err, setError, setSpeechDialogMessage, "音频转写失败");
      } finally {
        setTranscriptionLoadingToken("");
        setTranscriptionStartedAt(null);
      }
    },
    [ensureSpeechReady, loadBatchStatus, setTranscriptions],
  );

  const startBatchTranscription = useCallback(
    async (force = false) => {
      setBatchStarting(true);
      setError("");
      try {
        await ensureSpeechReady();
        const status = await bridge.startMediaBatchTranscription(force);
        setBatchStatus(status);
      } catch (err) {
        routeMediaWorkflowError(err, setError, setSpeechDialogMessage, "批量转写启动失败");
      } finally {
        setBatchStarting(false);
      }
    },
    [ensureSpeechReady, setBatchStatus],
  );

  const cancelBatchTranscription = useCallback(async () => {
    try {
      const status = await bridge.cancelMediaBatchTranscription();
      setBatchStatus(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : "取消批量转写失败");
    }
  }, [setBatchStatus]);

  const copyText = useCallback(async (text: string) => {
    if (await copyTextToClipboard(text)) {
      setError("");
    } else {
      setError("复制文本失败");
    }
  }, []);

  const exportBatchTranscription = useCallback(async (format: "txt" | "json") => {
    try {
      await bridge.exportMediaBatchTranscription(format);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "批量转写导出失败");
    }
  }, []);

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
      if (current) URL.revokeObjectURL(current);
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
        setFfmpegDialogMessage(ffmpeg.message || "未检测到 ffmpeg，请先将 ffmpeg 加入环境变量 PATH。");
        return;
      }
      const blob = await bridge.getMediaPlaybackBlob(session.artifact.token);
      const nextUrl = URL.createObjectURL(blob);
      setPlaybackUrl((current) => {
        if (current) URL.revokeObjectURL(current);
        return nextUrl;
      });
      setPlaybackSession(session);
    } catch (err) {
      const message = err instanceof Error ? err.message : "媒体播放初始化失败";
      if (isMediaDependencyError(message)) {
        setFfmpegDialogMessage(message);
      } else {
        setError(message);
      }
    } finally {
      setPlaybackLoadingToken("");
    }
  }, []);

  useEffect(() => {
    setTranscriptions({});
    setBatchStatus(EMPTY_BATCH_STATUS);
    setSpeechStatus(null);
    if (!isPreloadingCapture) {
      void loadBatchStatus();
    }
  }, [captureRevision, isPreloadingCapture, loadBatchStatus, setBatchStatus, setTranscriptions]);

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
    if (!transcriptionLoadingToken && !batchStatus.currentToken) return;
    const timer = window.setInterval(() => {
      setProgressClock(Date.now());
    }, 280);
    return () => window.clearInterval(timer);
  }, [batchStatus.currentToken, transcriptionLoadingToken]);

  useEffect(
    () => () => {
      if (playbackUrl) URL.revokeObjectURL(playbackUrl);
    },
    [playbackUrl],
  );

  return {
    error,
    hasAudioArtifacts,
    playbackSession,
    playbackUrl,
    playbackLoadingToken,
    ffmpegDialogMessage,
    speechDialogMessage,
    transcriptionLoadingToken,
    transcriptionStartedAt,
    batchStarting,
    batchTokenStartedAt,
    progressClock,
    setFfmpegDialogMessage,
    setSpeechDialogMessage,
    copyText,
    exportBatchTranscription,
    downloadArtifact,
    closePlayback,
    openPlayback,
    runTranscription,
    startBatchTranscription,
    cancelBatchTranscription,
  };
}

export function isMediaDependencyError(message: string) {
  const lower = message.toLowerCase();
  return lower.includes("vosk") || lower.includes("python") || lower.includes("ffmpeg") || message.includes("模型");
}

export function mergeBatchTranscriptions(
  prev: Record<string, MediaTranscription>,
  status: SpeechBatchTaskStatus,
  speechStatus: SpeechToTextStatus | null,
) {
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
}

function routeMediaWorkflowError(
  err: unknown,
  setError: (message: string) => void,
  setSpeechDialogMessage: (message: string) => void,
  fallback: string,
) {
  const message = err instanceof Error ? err.message : fallback;
  if (isMediaDependencyError(message)) {
    setSpeechDialogMessage(message);
  } else {
    setError(message);
  }
}
