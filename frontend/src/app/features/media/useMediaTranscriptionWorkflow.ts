/**
 * Stability: beta
 *
 * Batch media transcription depends on an external Vosk speech-to-text
 * runtime that must be installed and configured by the operator. Supported
 * languages, acoustic models, and accuracy characteristics are not yet fully
 * documented. Treat transcripts as advisory input to evidence review.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus, SpeechToTextStatus } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { copyTextToClipboard } from "../../utils/browserFile";
import { mergeBatchTranscriptions, routeMediaWorkflowError } from "./mediaTranscriptionRules";
import { EMPTY_BATCH_STATUS } from "./useMediaAnalysis";
import { useMediaPlaybackWorkflow } from "./useMediaPlaybackWorkflow";

export { isMediaDependencyError, mergeBatchTranscriptions } from "./mediaTranscriptionRules";

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
  const [speechDialogMessage, setSpeechDialogMessage] = useState("");
  const [speechStatus, setSpeechStatus] = useState<SpeechToTextStatus | null>(null);
  const [transcriptionLoadingToken, setTranscriptionLoadingToken] = useState("");
  const [transcriptionStartedAt, setTranscriptionStartedAt] = useState<number | null>(null);
  const [batchStarting, setBatchStarting] = useState(false);
  const [batchTokenStartedAt, setBatchTokenStartedAt] = useState<number | null>(null);
  const [progressClock, setProgressClock] = useState(() => Date.now());
  const playback = useMediaPlaybackWorkflow({ setError });

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
      const status = await backendClients.media.getMediaBatchTranscriptionStatus();
      setBatchStatus(status);
      if (status.items.length > 0) {
        setTranscriptions((prev) => mergeBatchTranscriptions(prev, status, speechStatus));
      }
    } catch {
      setBatchStatus(EMPTY_BATCH_STATUS);
    }
  }, [backendConnected, setBatchStatus, setTranscriptions, speechStatus]);

  const ensureSpeechReady = useCallback(async () => {
    const nextStatus = await backendClients.runtime.checkSpeechToText();
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
        const result = await backendClients.media.transcribeMediaArtifact(session.artifact.token, force);
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
        const status = await backendClients.media.startMediaBatchTranscription(force);
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
      const status = await backendClients.media.cancelMediaBatchTranscription();
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
      await backendClients.media.exportMediaBatchTranscription(format);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "批量转写导出失败");
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

  return {
    error,
    hasAudioArtifacts,
    playbackSession: playback.playbackSession,
    playbackUrl: playback.playbackUrl,
    playbackLoadingToken: playback.playbackLoadingToken,
    ffmpegDialogMessage: playback.ffmpegDialogMessage,
    speechDialogMessage,
    transcriptionLoadingToken,
    transcriptionStartedAt,
    batchStarting,
    batchTokenStartedAt,
    progressClock,
    setFfmpegDialogMessage: playback.setFfmpegDialogMessage,
    setSpeechDialogMessage,
    copyText,
    exportBatchTranscription,
    downloadArtifact: playback.downloadArtifact,
    closePlayback: playback.closePlayback,
    openPlayback: playback.openPlayback,
    runTranscription,
    startBatchTranscription,
    cancelBatchTranscription,
  };
}
