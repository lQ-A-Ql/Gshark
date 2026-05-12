import { useCallback, useEffect, useState } from "react";
import type { MediaSession } from "../../core/types";
import { backendClients } from "../../integrations/wailsBridge";
import { isMediaDependencyError } from "./mediaTranscriptionRules";

interface UseMediaPlaybackWorkflowOptions {
  setError: (message: string) => void;
}

export function useMediaPlaybackWorkflow({ setError }: UseMediaPlaybackWorkflowOptions) {
  const [playbackSession, setPlaybackSession] = useState<MediaSession | null>(null);
  const [playbackUrl, setPlaybackUrl] = useState("");
  const [playbackLoadingToken, setPlaybackLoadingToken] = useState("");
  const [ffmpegDialogMessage, setFfmpegDialogMessage] = useState("");

  const downloadArtifact = useCallback(
    async (session: MediaSession) => {
      if (!session.artifact) return;
      try {
        await backendClients.media.downloadMediaArtifact(session.artifact.token, session.artifact.name);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "媒体文件下载失败");
      }
    },
    [setError],
  );

  const closePlayback = useCallback(() => {
    setPlaybackSession(null);
    setPlaybackUrl((current) => {
      if (current) URL.revokeObjectURL(current);
      return "";
    });
  }, []);

  const openPlayback = useCallback(
    async (session: MediaSession) => {
      if (!session.artifact) return;
      setPlaybackLoadingToken(session.artifact.token);
      setError("");
      try {
        const ffmpeg = await backendClients.runtime.checkFFmpeg();
        if (!ffmpeg.available) {
          setFfmpegDialogMessage(ffmpeg.message || "未检测到 ffmpeg，请先将 ffmpeg 加入环境变量 PATH。");
          return;
        }
        const blob = await backendClients.media.getMediaPlaybackBlob(session.artifact.token);
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
    },
    [setError],
  );

  useEffect(
    () => () => {
      if (playbackUrl) URL.revokeObjectURL(playbackUrl);
    },
    [playbackUrl],
  );

  return {
    playbackSession,
    playbackUrl,
    playbackLoadingToken,
    ffmpegDialogMessage,
    setFfmpegDialogMessage,
    downloadArtifact,
    closePlayback,
    openPlayback,
  };
}
