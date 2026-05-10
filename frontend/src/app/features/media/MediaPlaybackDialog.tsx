import { Headphones } from "lucide-react";
import type { MediaSession } from "../../core/types";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../components/ui/dialog";

interface MediaPlaybackDialogProps {
  playbackSession: MediaSession | null;
  playbackUrl: string;
  onClose: () => void;
}

export function MediaPlaybackDialog({ playbackSession, playbackUrl, onClose }: MediaPlaybackDialogProps) {
  return (
    <Dialog
      open={Boolean(playbackSession)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>媒体播放</DialogTitle>
          <DialogDescription>
            {playbackSession
              ? `${playbackSession.application || "媒体流"} · ${playbackSession.codec || "未知编码"} · ${playbackSession.source}:${playbackSession.sourcePort} -> ${playbackSession.destination}:${playbackSession.destinationPort}`
              : "使用 ffmpeg 将裸流转为浏览器可播放的音视频文件。"}
          </DialogDescription>
        </DialogHeader>
        <div
          className={`overflow-hidden rounded-lg border border-border ${
            playbackSession?.mediaType === "audio"
              ? "bg-gradient-to-br from-slate-50 via-rose-50 to-orange-50 p-6"
              : "bg-black"
          }`}
        >
          {playbackUrl ? (
            playbackSession?.mediaType === "audio" ? (
              <div className="flex min-h-48 flex-col items-center justify-center gap-4 text-center">
                <div className="inline-flex h-16 w-16 items-center justify-center rounded-full bg-white/80 text-rose-600 shadow-sm">
                  <Headphones className="h-8 w-8" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-foreground">{playbackSession.codec || "音频流"}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {playbackSession.source}:{playbackSession.sourcePort} {"->"} {playbackSession.destination}:
                    {playbackSession.destinationPort}
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
            <div
              className={`flex items-center justify-center text-sm ${
                playbackSession?.mediaType === "audio" ? "min-h-48 text-muted-foreground" : "aspect-video text-white/70"
              }`}
            >
              正在准备媒体播放...
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
