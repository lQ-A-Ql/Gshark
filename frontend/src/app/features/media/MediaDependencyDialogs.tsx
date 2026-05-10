import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../components/ui/alert-dialog";

interface MediaDependencyDialogsProps {
  ffmpegDialogMessage: string;
  speechDialogMessage: string;
  onFfmpegDialogMessageChange: (message: string) => void;
  onSpeechDialogMessageChange: (message: string) => void;
}

export function MediaDependencyDialogs({
  ffmpegDialogMessage,
  speechDialogMessage,
  onFfmpegDialogMessageChange,
  onSpeechDialogMessageChange,
}: MediaDependencyDialogsProps) {
  return (
    <>
      <AlertDialog
        open={Boolean(ffmpegDialogMessage)}
        onOpenChange={(open) => {
          if (!open) onFfmpegDialogMessageChange("");
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>缺少 ffmpeg</AlertDialogTitle>
            <AlertDialogDescription>
              {ffmpegDialogMessage || "未在环境变量 PATH 中找到 ffmpeg，请先安装 ffmpeg 并将其加入 PATH。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => onFfmpegDialogMessageChange("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={Boolean(speechDialogMessage)}
        onOpenChange={(open) => {
          if (!open) onSpeechDialogMessageChange("");
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>语音转写不可用</AlertDialogTitle>
            <AlertDialogDescription>
              {speechDialogMessage || "本地语音转写依赖未就绪，请检查 Python、vosk 模块、模型目录与 ffmpeg。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => onSpeechDialogMessageChange("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
