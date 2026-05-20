import { FolderOpen, Square } from "lucide-react";

type CaptureFileControlsProps = {
  capturePath: string;
  onCapturePathChange: (value: string) => void;
  onChooseFile: () => void;
  onOpenPath: () => void;
  onStop: () => void;
  disabled: boolean;
  backendConnected: boolean;
};

export function CaptureFileControls({
  capturePath,
  onCapturePathChange,
  onChooseFile,
  onOpenPath,
  onStop,
  disabled,
  backendConnected,
}: CaptureFileControlsProps) {
  return (
    <div className="gshark-tile-toolbar flex min-w-0 flex-wrap items-center gap-2 px-2 py-1">
      <div className="gshark-field flex w-[320px] min-w-[220px] items-center overflow-hidden">
        <FolderOpen className="ml-2 h-4 w-4 text-muted-foreground" />
        <input
          value={capturePath}
          onChange={(event) => onCapturePathChange(event.target.value)}
          name="capture-path-input"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="none"
          spellCheck={false}
          className="w-full border-none bg-transparent px-2 py-1 text-xs font-mono text-foreground outline-none placeholder:text-muted-foreground"
          placeholder="输入 PCAP/PCAPNG 绝对路径"
        />
      </div>
      <button
        onClick={onChooseFile}
        disabled={disabled}
        className="gshark-control flex items-center gap-1 px-3 py-1 text-xs text-foreground transition-all disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "选择并打开 PCAP/PCAPNG 文件" : "后端未连接"}
      >
        <FolderOpen className="h-3.5 w-3.5 text-blue-600" /> 选择文件
      </button>
      <button
        onClick={onOpenPath}
        disabled={disabled}
        className="gshark-control flex items-center gap-1 px-3 py-1 text-xs text-foreground transition-all disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "按路径打开（适用于本机路径）" : "后端未连接"}
      >
        <FolderOpen className="h-3.5 w-3.5 text-indigo-600" /> 路径打开
      </button>
      <button
        onClick={onStop}
        disabled={!backendConnected}
        className="gshark-control flex items-center gap-1 px-3 py-1 text-xs text-foreground transition-all disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "关闭当前抓包并清理临时数据库" : "后端未连接"}
      >
        <Square className="h-3.5 w-3.5 text-rose-600" /> 关闭抓包
      </button>
    </div>
  );
}
