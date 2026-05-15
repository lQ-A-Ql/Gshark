import type { ToolRuntimeSnapshot } from "../core/types";

export function capturePathHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时使用后端进程的 PATH 或 Windows 默认 Wireshark 目录探测结果。",
    autoDetectedPathHint(snapshot?.tshark.available, value, snapshot?.tshark.path, "TShark"),
  );
}

export function ffmpegPathHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时优先使用后端进程的 GSHARK_FFMPEG，未设置时再走 PATH 探测；保存只提交输入框中的显式值。",
    autoDetectedPathHint(snapshot?.ffmpeg.available, value, snapshot?.ffmpeg.path, "FFmpeg"),
  );
}

export function pythonPathHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时优先使用后端进程的 GSHARK_PYTHON，未设置时再尝试默认 Python 3。",
    autoDetectedPathHint(snapshot?.speech.pythonAvailable, value, snapshot?.speech.pythonCommand, "Python"),
  );
}

export function voskModelPathHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时优先使用后端进程的 GSHARK_VOSK_MODEL，未设置时再检查默认模型目录。",
    autoDetectedPathHint(snapshot?.speech.modelAvailable, value, snapshot?.speech.modelPath, "Vosk 模型"),
  );
}

export function yaraBinHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时使用 PATH 探测，保存不会自动把探测路径写入配置。",
    autoDetectedPathHint(snapshot?.yara.available, value, snapshot?.yara.path, "YARA"),
  );
}

export function yaraRulesHint(snapshot?: ToolRuntimeSnapshot | null, value = "") {
  return joinHints(
    "留空时使用内置规则资源或默认规则目录，保存只提交输入框中的显式值。",
    autoDetectedPathHint(Boolean(snapshot?.yara.rulePath), value, snapshot?.yara.rulePath, "YARA 规则"),
  );
}

export function autoDetectedPathHint(available?: boolean, configValue = "", detectedPath = "", label = "") {
  if (configValue.trim() || !available || !detectedPath.trim()) return "";
  return `${label} 当前通过 PATH/默认路径探测到：${detectedPath}。填写并保存后才会固定为显式配置。`;
}

export function joinHints(...items: Array<string | undefined>) {
  return items
    .map((item) => String(item ?? "").trim())
    .filter(Boolean)
    .join(" ");
}
