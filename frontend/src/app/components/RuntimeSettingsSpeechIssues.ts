import type { ToolRuntimeSnapshot } from "../core/types";

export function buildSpeechIssues(snapshot?: ToolRuntimeSnapshot | null) {
  const speech = snapshot?.speech;
  if (!speech) return [];
  const issues: string[] = [];
  if (!speech.pythonAvailable) issues.push("Python 不可用");
  if (!speech.voskAvailable) issues.push("vosk 模块缺失");
  if (!speech.modelAvailable) issues.push("Vosk 模型目录缺失");
  if (!speech.ffmpegAvailable) issues.push("ffmpeg 不可用");
  return issues;
}
