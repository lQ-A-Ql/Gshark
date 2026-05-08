const CAPTURE_LIFECYCLE_KEYWORDS = ["解析", "预加载", "威胁分析", "媒体流"] as const;

export function isProgressStatusMessage(message: string): boolean {
  return message.startsWith("__progress__:");
}

export function isCaptureLifecycleMessage(message: string): boolean {
  if (isProgressStatusMessage(message)) {
    return true;
  }
  return CAPTURE_LIFECYCLE_KEYWORDS.some((keyword) => message.includes(keyword));
}

export function shouldIgnoreCaptureStatusWithoutActiveCapture(message: string, hasActiveCapture: boolean): boolean {
  return !hasActiveCapture && isCaptureLifecycleMessage(message);
}

export function shouldIgnoreCaptureErrorWithoutActiveCapture(message: string, hasActiveCapture: boolean): boolean {
  return !hasActiveCapture && CAPTURE_LIFECYCLE_KEYWORDS.some((keyword) => message.includes(keyword));
}

export function shouldMarkParseFinishedFromStatus(message: string): boolean {
  return message.includes("解析完成") || message.includes("解析失败") || message.includes("解析被取消");
}

export function shouldMarkParseErrorFromStatus(message: string): boolean {
  return message.includes("解析失败");
}

export function shouldResetMediaAnalysisFromStatus(message: string): boolean {
  return message.includes("媒体流分析完成") || message.includes("媒体流分析失败");
}

export function shouldResetThreatAnalysisFromStatus(message: string): boolean {
  return message.includes("威胁分析完成") || message.includes("威胁分析失败");
}

export function shouldResetMediaAnalysisFromError(message: string): boolean {
  return message.includes("媒体流");
}

export function shouldResetThreatAnalysisFromError(message: string): boolean {
  return message.includes("威胁分析");
}
