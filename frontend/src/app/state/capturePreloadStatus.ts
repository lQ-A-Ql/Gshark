export const CAPTURE_PRELOAD_TIMEOUT_MS = 120000;

export function getCaptureOpenDisconnectedStatus(): string {
  return "桌面后端未连接，无法打开文件";
}

export function getCapturePreloadWorkingStatus(fileName: string): string {
  return `正在预加载全部数据: ${fileName}`;
}

export function getCapturePreloadDoneStatus(fileName: string): string {
  return `预加载完成，可浏览全部流量: ${fileName}`;
}

export function getCaptureEmptyParseError(parseError: string): string {
  return parseError || "capture parsing finished without any packets; please verify tshark compatibility";
}

export function getCapturePreloadTimeoutError(): string {
  return "capture parsing timed out before preloading finished";
}

export function getCaptureOpenErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "打开文件失败";
}
