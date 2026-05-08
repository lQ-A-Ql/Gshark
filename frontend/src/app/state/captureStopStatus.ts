export function getCaptureStopRequestStatus(backendConnected: boolean): string {
  return backendConnected ? "当前抓包已从界面移除，正在请求后端清理线程" : "当前抓包已从界面移除；后端未连接";
}

export function getCaptureCloseErrorMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "关闭抓包失败";
}

export function getCaptureStopDoneStatus(closeError: string): string {
  return closeError ? `当前抓包已从界面移除；后端清理返回: ${closeError}` : "当前抓包已关闭，临时数据库已清理";
}
