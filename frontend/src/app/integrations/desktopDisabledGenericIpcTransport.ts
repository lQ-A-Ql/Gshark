import { DesktopIpcRequestError, type IpcBackendTransport } from "./desktopIpcControls";
import { subscribeDesktopEvents } from "./desktopEventTransport";

export function createDisabledGenericIpcBackendTransport(): IpcBackendTransport {
  return {
    async requestJSON(path: string, init?: RequestInit): Promise<never> {
      return throwGenericIpcDisabled(path, init);
    },
    async requestBlob(path: string, init?: RequestInit) {
      return throwGenericIpcDisabled(path, init);
    },
    async requestText(path: string, init?: RequestInit) {
      return throwGenericIpcDisabled(path, init);
    },
    subscribeEvents(handlers) {
      return subscribeDesktopEvents(handlers);
    },
  };
}

function throwGenericIpcDisabled(path: string, init?: RequestInit): never {
  if (init?.signal?.aborted) {
    throw new DOMException("The operation was aborted.", "AbortError");
  }
  throw new DesktopIpcRequestError(
    "generic_ipc_disabled",
    `桌面 generic IPC adapter 已被策略禁用，缺少 typed IPC 覆盖：${path}。如需回滚兼容路径，设置 VITE_DESKTOP_GENERIC_IPC_POLICY=compat。`,
    path,
    0,
  );
}
