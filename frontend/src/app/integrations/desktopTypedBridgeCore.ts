import { assertDesktopBlobWithinLimit, withDesktopIpcControls } from "./desktopIpcControls";

export const DEFAULT_TYPED_IPC_TIMEOUT_MS = 10000;
export const LONG_TYPED_IPC_TIMEOUT_MS = 60000;

export async function typedCall<T>(
  operation: () => Promise<T>,
  endpoint: string,
  signal?: AbortSignal,
  timeoutMs = DEFAULT_TYPED_IPC_TIMEOUT_MS,
): Promise<T> {
  return await withDesktopIpcControls(operation, {
    endpoint,
    responseKind: "typed-ipc",
    signal,
    timeoutMs,
  });
}

export async function typedBlobCall(
  operation: () => Promise<unknown>,
  endpoint: string,
  signal?: AbortSignal,
): Promise<Blob> {
  const payload = (await typedCall(operation, endpoint, signal, LONG_TYPED_IPC_TIMEOUT_MS)) as {
    data_base64?: unknown;
    content_type?: unknown;
    size?: unknown;
  };
  assertDesktopBlobWithinLimit(payload, endpoint);
  return base64ToBlob(String(payload.data_base64 ?? ""), String(payload.content_type ?? "application/octet-stream"));
}

function base64ToBlob(dataBase64: string, contentType: string): Blob {
  const binary = atob(dataBase64 || "");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new Blob([bytes], { type: contentType || "application/octet-stream" });
}
