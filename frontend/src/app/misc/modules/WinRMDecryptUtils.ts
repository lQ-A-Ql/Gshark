import type { WinRMDecryptRequest } from "../../core/types";

export type WinRMAuthMode = WinRMDecryptRequest["authMode"];

export const DEFAULT_WINRM_PORT = "5985";
export const DEFAULT_WINRM_PREVIEW_LINES = "200";

export interface WinRMDecryptFormValues {
  authMode: WinRMAuthMode;
  hash: string;
  password: string;
  port: string;
  previewLines: string;
}

export interface WinRMResultResetState {
  error: string;
  previewDialogError: string;
  previewDialogText: string;
  previewOpen: boolean;
  result: null;
}

export function sanitizeWinRMNumericInput(value: string) {
  return value.replace(/[^0-9]/g, "");
}

export function parseWinRMNumericInput(value: string) {
  return Number(sanitizeWinRMNumericInput(value) || "0");
}

export function buildWinRMDecryptRequest(values: WinRMDecryptFormValues): WinRMDecryptRequest {
  return {
    port: parseWinRMNumericInput(values.port),
    authMode: values.authMode,
    password: values.authMode === "password" ? values.password : "",
    ntHash: values.authMode === "nt_hash" ? values.hash : "",
    previewLines: parseWinRMNumericInput(values.previewLines),
    includeErrorFrames: false,
    extractCommandOutput: true,
  };
}

export function getWinRMResultResetState(): WinRMResultResetState {
  return {
    error: "",
    previewDialogError: "",
    previewDialogText: "",
    previewOpen: false,
    result: null,
  };
}
