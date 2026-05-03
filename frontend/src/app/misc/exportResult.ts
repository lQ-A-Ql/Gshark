import { downloadText } from "../utils/browserFile";

export type MiscExportFormat = "json" | "txt";

interface ExportStructuredResultOptions<T> {
  filenameBase: string;
  format: MiscExportFormat;
  payload: T;
  renderText: (payload: T) => string;
}

export function exportStructuredResult<T>({ filenameBase, format, payload, renderText }: ExportStructuredResultOptions<T>) {
  const filename = `${filenameBase}.${format}`;
  const content = format === "json" ? JSON.stringify(payload, null, 2) : renderText(payload);
  downloadText(filename, content, format === "json" ? "application/json;charset=utf-8" : "text/plain;charset=utf-8");
}
