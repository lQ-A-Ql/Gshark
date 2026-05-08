export type WinRMPreviewMode = "full" | "extract" | "command" | "stdout" | "stderr";

export interface WinRMExtractEntry {
  header: string;
  command: string;
  stdin: string;
  stdout: string;
  stderr: string;
}

export const winrmPreviewModeLabels: Record<WinRMPreviewMode, string> = {
  full: "完整原文",
  extract: "仅提取结果",
  command: "仅看 Command",
  stdout: "仅看 Stdout",
  stderr: "仅看 Stderr",
};

export const winrmPreviewModes: WinRMPreviewMode[] = ["full", "extract", "command", "stdout", "stderr"];

export function parseWinRMExtractEntries(raw: string): WinRMExtractEntry[] {
  const lines = raw.replaceAll("\r\n", "\n").split("\n");
  const entries: WinRMExtractEntry[] = [];
  let currentHeader = "";
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    if (line.startsWith("No: ")) {
      currentHeader = line.trim();
      index++;
      continue;
    }
    if (line.trim() !== "[extract]") {
      index++;
      continue;
    }

    const entry: WinRMExtractEntry = {
      header: currentHeader || "No: unknown frame",
      command: "",
      stdin: "",
      stdout: "",
      stderr: "",
    };
    index++;
    let currentField: keyof Omit<WinRMExtractEntry, "header"> | null = null;
    let buffer: string[] = [];

    const flush = () => {
      if (!currentField) return;
      entry[currentField] = buffer.join("\n").replace(/\s+$/g, "");
      currentField = null;
      buffer = [];
    };

    while (index < lines.length) {
      const currentLine = lines[index];
      if (currentLine.startsWith("No: ") || currentLine.trim() === "[extract]") {
        break;
      }

      const fieldName = currentLine.trim().replace(/:$/, "");
      if (fieldName === "command" || fieldName === "stdin" || fieldName === "stdout" || fieldName === "stderr") {
        flush();
        currentField = fieldName;
        index++;
        continue;
      }

      if (!currentField) {
        if (currentLine.trim() === "") {
          index++;
          continue;
        }
        break;
      }

      if (currentLine.startsWith("  ")) {
        buffer.push(currentLine.slice(2));
        index++;
        continue;
      }
      if (currentLine === "") {
        buffer.push("");
        index++;
        continue;
      }
      break;
    }

    flush();
    if (entry.command || entry.stdin || entry.stdout || entry.stderr) {
      entries.push(entry);
    }
  }

  return entries;
}

export function renderWinRMPreviewMode(entries: WinRMExtractEntry[], mode: Exclude<WinRMPreviewMode, "full">): string {
  if (entries.length === 0) {
    return "当前结果中没有可展示的提取块。请确认该抓包里存在可提取的 WinRM command 或回显内容。";
  }

  const blocks = entries.map((entry) => formatWinRMExtractEntry(entry, mode)).filter((block) => block.length > 0);

  if (blocks.length === 0) {
    return `当前结果里没有可展示的 ${winrmPreviewModeLabels[mode]} 内容。`;
  }
  return blocks.join("\n\n");
}

export function formatWinRMExtractEntry(entry: WinRMExtractEntry, mode: Exclude<WinRMPreviewMode, "full">): string {
  const sections: string[] = [];
  if (mode === "extract") {
    if (entry.command) sections.push("command:\n" + indentPreviewText(entry.command));
    if (entry.stdin) sections.push("stdin:\n" + indentPreviewText(entry.stdin));
    if (entry.stdout) sections.push("stdout:\n" + indentPreviewText(entry.stdout));
    if (entry.stderr) sections.push("stderr:\n" + indentPreviewText(entry.stderr));
  }
  if (mode === "command" && entry.command) sections.push("command:\n" + indentPreviewText(entry.command));
  if (mode === "stdout" && entry.stdout) sections.push("stdout:\n" + indentPreviewText(entry.stdout));
  if (mode === "stderr" && entry.stderr) sections.push("stderr:\n" + indentPreviewText(entry.stderr));
  if (sections.length === 0) {
    return "";
  }
  return entry.header + "\n" + sections.join("\n");
}

function indentPreviewText(raw: string): string {
  return raw
    .split("\n")
    .map((line) => `  ${line}`)
    .join("\n");
}
