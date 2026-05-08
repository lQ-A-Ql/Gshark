import { useEffect, useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { ErrorBlock } from "../ui";

type WinRMPreviewMode = "full" | "extract" | "command" | "stdout" | "stderr";

interface WinRMExtractEntry {
  header: string;
  command: string;
  stdin: string;
  stdout: string;
  stderr: string;
}

interface WinRMPreviewDialogProps {
  error: string;
  loading: boolean;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  text: string;
  title: string;
}

const winrmPreviewModeLabels: Record<WinRMPreviewMode, string> = {
  full: "完整原文",
  extract: "仅提取结果",
  command: "仅看 Command",
  stdout: "仅看 Stdout",
  stderr: "仅看 Stderr",
};

const winrmPreviewModes: WinRMPreviewMode[] = ["full", "extract", "command", "stdout", "stderr"];

export function WinRMPreviewDialog({ error, loading, onOpenChange, open, text, title }: WinRMPreviewDialogProps) {
  const [previewMode, setPreviewMode] = useState<WinRMPreviewMode>("extract");
  const extractEntries = useMemo(() => parseWinRMExtractEntries(text), [text]);
  const displayText = useMemo(() => {
    if (previewMode === "full") {
      return text;
    }
    return renderWinRMPreviewMode(extractEntries, previewMode);
  }, [extractEntries, previewMode, text]);

  useEffect(() => {
    if (open) {
      setPreviewMode("extract");
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-6xl overflow-hidden p-0">
        <DialogHeader className="border-b border-slate-100 px-6 py-5">
          <DialogTitle>{title}结果预览</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 bg-slate-50/50 px-6 py-5">
          {error && <ErrorBlock message={error} />}
          {!loading && !error && (
            <div className="flex flex-wrap items-center gap-2">
              {winrmPreviewModes.map((mode) => (
                <Button
                  key={mode}
                  variant={previewMode === mode ? "default" : "outline"}
                  size="sm"
                  onClick={() => setPreviewMode(mode)}
                  className={previewMode === mode ? "shadow-sm" : "bg-white"}
                >
                  {winrmPreviewModeLabels[mode]}
                </Button>
              ))}
              {extractEntries.length > 0 && (
                <span className="ml-2 inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600 shadow-sm">
                  已解析 {extractEntries.length} 个提取块
                </span>
              )}
            </div>
          )}
          {loading ? (
            <div className="rounded-lg border border-slate-200 bg-white px-4 py-8 text-center text-sm font-medium text-slate-500 shadow-sm">
              正在加载完整结果...
            </div>
          ) : (
            <pre className="max-h-[68vh] min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-slate-200 bg-white p-5 font-mono text-[13px] leading-relaxed text-slate-800 shadow-sm selection:bg-sky-100">
              {displayText || "(empty result)"}
            </pre>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function parseWinRMExtractEntries(raw: string): WinRMExtractEntry[] {
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

function renderWinRMPreviewMode(entries: WinRMExtractEntry[], mode: Exclude<WinRMPreviewMode, "full">): string {
  if (entries.length === 0) {
    return "当前结果中没有可展示的提取块。请确认该抓包里存在可提取的 WinRM command 或回显内容。";
  }

  const blocks = entries.map((entry) => formatWinRMExtractEntry(entry, mode)).filter((block) => block.length > 0);

  if (blocks.length === 0) {
    return `当前结果里没有可展示的 ${winrmPreviewModeLabels[mode]} 内容。`;
  }
  return blocks.join("\n\n");
}

function formatWinRMExtractEntry(entry: WinRMExtractEntry, mode: Exclude<WinRMPreviewMode, "full">): string {
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
