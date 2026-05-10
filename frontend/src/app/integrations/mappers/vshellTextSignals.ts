const vshellLowInfoControlMaxBytes = 24;

export function hasMeaningfulVisibleText(value: string): boolean {
  const normalized = stripAnsiControlSequences(value).replace(/[\u0000-\u001f\u007f]/g, "");
  const visibleChars = Array.from(normalized).filter((char) => /\S/.test(char));
  if (visibleChars.length < 2) {
    return false;
  }
  if (hasForensicTextSignal(normalized)) {
    return true;
  }
  const meaningfulChars = visibleChars.filter((char) => /[\p{L}\p{N}_{}\[\]:"'./\\=&()\-]/u.test(char));
  if (meaningfulChars.length >= 3) {
    return true;
  }
  return false;
}

export function isTimestampOnlyText(value: string): boolean {
  const normalized = stripAnsiControlSequences(value).trim();
  if (!normalized) {
    return false;
  }
  if (/^\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?$/.test(normalized)) {
    return true;
  }
  if (/^\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(normalized)) {
    return true;
  }
  if (/^\d{10}$/.test(normalized)) {
    const epochMs = Number(normalized) * 1000;
    return epochMs >= Date.UTC(2000, 0, 1) && epochMs <= Date.UTC(2100, 0, 1);
  }
  if (/^\d{13}$/.test(normalized)) {
    const epochMs = Number(normalized);
    return epochMs >= Date.UTC(2000, 0, 1) && epochMs <= Date.UTC(2100, 0, 1);
  }
  return false;
}

export function hasForensicTextSignal(value: string): boolean {
  const normalized = value.trim();
  if (!normalized) {
    return false;
  }
  if (/^\s*[\[{]/.test(value)) {
    return true;
  }
  if (/\b(?:ok|id|ip|cmd|whoami|powershell|verifykey|hacked_by|fallsnow|paperplane)\b/i.test(normalized)) {
    return true;
  }
  if (/\b\d+(?:\.\d+){1,3}\b/.test(normalized)) {
    return true;
  }
  if (
    /(?:[A-Za-z]:\\|\\\\|\/(?:bin|etc|home|tmp|usr|var)\/|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/.test(
      normalized,
    )
  ) {
    return true;
  }
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(normalized)) {
    return true;
  }
  return /\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/.test(normalized);
}

export function stripAnsiControlSequences(value: string): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "");
}

export function normalizePreviewTextForDisplay(value: string): { text: string; ansiStripped: boolean } {
  const ansiStripped = stripAnsiControlSequences(value);
  const controlCleaned = ansiStripped
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001a\u001c-\u001f\u007f]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  return {
    text: controlCleaned.trim(),
    ansiStripped: ansiStripped !== value,
  };
}

export function getVShellLowInfoControlMaxBytes(): number {
  return vshellLowInfoControlMaxBytes;
}
