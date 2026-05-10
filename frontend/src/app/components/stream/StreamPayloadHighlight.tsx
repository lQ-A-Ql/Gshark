import type { ReactNode } from "react";

export function HighlightedPayloadText({ text, highlight }: { text: string; highlight?: string }) {
  return <>{renderHighlightedText(text, highlight)}</>;
}

function renderHighlightedText(text: string, query?: string) {
  const needle = query?.trim();
  if (!needle) return text;

  const lowerText = text.toLowerCase();
  const lowerNeedle = needle.toLowerCase();
  const parts: ReactNode[] = [];
  let cursor = 0;
  let matchIndex = lowerText.indexOf(lowerNeedle);

  while (matchIndex >= 0) {
    if (matchIndex > cursor) {
      parts.push(text.slice(cursor, matchIndex));
    }
    const end = matchIndex + needle.length;
    parts.push(
      <mark
        key={`${matchIndex}-${end}`}
        className="rounded bg-amber-200/90 px-0.5 text-inherit ring-1 ring-amber-300/70"
      >
        {text.slice(matchIndex, end)}
      </mark>,
    );
    cursor = end;
    matchIndex = lowerText.indexOf(lowerNeedle, cursor);
  }

  if (cursor < text.length) {
    parts.push(text.slice(cursor));
  }
  return parts;
}
