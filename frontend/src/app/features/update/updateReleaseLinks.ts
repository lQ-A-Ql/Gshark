const SAFE_RELEASE_MARKDOWN_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;
const SAFE_RELEASE_MARKDOWN_BASE_URL = "https://gshark.local/";

export function normalizeReleaseMarkdownHref(href?: string): string | null {
  if (!href) {
    return null;
  }

  const trimmedHref = href.trim();
  if (!trimmedHref || CONTROL_CHAR_RE.test(trimmedHref) || trimmedHref.startsWith("//")) {
    return null;
  }

  const hasExplicitProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmedHref);
  try {
    const base = new URL(SAFE_RELEASE_MARKDOWN_BASE_URL);
    const url = hasExplicitProtocol ? new URL(trimmedHref) : new URL(trimmedHref, base);
    if (!SAFE_RELEASE_MARKDOWN_PROTOCOLS.has(url.protocol)) {
      return null;
    }
    return hasExplicitProtocol ? url.href : url.origin === base.origin ? trimmedHref : null;
  } catch {
    return null;
  }
}
