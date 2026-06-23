export const DEFAULT_BACKEND_API_BASE = "http://127.0.0.1:17891";

export const API_BASE = normalizeBackendApiBase(
  (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? DEFAULT_BACKEND_API_BASE,
);

export function buildBackendEndpoint(path: string, apiBase = API_BASE): string {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${normalizeBackendApiBase(apiBase)}${cleanPath}`;
}

function normalizeBackendApiBase(apiBase: string): string {
  const trimmed = apiBase.trim() || DEFAULT_BACKEND_API_BASE;
  return trimmed.replace(/\/+$/, "");
}
