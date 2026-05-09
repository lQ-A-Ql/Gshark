import { useCallback, useEffect, useMemo, useState } from "react";

const FILTER_HISTORY_KEY = "gshark.filter-history.v1";
const MAX_FILTER_HISTORY = 12;

const DEFAULT_FILTER_SUGGESTIONS = [
  "http",
  "tcp",
  "udp",
  "dns",
  "tls",
  "arp",
  "icmp",
  "ip",
  "ipv6",
  'tcp contains "GET"',
  "http.request",
  "http.response",
  'http.host contains "bing"',
  'http.request.uri contains "login"',
  'http.content_type contains "json"',
  "tcp.stream == 39",
  "udp.stream == 1",
  "tcp.flags.syn == 1 and tcp.flags.ack == 0",
  "frame.len > 1000",
  "frame.number >= 100 and frame.number <= 500",
  "ip.addr == 192.168.204.146",
  "ip.src == 192.168.1.10",
  "ip.dst == 10.0.0.5",
  "tcp.port == 80",
  "udp.port == 53",
  "http.request.method == POST",
  "http.response.code == 200",
  "http and http.request.method == POST",
];

export function useWorkspaceFilterHistory() {
  const [recentFilters, setRecentFilters] = useState<string[]>([]);

  const filterSuggestions = useMemo(() => {
    const merged = [...recentFilters, ...DEFAULT_FILTER_SUGGESTIONS];
    return Array.from(new Set(merged.map((item) => item.trim()).filter(Boolean)));
  }, [recentFilters]);

  const persistRecentFilters = useCallback((items: string[]) => {
    setRecentFilters(items);
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(FILTER_HISTORY_KEY, JSON.stringify(items));
    } catch {
      // ignore persistence errors
    }
  }, []);

  const rememberFilter = useCallback(
    (rawValue: string) => {
      const value = rawValue.trim();
      if (!value) return;
      const next = [value, ...recentFilters.filter((item) => item !== value)].slice(0, MAX_FILTER_HISTORY);
      persistRecentFilters(next);
    },
    [persistRecentFilters, recentFilters],
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = window.localStorage.getItem(FILTER_HISTORY_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return;
      const cleaned = parsed
        .map((item) => String(item ?? "").trim())
        .filter(Boolean)
        .slice(0, MAX_FILTER_HISTORY);
      setRecentFilters(cleaned);
    } catch {
      // ignore malformed history
    }
  }, []);

  return {
    filterSuggestions,
    rememberFilter,
    clearFilterHistory: () => persistRecentFilters([]),
  };
}
