import { useEffect, useState } from "react";

const BACKEND_AUTH_TOKEN_TIMEOUT_MS = 1500;

export function useBackendAuthToken(backendConnected: boolean) {
  const [backendAuthToken, setBackendAuthToken] = useState("");
  const [isBackendAuthTokenLoading, setIsBackendAuthTokenLoading] = useState(false);

  useEffect(() => {
    if (!backendConnected) {
      setBackendAuthToken("");
      setIsBackendAuthTokenLoading(false);
      return;
    }

    let cancelled = false;
    const loadToken = async () => {
      setIsBackendAuthTokenLoading(true);
      try {
        const token = await readBackendAuthTokenFromWindow();
        if (!cancelled) {
          setBackendAuthToken(token);
        }
      } catch {
        if (!cancelled) {
          setBackendAuthToken("");
        }
      } finally {
        if (!cancelled) {
          setIsBackendAuthTokenLoading(false);
        }
      }
    };

    void loadToken();
    return () => {
      cancelled = true;
    };
  }, [backendConnected]);

  return { backendAuthToken, isBackendAuthTokenLoading };
}

function getBackendAuthTokenBinding() {
  return (window as Window & {
    go?: { main?: { DesktopApp?: { GetBackendAuthToken?: () => Promise<string | null | undefined> } } };
  })?.go?.main?.DesktopApp?.GetBackendAuthToken;
}

async function readBackendAuthTokenFromWindow(): Promise<string> {
  const envToken = String(import.meta.env.VITE_BACKEND_TOKEN ?? "").trim();
  if (envToken) {
    return envToken;
  }

  const getBackendAuthToken = getBackendAuthTokenBinding();
  if (!getBackendAuthToken) {
    return "";
  }

  const token = await promiseWithTimeout(
    Promise.resolve().then(() => getBackendAuthToken()),
    BACKEND_AUTH_TOKEN_TIMEOUT_MS,
  );
  return String(token ?? "").trim();
}

function promiseWithTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("backend auth token timed out")), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  });
}
