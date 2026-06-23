export type AnalysisResourceCacheOptions<T> = {
  capacity?: number;
  onEvict?: (key: string, value: T) => void;
};

export type AnalysisResourceCache<T> = {
  get(key: string): T | undefined;
  set(key: string, value: T): void;
  has(key: string): boolean;
  clear(): void;
  getInflight(key: string): Promise<T> | undefined;
  request(key: string, options: { force?: boolean; signal: AbortSignal; load: () => Promise<T> }): Promise<T>;
};

export function createAnalysisResourceCache<T>({
  capacity,
  onEvict,
}: AnalysisResourceCacheOptions<T> = {}): AnalysisResourceCache<T> {
  const cache = new Map<string, T>();
  const inflight = new Map<string, Promise<T>>();

  const touch = (key: string, value: T) => {
    cache.delete(key);
    cache.set(key, value);
  };

  return {
    get(key) {
      const value = cache.get(key);
      if (value !== undefined && capacity) {
        touch(key, value);
      }
      return value;
    },
    set(key, value) {
      if (!key) return;
      touch(key, value);
      while (capacity && cache.size > capacity) {
        const oldestKey = cache.keys().next().value as string | undefined;
        if (!oldestKey) break;
        const oldest = cache.get(oldestKey);
        cache.delete(oldestKey);
        if (oldest !== undefined) {
          onEvict?.(oldestKey, oldest);
        }
      }
    },
    has(key) {
      return cache.has(key);
    },
    clear() {
      cache.clear();
      inflight.clear();
    },
    getInflight(key) {
      return inflight.get(key);
    },
    request(key, { force = false, signal, load }) {
      if (!force && key) {
        const cached = this.get(key);
        if (cached !== undefined) return Promise.resolve(cached);
        const existing = inflight.get(key);
        if (existing) return waitForCallerSignal(existing, signal);
      }

      const promise = load().then((payload) => {
        if (key) {
          this.set(key, payload);
        }
        return payload;
      });

      if (!force && key) {
        inflight.set(key, promise);
        promise.then(
          () => inflight.delete(key),
          () => inflight.delete(key),
        );
      }
      return waitForCallerSignal(promise, signal);
    },
  };
}

function waitForCallerSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(abortError());
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function abortError() {
  return new DOMException("The operation was aborted.", "AbortError");
}
