import { useCallback, useEffect, useRef } from "react";
import { isAbortLikeError } from "../utils/asyncControl";

export { isAbortLikeError };

export type AbortableRequestOptions<T> = {
  request: (signal: AbortSignal) => Promise<T>;
  onSuccess: (payload: T) => void;
  onError?: (error: unknown) => void;
  onSettled?: () => void;
};

export function useAbortableRequest() {
  const abortRef = useRef<AbortController | null>(null);
  const sequenceRef = useRef(0);

  const cancel = useCallback(() => {
    sequenceRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  const run = useCallback(<T,>({
    request,
    onSuccess,
    onError,
    onSettled,
  }: AbortableRequestOptions<T>) => {
    abortRef.current?.abort();

    const controller = new AbortController();
    abortRef.current = controller;
    const sequence = ++sequenceRef.current;

    const isCurrent = () => sequence === sequenceRef.current && abortRef.current === controller && !controller.signal.aborted;

    void request(controller.signal)
      .then((payload) => {
        if (!isCurrent()) return;
        onSuccess(payload);
      })
      .catch((error) => {
        if (!isCurrent() || isAbortLikeError(error, controller.signal)) return;
        onError?.(error);
      })
      .finally(() => {
        const settledCurrent = sequence === sequenceRef.current && abortRef.current === controller;
        if (abortRef.current === controller) {
          abortRef.current = null;
        }
        if (settledCurrent) {
          onSettled?.();
        }
      });

    return () => {
      controller.abort();
      if (abortRef.current === controller) {
        abortRef.current = null;
      }
    };
  }, []);

  useEffect(() => cancel, [cancel]);

  return {
    run,
    cancel,
  };
}
