import { useEffect } from "react";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";

type Ref<T> = { current: T };

export function useCaptureTaskScopeCleanup(captureTaskScopeRef: Ref<CaptureTaskScope>) {
  useEffect(
    () => () => {
      captureTaskScopeRef.current.invalidate();
    },
    [captureTaskScopeRef],
  );
}
