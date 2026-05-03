export interface CaptureScopedTask {
  readonly key: string;
  readonly scopeId: number;
  readonly signal: AbortSignal;
  isCurrent: () => boolean;
  finish: () => void;
  abort: () => void;
}

export interface CaptureTaskScope {
  readonly currentScopeId: () => number;
  readonly isScopeCurrent: (scopeId: number) => boolean;
  readonly invalidate: () => number;
  readonly beginTask: (key: string, options?: { abortPrevious?: boolean }) => CaptureScopedTask;
  readonly abortTask: (key: string) => void;
  readonly abortAll: () => void;
}

export function createCaptureTaskScope(): CaptureTaskScope {
  let scopeId = 0;
  const controllers = new Map<string, AbortController>();

  const abortTask = (key: string) => {
    const controller = controllers.get(key);
    if (!controller) return;
    controller.abort();
    controllers.delete(key);
  };

  const abortAll = () => {
    for (const controller of controllers.values()) {
      controller.abort();
    }
    controllers.clear();
  };

  const isScopeCurrent = (candidate: number) => candidate === scopeId;

  const beginTask = (key: string, options: { abortPrevious?: boolean } = {}): CaptureScopedTask => {
    if (options.abortPrevious !== false) {
      abortTask(key);
    }

    const controller = new AbortController();
    const taskScopeId = scopeId;
    controllers.set(key, controller);
    let finished = false;

    const isCurrent = () => (
      !finished
      && taskScopeId === scopeId
      && controllers.get(key) === controller
      && !controller.signal.aborted
    );

    const finish = () => {
      finished = true;
      if (controllers.get(key) === controller) {
        controllers.delete(key);
      }
    };

    const abort = () => {
      controller.abort();
      finish();
    };

    return {
      key,
      scopeId: taskScopeId,
      signal: controller.signal,
      isCurrent,
      finish,
      abort,
    };
  };

  return {
    currentScopeId: () => scopeId,
    isScopeCurrent,
    invalidate: () => {
      scopeId += 1;
      abortAll();
      return scopeId;
    },
    beginTask,
    abortTask,
    abortAll,
  };
}
