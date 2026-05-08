type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface CaptureParseRuntimeOptions {
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadingRef: Ref<boolean>;
  readonly setIsPreloadingCapture: Setter<boolean>;
}

interface CaptureParseFinishedOptions {
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly errorMessage?: string;
}

export function startCaptureParseRuntime({
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  setIsPreloadingCapture,
}: CaptureParseRuntimeOptions): void {
  setIsPreloadingCapture(true);
  parseFinishedRef.current = false;
  parseErrorRef.current = "";
  preloadingRef.current = true;
}

export function finishCaptureParseRuntime({
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  setIsPreloadingCapture,
}: CaptureParseRuntimeOptions): void {
  preloadingRef.current = false;
  parseFinishedRef.current = true;
  parseErrorRef.current = "";
  setIsPreloadingCapture(false);
}

export function stopCapturePreloading({
  preloadingRef,
  setIsPreloadingCapture,
}: Pick<CaptureParseRuntimeOptions, "preloadingRef" | "setIsPreloadingCapture">): void {
  preloadingRef.current = false;
  setIsPreloadingCapture(false);
}

export function markCaptureParseFinished({
  parseFinishedRef,
  parseErrorRef,
  errorMessage,
}: CaptureParseFinishedOptions): void {
  parseFinishedRef.current = true;
  if (errorMessage) {
    parseErrorRef.current = errorMessage;
  }
}
