import { useCallback } from "react";
import type { PacketsPageResult } from "../../integrations/clients/captureClient";
import { runPacketFilterAction } from "../packetFilterAction";

type Ref<T> = { current: T };

type UseDisplayFilterWorkflowOptions = {
  readonly activeCapturePathRef: Ref<string>;
  readonly backendConnected: boolean;
  readonly displayFilter: string;
  readonly isPreloadingCapture: boolean;
  readonly filterSeqRef: Ref<number>;
  readonly loadPacketPage: (cursor: number, filterOverride?: string) => Promise<PacketsPageResult | null>;
  readonly resetPacketViewport: () => void;
  readonly setDisplayFilter: (value: string) => void;
  readonly setIsFilterLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
  readonly setBackendStatus: (value: string) => void;
};

export function useDisplayFilterWorkflow({
  activeCapturePathRef,
  backendConnected,
  displayFilter,
  isPreloadingCapture,
  filterSeqRef,
  loadPacketPage,
  resetPacketViewport,
  setDisplayFilter,
  setIsFilterLoading,
  setPacketPageError,
  setBackendStatus,
}: UseDisplayFilterWorkflowOptions) {
  const shouldRun = useCallback(
    () => Boolean(activeCapturePathRef.current && backendConnected && !isPreloadingCapture),
    [activeCapturePathRef, backendConnected, isPreloadingCapture],
  );

  const runFilterAction = useCallback(
    (filter: string, syncDisplayFilter: boolean, pollUntilSettled: boolean) => {
      void runPacketFilterAction({
        filter,
        syncDisplayFilter,
        pollUntilSettled,
        shouldRun: shouldRun(),
        filterSeqRef,
        loadPacketPage,
        resetPacketViewport,
        setDisplayFilter,
        setIsFilterLoading,
        setPacketPageError,
        setBackendStatus,
      });
    },
    [
      filterSeqRef,
      loadPacketPage,
      resetPacketViewport,
      setBackendStatus,
      setDisplayFilter,
      setIsFilterLoading,
      setPacketPageError,
      shouldRun,
    ],
  );

  const applyFilter = useCallback(
    (value?: string) => {
      runFilterAction(value ?? displayFilter, value !== undefined, true);
    },
    [displayFilter, runFilterAction],
  );

  const clearFilter = useCallback(() => {
    runFilterAction("", true, false);
  }, [runFilterAction]);

  return { applyFilter, clearFilter };
}
