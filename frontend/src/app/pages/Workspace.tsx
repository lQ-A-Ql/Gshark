import { useEffect, useMemo, useRef, useState } from "react";
import { Network } from "lucide-react";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { WorkbenchTitleBar } from "../components/DesignSystem";
import { CaptureTransactionBanner } from "../components/workspace/CaptureTransactionBanner";
import { CaptureTransactionErrorPanel } from "../components/workspace/CaptureTransactionErrorPanel";
import { WorkspaceFilterSection } from "../components/workspace/WorkspaceFilterSection";
import { WorkspacePanels } from "../components/workspace/WorkspacePanels";
import { WorkspacePreloadProgress } from "../components/workspace/WorkspacePreloadProgress";
import { WorkspaceTitleActions } from "../components/workspace/WorkspaceTitleActions";
import { useWorkspaceFilterProgress } from "../components/workspace/useWorkspaceFilterProgress";
import { useWorkspaceFilterHistory } from "../components/workspace/useWorkspaceFilterHistory";
import { useWorkspaceProtocolSelection } from "../components/workspace/useWorkspaceProtocolSelection";
import { usePreloadElapsedMs } from "../components/workspace/usePreloadElapsedMs";
import { useSentinel } from "../state/SentinelContext";
import { useWorkspaceFilterAction } from "./useWorkspaceFilterAction";
import { useWorkspaceStreamNavigation } from "./useWorkspaceStreamNavigation";
import {
  getWorkspaceFilterPanelState,
  shouldShowWorkspaceOpenFailure,
  shouldShowWorkspaceSwitchFailureBanner,
  shouldShowWorkspaceWelcome,
} from "./workspaceStatus";
import {
  getWorkspacePagerItems,
  shouldShowWorkspaceFilterLoadingBlankState,
} from "./workspaceViewRules";

export default function Workspace() {
  const {
    displayFilter,
    setDisplayFilter,
    applyFilter,
    clearFilter,
    filteredPackets,
    totalPackets,
    currentPage,
    totalPages,
    isPreloadingCapture,
    preloadProcessed,
    preloadTotal,
    capturePreloadDiagnostics,
    hasMorePackets,
    hasPrevPackets,
    isPageLoading,
    isFilterLoading,
    packetPageError,
    captureTransaction,
    loadMorePackets,
    loadPrevPackets,
    jumpToPage,
    retryPacketPage,
    locatePacketById,
    selectedPacket,
    selectedPacketRawHex,
    selectedPacketId,
    selectPacket,
    protocolTree,
    fileMeta,
    openCapture,
    stopCapture,
    retryCapturePreloadConfirm,
    setActiveStream,
    backendConnected,
    backendStatus,
    tsharkStatus,
  } = useSentinel();

  const [capturePath, setCapturePath] = useState(fileMeta.name);
  const [pageInput, setPageInput] = useState("1");
  const [packetIdInput, setPacketIdInput] = useState("");
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const { filterSuggestions, rememberFilter, clearFilterHistory } = useWorkspaceFilterHistory();
  const filterLoadingProgress = useWorkspaceFilterProgress(isFilterLoading, isPreloadingCapture);
  const applyFilterWithHistory = useWorkspaceFilterAction({
    applyFilter,
    displayFilter,
    rememberFilter,
    setDisplayFilter,
  });
  const { followStream, openHttpStream } = useWorkspaceStreamNavigation({ selectPacket, setActiveStream });
  const {
    selectedTreeNode,
    selectedByteOffset,
    selectedByteRange,
    frameBytes,
    hexPanelRef,
    handleSelectTreeNode,
    handleSelectByte,
    registerNodeRef,
  } = useWorkspaceProtocolSelection(selectedPacket, selectedPacketRawHex, protocolTree);

  useEffect(() => {
    setCapturePath(fileMeta.name);
  }, [fileMeta.name]);

  useEffect(() => {
    setPageInput(String(currentPage));
  }, [currentPage]);

  useEffect(() => {
    const handler = () => {
      filterInputRef.current?.focus();
      filterInputRef.current?.select();
    };

    window.addEventListener("gshark:focus-filter", handler);
    return () => window.removeEventListener("gshark:focus-filter", handler);
  }, []);

  const hasOpenedCapture = Boolean(fileMeta.path);
  const showFilterLoadingBlankState = useMemo(
    () => shouldShowWorkspaceFilterLoadingBlankState(filteredPackets.length, isFilterLoading, isPreloadingCapture),
    [filteredPackets.length, isFilterLoading, isPreloadingCapture],
  );
  const filterPanelState = useMemo(
    () => getWorkspaceFilterPanelState(backendStatus, displayFilter),
    [backendStatus, displayFilter],
  );
  const pagerItems = useMemo(() => getWorkspacePagerItems(currentPage, totalPages), [currentPage, totalPages]);
  const preloadElapsedMs = usePreloadElapsedMs(isPreloadingCapture, captureTransaction.pendingCapturePath);

  const captureActionsDisabled = !backendConnected || !tsharkStatus.available;

  if (shouldShowWorkspaceWelcome(hasOpenedCapture, captureTransaction)) {
    return <CaptureWelcomePanel />;
  }

  if (shouldShowWorkspaceOpenFailure(hasOpenedCapture, captureTransaction)) {
    return (
      <CaptureTransactionErrorPanel
        captureName={captureTransaction.pendingCaptureName}
        message={captureTransaction.message}
        hasActiveCapture={captureTransaction.hasActiveCapture}
        onRetry={() => void openCapture(captureTransaction.pendingCapturePath)}
        onChooseAnother={() => void openCapture()}
      />
    );
  }

  return (
    <div className="gshark-tile-page flex h-full flex-col overflow-hidden text-sm text-foreground">
      <WorkbenchTitleBar
        title="流量工作区"
        subtitle={
          fileMeta.path ? `${fileMeta.name} · ${totalPackets.toLocaleString()} packets` : "打开 PCAP/PCAPNG 后开始分析"
        }
        icon={<Network className="h-4 w-4 text-blue-600" />}
        className="gshark-tile-header border-blue-100"
        actions={
          <WorkspaceTitleActions
            capturePath={capturePath}
            pageInput={pageInput}
            packetIdInput={packetIdInput}
            hasPrevPackets={hasPrevPackets}
            hasMorePackets={hasMorePackets}
            isPreloadingCapture={isPreloadingCapture}
            isPageLoading={isPageLoading}
            totalPackets={totalPackets}
            currentPage={currentPage}
            totalPages={totalPages}
            pagerItems={pagerItems}
            captureActionsDisabled={captureActionsDisabled}
            backendConnected={backendConnected}
            onCapturePathChange={setCapturePath}
            onChooseFile={() => void openCapture()}
            onOpenPath={() => void openCapture(capturePath)}
            onStop={() => void stopCapture()}
            onPageInputChange={setPageInput}
            onLoadPrev={() => void loadPrevPackets()}
            onLoadMore={() => void loadMorePackets()}
            onJumpToPage={(page) => void jumpToPage(page)}
            onPacketIdInputChange={setPacketIdInput}
            onLocatePacket={(packetId) => void locatePacketById(packetId)}
          />
        }
      />
      <WorkspaceFilterSection
        value={displayFilter}
        suggestions={filterSuggestions}
        inputRef={filterInputRef}
        disabled={isPreloadingCapture || isPageLoading}
        errorMessage={filterPanelState.errorMessage}
        onChange={setDisplayFilter}
        onApply={() => applyFilterWithHistory()}
        onClear={clearFilter}
        onClearHistory={clearFilterHistory}
      />
      {isPreloadingCapture && (
        <WorkspacePreloadProgress
          preloadProcessed={preloadProcessed}
          preloadTotal={preloadTotal}
          totalPackets={totalPackets}
          diagnostics={capturePreloadDiagnostics}
          elapsedMs={preloadElapsedMs}
          onRetryConfirm={() => void retryCapturePreloadConfirm()}
          onStop={() => void stopCapture()}
        />
      )}

      {shouldShowWorkspaceSwitchFailureBanner(captureTransaction) && (
        <CaptureTransactionBanner
          captureName={captureTransaction.pendingCaptureName}
          message={captureTransaction.message}
          onRetry={() => void openCapture(captureTransaction.pendingCapturePath)}
          onChooseAnother={() => void openCapture()}
        />
      )}

      <WorkspacePanels
        showFilterLoadingBlankState={showFilterLoadingBlankState}
        filterLoadingTitle={filterPanelState.loadingTitle}
        filterLoadingDetail={filterPanelState.loadingDetail}
        filterLoadingProgress={filterLoadingProgress}
        packetPageError={packetPageError}
        captureName={fileMeta.name}
        displayFilter={displayFilter}
        packets={filteredPackets}
        selectedPacketId={selectedPacketId}
        hasMorePackets={hasMorePackets}
        protocolTree={protocolTree}
        selectedTreeNode={selectedTreeNode}
        selectedPacket={selectedPacket}
        frameBytes={frameBytes}
        selectedByteRange={selectedByteRange}
        selectedByteOffset={selectedByteOffset}
        hexPanelRef={hexPanelRef}
        onSelectPacket={selectPacket}
        onDoubleClickHttp={openHttpStream}
        onFollowStream={followStream}
        onRetryPacketPage={() => void retryPacketPage()}
        onLoadMorePackets={() => void loadMorePackets()}
        onSelectTreeNode={handleSelectTreeNode}
        onSelectByte={handleSelectByte}
        registerNodeRef={registerNodeRef}
      />
    </div>
  );
}
