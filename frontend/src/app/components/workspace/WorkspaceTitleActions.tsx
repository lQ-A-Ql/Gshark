import { CaptureFileControls, PacketLocatorControls, PacketPagingControls } from "./WorkspaceTopControls";

type WorkspaceTitleActionsProps = {
  capturePath: string;
  pageInput: string;
  packetIdInput: string;
  hasPrevPackets: boolean;
  hasMorePackets: boolean;
  isPreloadingCapture: boolean;
  isPageLoading: boolean;
  totalPackets: number;
  currentPage: number;
  totalPages: number;
  pagerItems: number[];
  captureActionsDisabled: boolean;
  backendConnected: boolean;
  onCapturePathChange: (value: string) => void;
  onChooseFile: () => void;
  onOpenPath: () => void;
  onStop: () => void;
  onPageInputChange: (value: string) => void;
  onLoadPrev: () => void;
  onLoadMore: () => void;
  onJumpToPage: (page: number) => void;
  onPacketIdInputChange: (value: string) => void;
  onLocatePacket: (packetId: number) => void;
};

export function WorkspaceTitleActions({
  capturePath,
  pageInput,
  packetIdInput,
  hasPrevPackets,
  hasMorePackets,
  isPreloadingCapture,
  isPageLoading,
  totalPackets,
  currentPage,
  totalPages,
  pagerItems,
  captureActionsDisabled,
  backendConnected,
  onCapturePathChange,
  onChooseFile,
  onOpenPath,
  onStop,
  onPageInputChange,
  onLoadPrev,
  onLoadMore,
  onJumpToPage,
  onPacketIdInputChange,
  onLocatePacket,
}: WorkspaceTitleActionsProps) {
  return (
    <>
      <CaptureFileControls
        capturePath={capturePath}
        onCapturePathChange={onCapturePathChange}
        onChooseFile={onChooseFile}
        onOpenPath={onOpenPath}
        onStop={onStop}
        disabled={captureActionsDisabled}
        backendConnected={backendConnected}
      />
      <PacketPagingControls
        hasPrevPackets={hasPrevPackets}
        hasMorePackets={hasMorePackets}
        isPreloadingCapture={isPreloadingCapture}
        isPageLoading={isPageLoading}
        totalPackets={totalPackets}
        currentPage={currentPage}
        totalPages={totalPages}
        pageInput={pageInput}
        pagerItems={pagerItems}
        onPageInputChange={onPageInputChange}
        onLoadPrev={onLoadPrev}
        onLoadMore={onLoadMore}
        onJumpToPage={onJumpToPage}
      />
      <PacketLocatorControls
        packetIdInput={packetIdInput}
        onPacketIdInputChange={onPacketIdInputChange}
        onLocatePacket={onLocatePacket}
        disabled={isPreloadingCapture || isPageLoading}
      />
    </>
  );
}
