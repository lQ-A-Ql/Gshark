import type { Location } from "react-router";
import type { Packet } from "../core/types";
import type { PageTheme } from "./mainLayoutConfig";

export interface MainLayoutChromeProps {
  activeTheme: PageTheme;
  backendConnected: boolean;
  backendStatus: string;
  decryptionConfigured: boolean;
  fileMeta: { name: string; sizeBytes: number };
  filteredPacketCount: number;
  packets: Packet[];
  settingsOpen: boolean;
  totalPackets: number;
  onApplyHttpFilter: () => void;
  onCloseSettings: () => void;
  onCopySelectedPacket: () => void;
  onExportEndpointStats: () => void;
  onExportPacketsJson: () => void;
  onExportProtocolStats: () => void;
  onFocusFilter: () => void;
  onFollowSelectedStream: () => void;
  onNavigate: (path: string) => void;
  onOpenCapture: () => void;
  onOpenSettings: () => void;
  onOpenTLSDialog: () => void;
  pathname: Location["pathname"];
}
