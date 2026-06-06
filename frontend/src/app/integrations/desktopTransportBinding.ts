import type { DesktopAnalysisBinding } from "./desktopTransportBindingAnalysis";
import type { DesktopControlPlaneBinding } from "./desktopTransportBindingControl";
import type { DesktopPacketBinding, DesktopStreamBinding } from "./desktopTransportBindingStream";
import type { DesktopRulesBinding } from "./desktopTransportBindingRules";
import type { DesktopShellBinding } from "./desktopTransportBindingShell";
import type { DesktopToolingBinding } from "./desktopTransportBindingTooling";

export interface DesktopTransportBinding
  extends
    DesktopShellBinding,
    DesktopControlPlaneBinding,
    DesktopPacketBinding,
    DesktopStreamBinding,
    DesktopRulesBinding,
    DesktopToolingBinding,
    DesktopAnalysisBinding {}
