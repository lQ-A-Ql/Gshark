import { lazy, type ComponentType } from "react";
import type { MiscModuleRendererProps } from "./types";
import { GenericMiscModule } from "./modules/GenericMiscModule";

function lazyModule(loader: () => Promise<{ [key: string]: ComponentType<MiscModuleRendererProps> }>, exportName: string) {
  const LazyComponent = lazy(() =>
    loader().then((module) => ({ default: module[exportName] as ComponentType<MiscModuleRendererProps> })),
  );
  return function LazyWrapper(props: MiscModuleRendererProps) {
    return <LazyComponent {...props} />;
  };
}

const moduleRenderers: Record<string, ComponentType<MiscModuleRendererProps>> = {
  "http-login-analysis": lazyModule(() => import("./modules/HTTPLoginAnalysisModule"), "HTTPLoginAnalysisModule"),
  "mysql-session-analysis": lazyModule(() => import("./modules/MySQLSessionAnalysisModule"), "MySQLSessionAnalysisModule"),
  "payload-webshell-decoder": lazyModule(() => import("./modules/PayloadWebShellDecoderModule"), "PayloadWebShellDecoderModule"),
  "shiro-rememberme-analysis": lazyModule(() => import("./modules/ShiroRememberMeAnalysisModule"), "ShiroRememberMeAnalysisModule"),
  "smtp-session-analysis": lazyModule(() => import("./modules/SMTPSessionAnalysisModule"), "SMTPSessionAnalysisModule"),
  "winrm-decrypt": lazyModule(() => import("./modules/WinRMDecryptModule"), "WinRMDecryptModule"),
  "smb3-session-key": lazyModule(() => import("./modules/SMB3SessionKeyModule"), "SMB3SessionKeyModule"),
  "ntlm-session-materials": lazyModule(() => import("./modules/NTLMSessionMaterialsModule"), "NTLMSessionMaterialsModule"),
};

export function resolveMiscModuleRenderer(moduleID: string): ComponentType<MiscModuleRendererProps> {
  return moduleRenderers[moduleID] ?? GenericMiscModule;
}
