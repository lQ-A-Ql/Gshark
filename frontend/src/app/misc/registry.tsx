import { lazy, type ComponentType } from "react";
import { HTTPLoginAnalysisModule } from "./modules/HTTPLoginAnalysisModule";
import { MySQLSessionAnalysisModule } from "./modules/MySQLSessionAnalysisModule";
import type { MiscModuleRendererProps } from "./types";
import { GenericMiscModule } from "./modules/GenericMiscModule";
import { NTLMSessionMaterialsModule } from "./modules/NTLMSessionMaterialsModule";
import { SMB3SessionKeyModule } from "./modules/SMB3SessionKeyModule";
import { ShiroRememberMeAnalysisModule } from "./modules/ShiroRememberMeAnalysisModule";
import { SMTPSessionAnalysisModule } from "./modules/SMTPSessionAnalysisModule";
import { WinRMDecryptModule } from "./modules/WinRMDecryptModule";

const LazyPayloadWebShellDecoderModule = lazy(() =>
  import("./modules/PayloadWebShellDecoderModule").then((module) => ({ default: module.PayloadWebShellDecoderModule })),
);

function PayloadWebShellDecoderLazy(props: MiscModuleRendererProps) {
  return <LazyPayloadWebShellDecoderModule {...props} />;
}

const moduleRenderers: Record<string, ComponentType<MiscModuleRendererProps>> = {
  "http-login-analysis": HTTPLoginAnalysisModule,
  "mysql-session-analysis": MySQLSessionAnalysisModule,
  "payload-webshell-decoder": PayloadWebShellDecoderLazy,
  "shiro-rememberme-analysis": ShiroRememberMeAnalysisModule,
  "smtp-session-analysis": SMTPSessionAnalysisModule,
  "winrm-decrypt": WinRMDecryptModule,
  "smb3-session-key": SMB3SessionKeyModule,
  "ntlm-session-materials": NTLMSessionMaterialsModule,
};

export function resolveMiscModuleRenderer(moduleID: string): ComponentType<MiscModuleRendererProps> {
  return moduleRenderers[moduleID] ?? GenericMiscModule;
}
