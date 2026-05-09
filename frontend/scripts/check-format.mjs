import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const prettierTargets = [
  "eslint.config.js",
  "package.json",
  "scripts/**/*.mjs",
  "src/app/components/StreamDecoderBatchPanel.tsx",
  "src/app/components/StreamDecoderBatchPanel.test.tsx",
  "src/app/components/StreamDecoderToolbar.tsx",
  "src/app/components/StreamDecoderToolbar.test.tsx",
  "src/app/components/StreamDecoderWorkbench.tsx",
  "src/app/components/StreamDecoderWorkbenchParts.tsx",
  "src/app/components/StreamDecoderWorkbenchUtils.ts",
  "src/app/components/StreamDecoderWorkbenchUtils.test.ts",
  "src/app/components/RuntimeSettingsSidebar.tsx",
  "src/app/components/RuntimeSettingsSidebarParts.tsx",
  "src/app/components/RuntimeSettingsSidebarParts.test.tsx",
  "src/app/features/c2/**/*.{ts,tsx}",
  "src/app/features/media/MediaDisplayPanels.tsx",
  "src/app/features/media/MediaOverviewPanels.tsx",
  "src/app/features/media/MediaOverviewPanels.test.tsx",
  "src/app/features/media/MediaSessionCells.tsx",
  "src/app/features/media/MediaSessionCells.test.tsx",
  "src/app/features/media/MediaSessionTable.tsx",
  "src/app/features/media/MediaSessionTableUtils.ts",
  "src/app/features/media/MediaSessionTableUtils.test.ts",
  "src/app/features/media/MediaTranscriptionSummaryPanel.tsx",
  "src/app/features/usb/UsbHidPanels.tsx",
  "src/app/features/usb/UsbTables.tsx",
  "src/app/pages/HttpStream.tsx",
  "src/app/pages/HttpStreamUtils.ts",
  "src/app/pages/HttpStreamUtils.test.ts",
  "src/app/integrations/clients/**/*.{ts,tsx}",
  "src/app/integrations/mappers/**/*.{ts,tsx}",
  "src/app/state/SentinelContext.tsx",
  "src/app/state/captureConstants.ts",
  "src/app/state/progressHelpers.ts",
  "src/app/state/progressStatus*.ts",
  "src/app/state/backendStatusMessage*.ts",
  "src/app/state/captureSignal*.ts",
  "src/app/state/captureOpenState*.ts",
  "src/app/state/captureParseRuntimeState*.ts",
  "src/app/state/capturePreloadStatus*.ts",
  "src/app/state/captureResetState*.ts",
  "src/app/state/captureStopStatus*.ts",
  "src/app/state/recentCaptures.ts",
  "src/app/state/sentinelTypes.ts",
  "src/app/state/streamState*.ts",
  "src/app/state/streamPrefetchPlan*.ts",
  "src/app/state/streamPrefetchScheduler*.ts",
  "src/app/state/streamPrefetchTask*.ts",
  "src/app/state/streamPayloadPatch*.ts",
  "src/app/state/streamProtocol*.ts",
  "src/app/state/streamSwitchCache*.ts",
  "src/app/state/streamSwitchCommit*.ts",
  "src/app/state/streamSwitchMetrics*.ts",
  "src/app/state/streamSwitchSequence*.ts",
  "src/app/state/streamSwitchTask*.ts",
  "src/app/state/packetFilterStatus*.ts",
  "src/app/state/packetPagination*.ts",
  "src/app/state/selectedPacketState*.ts",
  "src/app/state/hooks/useSelectedPacketArtifact*.ts",
  "src/app/state/hooks/useSelectedPacketDetail*.ts",
  "src/app/state/hooks/useSyncedRefValue*.ts",
  "src/app/misc/FilterActions.tsx",
  "src/app/misc/MiscToolsShell.tsx",
  "src/app/misc/modules/GenericMiscDeleteAction.tsx",
  "src/app/misc/modules/GenericMiscFormFields.tsx",
  "src/app/misc/modules/GenericMiscModule.tsx",
  "src/app/misc/modules/GenericMiscModuleBadges.tsx",
  "src/app/misc/modules/GenericMiscModuleChrome.tsx",
  "src/app/misc/modules/GenericMiscModuleHeader.tsx",
  "src/app/misc/modules/GenericMiscResultPanel.tsx",
  "src/app/misc/modules/GenericMiscSelectField.tsx",
  "src/app/misc/modules/HTTPLoginAnalysisModule.tsx",
  "src/app/misc/modules/HTTPLoginAnalysisUtils.ts",
  "src/app/misc/modules/HTTPLoginAttemptTable.tsx",
  "src/app/misc/modules/HTTPLoginDetailsPanel.tsx",
  "src/app/misc/modules/HTTPLoginEndpointDetailsPanel.tsx",
  "src/app/misc/modules/HTTPLoginEndpointList.tsx",
  "src/app/misc/modules/HTTPLoginStatusAlerts.tsx",
  "src/app/misc/modules/MySQLQueryTraceTable.tsx",
  "src/app/misc/modules/MySQLServerEventPanel.tsx",
  "src/app/misc/modules/MySQLSessionAnalysisModule.tsx",
  "src/app/misc/modules/MySQLSessionAnalysisUtils.ts",
  "src/app/misc/modules/MySQLSessionDetails.tsx",
  "src/app/misc/modules/MySQLSessionList.tsx",
  "src/app/misc/modules/MySQLSessionOverviewPanel.tsx",
  "src/app/misc/modules/NTLMSessionMaterialDetails.tsx",
  "src/app/misc/modules/NTLMSessionMaterialList.tsx",
  "src/app/misc/modules/NTLMSessionMaterialsModule.tsx",
  "src/app/misc/modules/NTLMSessionMaterialsToolbar.tsx",
  "src/app/misc/modules/NTLMSessionMaterialsUtils.ts",
  "src/app/misc/modules/PayloadWebShellDecoderModule.tsx",
  "src/app/misc/modules/PayloadWebShellInputPanel.tsx",
  "src/app/misc/modules/PayloadWebShellInputPanelUtils.ts",
  "src/app/misc/modules/PayloadWebShellInputPanelUtils.test.ts",
  "src/app/misc/modules/PayloadWebShellSourceList.tsx",
  "src/app/misc/modules/PayloadWebShellSourceUtils.ts",
  "src/app/misc/modules/PayloadWebShellSourceUtils.test.ts",
  "src/app/misc/modules/ShiroRememberMeAnalysisModule.tsx",
  "src/app/misc/modules/ShiroRememberMeCandidateList.tsx",
  "src/app/misc/modules/ShiroRememberMeControls.tsx",
  "src/app/misc/modules/ShiroRememberMeKeyResultsPanel.tsx",
  "src/app/misc/modules/ShiroRememberMeUtils.ts",
  "src/app/misc/modules/SMB3SessionCandidateSelector.tsx",
  "src/app/misc/modules/SMB3SessionKeyInputForm.tsx",
  "src/app/misc/modules/SMB3SessionKeyModule.tsx",
  "src/app/misc/modules/SMB3SessionKeyResultPanel.tsx",
  "src/app/misc/modules/SMB3SessionKeyUtils.ts",
  "src/app/misc/modules/SMTPSessionAnalysisModule.tsx",
  "src/app/misc/modules/SMTPSessionAnalysisUtils.ts",
  "src/app/misc/modules/SMTPSessionCommandTrace.tsx",
  "src/app/misc/modules/SMTPSessionDetailsPanel.tsx",
  "src/app/misc/modules/SMTPSessionList.tsx",
  "src/app/misc/modules/SMTPSessionMessagePanel.tsx",
  "src/app/misc/modules/WinRMDecryptActions.tsx",
  "src/app/misc/modules/WinRMDecryptForm.tsx",
  "src/app/misc/modules/WinRMDecryptModule.tsx",
  "src/app/misc/modules/WinRMDecryptUtils.ts",
  "src/app/misc/modules/WinRMDecryptUtils.test.ts",
  "src/app/misc/modules/WinRMPreviewDialog.tsx",
  "src/app/misc/modules/WinRMPreviewUtils.ts",
  "src/app/misc/modules/WinRMPreviewUtils.test.ts",
  "src/app/misc/modules/WinRMResultSummary.tsx",
];

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const formatBatchSize = 24;

export function createPrettierBatches(targets = prettierTargets, batchSize = formatBatchSize) {
  if (batchSize <= 0) {
    throw new Error("batchSize must be greater than zero");
  }

  const batches = [];
  for (let index = 0; index < targets.length; index += batchSize) {
    batches.push(targets.slice(index, index + batchSize));
  }
  return batches;
}

export function runPrettierFormatCheck({
  frontendRoot = root,
  targets = prettierTargets,
  batchSize = formatBatchSize,
  spawn = spawnSync,
  nodePath = process.execPath,
  stdio = "inherit",
} = {}) {
  const prettierCli = resolve(frontendRoot, "node_modules", "prettier", "bin", "prettier.cjs");

  for (const batch of createPrettierBatches(targets, batchSize)) {
    const result = spawn(nodePath, [prettierCli, "--check", ...batch], {
      stdio,
    });

    if (result.error) {
      return { status: 1, errorMessage: result.error.message };
    }

    if (result.status !== 0) {
      return { status: result.status ?? 1 };
    }
  }

  return { status: 0 };
}

function runCli() {
  const result = runPrettierFormatCheck();

  if (result.errorMessage) {
    console.error(result.errorMessage);
  }

  if (result.status !== 0) {
    process.exit(result.status);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
