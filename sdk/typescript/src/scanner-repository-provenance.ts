import { CodexSecurityError } from "./errors.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
} from "./inspector-findings.js";

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  inspectorProjectMap,
}: ExternalPublicationOptions & { provider: P }) {
  if (inspectorProjectMap !== undefined && provider !== "inspector")
    throw new CodexSecurityError(
      "An Inspector project map requires the inspector provider.",
    );
  return {
    repository,
    provider,
    sourceKey,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
  inspectorProjectMap?: ReadonlyMap<string, string>,
): Map<string, ExternalSourceRepository> {
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target, inspectorProjectMap);
  if (
    findings.some(({ evidence }) => hasInspectorEvidence(evidence.source_data))
  )
    throw new CodexSecurityError(
      "Retained Inspector evidence requires the inspector provider.",
    );
  return new Map();
}
