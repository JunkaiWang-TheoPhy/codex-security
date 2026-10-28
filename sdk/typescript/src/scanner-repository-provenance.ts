import { CodexSecurityError } from "./errors.js";
import { type ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
  normalizeInspectorFindings,
} from "./inspector-findings.js";
import {
  blackDuckReportRepositories,
  hasBlackDuckEvidence,
  normalizeBlackDuckFindings,
} from "./blackduck-findings.js";

export const repositoryBoundScanners: Partial<
  Record<Provider, typeof normalizeInspectorFindings>
> = {
  inspector: normalizeInspectorFindings,
  blackduck: normalizeBlackDuckFindings,
};

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
  if (
    provider !== "inspector" &&
    findings.some(({ evidence }) => hasInspectorEvidence(evidence.source_data))
  )
    throw new CodexSecurityError(
      "Retained Inspector evidence requires the inspector provider.",
    );
  if (
    provider !== "blackduck" &&
    findings.some(({ evidence }) => hasBlackDuckEvidence(evidence.source_data))
  )
    throw new CodexSecurityError(
      "Retained Black Duck evidence requires the blackduck provider.",
    );
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target, inspectorProjectMap);
  if (provider === "blackduck")
    return blackDuckReportRepositories(findings, target);
  return new Map();
}
