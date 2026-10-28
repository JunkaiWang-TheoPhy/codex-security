import { CodexSecurityError } from "./errors.js";
import { type ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
  readInspectorFindings,
} from "./inspector-findings.js";
import {
  blackDuckReportRepositories,
  hasBlackDuckEvidence,
  readBlackDuckFindings,
} from "./blackduck-findings.js";

export const repositoryBoundScanners: Partial<
  Record<Provider, typeof readInspectorFindings>
> = {
  inspector: readInspectorFindings,
  blackduck: readBlackDuckFindings,
};

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
