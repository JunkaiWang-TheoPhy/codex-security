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
import {
  hasVeracodeEvidence,
  readVeracodeFindings,
  veracodeReportRepositories,
} from "./veracode-findings.js";

export const repositoryBoundScanners: Partial<
  Record<Provider, typeof readInspectorFindings>
> = {
  inspector: readInspectorFindings,
  blackduck: readBlackDuckFindings,
  veracode: readVeracodeFindings,
};

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
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
  if (
    provider !== "veracode" &&
    findings.some(({ evidence, source_finding_id }) =>
      hasVeracodeEvidence(evidence.source_data, source_finding_id),
    )
  )
    throw new CodexSecurityError(
      "Retained Veracode evidence requires the veracode provider.",
    );
  if (provider === "veracode")
    return veracodeReportRepositories(findings, target);
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target);
  if (provider === "blackduck")
    return blackDuckReportRepositories(findings, target);
  return new Map();
}
