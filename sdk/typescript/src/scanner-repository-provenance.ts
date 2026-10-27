import { CodexSecurityError } from "./errors.js";
import { cloudRepositoryUrlKey, repositoryUrlKey, type ExternalImportTarget } from "./external-import-contract.js";
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

import { readVeracodeFindings, veracodeEvidenceRepositoryUrls } from "./veracode-findings.js";

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
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target);
  if (provider === "blackduck")
    return blackDuckReportRepositories(findings, target);
  const repositories = new Map<string, ExternalSourceRepository>();
  if (provider === "veracode") {
    const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
    for (const { source_finding_id: id, evidence } of findings) {
      const [url] = veracodeEvidenceRepositoryUrls(evidence.source_data, id);
      if (!url) continue;
      const declared = evidence.details?.repository?.url;
      if (declared && key(declared) !== key(url))
        throw new CodexSecurityError("Retained scanner repository does not match the normalized evidence repository.");
      repositories.set(id, { url });
    }
  }
  return repositories;
}
