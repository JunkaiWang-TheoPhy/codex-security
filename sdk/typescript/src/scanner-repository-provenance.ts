import { CodexSecurityError } from "./errors.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import type { ExternalFinding } from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import { inspectorEvidenceRepositoryUrls } from "./inspector-findings.js";

export function boundScannerRepositoryUrls(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget,
): string[] {
  const { evidence, source_finding_id: sourceId } = finding;
  const urls =
    provider === "inspector"
      ? inspectorEvidenceRepositoryUrls(evidence.source_data, sourceId, target)
      : [];
  const declared = evidence.details?.repository?.url;
  const compare = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
  if (declared && urls.some((url) => compare(url) !== compare(declared)))
    throw new CodexSecurityError(
      "Retained scanner repository does not match the normalized evidence repository.",
    );
  return urls;
}
