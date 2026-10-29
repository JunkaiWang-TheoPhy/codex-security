import type {
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  hostedRepositoryUrlKey,
  isVerifiedGitHubRepository,
} from "./external-import-contract.js";
import { readSnykFindings } from "./snyk-findings.js";
import {
  normalizeSemgrepReport,
  semgrepSarifSourceRepositories,
} from "./semgrep-findings.js";
import { readScannerJson } from "./scanner-import.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import { readEndorFindings, endorRepositoryUrls } from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readInspectorFindings } from "./inspector-findings.js";
import {
  readVendorFindingsForPublication,
  wizPackageRepository,
} from "./wiz-findings.js";

/** File reader names mapped to their stored and Cloud source provider. */
export const EXTERNAL_FINDINGS_PROVIDERS = {
  wiz: "wiz",
  snyk: "snyk",
  semgrep: "semgrep",
  // OpenGrep uses the existing SAST contract; evidence retains its scanner origin.
  opengrep: "semgrep",
  endor: "endor",
  github: "github",
  inspector: "inspector",
} as const satisfies Record<string, Provider>;

export type ExternalFindingsReader = keyof typeof EXTERNAL_FINDINGS_PROVIDERS;

export const EXTERNAL_FINDINGS_READERS = Object.keys(
  EXTERNAL_FINDINGS_PROVIDERS,
) as ExternalFindingsReader[];

/** File readers available in this SDK, shared by local and Cloud imports. */
export interface ExternalFindingsReaderOptions {
  provider: ExternalFindingsReader;
  sourceRepositoryUrl?: string;
  inspectorProjectMap?: ReadonlyMap<string, string>;
}

/** @internal Shared parser output, including immutable Cloud retry projections. */
export interface ReadExternalFindings {
  findings: ExternalFindings;
  /** Preserve previous Wiz projections when resuming immutable Cloud requests. */
  publication?: ExternalPublicationInput;
  sourceRepositories?: ExternalSourceRepository[];
}

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
  references?: readonly ExternalSourceRepository[],
): Promise<ReadExternalFindings> {
  if (options.provider === "opengrep") {
    const sourceRepositoryUrl = options.sourceRepositoryUrl ?? "";
    return {
      findings: await readOpenGrepFindings(
        path,
        { sourceRepositoryUrl },
        target,
      ),
      sourceRepositories: [{ url: sourceRepositoryUrl }],
    };
  }
  if (options.provider === "snyk") {
    const findings = await readSnykFindings(path, target);
    if (findings.sourceRepositoryUrl) {
      const github =
        findings.sourceRepositoryPlatform === "github" ||
        (findings.sourceRepositoryPlatform === undefined &&
          (target === "cloud" ||
            isVerifiedGitHubRepository(
              findings.sourceRepositoryUrl,
              references,
            )));
      if (
        options.sourceRepositoryUrl &&
        hostedRepositoryUrlKey(findings.sourceRepositoryUrl, github) !==
          hostedRepositoryUrlKey(options.sourceRepositoryUrl, github)
      )
        throw new Error(
          "Snyk REST source repository does not match the declared source repository URL.",
        );
    }
    return { findings };
  }
  if (options.provider === "semgrep") {
    // Cloud checks retained URLs against its connected destination before publication.
    const findings = normalizeSemgrepReport(
      await readScannerJson(path),
      { sourceRepositoryUrl: options.sourceRepositoryUrl },
      target,
      (url) =>
        target === "cloud" || isVerifiedGitHubRepository(url, references),
    );
    if (findings.sourceRepositoryUrl) return { findings };
    const sourceRepositories = findings.findings.flatMap(({ evidence }) =>
      semgrepSarifSourceRepositories(evidence.source_data),
    );
    return { findings, sourceRepositories };
  }
  if (options.provider === "endor") {
    const parsed = await readEndorFindings(path, target);
    return {
      findings: parsed,
      sourceRepositories: parsed.findings.flatMap((finding) =>
        endorRepositoryUrls(finding.evidence.source_data).map((url) => ({
          url,
        })),
      ),
    };
  }
  if (options.provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (options.provider === "inspector") {
    const url = options.sourceRepositoryUrl ?? "";
    return {
      findings: await readInspectorFindings(
        path,
        url,
        target,
        options.inspectorProjectMap,
      ),
      sourceRepositories: [{ url }],
    };
  }
  const publication = await readVendorFindingsForPublication(path, target);
  return {
    findings: publication.current,
    publication,
    sourceRepositories: [
      ...publication.sourceRepositories,
      ...publication.current.findings.flatMap(
        ({ evidence }) => wizPackageRepository(evidence) ?? [],
      ),
    ],
  };
}
