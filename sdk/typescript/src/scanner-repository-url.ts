import {
  type ExternalImportTarget,
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import { requiredText } from "./scanner-import.js";

function repositorySegment(encoded: string): boolean {
  try {
    const segment = decodeURIComponent(encoded);
    return (
      Boolean(segment) &&
      segment.trim() === segment &&
      !["", ".", ".."].includes(segment.replace(/\.git$/iu, "")) &&
      !/[/\\?#\p{Cc}]|%[\da-f]{2}/iu.test(segment)
    );
  } catch {
    return false;
  }
}

export function declaredScannerRepositoryUrl(
  value: unknown,
  provider: string,
  target: ExternalImportTarget = "cloud",
): string {
  const source = requiredText(value, `${provider} --source-repository-url`);
  const url = URL.parse(source);
  const parts = /^https?:\/\/([^/?#\\]+)\/([^?#\\]+)$/iu.exec(source);
  const segments = parts?.[2]?.replace(/\/$/u, "").split("/") ?? [];
  if (
    !url ||
    !parts ||
    parts[1]!.includes("@") ||
    /[\s\p{Cc}]/u.test(source) ||
    url.username ||
    url.password ||
    segments.length < (target === "local" ? 1 : 2) ||
    !segments.every(repositorySegment)
  )
    throw new Error(
      `${provider} --source-repository-url requires an HTTP(S) repository path without credentials, query, fragment, or ambiguous path segments.`,
    );
  return source;
}

/** A native application or project version maps to one source repository per report. */
export function repositoryScopeValidator(
  retainedRepository: (
    data: unknown,
    id: string,
    target: ExternalImportTarget,
  ) => { url: string; scope?: string } | undefined,
  scopeError: string,
) {
  return (
    findings: readonly ExternalFinding[],
    target: ExternalImportTarget,
  ): Map<string, ExternalSourceRepository> => {
    const repositories = new Map<string, ExternalSourceRepository>();
    const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
    let scope: string | undefined;
    let repository: string | undefined;
    for (const { source_finding_id: id, evidence } of findings) {
      const retained = retainedRepository(evidence.source_data, id, target);
      const declared = evidence.details?.repository?.url;
      if (!retained) {
        if (target === "cloud" && declared)
          repositories.set(id, { url: declared });
        continue;
      }
      const repositoryKey = key(retained.url);
      if (retained.scope) {
        if (scope && (scope !== retained.scope || repository !== repositoryKey))
          throw new Error(scopeError);
        scope = retained.scope;
        repository = repositoryKey;
      }
      if (declared && key(declared) !== repositoryKey)
        throw new Error(
          "Retained scanner repository does not match the normalized evidence repository.",
        );
      repositories.set(id, { url: retained.url });
    }
    return repositories;
  };
}
