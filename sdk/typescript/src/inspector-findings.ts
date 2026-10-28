import { posix } from "node:path";
import validSemver from "semver/functions/valid.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  text,
} from "./scanner-import.js";

type Native = Record<string, unknown>;

const format = "aws-inspector2-list-findings/v1";
const findingArn =
  /^(arn:(aws[a-zA-Z-]*):inspector2:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12})):finding\/[a-f0-9]{32}$/u;
const integrationSuffix = /^codesecurity-integration\/[a-f0-9-]{36}$/u;
const projectSuffix =
  /^project-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const absoluteUrl = /^[a-z][a-z\d+.-]*:\/\//iu;

function repositoryUrl(value: unknown): string {
  const raw = requiredText(value, "Inspector --source-repository-url");
  const url = URL.parse(raw);
  const path = /^https?:\/\/[^/?#]+(\/[^?#]+)$/iu.exec(raw)?.[1];
  if (
    !url ||
    !path ||
    url.username ||
    url.password ||
    /[\s\\?#]|%(?:2f|5c)/iu.test(raw) ||
    path !== url.pathname ||
    !/^\/[^/]+(?:\/[^/]+)+\/?$/u.test(path)
  )
    throw new Error(
      "Use a complete HTTP(S) Inspector source repository URL with a namespace and repository, without credentials, query or fragment.",
    );
  return raw;
}

function matchesProject(
  name: string,
  source: string,
  github: boolean,
): boolean {
  const urlKey = github ? cloudRepositoryUrlKey : repositoryUrlKey;
  const key = urlKey(source);
  const path = new URL(key).pathname.slice(1);
  const literal = github ? name.toLowerCase() : name;
  if (absoluteUrl.test(name)) {
    if (urlKey(repositoryUrl(name)) === key) return true;
  } else if (literal === path) return true;
  else if (literal === posix.basename(path)) return false;
  throw new Error(
    "Inspector native repository does not match --source-repository-url.",
  );
}

function identity(finding: Native) {
  const arn = requiredText(finding["findingArn"], "Inspector finding ARN");
  const match = findingArn.exec(arn);
  if (!match) throw new Error("Expected an Inspector2 finding ARN.");
  if (finding["awsAccountId"] !== match[4])
    throw new Error("Inspector finding ARN and AWS account do not match.");
  return { arn, issuer: match[1]!, partition: match[2]!, region: match[3]! };
}

function repositoryClaim(finding: Native, resource: Native) {
  const { issuer, partition, region } = identity(finding);
  if (
    (resource["partition"] !== undefined &&
      resource["partition"] !== partition) ||
    (resource["region"] !== undefined && resource["region"] !== region) ||
    (resource["provider"] !== undefined && resource["provider"] !== "AWS") ||
    (resource["providerAccountId"] !== undefined &&
      resource["providerAccountId"] !== finding["awsAccountId"])
  )
    throw new Error(
      "Inspector repository resource and finding scope do not match.",
    );
  const details = record(
    resource["details"] ?? {},
    "Inspector resource details",
  );
  const repo = record(
    details["codeRepository"] ?? {},
    "Inspector codeRepository",
  );
  const provider =
    repo["providerType"] === undefined
      ? undefined
      : requiredText(repo["providerType"], "Inspector repository provider");
  const nativeId = requiredText(
    resource["id"],
    "Inspector repository resource ID",
  );
  const name =
    repo["projectName"] === undefined
      ? null
      : requiredText(repo["projectName"], "Inspector native project name");
  let integration =
    repo["integrationArn"] === undefined
      ? undefined
      : requiredText(repo["integrationArn"], "Inspector integration ARN");
  if (
    integration !== undefined &&
    (!integration.startsWith(issuer + ":") ||
      !integrationSuffix.test(integration.slice(issuer.length + 1)))
  )
    throw new Error(
      "Inspector integration ARN does not match the finding scope.",
    );
  if (nativeId.startsWith("arn:")) {
    const separator = nativeId.lastIndexOf("/");
    const parent = nativeId.slice(0, separator);
    if (
      !parent.startsWith(issuer + ":") ||
      !integrationSuffix.test(parent.slice(issuer.length + 1)) ||
      !projectSuffix.test(nativeId.slice(separator + 1)) ||
      (integration !== undefined && parent !== integration)
    )
      throw new Error(
        "Inspector repository resource ARN does not match its project or integration.",
      );
    integration = parent;
  }
  return {
    project: JSON.stringify([issuer, nativeId]),
    integration,
    provider,
    nativeId,
    name,
  };
}

function checkRepositoryMapping(
  nativeId: string,
  name: string | null,
  source: string,
  provider: string | undefined,
  target?: ExternalImportTarget,
) {
  const mapped = new URL(source);
  const knownGitHub = isGitHubCloudHost(mapped.hostname);
  if (
    (provider !== undefined &&
      !["GITHUB", "GITLAB_SELF_MANAGED"].includes(provider)) ||
    (provider === "GITLAB_SELF_MANAGED" && knownGitHub) ||
    mapped.hostname === "gitlab.com"
  )
    throw new Error(
      "Inspector repository provider does not match the selected mapping.",
    );
  if (
    target === "cloud" &&
    (provider === "GITLAB_SELF_MANAGED" ||
      (!knownGitHub && provider !== "GITHUB"))
  )
    throw new Error(
      "Inspector Cloud requires a GitHub repository provider; self-managed GitLab is local only.",
    );
  const github = provider === "GITHUB" || knownGitHub;
  if (absoluteUrl.test(nativeId)) matchesProject(nativeId, source, github);
  if (name !== null) matchesProject(name, source, github);
  return (
    absoluteUrl.test(nativeId) || (name !== null && absoluteUrl.test(name))
  );
}

class InspectorReportScope {
  private readonly projects = new Set<string>();
  private readonly integrations = new Set<string>();
  private readonly providers = new Set<string>();
  private readonly mappings: {
    nativeId: string;
    name: string | null;
    source: string;
  }[] = [];

  include(row: unknown, source: string): void {
    if (!isRecord(row) || !Array.isArray(row["resources"])) return;
    for (const resource of row["resources"]) {
      if (!isRecord(resource) || resource["type"] !== "CODE_REPOSITORY")
        continue;
      const claim = repositoryClaim(row, resource);
      this.mappings.push({
        nativeId: claim.nativeId,
        name: claim.name,
        source,
      });
      this.projects.add(claim.project);
      if (claim.integration) this.integrations.add(claim.integration);
      if (claim.provider) this.providers.add(claim.provider);
      if (
        this.projects.size > 1 ||
        this.integrations.size > 1 ||
        this.providers.size > 1
      )
        throw new Error(
          "Inspector export identifies more than one repository project or integration.",
        );
    }
  }
  validate(target?: ExternalImportTarget): string | undefined {
    const provider = this.providers.values().next().value;
    let hasNativeUrl = false;
    for (const { nativeId, name, source } of this.mappings) {
      if (checkRepositoryMapping(nativeId, name, source, provider, target))
        hasNativeUrl = true;
    }
    if (this.mappings.length && !hasNativeUrl)
      throw new Error(
        "Inspector needs a matching native repository URL for the project; a project name or resource ARN does not identify its Git host.",
      );
    return provider;
  }
}

function checkReportScope(
  rows: unknown[],
  source: string,
  target?: ExternalImportTarget,
): string | undefined {
  const scope = new InspectorReportScope();
  for (const row of rows) scope.include(row, source);
  return scope.validate(target);
}

function selectedFinding(value: unknown): Native {
  const finding = record(value, "Inspector finding");
  const resources = array(finding["resources"], "Inspector resources");
  if (
    !resources.length ||
    resources.some(
      (resource) =>
        !isRecord(resource) ||
        resource["type"] !== "CODE_REPOSITORY" ||
        Object.keys(
          record(resource["details"] ?? {}, "Inspector resource details"),
        ).some((key) => key !== "codeRepository"),
    )
  )
    throw new Error(
      "Only Inspector findings exclusively on CODE_REPOSITORY resources are supported.",
    );
  const type = finding["type"];
  if (type !== "PACKAGE_VULNERABILITY" && type !== "CODE_VULNERABILITY")
    throw new Error(
      "Only Inspector package and code vulnerability findings are supported.",
    );
  if (
    finding["networkReachabilityDetails"] !== undefined ||
    (type === "PACKAGE_VULNERABILITY" &&
      finding["codeVulnerabilityDetails"] !== undefined) ||
    (type === "CODE_VULNERABILITY" &&
      finding["packageVulnerabilityDetails"] !== undefined)
  )
    throw new Error(
      "Inspector finding contains details for a different finding type.",
    );
  const code = finding["codeVulnerabilityDetails"];
  const pkg = finding["packageVulnerabilityDetails"];
  if (
    (isRecord(code) && code["sourceLambdaLayerArn"] !== undefined) ||
    (isRecord(pkg) &&
      array(
        pkg["vulnerablePackages"] ?? [],
        "Inspector vulnerable packages",
      ).some(
        (item) =>
          isRecord(item) &&
          (item["sourceLayerHash"] !== undefined ||
            item["sourceLambdaLayerArn"] !== undefined),
      ))
  )
    throw new Error(
      "Inspector workload layer evidence is not repository evidence.",
    );
  return finding;
}

function isInspectorRepositoryFinding(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value["findingArn"] === "string" &&
    findingArn.test(value["findingArn"]) &&
    Array.isArray(value["resources"]) &&
    value["resources"].some(
      (resource) =>
        isRecord(resource) && resource["type"] === "CODE_REPOSITORY",
    )
  );
}

export function hasInspectorEvidence(sourceData: unknown): boolean {
  return (
    isRecord(sourceData) &&
    (sourceData["format"] === format ||
      isInspectorRepositoryFinding(sourceData["finding"]) ||
      isInspectorRepositoryFinding(sourceData))
  );
}

function retainedRepository(sourceData: unknown, expectedSourceId?: string) {
  if (!isRecord(sourceData) || sourceData["format"] !== format) {
    if (
      hasInspectorEvidence(sourceData) ||
      (expectedSourceId !== undefined && findingArn.test(expectedSourceId))
    )
      throw new Error(
        "Expected retained Inspector ListFindings evidence for the finding ARN.",
      );
    return;
  }
  const source = repositoryUrl(sourceData["sourceRepositoryUrl"]);
  const finding = selectedFinding(sourceData["finding"]);
  if (
    expectedSourceId !== undefined &&
    finding["findingArn"] !== expectedSourceId
  )
    throw new Error(
      "Inspector source_finding_id does not match the retained finding ARN.",
    );
  return { source, finding };
}

export function inspectorEvidenceRepositoryUrls(
  sourceData: unknown,
  expectedSourceId?: string,
  target?: ExternalImportTarget,
): string[] {
  const retained = retainedRepository(sourceData, expectedSourceId);
  if (!retained) return [];
  checkReportScope([retained.finding], retained.source, target);
  return [retained.source];
}

export function inspectorReportRepositories(
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  const scope = new InspectorReportScope();
  const repositories = new Map<string, ExternalSourceRepository>();
  for (const { source_finding_id: id, evidence } of findings) {
    const retained = retainedRepository(evidence.source_data, id);
    if (!retained) continue;
    scope.include(retained.finding, retained.source);
    repositories.set(id, { url: retained.source });
  }
  const github = scope.validate(target) === "GITHUB";
  const key =
    github || target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
  if (new Set([...repositories.values()].map(({ url }) => key(url))).size > 1)
    throw new Error(
      "Inspector export identifies more than one source repository.",
    );
  for (const { source_finding_id: id, evidence } of findings) {
    const repository = repositories.get(id);
    if (!repository) continue;
    if (github) repository.platform = "github";
    const declared = evidence.details?.repository?.url;
    if (declared && key(declared) !== key(repository.url))
      throw new Error(
        "Retained scanner repository does not match the normalized evidence repository.",
      );
  }
  return repositories;
}

function repoFile(value: unknown): string | null {
  const relative = relativePath(value);
  if (!relative) return null;
  const path = posix.normalize(relative);
  return path === "." ||
    path.endsWith("/") ||
    /^(?:[a-z][a-z\d+.-]*:|~[^/]*(?:\/|$)|[^/]+@[^/]+:)/iu.test(path)
    ? null
    : path;
}

function timestamp(value: unknown): number {
  const seconds =
    typeof value === "number"
      ? value
      : typeof value === "string" &&
          /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(
            value,
          )
        ? Date.parse(value) / 1000
        : NaN;
  if (!Number.isFinite(seconds))
    throw new Error("Invalid Inspector timestamp.");
  return Math.floor(seconds);
}

const ecosystems: Record<string, string> = {
  BUNDLER: "rubygems",
  GEMSPEC: "rubygems",
  CARGO: "cargo",
  COMPOSER: "composer",
  NPM: "npm",
  YARN: "npm",
  NODEPKG: "npm",
  NUGET: "nuget",
  DOTNET_CORE: "nuget",
  GOBINARY: "go",
  GOMOD: "go",
  JAR: "java",
  POM: "maven",
  PIP: "pypi",
  PIPENV: "pypi",
  POETRY: "pypi",
  PYTHONPKG: "pypi",
};

const manifests = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.toml",
  "Cargo.lock",
  "composer.json",
  "composer.lock",
  "Gemfile",
  "Gemfile.lock",
  "go.mod",
  "go.sum",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "gradle.lockfile",
  "Pipfile",
  "Pipfile.lock",
  "poetry.lock",
  "pyproject.toml",
  "uv.lock",
  "packages.config",
  "packages.lock.json",
]);

function manifestPath(path: string | null): string | null {
  if (!path) return null;
  const name = posix.basename(path);
  return manifests.has(name) ||
    /^requirements(?:[-_.].*)?\.txt$/u.test(name) ||
    /\.(?:csproj|fsproj|vbproj|gemspec)$/u.test(name)
    ? path
    : null;
}

function concreteVersion(
  value: unknown,
  ecosystem: string | null,
): string | null {
  const version = text(value);
  if (!version) return null;
  if (validSemver(version)) return version;
  if (ecosystem === "npm") return null;
  if (ecosystem === "java" || ecosystem === "maven") {
    if (
      version === "LATEST" ||
      version === "RELEASE" ||
      version.startsWith("latest.")
    )
      return null;
    return /^[a-z\d][\w.+-]*$/iu.test(version) && !version.endsWith("+")
      ? version
      : null;
  }
  if (!ecosystem && version.endsWith("+")) return null;
  const publicVersion =
    ecosystem === "pypi" ? version.split("+", 1)[0]! : version;
  return /\d/u.test(version) &&
    /^(?:\d+:)?[a-z\d][\w.+!-]*$/iu.test(version) &&
    !/(?:^|\.)x(?:\.|$)/iu.test(publicVersion)
    ? version
    : null;
}

function evidence(
  finding: Native,
  id: string,
  source: string,
  target: ExternalImportTarget,
) {
  const description = requiredText(
    finding["description"],
    "Inspector description",
  );
  const remediation = record(finding["remediation"], "Inspector remediation");
  record(remediation["recommendation"] ?? {}, "Inspector recommendation");
  requiredText(finding["status"], "Inspector status");
  timestamp(finding["firstObservedAt"]);
  timestamp(finding["lastObservedAt"]);
  const level = requiredText(
    finding["severity"],
    "Inspector severity",
  ).toLowerCase();
  const packages = [];
  const locations: { path: string; line: number | null }[] = [];
  const advisoryIds = new Set<string>();
  let fallbackTitle: string | undefined;
  let url: string | null = null;
  if (finding["packageVulnerabilityDetails"] !== undefined) {
    const detail = record(
      finding["packageVulnerabilityDetails"],
      "Inspector package vulnerability",
    );
    fallbackTitle = requiredText(
      detail["vulnerabilityId"],
      "Inspector vulnerability ID",
    );
    requiredText(detail["source"], "Inspector vulnerability source");
    advisoryIds.add(fallbackTitle);
    for (const alias of array(
      detail["relatedVulnerabilities"] ?? [],
      "Inspector related vulnerabilities",
    ))
      advisoryIds.add(
        requiredText(alias, "Inspector related vulnerability ID"),
      );
    url = text(detail["sourceUrl"]);
    const seenPaths = new Set<string>();
    for (const value of array(
      detail["vulnerablePackages"] ?? [],
      "Inspector vulnerable packages",
    )) {
      const item = record(value, "Inspector vulnerable package");
      const version = requiredText(
        item["version"],
        "Inspector package version",
      );
      const path = repoFile(item["filePath"]);
      const manager = text(item["packageManager"]);
      const ecosystem =
        manager && Object.hasOwn(ecosystems, manager)
          ? (ecosystems[manager] ?? null)
          : null;
      const fixed = concreteVersion(item["fixedInVersion"], ecosystem);
      packages.push({
        name: requiredText(item["name"], "Inspector package name"),
        ecosystem,
        installed_version: concreteVersion(version, ecosystem),
        manifest_path: manifestPath(path),
        fixed_versions: fixed ? [fixed] : [],
      });
      if (path && !seenPaths.has(path)) {
        seenPaths.add(path);
        locations.push({ path, line: null });
      }
    }
  }
  if (finding["codeVulnerabilityDetails"] !== undefined) {
    const detail = record(
      finding["codeVulnerabilityDetails"],
      "Inspector code vulnerability",
    );
    fallbackTitle = requiredText(
      detail["detectorName"],
      "Inspector detector name",
    );
    requiredText(detail["detectorId"], "Inspector detector ID");
    array(detail["cwes"], "Inspector CWEs");
    const file = record(detail["filePath"], "Inspector code file path");
    const path = repoFile(file["filePath"]);
    if (path && posix.basename(path) === file["fileName"]) {
      const start = file["startLine"];
      locations.push({
        path,
        line:
          typeof start === "number" && Number.isSafeInteger(start) && start > 0
            ? start
            : null,
      });
    }
  }
  return validateExternalEvidence(
    {
      title: text(finding["title"]) ?? fallbackTitle ?? id,
      description,
      severity: ["critical", "high", "medium", "low", "informational"].includes(
        level,
      )
        ? level
        : "unknown",
      url,
      advisory_ids: [...advisoryIds],
      packages,
      locations,
      source_updated_at:
        finding["updatedAt"] === undefined
          ? null
          : timestamp(finding["updatedAt"]),
      source_data: {
        format,
        sourceRepositoryUrl: source,
        finding: structuredClone(finding),
      },
    },
    target,
  );
}

export function normalizeInspectorFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const source = repositoryUrl(sourceRepositoryUrl);
  const report = record(input, "Inspector ListFindings response");
  if (Object.hasOwn(report, "NextToken") || Object.hasOwn(report, "nextToken"))
    throw new Error(
      "Inspector export has a continuation key; supply the complete paginated CLI JSON output.",
    );
  if (Object.keys(report).some((key) => key !== "findings"))
    throw new Error(
      "Expected only a complete native Inspector ListFindings response.",
    );
  const rows = array(report["findings"], "Inspector findings");
  checkReportScope(rows, source, target);
  const normalize = (requireOwnMapping: boolean) =>
    normalizeRecords(
      rows,
      (row, id) => {
        const finding = selectedFinding(row);
        const projected = evidence(finding, id, source, target);
        if (requireOwnMapping) checkReportScope([finding], source, target);
        return { source_finding_id: id, evidence: projected };
      },
      (row) => identity(record(row, "Inspector finding")).arn,
      target,
    );
  const result = normalize(false);
  if (result.excluded.length && result.findings.length) {
    try {
      inspectorReportRepositories(result.findings, target);
    } catch {
      // An excluded finding may have supplied the only native host or provider
      // for this project. Keep findings still bound by their own evidence.
      return normalize(true);
    }
  }
  return result;
}

export async function readInspectorFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeInspectorFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
