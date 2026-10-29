import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import type { ImportedPackage } from "./external-import-models.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  isPublicGitHost,
  normalizeHostedGitRepositoryUrl,
  publicGitSsh443Host,
} from "./git-remote.js";
import {
  hostedScannerHttp,
  hostedEnvironmentToken,
  hostedRepositoryUrl,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  record,
  relativePath,
  requiredText,
  scannerSeverity,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

export const SNYK_REST_ISSUES_FORMAT = "snyk-rest-issues/v1";
const apiVersion = "2026-03-25";
const formatVersion = { format: SNYK_REST_ISSUES_FORMAT, apiVersion } as const;
const defaultOrigin = "https://api.snyk.io";
const origins = new Set([
  defaultOrigin,
  "https://api.us.snyk.io",
  "https://api.eu.snyk.io",
  "https://api.au.snyk.io",
]);
const scmOrigins = new Set([
  "azure-repos",
  "bitbucket-cloud",
  "bitbucket-connect-app",
  "bitbucket-server",
  "github",
  "github-app",
  "github-cloud-app",
  "github-enterprise",
  "github-server-app",
  "gitlab",
]);
const openSourceProjects = new Set([
  "cargo",
  "cocoapods",
  "composer",
  "conan",
  "cpp",
  "golang",
  "golangdep",
  "gomodules",
  "govendor",
  "gradle",
  "hex",
  "maven",
  "npm",
  "nuget",
  "paket",
  "pip",
  "pipenv",
  "pnpm",
  "poetry",
  "pub",
  "rubygems",
  "sbt",
  "swift",
  "unmanaged",
  "uv",
  "yarn",
  "yarn-workspace",
]);
const issueTypes = {
  "open-source": "package_vulnerability",
  code: "code",
} as const;
export type SnykIssuesProduct = keyof typeof issueTypes;

interface SnykScope {
  organizationId: string;
  projectId: string;
  product: SnykIssuesProduct;
  sourceRepositoryUrl: string;
}

export interface CollectSnykIssuesOptions extends SnykScope {
  token?: string;
  apiOrigin?: string;
  signal?: AbortSignal;
}

type Resource = Record<string, unknown>;

export interface SnykIssuesExport extends SnykScope {
  format: typeof SNYK_REST_ISSUES_FORMAT;
  apiVersion: typeof apiVersion;
  apiOrigin: string;
  complete: true;
  project: Resource;
  target: Resource | null;
  pages: { startingAfter: string | null; response: Resource }[];
}

function uuid(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/iu.test(value)
  )
    throw new Error(`${label} must be a UUID.`);
  return value.toLowerCase();
}

type Scope = SnykScope & { apiOrigin: string };

function scope(
  input: Resource | CollectSnykIssuesOptions,
  origin: unknown,
): Scope {
  const apiOrigin = requiredText(origin, "Snyk API origin").replace(/\/$/u, "");
  if (!origins.has(apiOrigin))
    throw new Error("Select a documented Snyk regional HTTPS API origin.");
  const product = input["product"];
  if (product !== "open-source" && product !== "code")
    throw new Error("Snyk product must be open-source or code.");
  return {
    apiOrigin,
    product,
    sourceRepositoryUrl: hostedRepositoryUrl(
      input["sourceRepositoryUrl"],
      "Snyk source repository URL",
    ),
    organizationId: uuid(input["organizationId"], "Snyk organization ID"),
    projectId: uuid(input["projectId"], "Snyk project ID"),
  };
}

function endpoint(selected: Scope, route: string) {
  const url = new URL(
    `/rest/orgs/${selected.organizationId}/${route}`,
    selected.apiOrigin,
  );
  url.searchParams.set("version", apiVersion);
  return url;
}

function issuesEndpoint(selected: Scope) {
  const url = endpoint(selected, "issues");
  url.searchParams.set("scan_item.type", "project");
  url.searchParams.set("scan_item.id", selected.projectId);
  url.searchParams.set("type", issueTypes[selected.product]);
  url.searchParams.set("status", "open,resolved");
  url.searchParams.set("limit", "100");
  if (selected.product === "code")
    url.searchParams.set("include_code_flows", "true");
  return url;
}

function jsonApi(input: unknown, label: string) {
  const document = record(input, label);
  if ("errors" in document)
    throw new Error(
      `${label}: JSON:API errors: ${JSON.stringify(document["errors"])}`,
    );
  return document;
}

function resourceId(resource: Resource, type: string) {
  if (resource["type"] !== type)
    throw new Error(`Expected a Snyk ${type} resource.`);
  return uuid(resource["id"], `Snyk ${type} ID`);
}

function relationship(relationships: Resource, name: string) {
  return record(
    record(relationships[name], `Snyk ${name} relationship`)["data"],
    `Snyk ${name} linkage`,
  );
}

function checkOrganization(
  relationships: Resource,
  selected: Scope,
  project = false,
) {
  const org = relationship(relationships, "organization");
  if (
    (org["type"] !== "organization" && !(project && org["type"] === "org")) ||
    uuid(org["id"], "Snyk organization relationship ID") !==
      selected.organizationId
  )
    throw new Error(
      "Snyk resource does not belong to the selected organization.",
    );
}

// Snyk CLI renders HTTPS and SSH Git remotes as HTTP, preserving explicit ports.
function cliRepositoryKey(remote: string) {
  const parts = /^http:\/\/([^/]+)(\/.*)$/iu.exec(remote);
  if (!parts) return;
  const authority = parts[1]!.toLowerCase();
  const alternate = publicGitSsh443Host(authority);
  const hostname = authority.replace(/:\d+$/u, "");
  if (
    alternate ||
    isPublicGitHost(hostname) ||
    hostname === "dev.azure.com" ||
    /^[a-z\d-]+\.visualstudio\.com$/u.test(hostname)
  )
    return repositoryUrlKey(`https://${alternate ?? authority}${parts[2]}`);
}

function checkRemote(remote: unknown, selected: Scope, origin: string) {
  if (remote === null || remote === "") return;
  const url = requiredText(remote, "Snyk target URL");
  const normalized = normalizeHostedGitRepositoryUrl(
    url,
    selected.sourceRepositoryUrl,
    origin.startsWith("github"),
  );
  const enterprise =
    origin === "github-enterprise" || origin === "github-server-app";
  const key = enterprise ? cloudRepositoryUrlKey : repositoryUrlKey;
  const target = key(normalized);
  const source = key(selected.sourceRepositoryUrl);
  const cliTarget = origin === "cli" && cliRepositoryKey(url) === source;
  if (/[?#]/u.test(url) || (target !== source && !cliTarget))
    throw new Error(
      "Snyk target URL does not match the selected source repository URL.",
    );
  if (enterprise) return "github" as const;
  if (scmOrigins.has(origin) && !origin.startsWith("github"))
    return "other" as const;
}

function projectContext(project: Resource, selected: Scope) {
  if (resourceId(project, "project") !== selected.projectId)
    throw new Error(
      "Snyk returned a different project from the selected project.",
    );
  const attributes = record(project["attributes"], "Snyk project attributes");
  const manager = requiredText(attributes["type"], "Snyk project type");
  const origin = requiredText(attributes["origin"], "Snyk project origin");
  const scm = scmOrigins.has(origin);
  if (
    (!scm && origin !== "cli" && origin !== "api") ||
    (selected.product === "code"
      ? manager !== "sast"
      : !openSourceProjects.has(manager))
  )
    throw new Error(
      `Snyk project type ${manager} from ${origin} is not a supported ${selected.product} project.`,
    );
  const context = {
    manager,
    scm,
    origin,
    manifest: scm ? repoPath(attributes["target_file"]) : null,
  };
  if (project["relationships"] === undefined)
    return { ...context, targetId: undefined, expandedUrl: undefined };
  const relationships = record(
    project["relationships"],
    "Snyk project relationships",
  );
  checkOrganization(relationships, selected, true);
  const link = relationship(relationships, "target");
  const expandedUrl =
    link["attributes"] === undefined
      ? undefined
      : record(link["attributes"], "Snyk expanded target attributes")["url"];
  return {
    ...context,
    targetId: resourceId(link, "target"),
    expandedUrl,
  };
}

function checkTarget(
  value: unknown,
  selected: Scope,
  { expandedUrl, targetId, origin }: ReturnType<typeof projectContext>,
) {
  if (targetId === undefined || expandedUrl !== undefined) {
    if (value !== null)
      throw new Error(
        "Unexpected separate Snyk target without a project target lookup.",
      );
    if (expandedUrl !== undefined)
      return checkRemote(expandedUrl, selected, origin);
    return;
  }
  const target = record(value, "Snyk target resource");
  if (resourceId(target, "target") !== targetId)
    throw new Error(
      "Snyk target does not match the selected project's target.",
    );
  if (target["relationships"] !== undefined) {
    const relationships = record(
      target["relationships"],
      "Snyk target relationships",
    );
    checkOrganization(relationships, selected, true);
    if (relationships["integration"] !== undefined) {
      const integration = relationship(relationships, "integration");
      const attributes = record(
        integration["attributes"],
        "Snyk integration attributes",
      );
      const type = requiredText(
        attributes["integration_type"],
        "Snyk integration type",
      );
      if (
        scmOrigins.has(origin) &&
        scmOrigins.has(type) &&
        origin.split("-")[0] !== type.split("-")[0]
      )
        throw new Error(
          "Snyk target integration does not match the project's SCM origin.",
        );
    }
  }
  return checkRemote(
    record(target["attributes"], "Snyk target attributes")["url"],
    selected,
    origin,
  );
}

function nextCursor(links: unknown, endpoint: URL) {
  if (links === undefined) return null;
  const next = record(links, "Snyk issue page links")["next"];
  if (next === null || next === undefined) return null;
  const href = requiredText(
    isRecord(next) ? next["href"] : next,
    "Snyk next page link",
  );
  const url = new URL(
    href.startsWith("/orgs/") ? `/rest${href}` : href,
    endpoint,
  );
  if (
    url.origin !== endpoint.origin ||
    url.pathname !== endpoint.pathname ||
    url.username ||
    url.password ||
    url.hash
  )
    throw new Error("Snyk next page link leaves the selected Issues endpoint.");
  for (const [key, value] of url.searchParams) {
    if (
      url.searchParams.getAll(key).length !== 1 ||
      (key !== "starting_after" && endpoint.searchParams.get(key) !== value)
    )
      throw new Error("Snyk next page link changes the selected Issues query.");
  }
  return requiredText(
    url.searchParams.get("starting_after"),
    "Snyk next page starting_after cursor",
  );
}

function scopedIssue(value: unknown, selected: Scope) {
  const issue = record(value, "Snyk issue");
  const relationships = record(
    issue["relationships"],
    "Snyk issue relationships",
  );
  checkOrganization(relationships, selected);
  const item = relationship(relationships, "scan_item");
  if (resourceId(item, "project") !== selected.projectId)
    throw new Error("Snyk issue does not belong to the selected project.");
  return issue;
}

function selectedIssueAttributes(issue: Resource, selected: Scope) {
  resourceId(issue, "issue");
  const attributes = record(issue["attributes"], "Snyk issue attributes");
  if (attributes["type"] !== issueTypes[selected.product])
    throw new Error(
      `Only ${issueTypes[selected.product]} issues are supported for this Snyk project selection.`,
    );
  return attributes;
}

function issuePage(
  response: Resource,
  selected: Scope,
  url: URL,
  seen: Set<string>,
) {
  const issues = array(response["data"], "Snyk issue page data").map((value) =>
    scopedIssue(value, selected),
  );
  const next = nextCursor(response["links"], url);
  if (next !== null) {
    if (seen.has(next))
      throw new Error("Snyk Issues pagination repeated a cursor.");
    seen.add(next);
  }
  return { issues, next };
}

export async function collectSnykIssues(
  options: CollectSnykIssuesOptions,
  dependencies: HostedScannerHttpOptions = {},
): Promise<SnykIssuesExport> {
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const { getJson, signal } = hostedScannerHttp(dependencies, options.signal);
  const selected = scope(options, options.apiOrigin ?? defaultOrigin);
  const token = requiredText(
    options.token ??
      hostedEnvironmentToken(
        environment,
        "SNYK_TOKEN",
        selected.apiOrigin,
        "API_V3_URL",
        "SNYK_API_V3_URL",
        "API_REST_URL",
        "SNYK_API_REST_URL",
        "SNYK_API",
        "SNYK_CFG_ENDPOINT",
      ),
    "Snyk API token (SNYK_TOKEN)",
  );
  if (/[\r\n]/u.test(token))
    throw new Error("Snyk API token cannot contain a line break.");
  const get = async (url: URL, label: string) =>
    jsonApi(await getJson(url, `token ${token}`), label);
  const getResource = async (url: URL, kind: string) =>
    record(
      (await get(url, `Snyk ${kind} response`))["data"],
      `Snyk ${kind} resource`,
    );
  const projectUrl = endpoint(selected, `projects/${selected.projectId}`);
  projectUrl.searchParams.set("expand", "target");
  const project = await getResource(projectUrl, "project");
  const context = projectContext(project, selected);
  const target =
    context.targetId === undefined || context.expandedUrl !== undefined
      ? null
      : await getResource(
          endpoint(selected, `targets/${context.targetId}`),
          "target",
        );
  checkTarget(target, selected, context);
  const pages: SnykIssuesExport["pages"] = [];
  const base = issuesEndpoint(selected);
  const seen = new Set<string>();
  let startingAfter: string | null = null;
  do {
    const url = new URL(base);
    if (startingAfter !== null)
      url.searchParams.set("starting_after", startingAfter);
    const response = await get(url, "Snyk issue page");
    pages.push({ startingAfter, response });
    startingAfter = issuePage(response, selected, base, seen).next;
  } while (startingAfter !== null);
  signal?.throwIfAborted();
  return {
    ...formatVersion,
    ...selected,
    complete: true,
    project,
    target,
    pages,
  };
}

function savedContext(document: Resource) {
  if (
    document["format"] !== SNYK_REST_ISSUES_FORMAT ||
    document["apiVersion"] !== apiVersion
  )
    throw new Error(
      `Expected ${SNYK_REST_ISSUES_FORMAT} for API version ${apiVersion}.`,
    );
  const selected = scope(document, document["apiOrigin"]);
  const project = record(document["project"], "Snyk project resource");
  const context = projectContext(project, selected);
  const target = document["target"];
  const platform = checkTarget(target, selected, context);
  return {
    source: { ...formatVersion, ...selected, project, target },
    context,
    platform,
  };
}

export function snykRestFindingRepository(sourceData: Resource): {
  url: string;
  platform?: ExternalFindings["sourceRepositoryPlatform"];
} {
  const { source, platform } = savedContext(sourceData);
  selectedIssueAttributes(scopedIssue(sourceData["issue"], source), source);
  return { url: source.sourceRepositoryUrl, platform };
}

function readIssues(document: Resource, selected: Scope) {
  if (document["complete"] !== true)
    throw new Error("Expected a complete Snyk REST Issues export.");
  const url = issuesEndpoint(selected);
  const pages = array(document["pages"], "Snyk issue pages");
  if (!pages.length)
    throw new Error("Incomplete Snyk collection: no issue page.");
  const seen = new Set<string>();
  let cursor: string | null = null;
  const issues = pages.flatMap((value, index) => {
    const page = record(value, "Snyk saved page");
    if ((index !== 0 && cursor === null) || page["startingAfter"] !== cursor)
      throw new Error("Incomplete or inconsistent Snyk issue page sequence.");
    const parsed = issuePage(
      jsonApi(page["response"], "Snyk issue page"),
      selected,
      url,
      seen,
    );
    cursor = parsed.next;
    return parsed.issues;
  });
  if (cursor !== null)
    throw new Error("Incomplete Snyk collection: missing next issue page.");
  return issues;
}

function records(parent: Resource, field: string) {
  const label = `Snyk ${field}`;
  return array(parent[field] ?? [], label).map((entry) => record(entry, label));
}

function problemIds(entries: Resource[], type?: string) {
  const ids = new Set<string>();
  for (const entry of entries) {
    if (type === undefined || entry["type"] === type)
      ids.add(requiredText(entry["id"], "Snyk problem or class ID"));
  }
  return [...ids];
}

function repoPath(value: unknown) {
  const path = text(value);
  return path && !path.includes("\\") && !path.includes("://")
    ? relativePath(path)
    : null;
}

function packageEvidence(
  coordinates: Resource[],
  { manager, manifest }: ReturnType<typeof projectContext>,
) {
  const packages: ImportedPackage[] = [];
  for (const coordinate of coordinates) {
    const fixed = records(coordinate, "remedies").flatMap((remedy) => {
      const meta = remedy["meta"];
      return isRecord(meta) &&
        meta["schema_version"] === "package_vulnerability/v0"
        ? strings(record(meta["data"], "Snyk package remedy data")["fixed_in"])
        : [];
    });
    for (const representation of records(coordinate, "representations")) {
      if (!("dependency" in representation)) continue;
      const dependency = record(
        representation["dependency"],
        "Snyk dependency",
      );
      packages.push({
        name: requiredText(
          dependency["package_name"],
          "Snyk dependency package name",
        ),
        installed_version: requiredText(
          dependency["package_version"],
          "Snyk dependency package version",
        ),
        ecosystem: manager,
        manifest_path: manifest,
        fixed_versions: [...new Set(fixed)],
      });
    }
  }
  return packages;
}

function codeEvidence(coordinates: Resource[], scm: boolean) {
  const locations: { path: string }[] = [];
  const revisions = new Set<string | null>();
  for (const coordinate of coordinates) {
    for (const representation of records(coordinate, "representations")) {
      const value =
        representation["sourceLocation"] ?? representation["source_location"];
      if (value === undefined) continue;
      const location = record(value, "Snyk source location");
      revisions.add(text(location["commit_id"]));
      const path = repoPath(location["file"]);
      if (scm && path) locations.push({ path });
    }
  }
  return {
    locations,
    code_revision: revisions.size === 1 ? ([...revisions][0] ?? null) : null,
  };
}

export function normalizeSnykIssues(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "Snyk REST Issues export");
  const { source, context, platform } = savedContext(document);
  const code = source.product === "code";
  const result = normalizeRecords(
    readIssues(document, source),
    (issue, sourceFindingId) => {
      const attributes = record(issue["attributes"], "Snyk issue attributes");
      const status = attributes["status"];
      if (
        (status !== "open" && status !== "resolved") ||
        typeof attributes["ignored"] !== "boolean"
      )
        throw new Error(
          "Snyk issue must have a source status and an ignored flag.",
        );
      const updated = Date.parse(
        requiredText(attributes["updated_at"], "Snyk updated_at"),
      );
      if (!Number.isFinite(updated) || updated < 0)
        throw new Error("Invalid Snyk issue updated_at.");
      const severity = requiredText(
        attributes["effective_severity_level"],
        "Snyk effective severity",
      );
      const problems = records(attributes, "problems");
      const rules = problemIds(problems, "rule");
      const activeCoordinates = records(attributes, "coordinates").filter(
        (coordinate) => status === "open" && coordinate["state"] === "open",
      );
      return {
        source_finding_id: sourceFindingId,
        evidence: validateExternalEvidence(
          {
            title: requiredText(attributes["title"], "Snyk issue title"),
            description: text(attributes["description"]),
            severity:
              severity === "info" ? "informational" : scannerSeverity(severity),
            advisory_ids: code ? [] : problemIds(problems),
            ...(code
              ? codeEvidence(activeCoordinates, context.scm)
              : {
                  packages: packageEvidence(activeCoordinates, context),
                }),
            source_updated_at: Math.floor(updated / 1000),
            source_data: structuredClone({ ...source, issue }),
            ...(code && {
              details: {
                kind: "sast",
                repository: { url: source.sourceRepositoryUrl },
                scanner_origin: "Snyk Code",
                source_status: status,
                rule: rules.length === 1 ? { id: rules[0] } : null,
                weakness_ids: problemIds(
                  records(attributes, "classes"),
                  "weakness",
                ),
              },
            }),
          },
          target,
        ),
      };
    },
    (issue) => {
      const attributes = selectedIssueAttributes(issue, source);
      return stableId("snyk-rest", [
        source.apiOrigin,
        source.organizationId,
        source.projectId,
        source.product,
        requiredText(attributes["key"], "Snyk issue key"),
      ]);
    },
    target,
  );
  return {
    ...result,
    sourceRepositoryUrl: source.sourceRepositoryUrl,
    ...(platform && { sourceRepositoryPlatform: platform }),
  };
}
