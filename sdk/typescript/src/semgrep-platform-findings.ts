import {
  DEFAULT_CLOUD_STRING_BYTES,
  type ExternalImportTarget,
  hostedRepositoryUrlKey,
  repositoryUrlKey,
  isVerifiedGitHubRepository,
  validateExternalEvidence,
} from "./external-import-contract.js";
import {
  HOSTED_FINDINGS_FORMATS,
  type HostedExternalFindings,
} from "./external-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  hostedScannerHttp,
  hostedEnvironmentToken,
  hostedRepositoryUrl,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import type { SemgrepImportOptions } from "./semgrep-findings.js";
import {
  isGitHubCloudHost,
  isKnownGitHost,
  isPublicGitHost,
  normalizeHostedGitRepositoryUrl,
} from "./git-remote.js";
import { position, weaknessIds } from "./native-json-findings.js";
import { canonicalJson, isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  positiveInt64,
  hostedNumber,
  hostedWireValue,
  type HostedNumericFields,
  restoreHostedNumbers,
  record,
  hostedRepositoryPath,
  requiredText,
  scannerSeverity,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

const format = HOSTED_FINDINGS_FORMATS.semgrep;
export const SEMGREP_PLATFORM_PRODUCTS = ["sast", "sca", "ai_sast"] as const;
type Product = (typeof SEMGREP_PLATFORM_PRODUCTS)[number];

export interface SemgrepPlatformOptions {
  deployment: string;
  project: string;
  ref: string;
  product?: Product;
  sourceRepositoryUrl?: string;
  token?: string;
  signal?: AbortSignal;
}

interface Project {
  id: number | string;
  name: string;
  url: string | null;
}

export interface SemgrepPlatformReport {
  format: typeof format;
  deployment: string;
  project: Project;
  /** Operator-supplied HTTP(S) mapping when the native project URL is missing or differs. */
  sourceRepositoryUrl?: string;
  /** Repository labels observed in the project-ID-filtered query. Older exports omit this field. */
  repositoryAliases?: string[];
  ref: string;
  product: Product;
  numericFields?: HostedNumericFields;
  findingCount: number;
  findings: unknown[];
}

function productType(value: unknown): Product {
  if (!SEMGREP_PLATFORM_PRODUCTS.some((product) => product === value))
    throw new Error("Select a Semgrep Platform product: sast, sca or ai_sast.");
  return value as Product;
}

function platformId(
  record: Record<string, unknown>,
): number | string | undefined {
  const value = hostedNumber(record, "id");
  if (typeof value === "string") {
    const id = positiveInt64(value);
    if (id !== undefined)
      return Number.isSafeInteger(Number(id)) ? Number(id) : id;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0)
    return value;
}

function requiredId(
  record: Record<string, unknown>,
  label: string,
): number | string {
  const id = platformId(record);
  if (id === undefined) throw new Error(`${label} must be a positive integer.`);
  return id;
}

function matchingRepositoryUrl(
  value: unknown,
  expected: string,
  github: boolean,
): void {
  const url = hostedRepositoryUrl(value, "Semgrep repository URL");
  if (
    hostedRepositoryUrlKey(url, github) !==
    hostedRepositoryUrlKey(expected, github)
  )
    throw new Error(
      "Semgrep Platform repository does not match the selected source repository.",
    );
}

function legacyRepositoryNames(
  projectName: string,
  pathname: string,
  gitSuffix: boolean,
) {
  const path = pathname.slice(1);
  const decoded = path
    .split("/")
    .map((segment) => {
      try {
        // decodeURI preserves escaped delimiters such as %2F.
        const label = decodeURI(segment);
        return label.includes("\\") ? segment : label;
      } catch {
        // Git paths may contain non-UTF-8 bytes.
        return segment;
      }
    })
    .join("/");
  return [
    projectName,
    ...[path, decoded].map((path) =>
      path.replace(gitSuffix ? /(?:\.git)?\/?$/u : /\/$/u, ""),
    ),
  ].flatMap((path) => [path, path.slice(path.lastIndexOf("/") + 1)]);
}

function projectContext(
  value: unknown,
  declared: unknown,
  isGitHub: (url: string) => boolean,
  repositoryAliases?: unknown,
  replayingUnrecordedMapping = false,
) {
  const original = record(value, "Semgrep project");
  const { name, url: nativeUrl } = original;
  if (nativeUrl != null && typeof nativeUrl !== "string")
    throw new Error("Semgrep project repository URL must be text.");
  const project: Project = {
    id: requiredId(original, "Semgrep project ID"),
    name: requiredText(name, "Semgrep project name"),
    url: text(nativeUrl),
  };
  const mapping =
    declared === undefined
      ? undefined
      : hostedRepositoryUrl(declared, "Semgrep source repository URL");
  const reference =
    mapping ??
    hostedRepositoryUrl(project.url, "Semgrep project repository URL");
  const github = isGitHub(reference);
  const native =
    project.url &&
    normalizeHostedGitRepositoryUrl(project.url, reference, github);
  if (native) matchingRepositoryUrl(native, reference, github);
  // Keep the provider's HTTP spelling. An SSH source needs the operator's HTTP(S) mapping.
  const url = native && native === project.url ? native : reference;
  const { hostname, pathname } = new URL(url);
  const publicGitHost = isPublicGitHost(hostname);
  // Older exports omitted equivalent .git mappings. Keep their original evidence
  // bytes when the caller supplies the mapping again on a publication retry.
  const omitGitSuffix = publicGitHost || replayingUnrecordedMapping;
  const binding =
    mapping &&
    (!project.url ||
      repositoryUrlKey(mapping, omitGitSuffix) !==
        repositoryUrlKey(project.url, omitGitSuffix))
      ? { project, sourceRepositoryUrl: mapping }
      : { project };
  const observed = repositoryAliases !== undefined;
  const names = observed
    ? array(repositoryAliases, "Semgrep repository aliases").map((name) =>
        requiredText(name, "Semgrep repository alias"),
      )
    : legacyRepositoryNames(project.name, pathname, github || publicGitHost);
  return { binding, url, github, names: new Set(names), observed };
}

function scopedFinding(
  value: unknown,
  selected: ReturnType<typeof projectContext>,
  ref: string,
  collecting = false,
) {
  const finding = record(value, "Semgrep Platform finding");
  const { url, name } = record(
    finding["repository"] === undefined ? {} : finding["repository"],
    "Semgrep finding repository",
  );
  if (name !== undefined && typeof name !== "string")
    throw new Error("Semgrep finding repository name must be text.");
  // Older named rows use a null URL for repositories without a native link.
  if (
    url !== undefined &&
    typeof url !== "string" &&
    !(url === null && text(name))
  )
    throw new Error("Semgrep finding repository URL must be text.");
  if (typeof url === "string" && url) {
    matchingRepositoryUrl(
      normalizeHostedGitRepositoryUrl(url, selected.url, selected.github),
      selected.url,
      selected.github,
    );
  }
  const label =
    !url && name !== undefined
      ? requiredText(name, "Semgrep finding repository name")
      : text(name);
  if (label) {
    if (collecting) selected.names.add(label);
    else if ((selected.observed || !url) && !selected.names.has(label))
      throw new Error(
        "Semgrep Platform finding lacks a matching source repository.",
      );
  }
  if (finding["ref"] !== undefined && finding["ref"] !== ref)
    throw new Error(
      "Semgrep Platform finding does not match the selected ref.",
    );
  return { finding, label };
}

export async function collectSemgrepPlatformFindings(
  options: SemgrepPlatformOptions,
  dependencies: HostedScannerHttpOptions = {},
): Promise<SemgrepPlatformReport> {
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const { getJson, signal } = hostedScannerHttp(dependencies, options.signal);
  const token = requiredText(
    options.token ??
      hostedEnvironmentToken(
        environment,
        "SEMGREP_APP_TOKEN",
        "https://semgrep.dev",
        "SEMGREP_URL",
        "SEMGREP_APP_URL",
      ),
    "Semgrep Web API token (SEMGREP_APP_TOKEN)",
  );
  const deployment = requiredText(options.deployment, "Semgrep deployment");
  const name = requiredText(options.project, "Semgrep project name");
  if (
    deployment.includes("/") ||
    [deployment, name].some((part) => part === "." || part === "..")
  )
    throw new Error("Invalid Semgrep deployment slug or project name.");
  const ref = requiredText(options.ref, "Semgrep ref");
  const product = productType(options.product ?? "sast");
  const base = `https://semgrep.dev/api/v1/deployments/${encodeURIComponent(deployment)}`;
  const get = async (url: URL) =>
    record(await getJson(url, `Bearer ${token}`), "Semgrep API response");
  const { sourceRepositoryUrl } = options;
  const lookup = await get(
    new URL(`${base}/projects/${encodeURIComponent(name)}`),
  );
  // Collection retains native URLs and the mapping. The importer verifies custom GitHub hosts.
  const nativeProject = record(lookup["project"], "Semgrep project");
  const selected = projectContext(
    nativeProject,
    sourceRepositoryUrl,
    (url) => {
      const host = new URL(url).hostname;
      return isGitHubCloudHost(host) || !isKnownGitHost(host);
    },
    [],
  );
  const { project } = selected.binding;
  if (project.name !== name)
    throw new Error("Semgrep returned a different project than requested.");
  const url = new URL(`${base}/findings`);
  const pageSize = 3000;
  url.search = new URLSearchParams({
    repository_ids: String(project.id),
    ref,
    issue_type: product,
    dedup: "false",
    page_size: String(pageSize),
  }).toString();
  const readPage = async (page: number, collecting = false) => {
    url.searchParams.set("page", String(page));
    const response = await get(new URL(url));
    return array(response["findings"], "Semgrep Platform findings").map(
      (row) => scopedFinding(row, selected, ref, collecting).finding,
    );
  };
  const pageId = (rows: Record<string, unknown>[]) =>
    stableId(
      "page",
      rows
        .map((row) => platformId(row) ?? canonicalJson(hostedWireValue(row)))
        .sort(),
    );
  const findings: Record<string, unknown>[] = [];
  const numericFields: HostedNumericFields = Object.create(null);
  if (typeof nativeProject["id"] === "number" && typeof project.id === "string")
    numericFields["project"] = { id: project.id };
  const previousIds = new Set<number | string>();
  for (let page = 0; ; page++) {
    const batch = await readPage(page, true);
    const ids = batch.map(platformId).filter((id) => id !== undefined);
    // Rows with invalid IDs are excluded during import. Still detect a repeated full page of them.
    if (!ids.length && batch.length >= pageSize) ids.push(pageId(batch));
    if (ids.some((id) => previousIds.has(id)))
      throw new Error(
        "Semgrep Platform repeated findings across pages; retry the collection.",
      );
    for (const finding of batch)
      findings.push(
        hostedWireValue(finding, numericFields, [
          "findings",
          String(findings.length),
        ]),
      );
    if (batch.length < pageSize) break;
    for (const id of ids) previousIds.add(id);
  }
  // A deletion at the front can shift later offsets without repeating any IDs.
  if (
    findings.length >= pageSize &&
    pageId(findings.slice(0, pageSize)) !== pageId(await readPage(0))
  )
    throw new Error(
      "Semgrep Platform findings changed across pages; retry the collection.",
    );
  signal?.throwIfAborted();
  return {
    format,
    deployment,
    ...selected.binding,
    repositoryAliases: [...selected.names],
    product,
    ref,
    findingCount: findings.length,
    ...(Object.keys(numericFields).length && { numericFields }),
    findings,
  };
}

export function isSemgrepPlatformReport(
  input: unknown,
): input is Record<string, unknown> & { format: typeof format } {
  return isRecord(input) && input["format"] === format;
}

export function semgrepPlatformFindingRepository(
  input: unknown,
  isGitHub: (url: string) => boolean = () => false,
): string | undefined {
  if (!isSemgrepPlatformReport(input)) return undefined;
  const selected = projectContext(
    input["project"],
    input["sourceRepositoryUrl"],
    isGitHub,
    input["repositoryAliases"],
  );
  scopedFinding(
    input["finding"],
    selected,
    requiredText(input["ref"], "Semgrep ref"),
  );
  return selected.url;
}

export function normalizeSemgrepPlatformFindings(
  input: unknown,
  options: string | SemgrepImportOptions = {},
  target: ExternalImportTarget = "cloud",
): HostedExternalFindings & { sourceRepositoryUrl: string } {
  if (!isSemgrepPlatformReport(input))
    throw new Error("Expected a complete Semgrep Platform export.");
  return normalizePlatformReport(
    input,
    typeof options === "string" ? { sourceRepositoryUrl: options } : options,
    target,
  );
}

export function normalizePlatformReport(
  input: Record<string, unknown>,
  options: SemgrepImportOptions,
  target: ExternalImportTarget,
  isGitHub: (url: string) => boolean = (url) =>
    isVerifiedGitHubRepository(url, options.sourceRepositories),
): HostedExternalFindings & { sourceRepositoryUrl: string } {
  input = restoreHostedNumbers(input);
  const declared = options.sourceRepositoryUrl;
  const deployment = requiredText(input["deployment"], "Semgrep deployment");
  const selected = projectContext(
    input["project"],
    input["sourceRepositoryUrl"] ?? declared,
    isGitHub,
    input["repositoryAliases"],
    input["sourceRepositoryUrl"] == null && declared !== undefined,
  );
  if (declared !== undefined)
    matchingRepositoryUrl(declared, selected.url, selected.github);
  const ref = requiredText(input["ref"], "Semgrep ref");
  const product = productType(input["product"]);
  const findings = array(input["findings"], "Semgrep Platform findings");
  if (hostedNumber(input, "findingCount") !== findings.length)
    throw new Error(
      "Incomplete Semgrep Platform export: finding count does not match.",
    );
  const context = { format, deployment, ...selected.binding, ref, product };
  const result = normalizeRecords(
    findings.map((finding) => scopedFinding(finding, selected, ref)),
    ({ finding, label }) => {
      const location = record(
        finding["location"] ?? {},
        "Semgrep finding location",
      );
      const path = hostedRepositoryPath(location["file_path"]);
      const line =
        path && location["line"] != null
          ? position(hostedNumber(location, "line"), "Semgrep starting line")
          : null;
      const rule = record(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      const description =
        text(rule["message"]) ?? text(finding["rule_message"]);
      // Retain fallback title bytes from exports that stored the ID as text.
      const messageTitle =
        target === "cloud" &&
        description &&
        Buffer.byteLength(description) > DEFAULT_CLOUD_STRING_BYTES
          ? `Semgrep finding ${text(finding["id"]) ?? platformId(finding)}`
          : description;
      let productEvidence;
      if (product === "sca") {
        const {
          package: pkg,
          ecosystem,
          version,
        } = record(
          finding["found_dependency"] ?? {},
          "Semgrep found dependency",
        );
        const advisory = text(finding["vulnerability_identifier"]);
        const packages = [];
        if (pkg !== undefined) {
          const packageName = requiredText(pkg, "Semgrep package name");
          const fixes = array(
            finding["fix_recommendations"] ?? [],
            "Semgrep fix recommendations",
          );
          packages.push({
            name: packageName,
            ecosystem: text(ecosystem),
            installed_version: text(version),
            fixed_versions: strings(
              fixes.flatMap((fix) =>
                isRecord(fix) && fix["package"] === packageName
                  ? [fix["version"]]
                  : [],
              ),
            ),
          });
        }
        productEvidence = {
          title: requiredText(
            name ?? advisory ?? packages[0]?.name ?? messageTitle,
            "Semgrep finding title",
          ),
          advisory_ids: advisory ? [advisory] : [],
          packages,
        };
      } else {
        if (
          finding["found_dependency"] != null ||
          finding["vulnerability_identifier"] != null
        )
          throw new Error(
            "Supply Chain evidence is not a Semgrep Code finding.",
          );
        productEvidence = {
          title: requiredText(name ?? messageTitle, "Semgrep finding title"),
          details: {
            kind: "sast",
            repository: { url: selected.url },
            scanner_origin: "Semgrep",
            rule: name ? { id: name } : null,
            source_status: text(finding["status"]),
            weakness_ids: weaknessIds(rule["cwe_names"]),
            code: {
              end_line:
                line !== null && location["end_line"] != null
                  ? position(
                      hostedNumber(location, "end_line"),
                      "Semgrep ending line",
                    )
                  : null,
            },
          },
        };
      }
      return validateExternalEvidence(
        {
          description,
          severity: scannerSeverity(text(finding["severity"])),
          locations: path ? [{ path, line }] : [],
          branch: ref,
          source_data: structuredClone({
            ...context,
            ...(selected.observed
              ? { repositoryAliases: label ? [label] : [] }
              : {}),
            finding: hostedWireValue(finding),
          }),
          ...productEvidence,
        },
        target,
      );
    },
    ({ finding }) =>
      stableId("semgrep-platform", [
        deployment,
        selected.binding.project.id,
        product,
        ref,
        requiredId(finding, "Semgrep finding ID"),
      ]),
    target,
  );
  return {
    ...result,
    sourceRepositoryUrl:
      declared ?? selected.binding.sourceRepositoryUrl ?? selected.url,
  };
}
