import {
  type ExternalImportTarget,
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  hostedScannerHttp,
  hostedEnvironmentToken,
  hostedRepositoryUrl,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import { position, weaknessIds } from "./native-json-findings.js";
import { canonicalJson, isRecord } from "./record.js";
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

const format = "semgrep-platform-findings/v1";
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
  /** Operator mapping retained when absent from or case-distinct from the native project URL. */
  sourceRepositoryUrl?: string;
  ref: string;
  product: Product;
  findingCount: number;
  findings: unknown[];
}

function productType(value: unknown): Product {
  if (!SEMGREP_PLATFORM_PRODUCTS.some((product) => product === value))
    throw new Error("Select a Semgrep Platform product: sast, sca or ai_sast.");
  return value as Product;
}

function platformId(value: unknown): number | string | undefined {
  if (
    typeof value === "string" &&
    /^[1-9]\d{0,18}$/u.test(value) &&
    BigInt(value) <= 9223372036854775807n
  )
    return Number.isSafeInteger(Number(value)) ? Number(value) : value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0)
    return value;
}

function requiredId(value: unknown, label: string): number | string {
  const id = platformId(value);
  if (id === undefined) throw new Error(`${label} must be a positive integer.`);
  return id;
}

function parsePlatformJson(body: string): unknown {
  return JSON.parse(
    body,
    (_key: string, value: unknown, context?: { source?: string }) => {
      if (
        typeof value === "number" &&
        Number.isInteger(value) &&
        !Number.isSafeInteger(value)
      )
        return requiredText(context?.source, "Exact Semgrep numeric value");
      return value;
    },
  );
}

function matchingRepositoryUrl(
  value: unknown,
  expected: string,
  key: typeof repositoryUrlKey,
): string {
  const url = hostedRepositoryUrl(value, "Semgrep repository URL");
  if (key(url) !== key(expected))
    throw new Error(
      "Semgrep Platform repository does not match the selected source repository.",
    );
  return url;
}

function projectContext(
  value: unknown,
  declared: unknown,
  key: typeof repositoryUrlKey,
) {
  const { id, name, url: nativeUrl } = record(value, "Semgrep project");
  const url = hostedRepositoryUrl(
    text(nativeUrl) ?? declared,
    "Semgrep project repository URL",
  );
  const mapping =
    declared === undefined
      ? undefined
      : matchingRepositoryUrl(declared, url, key);
  const project: Project = {
    id: requiredId(id, "Semgrep project ID"),
    name: requiredText(name, "Semgrep project name"),
    url: text(nativeUrl),
  };
  const binding =
    mapping &&
    (!project.url || repositoryUrlKey(mapping) !== repositoryUrlKey(url))
      ? { project, sourceRepositoryUrl: mapping }
      : { project };
  const scmPath = new URL(url).pathname.slice(1).replace(/(?:\.git)?\/?$/u, "");
  const names = [project.name, scmPath].flatMap((path) => [
    path,
    path.split("/").at(-1),
  ]);
  return { binding, url, key, names };
}

function scopedFinding(
  value: unknown,
  selected: ReturnType<typeof projectContext>,
  ref: string,
) {
  const finding = record(value, "Semgrep Platform finding");
  const { url, name } = record(
    finding["repository"],
    "Semgrep finding repository",
  );
  if (text(url)) matchingRepositoryUrl(url, selected.url, selected.key);
  else if (typeof name !== "string" || !selected.names.includes(name))
    throw new Error(
      "Semgrep Platform finding lacks a matching source repository.",
    );
  if (finding["ref"] !== ref)
    throw new Error(
      "Semgrep Platform finding does not match the selected ref.",
    );
  return finding;
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
    [deployment, ...name.split("/")].some(
      (part) => !part || part === "." || part === "..",
    )
  )
    throw new Error("Invalid Semgrep deployment slug or project name.");
  const ref = requiredText(options.ref, "Semgrep ref");
  const product = productType(options.product ?? "sast");
  const base = `https://semgrep.dev/api/v1/deployments/${encodeURIComponent(deployment)}`;
  const get = async (url: URL) =>
    record(
      await getJson(url, `Bearer ${token}`, parsePlatformJson),
      "Semgrep API response",
    );
  const { sourceRepositoryUrl } = options;
  const lookup = await get(
    new URL(`${base}/projects/${encodeURIComponent(name)}`),
  );
  // Collection retains both URL spellings. The importer verifies Enterprise casing against its destination.
  const selected = projectContext(
    lookup["project"],
    sourceRepositoryUrl,
    cloudRepositoryUrlKey,
  );
  const { project } = selected.binding;
  if (project.name !== name)
    throw new Error("Semgrep returned a different project than requested.");
  const url = new URL(`${base}/findings`);
  const pageSize = 100;
  url.search = new URLSearchParams({
    repository_ids: String(project.id),
    ref,
    issue_type: product,
    dedup: "false",
    page_size: String(pageSize),
  }).toString();
  const readPage = async (page: number) => {
    url.searchParams.set("page", String(page));
    const response = await get(new URL(url));
    return array(response["findings"], "Semgrep Platform findings").map((row) =>
      scopedFinding(row, selected, ref),
    );
  };
  const pageId = (rows: Record<string, unknown>[]) =>
    stableId(
      "page",
      rows.map((row) => platformId(row["id"]) ?? canonicalJson(row)),
    );
  const findings: Record<string, unknown>[] = [];
  const previousIds = new Set<number | string>();
  for (let page = 0; ; page++) {
    const batch = await readPage(page);
    const ids = batch
      .map(({ id }) => platformId(id))
      .filter((id) => id !== undefined);
    // Rows with invalid IDs are excluded during import. Still detect a repeated full page of them.
    if (!ids.length && batch.length >= pageSize) ids.push(pageId(batch));
    if (ids.some((id) => previousIds.has(id)))
      throw new Error(
        "Semgrep Platform repeated findings across pages; retry the collection.",
      );
    for (const finding of batch) findings.push(finding);
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
    product,
    ref,
    findingCount: findings.length,
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
  key = repositoryUrlKey,
): string | undefined {
  if (!isSemgrepPlatformReport(input)) return undefined;
  const selected = projectContext(
    input["project"],
    input["sourceRepositoryUrl"],
    key,
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
  declared?: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings & { sourceRepositoryUrl: string } {
  if (!isSemgrepPlatformReport(input))
    throw new Error("Expected a complete Semgrep Platform export.");
  return normalizePlatformReport(input, declared, target, repositoryUrlKey);
}

export function normalizePlatformReport(
  input: Record<string, unknown>,
  declared: string | undefined,
  target: ExternalImportTarget,
  key: typeof repositoryUrlKey,
): ExternalFindings & { sourceRepositoryUrl: string } {
  const deployment = requiredText(input["deployment"], "Semgrep deployment");
  const selected = projectContext(
    input["project"],
    input["sourceRepositoryUrl"] ?? declared,
    key,
  );
  if (declared !== undefined)
    matchingRepositoryUrl(declared, selected.url, key);
  const ref = requiredText(input["ref"], "Semgrep ref");
  const product = productType(input["product"]);
  const findings = array(input["findings"], "Semgrep Platform findings");
  if (input["findingCount"] !== findings.length)
    throw new Error(
      "Incomplete Semgrep Platform export: finding count does not match.",
    );
  const context = { format, deployment, ...selected.binding, ref, product };
  const result = normalizeRecords(
    findings.map((finding) => scopedFinding(finding, selected, ref)),
    (finding, id) => {
      const location = record(
        finding["location"] ?? {},
        "Semgrep finding location",
      );
      const path = relativePath(location["file_path"]);
      const line =
        path && location["line"] != null
          ? position(location["line"], "Semgrep starting line")
          : null;
      const rule = record(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      let productEvidence;
      if (product === "sca") {
        const dependency = finding["found_dependency"];
        const advisory = text(finding["vulnerability_identifier"]);
        const packages = [];
        if (dependency != null) {
          const {
            package: pkg,
            ecosystem,
            version,
          } = record(dependency, "Semgrep found dependency");
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
        const subject = requiredText(
          advisory ?? packages[0]?.name,
          "Semgrep advisory or package name",
        );
        productEvidence = {
          title: name ?? subject,
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
        const ruleName = requiredText(name, "Semgrep rule name");
        productEvidence = {
          title: ruleName,
          details: {
            kind: "sast",
            repository: { url: selected.url },
            scanner_origin: "Semgrep",
            rule: { id: ruleName },
            source_status: text(finding["status"]),
            weakness_ids: weaknessIds(rule["cwe_names"]),
            code: {
              end_line:
                line !== null && location["end_line"] != null
                  ? position(location["end_line"], "Semgrep ending line")
                  : null,
            },
          },
        };
      }
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            description: text(rule["message"]) ?? text(finding["rule_message"]),
            severity: scannerSeverity(text(finding["severity"])),
            locations: path ? [{ path, line }] : [],
            branch: ref,
            source_data: structuredClone({ ...context, finding }),
            ...productEvidence,
          },
          target,
        ),
      };
    },
    ({ id }) =>
      stableId("semgrep-platform", [
        deployment,
        selected.binding.project.id,
        product,
        ref,
        requiredId(id, "Semgrep finding ID"),
      ]),
    target,
  );
  return { ...result, sourceRepositoryUrl: selected.url };
}
