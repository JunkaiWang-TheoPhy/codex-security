import {
  type ExternalImportTarget,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  combineHostedSignals,
  getHostedJson,
  hostedRepositoryUrl,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import { position, weaknessIds } from "./native-json-findings.js";
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
  url: string;
}

export interface SemgrepPlatformReport {
  format: typeof format;
  deployment: string;
  project: Project;
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

function platformId(value: unknown, label: string): number | string {
  if (
    typeof value === "string" &&
    /^[1-9]\d{0,18}$/u.test(value) &&
    BigInt(value) <= 9223372036854775807n
  )
    return Number.isSafeInteger(Number(value)) ? Number(value) : value;
  return position(value, label);
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

function assertRepository(value: unknown, expected: string): void {
  const url = hostedRepositoryUrl(value, "Semgrep repository URL");
  if (repositoryUrlKey(url) !== repositoryUrlKey(expected))
    throw new Error(
      "Semgrep Platform repository does not match the selected source repository.",
    );
}

function projectContext(value: unknown, declared?: string): Project {
  const { id, name, url: nativeUrl } = record(value, "Semgrep project");
  const url = hostedRepositoryUrl(
    text(nativeUrl) ?? declared,
    "Semgrep project repository URL",
  );
  if (declared) assertRepository(declared, url);
  return {
    id: platformId(id, "Semgrep project ID"),
    name: requiredText(name, "Semgrep project name"),
    url,
  };
}

function scopedFinding(value: unknown, project: Project, ref: string) {
  const finding = record(value, "Semgrep Platform finding");
  const { url, name } = record(
    finding["repository"],
    "Semgrep finding repository",
  );
  if (text(url)) assertRepository(url, project.url);
  else if (name !== project.name)
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
  const signal = combineHostedSignals(options.signal, dependencies.signal);
  signal?.throwIfAborted();
  const token = requiredText(
    options.token ?? environment["SEMGREP_APP_TOKEN"],
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
  const http = { ...dependencies, signal };
  const get = async (url: URL) =>
    record(
      await getHostedJson(url, `Bearer ${token}`, http, parsePlatformJson),
      "Semgrep API response",
    );
  const { sourceRepositoryUrl } = options;
  const lookup = await get(
    new URL(`${base}/projects/${encodeURIComponent(name)}`),
  );
  const project = projectContext(lookup["project"], sourceRepositoryUrl);
  if (project.name !== name)
    throw new Error("Semgrep returned a different project than requested.");
  const url = new URL(`${base}/findings`);
  url.search = new URLSearchParams({
    repository_ids: String(project.id),
    ref,
    issue_type: product,
    dedup: "false",
    page_size: "100",
  }).toString();
  const findings: unknown[] = [];
  const fullPages = new Set<string>();
  for (let page = 0; ; page++) {
    url.searchParams.set("page", String(page));
    const response = await get(new URL(url));
    const batch = array(response["findings"], "Semgrep Platform findings").map(
      (row) => scopedFinding(row, project, ref),
    );
    for (const finding of batch) findings.push(finding);
    if (batch.length < 100) break;
    const fingerprint = stableId(
      "page",
      batch.map(({ id }) => id),
    );
    if (fullPages.has(fingerprint))
      throw new Error(
        "Semgrep Platform repeated a findings page; retry the collection.",
      );
    fullPages.add(fingerprint);
  }
  signal?.throwIfAborted();
  return {
    format,
    deployment,
    project,
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
): string | undefined {
  if (!isSemgrepPlatformReport(input)) return undefined;
  const project = projectContext(input["project"]);
  scopedFinding(
    input["finding"],
    project,
    requiredText(input["ref"], "Semgrep ref"),
  );
  return project.url;
}

export function normalizeSemgrepPlatformFindings(
  input: unknown,
  declared?: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings & { sourceRepositoryUrl: string } {
  if (!isSemgrepPlatformReport(input))
    throw new Error("Expected a complete Semgrep Platform export.");
  const deployment = requiredText(input["deployment"], "Semgrep deployment");
  const project = projectContext(input["project"], declared);
  const ref = requiredText(input["ref"], "Semgrep ref");
  const product = productType(input["product"]);
  const findings = array(input["findings"], "Semgrep Platform findings");
  if (input["findingCount"] !== findings.length)
    throw new Error(
      "Incomplete Semgrep Platform export: finding count does not match.",
    );
  const context = { format, deployment, project, ref, product };
  const result = normalizeRecords(
    findings.map((finding) => scopedFinding(finding, project, ref)),
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
        const {
          package: pkg,
          ecosystem,
          version,
        } = record(finding["found_dependency"], "Semgrep found dependency");
        const packageName = requiredText(pkg, "Semgrep package name");
        const advisory = text(finding["vulnerability_identifier"]);
        const fixes = array(
          finding["fix_recommendations"] ?? [],
          "Semgrep fix recommendations",
        );
        productEvidence = {
          title: name ?? advisory ?? packageName,
          advisory_ids: advisory ? [advisory] : [],
          packages: [
            {
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
            },
          ],
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
            repository: { url: project.url },
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
        project.id,
        product,
        ref,
        platformId(id, "Semgrep finding ID"),
      ]),
    target,
  );
  return { ...result, sourceRepositoryUrl: project.url };
}
