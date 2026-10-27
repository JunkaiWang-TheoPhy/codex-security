import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  combineHostedSignals,
  getHostedJson,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  record,
  relativePath,
  requiredText,
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

function positiveId(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new Error(`${label} must be a positive, safe integer.`);
  return value;
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
  return positiveId(value, label);
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

function repositoryUrl(value: unknown): string {
  const raw = requiredText(value, "Semgrep project repository URL");
  const url = new URL(raw);
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname === "/"
  )
    throw new Error(
      "Use an HTTP(S) Semgrep repository URL without credentials, query or fragment.",
    );
  return raw;
}

function assertRepository(value: unknown, expected: string): void {
  if (repositoryUrlKey(repositoryUrl(value)) !== repositoryUrlKey(expected))
    throw new Error(
      "Semgrep Platform repository does not match the selected source repository.",
    );
}

function projectContext(value: unknown, declared?: string): Project {
  const project = record(value, "Semgrep project");
  const url = repositoryUrl(text(project["url"]) ?? declared);
  if (declared) assertRepository(declared, url);
  return {
    id: platformId(project["id"], "Semgrep project ID"),
    name: requiredText(project["name"], "Semgrep project name"),
    url,
  };
}

function checkScope(value: unknown, project: Project, ref: string): void {
  const finding = record(value, "Semgrep Platform finding");
  const repository = record(
    finding["repository"],
    "Semgrep finding repository",
  );
  if (text(repository["url"])) assertRepository(repository["url"], project.url);
  else if (repository["name"] !== project.name)
    throw new Error(
      "Semgrep Platform finding lacks a matching source repository.",
    );
  if (finding["ref"] !== ref)
    throw new Error(
      "Semgrep Platform finding does not match the selected ref.",
    );
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
  const get = (url: URL) =>
    getHostedJson(
      url,
      `Bearer ${token}`,
      { ...dependencies, signal },
      parsePlatformJson,
    );
  const lookup = record(
    await get(new URL(`${base}/projects/${encodeURIComponent(name)}`)),
    "Semgrep project response",
  );
  const project = projectContext(
    lookup["project"],
    options.sourceRepositoryUrl,
  );
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
    const response = record(
      await get(new URL(url)),
      "Semgrep Platform findings response",
    );
    const batch = array(response["findings"], "Semgrep Platform findings");
    for (const finding of batch) {
      checkScope(finding, project, ref);
      findings.push(finding);
    }
    if (batch.length < 100) break;
    const fingerprint = stableId(
      "page",
      batch.map((finding) => (isRecord(finding) ? finding["id"] : null)),
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

export function semgrepPlatformRepository(
  input: Record<string, unknown>,
): string {
  return projectContext(input["project"]).url;
}

export function semgrepPlatformFindingRepository(
  input: Record<string, unknown>,
): string {
  const project = projectContext(input["project"]);
  checkScope(
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
): ExternalFindings {
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
  for (const finding of findings) checkScope(finding, project, ref);
  return normalizeRecords(
    findings,
    (value, id) => {
      const finding = record(value, "Semgrep Platform finding");
      const location = record(
        finding["location"] ?? {},
        "Semgrep finding location",
      );
      const path = relativePath(location["file_path"]);
      const line =
        path && location["line"] != null
          ? positiveId(location["line"], "Semgrep starting line")
          : null;
      const rule = record(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      const severity = text(finding["severity"]);
      const sourceData = structuredClone({
        format,
        deployment,
        project,
        ref,
        product,
        finding,
      });
      const common = {
        description: text(rule["message"]) ?? text(finding["rule_message"]),
        severity: ["critical", "high", "medium", "low"].includes(severity ?? "")
          ? severity
          : "unknown",
        locations: path ? [{ path, line }] : [],
        branch: ref,
        source_data: sourceData,
      };
      if (product === "sca") {
        const dependency = record(
          finding["found_dependency"],
          "Semgrep found dependency",
        );
        const packageName = requiredText(
          dependency["package"],
          "Semgrep package name",
        );
        const advisory = text(finding["vulnerability_identifier"]);
        return {
          source_finding_id: id,
          evidence: validateExternalEvidence(
            {
              ...common,
              title: name ?? advisory ?? packageName,
              advisory_ids: advisory ? [advisory] : [],
              packages: [
                {
                  name: packageName,
                  ecosystem: text(dependency["ecosystem"]),
                  installed_version: text(dependency["version"]),
                  fixed_versions: array(
                    finding["fix_recommendations"] ?? [],
                    "Semgrep fix recommendations",
                  ).flatMap((item) =>
                    isRecord(item) && item["package"] === packageName
                      ? strings([item["version"]])
                      : [],
                  ),
                },
              ],
            },
            target,
          ),
        };
      }
      if (
        finding["found_dependency"] != null ||
        finding["vulnerability_identifier"] != null
      )
        throw new Error("Supply Chain evidence is not a Semgrep Code finding.");
      const ruleName = requiredText(name, "Semgrep rule name");
      const end =
        line !== null && location["end_line"] != null
          ? positiveId(location["end_line"], "Semgrep ending line")
          : null;
      if (line && end && end < line)
        throw new Error("Semgrep source range ends before it starts.");
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            ...common,
            title: ruleName,
            details: {
              kind: "sast",
              repository: { url: project.url },
              scanner_origin: "Semgrep",
              rule: { id: ruleName },
              source_status: text(finding["status"]),
              weakness_ids: [
                ...new Set(
                  strings(rule["cwe_names"]).flatMap(
                    (label) => /^CWE-\d+(?=:|$)/u.exec(label)?.[0] ?? [],
                  ),
                ),
              ],
              code: { end_line: end },
            },
          },
          target,
        ),
      };
    },
    (value) =>
      stableId("semgrep-platform", [
        deployment,
        project.id,
        product,
        ref,
        platformId(
          record(value, "Semgrep finding")["id"],
          "Semgrep finding ID",
        ),
      ]),
    target,
  );
}
