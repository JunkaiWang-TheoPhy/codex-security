import { posix } from "node:path";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  isGitHubCloudHost,
  normalizeGitRepositoryUrl,
  parseGitRemote,
} from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

type NativeRecord = Record<string, unknown>;

function networkRepository(value: unknown): string | null {
  const source = text(value);
  if (!source || /^(?:[a-z]:|[./\\])/iu.test(source)) return null;
  const remote = parseGitRemote(source);
  if (!remote) return null;
  const { url } = remote;
  const ssh = ["ssh:", "git+ssh:", "ssh+git:"].includes(url.protocol);
  if (url.password || (!ssh && url.username) || /[?#\t\r\n]/u.test(source))
    throw new Error(
      "Use a Trivy repository URL without credentials, a query, or a fragment.",
    );
  if (url.protocol === "file:") return null;
  if (
    !url.hostname ||
    !remote.path ||
    (!ssh &&
      !["http:", "https:", "git:", "ftp:", "ftps:"].includes(url.protocol))
  )
    throw new Error("Unsupported Trivy repository URL.");
  return source;
}

function comparableGitHubRemote(
  remote: string,
  cloudRepositoryUrl?: string,
): string | undefined {
  if (/[?#\t\r\n]/u.test(remote)) return undefined;
  if (remote.startsWith("ssh://")) {
    const pathStart = remote.indexOf("/", "ssh://".length);
    if (pathStart < 0 || remote.slice(pathStart) !== new URL(remote).pathname)
      return undefined;
  }
  const normalized = normalizeGitRepositoryUrl(remote, cloudRepositoryUrl);
  if (!/^https?:\/\//iu.test(normalized)) return undefined;
  const host = new URL(normalized).hostname;
  if (
    !isGitHubCloudHost(host) &&
    (!cloudRepositoryUrl || new URL(cloudRepositoryUrl).hostname !== host)
  )
    return undefined;
  return normalized;
}

export function trivyRemoteKey(
  remote: string,
  cloudRepositoryUrl?: string,
): string {
  const normalized = comparableGitHubRemote(remote, cloudRepositoryUrl);
  if (!normalized) return remote;
  return cloudRepositoryUrl
    ? cloudRepositoryUrlKey(normalized)
    : repositoryUrlKey(normalized);
}

function trivyReportRemotes(sourceData: Record<string, unknown> | undefined): {
  repository: string | null;
  artifact: string | null;
} {
  const report = sourceData?.["report"];
  if (!isRecord(report) || report["SchemaVersion"] !== 2)
    return { repository: null, artifact: null };
  const metadata = report["Metadata"];
  const repository = networkRepository(
    isRecord(metadata) && metadata["RepoURL"],
  );
  const name = text(report["ArtifactName"]);
  const artifact =
    name && /^[a-z][a-z\d+.-]*:\/\//iu.test(name)
      ? networkRepository(name)
      : null;
  return { repository, artifact };
}

/** Compare the report's claims using the authenticated host when available. */
export function trivyRepositoryUrl(
  sourceData: Record<string, unknown> | undefined,
  cloudRepositoryUrl?: string,
): string | null {
  const { repository, artifact } = trivyReportRemotes(sourceData);
  if (
    repository &&
    artifact &&
    trivyRemoteKey(repository, cloudRepositoryUrl) !==
      trivyRemoteKey(artifact, cloudRepositoryUrl)
  )
    throw new Error(
      "Trivy Metadata.RepoURL and ArtifactName identify different repositories.",
    );
  const remote = repository ?? artifact;
  return remote && cloudRepositoryUrl
    ? (comparableGitHubRemote(remote, cloudRepositoryUrl) ?? remote)
    : remote;
}

function repositoryPath(value: unknown): string | null {
  const relative = relativePath(value);
  if (!relative) return null;
  const path = posix.normalize(relative);
  return path !== "." &&
    !path.endsWith("/") &&
    !/^(?:[a-z][a-z\d+.-]*:\/|[^/]+@[^/]+:)/iu.test(path)
    ? path
    : null;
}

const aggregateTargets = new Map([
  ["python-pkg", "Python"],
  ["conda-pkg", "Conda"],
  ["gemspec", "Ruby"],
  ["node-pkg", "Node.js"],
  ["jar", "Java"],
  ["kubernetes", "Kubernetes"],
]);
const nonManifestTypes = new Set([
  "gobinary",
  "rustbinary",
  "jar",
  "javascript",
]);

function resolveScanRoot(
  scanRoot: string | undefined,
  remoteRepository: boolean,
): string {
  if (scanRoot === undefined) {
    if (remoteRepository) return ".";
    throw new Error(
      "Specify --trivy-scan-root relative to the repository; use . for a whole-checkout scan.",
    );
  }
  const relative = relativePath(scanRoot);
  const root = relative && posix.normalize(relative).replace(/\/$/u, "");
  if (!root || (root !== "." && !repositoryPath(root)))
    throw new Error(
      "--trivy-scan-root must be a repository-relative directory without traversal.",
    );
  if (remoteRepository && root !== ".")
    throw new Error(
      "A remote Trivy repository scan starts at the checkout root; --trivy-scan-root must be .",
    );
  return root;
}

function scopedPath(root: string, value: unknown): string | null {
  const path = repositoryPath(value);
  return path === null ? null : posix.join(root, path);
}

function pick(source: NativeRecord, fields: string[]): NativeRecord {
  return Object.fromEntries(
    fields
      .filter((field) => Object.hasOwn(source, field))
      .map((field) => [field, source[field]]),
  );
}

function packageKeys(
  id: unknown,
  identifier: unknown,
  name: unknown,
  version: unknown,
  path: unknown,
) {
  const file = repositoryPath(path) ?? text(path);
  const key = (kind: string, value: unknown) =>
    text(value) && JSON.stringify([kind, value, file]);
  const native = isRecord(identifier) ? identifier : {};
  return {
    id: key("id", id),
    uid: key("uid", native["UID"]),
    purl: key("purl", native["PURL"]),
    bomRef: key("bomRef", native["BOMRef"]),
    nameVersion:
      text(name) &&
      text(version) &&
      JSON.stringify(["name-version", name, version, file]),
  };
}

type PackageIndex = Map<
  string,
  { pkg: NativeRecord; keys: ReturnType<typeof packageKeys> } | null
>;

function indexPackages(packages: unknown): PackageIndex {
  const index: PackageIndex = new Map();
  for (const value of array(packages ?? [], "Trivy Packages")) {
    const pkg = record(value, "Trivy package");
    const keys = packageKeys(
      pkg["ID"],
      pkg["Identifier"],
      pkg["Name"],
      pkg["Version"],
      pkg["FilePath"],
    );
    const match = { pkg, keys };
    for (const key of Object.values(keys))
      if (key) index.set(key, index.has(key) ? null : match);
  }
  return index;
}

function matchingPackage(vulnerability: NativeRecord, index: PackageIndex) {
  const keys = packageKeys(
    vulnerability["PkgID"],
    vulnerability["PkgIdentifier"],
    vulnerability["PkgName"],
    vulnerability["InstalledVersion"],
    vulnerability["PkgPath"],
  );
  const supplied = (["uid", "id", "purl", "bomRef"] as const).filter(
    (field) => keys[field],
  );
  for (const field of supplied.length ? supplied : (["nameVersion"] as const)) {
    const key = keys[field];
    const match = key && index.get(key);
    if (
      match &&
      agreesWhenPresent(vulnerability["PkgName"], match.pkg["Name"]) &&
      agreesWhenPresent(
        vulnerability["InstalledVersion"],
        match.pkg["Version"],
      ) &&
      supplied.every((id) => !match.keys[id] || keys[id] === match.keys[id])
    )
      return match.pkg;
  }
  return null;
}

function agreesWhenPresent(detected: unknown, inventoried: unknown): boolean {
  return !text(detected) || !text(inventoried) || detected === inventoried;
}

interface Entry {
  result: { Target?: string; Type: string; Class: string };
  packages: PackageIndex;
  value: unknown;
}

function occurrence(entry: Entry | string, root: string) {
  if (typeof entry === "string") throw new Error(entry);
  const vulnerability = record(entry.value, "Trivy vulnerability");
  const { Target, Type } = entry.result;
  return {
    ...entry,
    vulnerability,
    advisory: requiredText(
      vulnerability["VulnerabilityID"],
      "Trivy VulnerabilityID",
    ),
    name: requiredText(vulnerability["PkgName"], "Trivy PkgName"),
    pkgPath: text(vulnerability["PkgPath"]),
    targetPath:
      aggregateTargets.get(Type) === Target ? null : scopedPath(root, Target),
    packagePath: scopedPath(root, vulnerability["PkgPath"]),
  };
}

/** Import native Trivy dependency occurrences. Local scans require their checkout-relative
 * scan root. The package ecosystem is the PURL type when supplied, otherwise the analyzer. */
export function normalizeTrivyFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): ExternalFindings {
  const document = record(input, "Trivy report");
  if (document["SchemaVersion"] !== 2)
    throw new Error(
      "Expected a native Trivy JSON report with SchemaVersion 2.",
    );
  if (
    document["ArtifactType"] !== "repository" &&
    document["ArtifactType"] !== "filesystem"
  )
    throw new Error(
      "Only Trivy repository and filesystem reports are supported.",
    );
  const metadata = record(document["Metadata"] ?? {}, "Trivy Metadata");
  const report = {
    ...pick(document, [
      "SchemaVersion",
      "ArtifactType",
      "ArtifactName",
      "ArtifactID",
      "ReportID",
      "CreatedAt",
    ]),
    ...(isRecord(document["Trivy"])
      ? { Trivy: pick(document["Trivy"], ["Version"]) }
      : {}),
    Metadata: pick(metadata, ["RepoURL", "Branch", "Commit"]),
  };
  const { artifact } = trivyReportRemotes({ report });
  const root = resolveScanRoot(
    scanRoot,
    document["ArtifactType"] === "repository" && artifact !== null,
  );

  const entries: (Entry | string)[] = [];
  for (const group of array(document["Results"] ?? [], "Trivy Results")) {
    const result = record(group, "Trivy result");
    if (result["Class"] !== "lang-pkgs") {
      entries.push(
        `Unsupported Trivy result class: ${text(result["Class"]) ?? "(missing)"}. Only lang-pkgs vulnerabilities are imported.`,
      );
      continue;
    }
    for (const field of [
      "Misconfigurations",
      "Secrets",
      "Licenses",
      "CryptoAssets",
      "CustomResources",
      "ExperimentalModifiedFindings",
    ])
      if (array(result[field] ?? [], `Trivy ${field}`).length)
        entries.push(`Unsupported Trivy ${field} in lang-pkgs result.`);

    const vulnerabilities = array(
      result["Vulnerabilities"] ?? [],
      "Trivy Vulnerabilities",
    );
    if (!vulnerabilities.length) continue;
    const reportedTarget = result["Target"];
    if (reportedTarget != null && typeof reportedTarget !== "string")
      throw new Error("Trivy result Target must be text.");
    const context = {
      ...(reportedTarget == null ? {} : { Target: reportedTarget }),
      Type: requiredText(result["Type"], "Trivy result Type"),
      Class: result["Class"],
    };
    const packages = indexPackages(result["Packages"]);
    for (const value of vulnerabilities)
      entries.push({ result: context, packages, value });
  }

  return normalizeRecords(
    entries,
    (entry, id) => {
      const {
        result,
        packages,
        vulnerability,
        advisory,
        name,
        targetPath,
        packagePath,
      } = occurrence(entry, root);
      const identifier = vulnerability["PkgIdentifier"];
      const purl = isRecord(identifier) ? text(identifier["PURL"]) : null;
      const ecosystem =
        purl?.match(/^pkg:([a-z][a-z\d.+-]*)\//iu)?.[1]?.toLowerCase() ??
        result.Type;
      const pkg = matchingPackage(vulnerability, packages);
      const manifest = nonManifestTypes.has(result.Type) ? null : targetPath;
      const starts = new Set<number>();
      if (manifest && pkg)
        for (const range of array(
          pkg["Locations"] ?? [],
          "Trivy package Locations",
        )) {
          const start = isRecord(range) && range["StartLine"];
          if (
            typeof start === "number" &&
            Number.isSafeInteger(start) &&
            start > 0
          )
            starts.add(start);
        }
      const locations = [
        ...(targetPath
          ? (starts.size ? [...starts] : [null]).map((line) => ({
              path: targetPath,
              line,
            }))
          : []),
        ...(packagePath && packagePath !== targetPath
          ? [{ path: packagePath, line: null }]
          : []),
      ];
      const severity = text(vulnerability["Severity"])?.toLowerCase();
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            title: text(vulnerability["Title"]) ?? `${advisory} in ${name}`,
            severity:
              severity &&
              ["critical", "high", "medium", "low"].includes(severity)
                ? severity
                : "unknown",
            description: text(vulnerability["Description"]),
            url: text(vulnerability["PrimaryURL"]),
            advisory_ids: [
              ...new Set([advisory, ...strings(vulnerability["VendorIDs"])]),
            ],
            packages: [
              {
                name,
                ecosystem,
                manifest_path: manifest,
                installed_version: text(vulnerability["InstalledVersion"]),
                fixed_versions:
                  text(vulnerability["FixedVersion"])
                    ?.split(",")
                    .map((version) => version.trim())
                    .filter(Boolean) ?? [],
              },
            ],
            locations,
            branch: text(metadata["Branch"]),
            code_revision: text(metadata["Commit"]),
            source_scan_id: text(document["ReportID"]),
            source_data: structuredClone({
              scanRoot: root,
              report,
              result,
              vulnerability,
              ...(pkg
                ? {
                    package: pick(pkg, [
                      "ID",
                      "Name",
                      "Version",
                      "Identifier",
                      "FilePath",
                      "Relationship",
                      "Locations",
                    ]),
                  }
                : {}),
            }),
          },
          target,
        ),
      };
    },
    (entry) => {
      const { result, advisory, name, pkgPath, targetPath, packagePath } =
        occurrence(entry, root);
      const manifest = targetPath ?? text(result.Target);
      const concretePath = packagePath ?? pkgPath;
      return stableId("trivy", [
        result.Type,
        manifest,
        advisory,
        name,
        concretePath === manifest ? null : concretePath,
        ...(!targetPath && !packagePath && root !== "." ? [root] : []),
      ]);
    },
    target,
  );
}

export async function readTrivyFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): Promise<ExternalFindings> {
  return normalizeTrivyFindings(await readScannerJson(path), target, scanRoot);
}
