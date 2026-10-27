import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { ExternalImportTarget } from "../src/external-import-contract.js";
import {
  inspectorEvidenceRepositoryUrls,
  normalizeInspectorFindings,
  readInspectorFindings,
} from "../src/inspector-findings.js";
import {
  inspectorIntegrationArn,
  inspectorPackageFinding,
  inspectorProjectId,
  inspectorReport,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

function normalize(
  findings: unknown[],
  source = inspectorRepositoryUrl,
  target: ExternalImportTarget = "cloud",
) {
  return normalizeInspectorFindings({ findings }, source, target);
}

function codeFinding(
  filePath = "src/example.ts",
  fileName = "example.ts",
  startLine = 8,
) {
  const { packageVulnerabilityDetails: _packages, ...common } =
    inspectorPackageFinding();
  return {
    ...common,
    type: "CODE_VULNERABILITY",
    findingArn: common.findingArn.replace(/a{32}$/u, "b".repeat(32)),
    title: "Synthetic code finding",
    codeVulnerabilityDetails: {
      detectorId: "synthetic-detector",
      detectorName: "Synthetic detector",
      cwes: ["CWE-79"],
      detectorTags: ["example-tag"],
      filePath: { fileName, filePath, startLine, endLine: 12 },
    },
  };
}

function projectFinding(
  repoChanges: Record<string, unknown>,
  resourceChanges: Record<string, unknown> = {},
) {
  const finding = inspectorPackageFinding();
  const resource = finding.resources[0]!;
  return {
    ...finding,
    resources: [
      {
        ...resource,
        details: {
          codeRepository: {
            ...resource.details.codeRepository,
            ...repoChanges,
          },
        },
        ...resourceChanges,
      },
    ],
  };
}

test("projects a repository advisory and its reported package without inferring a revision or assessment", () => {
  const report = inspectorReport();
  const native = report.findings[0]!;
  const original = structuredClone(native);
  const output = normalizeInspectorFindings(report, inspectorRepositoryUrl);
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  const row = output.findings[0]!;
  expect(row.source_finding_id).toBe(native.findingArn);
  expect(row.evidence).toMatchObject({
    title: native.title,
    severity: "high",
    description: native.description,
    advisory_ids: ["CVE-2099-1234", "GHSA-2345-6789-cfgh"],
    url: native.packageVulnerabilityDetails.sourceUrl,
    packages: [
      {
        name: "example-package",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        ecosystem: "npm",
        manifest_path: "apps/web/package-lock.json",
      },
    ],
    locations: [{ path: "apps/web/package-lock.json", line: null }],
    details: {
      kind: "advisory",
      advisory: { source: "repository" },
      repository: {
        url: inspectorRepositoryUrl,
        id: native.resources[0]!.id,
        name: "example/project",
      },
      source_status: "ACTIVE",
      scanner_origin: "Amazon Inspector",
      remediation_instructions: "Review the dependency update.",
    },
    source_updated_at: Date.parse(native.updatedAt) / 1000,
    source_data: {
      sourceRepositoryUrl: inspectorRepositoryUrl,
      finding: original,
    },
  });
  expect(row.evidence.branch ?? null).toBeNull();
  expect(row.evidence.code_revision ?? null).toBeNull();
  expect(row.evidence.source_scan_id ?? null).toBeNull();
  expect(row).not.toHaveProperty("assessment");
  expect(inspectorEvidenceRepositoryUrls(row.evidence.source_data)).toEqual([
    inspectorRepositoryUrl,
  ]);
  expect(native).toEqual(original);
  native.status = "CLOSED";
  native.packageVulnerabilityDetails.vulnerablePackages[0]!.version = "^2.0";
  const updated = normalize([native]).findings[0]!;
  expect(updated.source_finding_id).toBe(row.source_finding_id);
  expect(updated.evidence.details?.source_status).toBe("CLOSED");
  expect(updated.evidence.packages![0]!.installed_version ?? null).toBeNull();
  expect(row.evidence.source_data?.["finding"]).toEqual(original);
  expect(updated.evidence.source_data?.["finding"]).toMatchObject({
    status: "CLOSED",
  });
});

test("code detector tags, ranges and weaknesses stay native; only supplied repository locations are projected", () => {
  const code = codeFinding();
  const output = normalize([code]);
  const evidence = output.findings[0]!.evidence;
  expect(evidence.locations).toEqual([{ path: "src/example.ts", line: 8 }]);
  expect(evidence.details ?? null).toBeNull();
  expect(evidence.source_data?.["finding"]).toEqual(code);
  for (const file of [
    "/tmp/example.ts",
    "C:\\work\\example.ts",
    "src/../example.ts",
    "file:///tmp/example.ts",
    "https://example.invalid/example.ts",
    "~/example.ts",
    "./C:/work/example.ts",
  ])
    expect(
      normalize([codeFinding(file)]).findings[0]!.evidence.locations,
    ).toEqual([]);
  expect(
    normalize([codeFinding("src/", "example.ts")]).findings[0]!.evidence
      .locations,
  ).toEqual([]);
  expect(
    normalize([codeFinding("src/example.ts", "different.ts")]).findings[0]!
      .evidence.locations,
  ).toEqual([]);
  expect(
    normalize([codeFinding("src\\example.ts", "example.ts", 0)]).findings[0]!
      .evidence.locations,
  ).toEqual([{ path: "src/example.ts", line: null }]);
});

test("no fix version, package path or scan time is inferred from other fields", () => {
  const native = inspectorPackageFinding();
  const pkg = { name: "synthetic", version: "^1", filePath: "/image/example" };
  const evidence = normalize([
    {
      ...native,
      updatedAt: undefined,
      severity: "UNTRIAGED",
      packageVulnerabilityDetails: {
        ...native.packageVulnerabilityDetails,
        vulnerablePackages: [pkg],
      },
    },
  ]).findings[0]!.evidence;
  expect(evidence.locations).toEqual([]);
  expect(evidence.severity).toBe("unknown");
  expect(evidence.packages![0]).toMatchObject({
    name: "synthetic",
    installed_version: null,
    manifest_path: null,
    ecosystem: null,
    fixed_versions: [],
  });
  expect(evidence.source_updated_at ?? null).toBeNull();
});

test("distinguishes native package file locations from dependency manifests and version selectors", () => {
  const native = inspectorPackageFinding();
  const base = native.packageVulnerabilityDetails.vulnerablePackages[0]!;
  const values = [
    {
      ...base,
      filePath: "src/example.ts",
      packageManager: "UNKNOWN",
      version: "1.2.x",
      fixedInVersion: ">=2.0",
    },
    {
      ...base,
      filePath: "api/requirements-dev.txt",
      packageManager: "PIP",
      version: "1!2.3rc1+lab",
    },
    { ...base, filePath: "../package-lock.json", version: "workspace:*" },
  ];
  const evidence = normalize([
    {
      ...native,
      packageVulnerabilityDetails: {
        ...native.packageVulnerabilityDetails,
        vulnerablePackages: values,
      },
    },
  ]).findings[0]!.evidence;
  expect(evidence.packages).toMatchObject([
    {
      installed_version: null,
      fixed_versions: [],
      ecosystem: null,
      manifest_path: null,
    },
    {
      installed_version: "1!2.3rc1+lab",
      ecosystem: "pypi",
      manifest_path: "api/requirements-dev.txt",
    },
    { installed_version: null, manifest_path: null },
  ]);
  expect(evidence.locations).toEqual([
    { path: "src/example.ts", line: null },
    { path: "api/requirements-dev.txt", line: null },
  ]);
  expect(evidence.source_data?.["finding"]).toMatchObject({
    packageVulnerabilityDetails: { vulnerablePackages: values },
  });
});

test("accepts both native CLI Unix and ISO timestamps without losing their original representation", () => {
  const native = inspectorPackageFinding();
  const epoch = Date.parse(native.updatedAt) / 1000;
  for (const updatedAt of [
    epoch + 0.125,
    native.updatedAt,
    "2026-01-04T06:06:07.125+01:00",
  ]) {
    const row = normalize([
      {
        ...native,
        firstObservedAt: epoch - 2,
        lastObservedAt: epoch - 1,
        updatedAt,
      },
    ]).findings[0]!;
    expect(row.evidence.source_updated_at).toBe(epoch);
    expect(row.evidence.source_data?.["finding"]).toMatchObject({ updatedAt });
  }
  for (const updatedAt of [
    "January 4",
    "2026-01-04T05:06:07",
    String(epoch),
    null,
  ]) {
    const result = normalize([{ ...native, updatedAt }]);
    expect(result.findings).toHaveLength(0);
    expect(result.excluded[0]?.reason).toContain("timestamp");
  }
});

test("accepts an explicitly empty report but not errors, projections, event envelopes or partial pages", () => {
  expect(normalize([])).toEqual({ read: 0, findings: [], excluded: [] });
  for (const invalid of [
    null,
    [],
    {},
    { Findings: [] },
    { findings: null },
    { findings: [], Error: { Code: "AccessDenied" } },
    { errors: [] },
    { detail: inspectorReport() },
    inspectorPackageFinding(),
  ])
    expect(() =>
      normalizeInspectorFindings(invalid, inspectorRepositoryUrl),
    ).toThrow();
  for (const key of ["nextToken", "NextToken"])
    for (const token of ["synthetic-token", null, ""])
      expect(() =>
        normalizeInspectorFindings(
          { ...inspectorReport(), [key]: token },
          inspectorRepositoryUrl,
        ),
      ).toThrow("continuation");
});

test("counts exclusions and rejects all duplicate finding ARNs without contaminating supported rows", () => {
  const supported = inspectorPackageFinding();
  const duplicate = codeFinding();
  const output = normalize([
    supported,
    null,
    duplicate,
    { ...duplicate, status: "SUPPRESSED" },
  ]);
  expect(output.read).toBe(4);
  expect(output.findings.map((row) => row.source_finding_id)).toEqual([
    supported.findingArn,
  ]);
  expect(
    output.excluded.map(({ position, source_finding_id }) => [
      position,
      source_finding_id,
    ]),
  ).toEqual([
    [2, null],
    [3, duplicate.findingArn],
    [4, duplicate.findingArn],
  ]);
  expect(output.excluded[1]!.reason).toContain("duplicate");
});

test.each([
  "AWS_EC2_INSTANCE",
  "AWS_ECR_CONTAINER_IMAGE",
  "AWS_ECR_REPOSITORY",
  "AWS_LAMBDA_FUNCTION",
])(
  "does not import %s, even when a finding also lists a code repository",
  (type) => {
    const supported = inspectorPackageFinding();
    const other = {
      type,
      id: "opaque-workload",
      tags: { unrelated: "synthetic-workload-only" },
    };
    for (const resources of [[other], [other, ...supported.resources]]) {
      const output = normalize([supported, { ...codeFinding(), resources }]);
      expect(output.read).toBe(2);
      expect(output.findings).toHaveLength(1);
      expect(output.excluded[0]!.position).toBe(2);
      expect(JSON.stringify(output.findings)).not.toContain(
        "synthetic-workload-only",
      );
    }
  },
);

test("rejects network, cross-family and layer payloads on apparently repository-only findings", () => {
  const pkg = inspectorPackageFinding();
  const code = codeFinding();
  const resource = pkg.resources[0]!;
  for (const row of [
    { ...pkg, type: "NETWORK_REACHABILITY" },
    { ...pkg, networkReachabilityDetails: {} },
    { ...code, packageVulnerabilityDetails: pkg.packageVulnerabilityDetails },
    {
      ...pkg,
      resources: [
        {
          ...resource,
          details: { ...resource.details, awsLambdaFunction: {} },
        },
      ],
    },
    {
      ...code,
      codeVulnerabilityDetails: {
        ...code.codeVulnerabilityDetails,
        sourceLambdaLayerArn: "synthetic-layer",
      },
    },
    ...["sourceLayerHash", "sourceLambdaLayerArn"].map((field) => ({
      ...pkg,
      packageVulnerabilityDetails: {
        ...pkg.packageVulnerabilityDetails,
        vulnerablePackages: [
          {
            ...pkg.packageVulnerabilityDetails.vulnerablePackages[0],
            [field]: "synthetic-layer",
          },
        ],
      },
    })),
  ]) {
    const output = normalize([row]);
    expect(output.findings).toEqual([]);
    expect(output.excluded).toHaveLength(1);
    expect(output.excluded[0]!.source_finding_id).toBe(row.findingArn);
  }
});

test("requires a complete explicit mapping; a bare name or opaque project ID cannot assign a host or namespace", () => {
  for (const source of [
    "",
    "example/project",
    "https://example.invalid/project",
    "https://u:p@example.invalid/org/project",
    inspectorRepositoryUrl + "?",
    inspectorRepositoryUrl + "#ref",
    "https://example.invalid/other/../example/project",
    "https://example.invalid/example%2fgroup/project",
  ])
    expect(() => normalize([], source)).toThrow();
  for (const name of [
    undefined,
    "project",
    inspectorProjectId,
    "other/project",
    "https://git.example.test/example/project",
  ])
    expect(() => normalize([projectFinding({ projectName: name })])).toThrow();
  expect(() =>
    normalize([
      projectFinding(
        { projectName: "example/project" },
        { id: "https://git.example.test/example/project" },
      ),
    ]),
  ).toThrow("does not match");
  const host = "https://git.example.test/group/sub/project";
  for (const providerType of ["GITHUB", "GITLAB_SELF_MANAGED"])
    expect(() =>
      normalize(
        [projectFinding({ providerType, projectName: "group/sub/project" })],
        "https://gitlab.com/group/sub/project",
      ),
    ).toThrow("provider");
  expect(
    normalize(
      [
        projectFinding({
          providerType: "GITLAB_SELF_MANAGED",
          projectName: "group/sub/project",
        }),
      ],
      host,
      "local",
    ).findings,
  ).toHaveLength(1);
  expect(() =>
    normalize(
      [
        projectFinding({
          providerType: "GITLAB_SELF_MANAGED",
          projectName: "Group/sub/project",
        }),
      ],
      host,
      "local",
    ),
  ).toThrow("does not match");
  expect(
    normalize([
      projectFinding({ projectName: "https://GITHUB.COM/EXAMPLE/PROJECT.git" }),
    ]).findings,
  ).toHaveLength(1);
});

test("GitHub project slugs bind only on known hosted endpoints; custom hosts require a matching native URL", () => {
  const host = "https://git.example.test/Example/Project";
  const slug = projectFinding({ projectName: "EXAMPLE/PROJECT" });
  const nativeUrl = projectFinding({
    projectName: "https://GIT.EXAMPLE.TEST/example/project.git",
  });
  for (const target of ["local", "cloud"] as const) {
    for (const source of [
      inspectorRepositoryUrl,
      "https://acme.ghe.com/example/project",
    ])
      expect(normalize([slug], source, target).findings).toHaveLength(1);
    for (const source of [
      host,
      "https://github.com.example.test/example/project",
      "https://github.com:8443/example/project",
    ])
      expect(() => normalize([slug], source, target)).toThrow(
        "native repository URL",
      );
    expect(normalize([nativeUrl], host, target).findings).toHaveLength(1);
    expect(() =>
      normalize([nativeUrl], host.replace("git.", "other."), target),
    ).toThrow("does not match");
    expect(() =>
      normalize([nativeUrl], host.replace("https:", "http:"), target),
    ).toThrow("does not match");
    const resourceUrl = projectFinding(
      { projectName: "project" },
      { id: host.toLowerCase() },
    );
    expect(normalize([resourceUrl], host, target).findings).toHaveLength(1);
    expect(() =>
      normalize(
        [projectFinding({ projectName: "wrong" }, { id: host })],
        host,
        target,
      ),
    ).toThrow("does not match");
  }
  const noProvider = projectFinding({
    projectName: host,
    providerType: undefined,
  });
  expect(normalize([noProvider], host, "local").findings).toHaveLength(1);
  expect(() => normalize([noProvider], host, "cloud")).toThrow(
    "GitHub repository provider",
  );
});

test("retained GitLab evidence is local only even when a Cloud catalog could contain the same hostname and slug", () => {
  const host = "https://git.example.test/group/project";
  for (const projectName of ["group/project", host]) {
    const native = projectFinding({
      providerType: "GITLAB_SELF_MANAGED",
      projectName,
    });
    const row = normalize([native], host, "local").findings[0]!;
    expect(
      inspectorEvidenceRepositoryUrls(
        row.evidence.source_data,
        native.findingArn,
        "local",
      ),
    ).toEqual([host]);
    expect(() => normalize([native], host, "cloud")).toThrow("local only");
    expect(() =>
      inspectorEvidenceRepositoryUrls(
        row.evidence.source_data,
        native.findingArn,
        "cloud",
      ),
    ).toThrow("local only");
  }
});

test("checks native scope before discarding duplicates or unsupported finding types", () => {
  const first = inspectorPackageFinding();
  const anotherProject =
    inspectorIntegrationArn + "/project-33333333-3333-4333-8333-333333333333";
  expect(() =>
    normalize([
      first,
      {
        ...projectFinding({}, { id: anotherProject }),
        type: "NETWORK_REACHABILITY",
      },
    ]),
  ).toThrow("more than one repository");
  const other = projectFinding({}, { id: anotherProject });
  expect(() =>
    normalize([
      { ...first, resources: [...first.resources, ...other.resources] },
    ]),
  ).toThrow("more than one repository");
  expect(() =>
    normalize([first, projectFinding({ projectName: "other/project" })]),
  ).toThrow("does not match");
  expect(() => normalize([{ ...first, awsAccountId: "999999999999" }])).toThrow(
    "account",
  );
  for (const change of [
    {
      id:
        inspectorIntegrationArn.replace("us-east-1", "us-west-2") +
        "/" +
        inspectorProjectId,
    },
    { id: "arn:aws:ecr:us-east-1:123456789012:repository/example/project" },
    { providerAccountId: "999999999999" },
    { region: "us-west-2" },
    { partition: "aws-cn" },
  ])
    expect(() => normalize([projectFinding({}, change)])).toThrow();
  expect(() =>
    normalize([
      projectFinding({
        integrationArn: inspectorIntegrationArn.replace("11111111", "44444444"),
      }),
    ]),
  ).toThrow("integration");
  expect(() =>
    normalize([projectFinding({ providerType: "GITLAB_SELF_MANAGED" })]),
  ).toThrow("provider");
});

test("retained Inspector evidence rechecks its own binding instead of trusting typed repository metadata", () => {
  const native = inspectorPackageFinding();
  const raw = normalize([native]).findings[0]!.evidence.source_data!;
  for (const target of ["cloud", "local"] as const) {
    expect(
      inspectorEvidenceRepositoryUrls(raw, native.findingArn, target),
    ).toEqual([inspectorRepositoryUrl]);
    expect(() =>
      inspectorEvidenceRepositoryUrls(raw, codeFinding().findingArn, target),
    ).toThrow("finding ARN");
    expect(() =>
      inspectorEvidenceRepositoryUrls(
        { ...raw, finding: codeFinding() },
        native.findingArn,
        target,
      ),
    ).toThrow("finding ARN");
    expect(() =>
      inspectorEvidenceRepositoryUrls(
        {
          ...raw,
          sourceRepositoryUrl: "https://git.example.test/example/project",
        },
        native.findingArn,
        target,
      ),
    ).toThrow("native repository URL");
  }
  expect(inspectorEvidenceRepositoryUrls(undefined)).toEqual([]);
  expect(inspectorEvidenceRepositoryUrls({ finding: "opaque" })).toEqual([]);
  expect(() =>
    inspectorEvidenceRepositoryUrls({ ...raw, sourceRepositoryUrl: undefined }),
  ).toThrow();
  expect(() =>
    inspectorEvidenceRepositoryUrls({
      ...raw,
      sourceRepositoryUrl: "https://github.com/other/project",
    }),
  ).toThrow("does not match");
  expect(() =>
    inspectorEvidenceRepositoryUrls({
      ...raw,
      finding: projectFinding({ projectName: "other/project" }),
    }),
  ).toThrow("does not match");
  expect(() =>
    inspectorEvidenceRepositoryUrls({
      ...raw,
      finding: { ...codeFinding(), resources: [] },
    }),
  ).toThrow("CODE_REPOSITORY");
});

test("reads saved JSON and gzip without treating JSONL or damaged bytes as a successful empty export", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synthetic-inspector-"));
  try {
    const path = join(directory, "input.json");
    const report = inspectorReport();
    const expected = normalizeInspectorFindings(report, inspectorRepositoryUrl);
    for (const bytes of [
      Buffer.from(JSON.stringify(report)),
      gzipSync(JSON.stringify(report)),
    ]) {
      await writeFile(path, bytes);
      expect(await readInspectorFindings(path, inspectorRepositoryUrl)).toEqual(
        expected,
      );
    }
    await writeFile(path, '{"findings":[]}\n{"findings":[]}');
    await expect(
      readInspectorFindings(path, inspectorRepositoryUrl),
    ).rejects.toThrow("JSON");
    await writeFile(path, Buffer.from([0xff]));
    await expect(
      readInspectorFindings(path, inspectorRepositoryUrl),
    ).rejects.toThrow("UTF-8");
    report.findings[0]!.description = "x".repeat(65537);
    await writeFile(path, JSON.stringify(report));
    expect(
      (await readInspectorFindings(path, inspectorRepositoryUrl, "cloud"))
        .excluded,
    ).toHaveLength(1);
    expect(
      (await readInspectorFindings(path, inspectorRepositoryUrl, "local"))
        .findings,
    ).toHaveLength(1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
