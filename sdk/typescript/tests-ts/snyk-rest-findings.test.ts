import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  collectSnykIssues,
  normalizeSnykIssues,
  snykRestFindingRepository,
  type CollectSnykIssuesOptions,
  type SnykIssuesExport,
} from "../src/snyk-rest-findings.js";
import {
  normalizeSnykInput,
  readSnykFindings,
  snykReportRepositoryUrls,
  snykRepositoryUrls,
} from "../src/snyk-findings.js";

import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  organizationId,
  projectId,
  targetId,
  issueId,
  apiOrigin,
  sourceRepositoryUrl,
  snykRestProject as project,
  snykRestIssue as issue,
  snykRestDocument as document,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

const otherId = "55555555-5555-4555-8555-555555555555";
const options: CollectSnykIssuesOptions = {
  organizationId,
  projectId,
  product: "open-source",
  sourceRepositoryUrl,
  apiOrigin,
};
const env = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SNYK_TOKEN: "synthetic-token",
};
const version = "2024-10-15";
const path = `/rest/orgs/${organizationId}/issues`;

function transport(...responses: unknown[]) {
  const requests: { url: URL; init: RequestInit }[] = [];
  return {
    requests,
    dependencies: {
      environment: env,
      fetch: async (url: URL, init: RequestInit) => {
        requests.push({ url: new URL(url), init });
        if (!responses.length) throw new Error("Unexpected request.");
        const response = responses.shift();
        return response instanceof Response
          ? response
          : Response.json(response);
      },
    },
  };
}

function envelope(data: unknown[] = [issue()]) {
  return {
    format: "snyk-rest-issues/v1",
    apiVersion: version,
    ...options,
    complete: true,
    project: project(),
    target: null,
    pages: [{ startingAfter: null, response: document(data) }],
  };
}

test("retries only the throttled JSON:API page within the selected Snyk scope", async () => {
  const primary = issue({
    description: "Original description",
    ignored: true,
    status: "open",
    problems: [
      { type: "rule", source: "Snyk", id: "SNYK-EXAMPLE-1" },
      { type: "vulnerability", source: "NVD", id: "CVE-2099-0001" },
    ],
    classes: [{ type: "weakness", source: "CWE", id: "CWE-79" }],
    coordinates: [
      {
        representations: [
          {
            dependency: {
              package_name: "@example/pkg",
              package_version: "1.0.0",
            },
          },
        ],
        state: "open",
        is_upgradeable: true,
        remedies: [
          {
            type: "manual",
            meta: {
              schema_version: "package_vulnerability/v0",
              data: { fixed_in: ["1.0.1"] },
            },
          },
        ],
      },
    ],
  });
  const secondary = issue({ key: "second-key" }, { id: otherId });
  const cursor = "opaque+/=";
  const { dependencies, requests } = transport(
    document(project()),
    document([primary], {
      href: `/orgs/${organizationId}/issues?version=${version}&starting_after=${encodeURIComponent(cursor)}`,
    }),
    new Response("try again", {
      status: 429,
      headers: { "Retry-After": "0", Location: "https://other.invalid/issues" },
    }),
    document([secondary], null),
  );
  const signal = new AbortController().signal;
  const report = await collectSnykIssues({ ...options, signal }, dependencies);
  expect(requests.map(({ url }) => url.pathname)).toEqual([
    `/rest/orgs/${organizationId}/projects/${projectId}`,
    path,
    path,
    path,
  ]);
  for (const { url, init } of requests) {
    expect(url.origin).toBe(apiOrigin);
    expect(url.searchParams.get("version")).toBe(version);
    expect(init).toMatchObject({ method: "GET", redirect: "error", signal });
    const headers = new Headers(init.headers);
    expect(headers.get("accept")).toContain("application/vnd.api+json");
    expect(init.body).toBeUndefined();
    expect(headers.get("authorization")).toBe("token synthetic-token");
  }
  expect(requests[0]!.url.searchParams.get("expand")).toBe("target");
  for (const { url } of requests.slice(1)) {
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      "scan_item.type": "project",
      "scan_item.id": projectId,
      type: "package_vulnerability",
      limit: "100",
      status: "open,resolved",
    });
    expect(url.searchParams.has("include_code_flows")).toBe(false);
  }
  expect(requests[1]!.url.searchParams.has("starting_after")).toBe(false);
  expect(requests[2]!.url.searchParams.get("starting_after")).toBe(cursor);
  expect(requests[3]!.url.href).toBe(requests[2]!.url.href);
  expect(report.pages.map((page) => page.startingAfter)).toEqual([
    null,
    cursor,
  ]);
  expect(JSON.stringify(report)).not.toContain(env.SNYK_TOKEN);
  const before = structuredClone(report);
  const normalized = normalizeSnykInput(report);
  expect(report).toEqual(before);
  expect(normalized.excluded).toEqual([]);
  expect(normalized.read).toBe(2);
  expect(normalized.findings[0]!.evidence).toMatchObject({
    title: "Synthetic issue",
    description: "Original description",
    severity: "high",
    branch: null,
    code_revision: null,
    source_updated_at: Math.floor(
      Date.parse(primary.attributes.updated_at) / 1000,
    ),
    advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
    packages: [
      {
        name: "@example/pkg",
        installed_version: "1.0.0",
        ecosystem: "npm",
        manifest_path: "app/package.json",
        fixed_versions: ["1.0.1"],
      },
    ],
    source_data: { issue: primary, project: report.project },
  });
  expect(normalized.findings[0]!.evidence.details).toBeUndefined();
  for (const origin of ["cli", "api"]) {
    const nested = normalizeSnykIssues({
      ...report,
      project: project({ origin }),
    }).findings[0]!.evidence;
    expect(nested.packages![0]!.manifest_path).toBeNull();
    expect(nested.source_data).toMatchObject({
      project: { attributes: { target_file: "app/package.json" } },
    });
  }
  expect(
    JSON.stringify(normalized.findings[0]!.evidence.source_data),
  ).not.toContain("second-key");
  expect(snykReportRepositoryUrls(normalized)).toEqual([sourceRepositoryUrl]);
});

test("collects hosted Code, retaining source locations, ranges, flow omissions, rule and independent ignore state", async () => {
  const finding = issue({
    type: "code",
    status: "open",
    ignored: true,
    effective_severity_level: "info",
    problems: [{ source: "Snyk", type: "rule", id: "example-rule" }],
    coordinates: [
      {
        state: "open",
        representations: [
          {
            sourceLocation: {
              file: "src/example%20file.ts",
              region: {
                start: { line: 0, column: 0 },
                end: { line: 2, column: 4 },
              },
              commit_id: "synthetic-commit",
            },
          },
          {
            source_location: {
              file: "../another-project/file",
              commit_id: "synthetic-commit",
            },
          },
        ],
        code_flows_omitted: true,
      },
    ],
  });
  const selected = {
    ...options,
    product: "code" as const,
    apiOrigin: undefined,
    token: "explicit-test-token",
  };
  const { dependencies, requests } = transport(
    document(project({ manager: "sast", remote: null })),
    document([finding]),
  );
  const report = await collectSnykIssues(selected, dependencies);
  expect(requests.map(({ url }) => url.origin)).toEqual([
    "https://api.snyk.io",
    "https://api.snyk.io",
  ]);
  expect(new Headers(requests[0]!.init.headers).get("authorization")).toBe(
    "token explicit-test-token",
  );
  expect(Object.fromEntries(requests[1]!.url.searchParams)).toMatchObject({
    type: "code",
    "scan_item.type": "project",
    "scan_item.id": projectId,
    include_code_flows: "true",
  });
  const output = normalizeSnykIssues(report);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence).toMatchObject({
    severity: "informational",
    locations: [{ path: "src/example%20file.ts", line: null }],
    code_revision: "synthetic-commit",
    details: {
      kind: "sast",
      source_status: "open",
      rule: { id: "example-rule" },
      repository: { url: sourceRepositoryUrl },
    },
    source_data: { issue: finding },
  });
  expect(
    normalizeSnykIssues({
      ...report,
      project: project({ manager: "sast", origin: "cli", remote: null }),
    }).findings[0]!.evidence.locations,
  ).toEqual([]);
  const otherRevision = issue({
    type: "code",
    status: "open",
    coordinates: [
      {
        state: "open",
        representations: [
          { sourceLocation: { file: "src/a", commit_id: "one" } },
          { sourceLocation: { file: "src/b", commit_id: "two" } },
        ],
      },
    ],
  });
  expect(
    normalizeSnykIssues({
      ...report,
      pages: [{ startingAfter: null, response: document([otherRevision]) }],
    }).findings[0]!.evidence.code_revision,
  ).toBeNull();
});

test.each(["open-source", "code"] as const)(
  "hosted %s projects only explicitly open coordinates of open issues and preserves historical evidence",
  (product) => {
    const report = snykRestFixture(product);
    const code = product === "code";
    const coordinates = ["open", "resolved", undefined].map((state, index) => ({
      ...(state && { state }),
      representations: [
        code
          ? {
              sourceLocation: {
                file: `src/file-${index}`,
                commit_id: `commit-${index}`,
              },
            }
          : {
              dependency: {
                package_name: "@example/pkg",
                package_version: `1.0.${index}`,
              },
            },
      ],
    }));
    for (const status of ["open", "resolved"]) {
      const native = issue(
        { type: code ? "code" : "package_vulnerability", status, coordinates },
        { project: report.projectId },
      );
      const normalized = normalizeSnykIssues({
        ...report,
        pages: [{ startingAfter: null, response: document([native]) }],
      });
      expect(normalized.excluded).toEqual([]);
      const evidence = normalized.findings[0]!.evidence;
      expect(evidence.source_data?.["issue"]).toEqual(native);
      expect(evidence.packages?.map((pkg) => pkg.installed_version)).toEqual(
        !code && status === "open" ? ["1.0.0"] : [],
      );
      expect(evidence.locations?.map((location) => location.path)).toEqual(
        code && status === "open" ? ["src/file-0"] : [],
      );
      expect(evidence.code_revision).toBe(
        code && status === "open" ? "commit-0" : null,
      );
    }
  },
);

test.each(["open-source", "code"] as const)(
  "hosted %s per-finding provenance validates all native scope claims independently of display fields",
  (product) => {
    const report = snykRestFixture(product);
    const source =
      normalizeSnykIssues(report).findings[0]!.evidence.source_data!;
    const code = product === "code";
    const manager = code ? "sast" : "npm";
    const attributes = {
      type: code ? "code" : "package_vulnerability",
      title: null,
      key: null,
    };
    const native = issue(attributes, { project: report.projectId });
    const scoped = { ...source, issue: native };
    expect(snykRestFindingRepository(scoped)).toBe(sourceRepositoryUrl);
    const lookup = {
      ...scoped,
      project: project({ manager, id: report.projectId, expanded: false }),
      target: {
        id: targetId,
        type: "target",
        attributes: { url: "git@github.com:EXAMPLE/repository.git" },
      },
    };
    expect(snykRestFindingRepository(lookup)).toBe(sourceRepositoryUrl);
    const swapped = {
      ...scoped,
      sourceRepositoryUrl: "https://github.com/example/other",
    };
    const caseSensitive = {
      ...scoped,
      sourceRepositoryUrl: "https://git.example.test/Example/repository",
      project: project({
        manager,
        id: report.projectId,
        remote: "https://git.example.test/example/repository",
      }),
    };
    for (const mode of [
      { normalizeGitRemote: false },
      { cloudRepositoryUrl: sourceRepositoryUrl },
    ]) {
      expect(snykRepositoryUrls(scoped, mode)).toEqual([sourceRepositoryUrl]);
      expect(() => snykRepositoryUrls(swapped, mode)).toThrow("target URL");
      expect(() => snykRepositoryUrls(caseSensitive, mode)).toThrow(
        "target URL",
      );
    }
    for (const invalid of [
      { ...scoped, format: "other" },
      { ...scoped, apiVersion: "latest" },
      { ...scoped, apiOrigin: "https://api.invalid" },
      { ...scoped, organizationId: otherId },
      { ...scoped, projectId: otherId },
      { ...scoped, product: code ? "open-source" : "code" },
      { ...lookup, target: null },
      { ...lookup, target: { ...lookup.target, id: otherId } },
      { ...lookup, sourceRepositoryUrl: swapped.sourceRepositoryUrl },
      { ...scoped, target: lookup.target },
      {
        ...scoped,
        issue: issue(attributes, { org: otherId, project: report.projectId }),
      },
      { ...scoped, issue: issue(attributes, { project: otherId }) },
      {
        ...scoped,
        issue: issue(attributes, {
          itemType: "environment",
          project: report.projectId,
        }),
      },
      { ...scoped, issue: { ...native, type: "project" } },
      {
        ...scoped,
        issue: { ...native, attributes: { ...attributes, type: "license" } },
      },
    ])
      expect(() => snykRestFindingRepository(invalid)).toThrow();
  },
);

test("looks up an unexpanded target by org and ID, never follows a relationship link", async () => {
  const target = {
    id: targetId,
    type: "target",
    attributes: {
      display_name: "not/the-mapping",
      url: "git@github.com:EXAMPLE/repository.git",
    },
    relationships: {
      organization: { data: { type: "organization", id: organizationId } },
    },
  };
  const lookup = document(project({ expanded: false }));
  const { dependencies, requests } = transport(
    lookup,
    document(target),
    document([]),
  );
  const report = await collectSnykIssues(options, dependencies);
  expect(requests[1]!.url.href).toBe(
    `${apiOrigin}/rest/orgs/${organizationId}/targets/${targetId}?version=${version}`,
  );
  expect(report.target).toEqual(target);
  expect(snykReportRepositoryUrls(normalizeSnykIssues(report))).toEqual([
    sourceRepositoryUrl,
  ]);
  for (const bad of [
    { ...target, id: otherId },
    { ...target, attributes: { url: "https://github.com/example/other" } },
    {
      ...target,
      relationships: {
        organization: { data: { id: otherId, type: "organization" } },
      },
    },
  ]) {
    const attempt = transport(lookup, document(bad));
    await expect(
      collectSnykIssues(options, attempt.dependencies),
    ).rejects.toThrow(/target|organization/i);
    expect(attempt.requests).toHaveLength(2);
    expect(() => normalizeSnykIssues({ ...report, target: bad })).toThrow();
  }
  expect(() => normalizeSnykIssues({ ...report, target: null })).toThrow();
});

test("issue identity is stable across updates, resource IDs, pages and display names, not across scopes", () => {
  const original = envelope();
  const id = (input: unknown) =>
    normalizeSnykIssues(input).findings[0]!.source_finding_id;
  const changed = envelope([
    issue(
      {
        title: "New title",
        effective_severity_level: "low",
        status: "open",
        ignored: true,
      },
      { id: otherId },
    ),
  ]);
  changed.project.attributes.name = "Repository renamed";
  expect(id(changed)).toBe(id(original));
  const other = {
    ...envelope([issue({}, { project: otherId })]),
    projectId: otherId,
    project: project({ id: otherId }),
  };
  const otherOrg = {
    ...envelope([issue({}, { org: otherId })]),
    organizationId: otherId,
    project: project({ org: otherId }),
  };
  const code = {
    ...envelope([issue({ type: "code" })]),
    product: "code",
    project: project({ manager: "sast" }),
  };
  const scopes = [
    original,
    other,
    otherOrg,
    code,
    { ...original, apiOrigin: "https://api.au.snyk.io" },
  ];
  expect(new Set(scopes.map(id)).size).toBe(scopes.length);
});

test("duplicates, unsupported products and malformed records have explicit positional exclusions", () => {
  const report = envelope([
    issue(),
    issue({ key: "valid" }, { id: otherId }),
    issue({ title: "Second copy" }),
    issue({ type: "license" }),
    issue({ type: "code" }),
    issue({ key: "" }),
    issue({ key: "bad-title", title: null }),
    issue({ key: "bad-status", ignored: "false" }),
    issue({ key: "bad-time", updated_at: "invalid" }),
  ]);
  const output = normalizeSnykIssues(report);
  expect(output.read).toBe(9);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded.map((entry) => entry.position)).toEqual([
    1, 3, 4, 5, 6, 7, 8, 9,
  ]);
  expect(output.excluded[0]!.source_finding_id).toBe(
    output.excluded[1]!.source_finding_id,
  );
  expect(output.excluded[0]!.reason).toContain("duplicate");
  expect(output.excluded[2]!.reason).toContain("package_vulnerability");
  expect(output.excluded[4]!.source_finding_id).toBeNull();
});

test("reads saved complete empty and excluded exports offline, retaining report-level mapping for either destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "snyk-rest-"));
  try {
    const filename = join(directory, "issues.json.gz");
    for (const rows of [[], [issue({ type: "license" })]]) {
      const report = envelope(rows);
      await writeFile(filename, gzipSync("\uFEFF" + JSON.stringify(report)));
      for (const target of ["local", "cloud"] as const) {
        const output = await readSnykFindings(filename, target);
        expect(output).toEqual(normalizeSnykInput(report, target));
        expect(output.findings).toEqual([]);
        expect(output.read).toBe(rows.length);
        expect(output.excluded).toHaveLength(rows.length);
        expect(snykReportRepositoryUrls(output)).toEqual([sourceRepositoryUrl]);
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects incomplete or inconsistent envelopes, including an empty tail without its preceding page", () => {
  const report = envelope([]);
  const first = {
    startingAfter: null,
    response: document([], "?starting_after=cursor"),
  };
  const last = { startingAfter: "cursor", response: document([]) };
  for (const invalid of [
    { ...report, pages: [] },
    { ...report, complete: false },
    { ...report, format: "snyk-rest-issues/v2" },
    { ...report, apiVersion: "latest" },
    { ...report, pages: [first] },
    { ...report, pages: [last] },
    { ...report, pages: [first, last, last] },
    { ...report, pages: [first, { ...last, startingAfter: "unrelated" }] },
    {
      ...report,
      pages: [{ startingAfter: null, response: { errors: [], data: [] } }],
    },
  ]) {
    expect(() => normalizeSnykInput(invalid)).toThrow();
  }
  expect(normalizeSnykIssues({ ...report, pages: [first, last] }).read).toBe(0);
});

test.each([
  `https://api.snyk.io${path}?starting_after=x`,
  `//other.invalid${path}?starting_after=x`,
  `https://name@api.eu.snyk.io${path}?starting_after=x`,
  `/rest/orgs/${otherId}/issues?starting_after=x`,
  `/rest/orgs/${organizationId}/projects?starting_after=x`,
  "?starting_after=x&scan_item.type=environment",
  `?starting_after=x&scan_item.id=${otherId}`,
  "?starting_after=x&type=code",
  "?starting_after=x&status=open",
  "?starting_after=x&version=other",
  "?starting_after=x&ending_before=z",
  "?starting_after=x&starting_after=y",
  "?starting_after=x#fragment",
  "?",
  "",
  { href: null },
])(
  "does not send credentials to a changed route or scoped query: %j",
  async (next) => {
    const { dependencies, requests } = transport(
      document(project()),
      document([], next),
    );
    await expect(collectSnykIssues(options, dependencies)).rejects.toThrow(
      /Snyk next page/,
    );
    expect(requests.map(({ url }) => url.pathname)).toEqual([
      `/rest/orgs/${organizationId}/projects/${projectId}`,
      path,
    ]);
  },
);

test("fails on a repeated cursor despite changes to the link spelling", async () => {
  const { dependencies, requests } = transport(
    document(project()),
    document([], "?starting_after=again"),
    document([], {
      href: `${apiOrigin}${path}?version=${version}&starting_after=again`,
    }),
  );
  await expect(collectSnykIssues(options, dependencies)).rejects.toThrow(
    /repeated a cursor/,
  );
  expect(requests).toHaveLength(3);
});

test("a wrong project, product or repository fails before listing issues or accepting replay", async () => {
  for (const source of [
    project({ id: otherId }),
    project({ org: otherId }),
    project({ manager: "sast" }),
    project({ manager: "deb" }),
    project({ origin: "docker-hub" }),
    project({ remote: "https://github.com/example/another" }),
    project({ remote: "ssh://git@github.com/example/repository.git?other" }),
  ]) {
    const { dependencies, requests } = transport(document(source));
    await expect(collectSnykIssues(options, dependencies)).rejects.toThrow();
    expect(requests).toHaveLength(1);
    expect(() =>
      normalizeSnykIssues({ ...envelope([]), project: source }),
    ).toThrow();
  }
  expect(() => normalizeSnykIssues({ ...envelope(), product: "code" })).toThrow(
    /project type/,
  );
});

test("does not save mixed or unverifiable issue scopes, even on the last page", async () => {
  for (const foreign of [
    issue({}, { project: otherId }),
    issue({}, { org: otherId }),
    issue({}, { itemType: "environment" }),
    { id: issueId },
  ]) {
    const report = transport(
      document(project()),
      document([issue()], "?starting_after=more"),
      document([foreign]),
    );
    await expect(
      collectSnykIssues(options, report.dependencies),
    ).rejects.toThrow(/project|organization|relationship/);
    expect(() => normalizeSnykIssues(envelope([foreign]))).toThrow();
  }
});

test("gates and validates configuration and cancellation before issuing any credentialed request", async () => {
  const { dependencies, requests } = transport();
  await expect(
    collectSnykIssues(options, { ...dependencies, environment: {} }),
  ).rejects.toThrow("disabled");
  await expect(
    collectSnykIssues(options, {
      ...dependencies,
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
    }),
  ).rejects.toThrow("SNYK_TOKEN");
  for (const choice of [
    { projectId: "../issues" },
    { organizationId: "org-name" },
    { sourceRepositoryUrl: "" },
    { sourceRepositoryUrl: "https://name@github.com/example/repository" },
    { apiOrigin: "https://api.snyk.io.evil.invalid" },
    { apiOrigin: "https://api.snyk.io/rest" },
    { apiOrigin: "http://api.snyk.io" },
    { apiOrigin: "https://api.snyk.io:8443" },
    { signal: AbortSignal.abort(new Error("cancelled")) },
  ]) {
    await expect(
      collectSnykIssues({ ...options, ...choice }, dependencies),
    ).rejects.toThrow();
  }
  expect(requests).toEqual([]);
});

test("HTTP, JSON, and second-page failures are errors, never successful partial or empty collections", async () => {
  for (const response of [
    new Response("forbidden", { status: 403 }),
    new Response("rate limited", {
      status: 429,
      headers: { "retry-after": "60" },
    }),
    new Response("bad hint", {
      status: 429,
      headers: { "Retry-After": "1.5" },
    }),
    new Response("{"),
    { errors: [{ status: "400", detail: "issue error" }] },
    { data: null },
  ]) {
    const { dependencies, requests } = transport(
      document(project()),
      document([issue()], "?starting_after=more"),
      response,
    );
    await expect(collectSnykIssues(options, dependencies)).rejects.toThrow();
    expect(requests).toHaveLength(3);
  }
});

test("reports the last HTTP error when the retried Snyk cursor is still throttled", async () => {
  const limited = (detail: string) =>
    new Response(detail, { status: 429, headers: { "Retry-After": "0" } });
  const { dependencies, requests } = transport(
    document(project()),
    document([issue()], "?starting_after=more"),
    limited("first failure"),
    limited("still throttled"),
  );
  await expect(collectSnykIssues(options, dependencies)).rejects.toThrow(
    `GET ${apiOrigin}${path} failed (HTTP 429); Retry-After: 0: still throttled`,
  );
  expect(requests).toHaveLength(4);
  expect(requests[3]!.url.href).toBe(requests[2]!.url.href);
});

test.each(["options", "dependencies"] as const)(
  "aborting the %s signal with the other signal live cancels the request and prevents new requests",
  async (caller) => {
    const controllers = {
      options: new AbortController(),
      dependencies: new AbortController(),
    };
    const reason = new Error(`cancelled by ${caller}`);
    let requests = 0;
    const collect = () =>
      collectSnykIssues(
        { ...options, signal: controllers.options.signal },
        {
          environment: env,
          signal: controllers.dependencies.signal,
          fetch: async (_url, init) => {
            requests++;
            controllers[caller].abort(reason);
            expect(init.signal?.reason).toBe(reason);
            init.signal!.throwIfAborted();
            throw new Error("Snyk request was not cancelled.");
          },
        },
      );
    await expect(collect()).rejects.toBe(reason);
    expect(
      controllers[caller === "options" ? "dependencies" : "options"].signal
        .aborted,
    ).toBe(false);
    await expect(collect()).rejects.toBe(reason);
    expect(requests).toBe(1);
  },
);

test.each(["open-source", "code"] as const)(
  "hosted Snyk %s rejects the wrong checkout and creates, replays and updates unassessed SQLite evidence",
  async (product) => {
    const fixture = await localFindingsFixture({ remote: sourceRepositoryUrl });
    const wrong = await localFindingsFixture({
      remote: "https://github.com/example/other",
    });
    try {
      const collect = async (
        overrides?: Parameters<typeof snykRestFixture>[1],
      ) => {
        const sample = snykRestFixture(product, overrides);
        const { dependencies } = transport(
          document(sample.project),
          sample.pages[0]!.response,
        );
        const report = await collectSnykIssues(
          {
            ...options,
            product,
            projectId: sample.projectId,
            sourceRepositoryUrl: sample.sourceRepositoryUrl,
          },
          dependencies,
        );
        expect(report).toEqual(sample);
        return report;
      };
      const initial = await collect();
      const selection = {
        repository: fixture.repository,
        provider: "snyk" as const,
        sourceKey: `${organizationId}/${initial.projectId}/${product}`,
      };
      const forged = normalizeSnykIssues(
        snykRestFixture(product, {
          sourceRepositoryUrl: "https://github.com/example/other",
        }),
      );
      const evidence = forged.findings[0]!.evidence;
      evidence.source_data!["sourceRepositoryUrl"] = sourceRepositoryUrl;
      if (evidence.details?.repository)
        evidence.details.repository.url = sourceRepositoryUrl;
      await expect(
        prepareNormalizedLocalImport(forged, selection, {
          environment: fixture.environment,
        }),
      ).rejects.toThrow("Snyk target URL");
      const prepare = async (report: SnykIssuesExport, local = fixture) => {
        const filename = join(local.root, "snyk-hosted.json");
        await writeFile(filename, JSON.stringify(report));
        return prepareLocalExternalImport(
          filename,
          { ...selection, repository: local.repository },
          { environment: local.environment },
        );
      };
      const empty = await collect({ empty: true });
      const excluded = {
        ...initial,
        pages: [
          {
            startingAfter: null,
            response: document([
              issue({ type: "license" }, { project: initial.projectId }),
            ]),
          },
        ],
      };
      expect(normalizeSnykIssues(excluded).excluded).toHaveLength(1);
      for (const report of [initial, empty, excluded]) {
        await expect(prepare(report, wrong)).rejects.toThrow(
          /does not match a configured remote/,
        );
      }
      expect(
        await listLocalExternalFindings(
          { ...selection, repository: wrong.repository },
          { environment: wrong.environment },
        ),
      ).toEqual([]);
      const first = await prepare(initial);
      expect(first.preview.excluded).toEqual([]);
      expect((await first.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const read = () =>
        listLocalExternalFindings(selection, {
          environment: fixture.environment,
        });
      const stored = await read();
      expect(stored).toHaveLength(1);
      expect(stored[0]).toMatchObject({
        sourceFindingId: first.preview.findings[0]!.source_finding_id,
        version: 1,
        assessment: { state: "not_assessed" },
        evidence: first.preview.findings[0]!.evidence,
      });
      expect((await (await prepare(initial)).import()).counts).toEqual({
        created: 0,
        updated: 0,
        unchanged: 1,
      });
      expect((await (await prepare(empty)).import()).ready).toBe(0);
      expect(await read()).toEqual(stored);
      const changed = await prepare(
        await collect({
          title: "Updated source title",
          updatedAt: "2025-02-04T00:00:00Z",
        }),
      );
      expect((await changed.import()).counts).toEqual({
        created: 0,
        updated: 1,
        unchanged: 0,
      });
      const updated = await read();
      expect(updated).toHaveLength(1);
      expect(updated[0]).toMatchObject({
        id: stored[0]!.id,
        sourceFindingId: stored[0]!.sourceFindingId,
        version: 2,
        assessment: { state: "not_assessed" },
        evidence: {
          title: "Updated source title",
          source_data: {
            issue: { attributes: { status: "resolved", ignored: true } },
          },
        },
      });
      expect(updated[0]!.evidence).toEqual(
        changed.preview.findings[0]!.evidence,
      );
    } finally {
      await Promise.all([fixture.dispose(), wrong.dispose()]);
    }
  },
);
