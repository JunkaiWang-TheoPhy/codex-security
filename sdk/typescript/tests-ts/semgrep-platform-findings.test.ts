import { expect, test } from "bun:test";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import {
  collectSemgrepPlatformFindings,
  normalizeSemgrepPlatformFindings,
} from "../src/semgrep-platform-findings.js";
import {
  collectProject,
  platformFinding,
  platformProject,
  platformRef,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";

const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SEMGREP_APP_TOKEN: "synthetic-web-token",
};
const options = {
  deployment: "example",
  project: platformProject.name,
  ref: platformRef,
};
const first = Array.from({ length: 100 }, (_, index) =>
  platformFinding(index + 1),
);

function collectPages(...pages: unknown[]) {
  const responses = [{ project: platformProject }, ...pages];
  return collectSemgrepPlatformFindings(options, {
    environment,
    fetch: async () => {
      const page = responses.shift();
      return page instanceof Response ? page : Response.json(page);
    },
  });
}

test("collects consecutive authenticated pages for exactly one project, ref and product", async () => {
  const pages: string[] = [];
  const name = "https://example.test/monorepo/.";
  const selection = {
    ...options,
    project: name,
    sourceRepositoryUrl: platformProject.url,
  };
  const report = await collectSemgrepPlatformFindings(selection, {
    environment,
    fetch: async (url, init) => {
      expect(url.origin).toBe("https://semgrep.dev");
      expect(new Headers(init.headers).get("authorization")).toBe(
        "Bearer synthetic-web-token",
      );
      expect(init.redirect).toBe("error");
      if (url.pathname.includes("/projects/")) {
        expect(url.pathname).toBe(
          `/api/v1/deployments/example/projects/${encodeURIComponent(name)}`,
        );
        selection.sourceRepositoryUrl = "https://github.com/other/project";
        return Response.json({ project: { ...platformProject, name } });
      }
      const query = Object.fromEntries(url.searchParams);
      expect(query).toMatchObject({
        ref: platformRef,
        repository_ids: "77",
        dedup: "false",
        issue_type: "sast",
        page_size: "100",
      });
      pages.push(query["page"]!);
      return Response.json({
        findings: query["page"] === "0" ? first : [platformFinding(101)],
      });
    },
  });
  expect(pages).toEqual(["0", "1", "0"]);
  expect(report.findings).toHaveLength(101);
  expect(JSON.stringify(report)).not.toContain("synthetic-web-token");
  const parsed = normalizeSemgrepPlatformFindings(report);
  expect(parsed.findings[0]?.evidence).toMatchObject({
    branch: platformRef,
    severity: "medium",
    locations: [{ path: "src/app.ts", line: 3 }],
    details: {
      kind: "sast",
      source_status: "open",
      weakness_ids: ["CWE-79"],
      code: { end_line: 5 },
    },
  });
  const original = platformFinding(1);
  const moved = normalizeSemgrepPlatformFindings(
    platformReport([{ ...original, location: null, status: "ignored" }]),
  );
  expect(moved.findings[0]?.source_finding_id).toBe(
    parsed.findings[0]?.source_finding_id,
  );
  expect(moved.findings[0]?.evidence.locations).toEqual([]);
  const partial = normalizeSemgrepPlatformFindings(
    platformReport([
      { ...original, location: { file_path: "src/app.ts", end_line: 17 } },
    ]),
  );
  expect(partial.findings[0]?.evidence).toMatchObject({
    locations: [{ path: "src/app.ts", line: null }],
    details: { code: { end_line: null } },
    source_data: { finding: { location: { end_line: 17 } } },
  });
});

test("uses the requested scope for missing row fields and preserves the original evidence", async () => {
  const { repository, ref, ...base } = platformFinding(1);
  const rows = [
    base,
    { ...base, id: 2, repository: {} },
    { ...base, id: 3, ref },
    { ...base, id: 4, repository },
    { ...base, id: 5, repository: { name: "project", url: null } },
  ];
  const report = await collectPages({ findings: rows });
  const parsed = normalizeSemgrepPlatformFindings(
    JSON.parse(JSON.stringify(report)),
  );
  expect(
    parsed.findings.map(({ evidence }) => evidence.source_data?.["finding"]),
  ).toEqual(rows);
  expect(
    parsed.findings.every(
      ({ evidence }) =>
        evidence.branch === platformRef &&
        evidence.details?.repository?.url === platformProject.url,
    ),
  ).toBe(true);
  for (const scope of [
    { repository: null },
    { repository: { url: 42, name: "project" } },
    { repository: { url: null } },
    { repository: { name: 42, url: platformProject.url } },
    { ref: null },
    { ref: "" },
    { ref: "refs/heads/foreign" },
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings(platformReport([{ ...base, ...scope }])),
    ).toThrow();
  }
});

test("fails before acquisition without opt-in, honors cancellation, and never returns a partial page set", async () => {
  const never = () => {
    throw new Error("unexpected request");
  };
  await expect(
    collectSemgrepPlatformFindings(options, { environment: {}, fetch: never }),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS");
  for (const project of [".", ".."])
    await expect(
      collectSemgrepPlatformFindings(
        { ...options, project },
        { environment, fetch: never },
      ),
    ).rejects.toThrow("Invalid Semgrep");
  const stopped = AbortSignal.abort(new Error("stopped"));
  for (const [signal, dependencySignal] of [
    [stopped],
    [new AbortController().signal, stopped],
  ]) {
    await expect(
      collectSemgrepPlatformFindings(
        { ...options, signal },
        { environment, signal: dependencySignal, fetch: never },
      ),
    ).rejects.toThrow("stopped");
  }
  for (const [response, error] of [
    [Response.json({ findings: first }), "repeated"],
    [
      Response.json({
        findings: [{ ...first[99], id: "100" }, platformFinding(101)],
      }),
      "repeated",
    ],
    [
      new Response("try later", {
        status: 429,
        headers: { "retry-after": "11" },
      }),
      "Retry-After: 11",
    ],
    [Response.json({ error: "not a findings page" }), "must be an array"],
  ] as const) {
    await expect(collectPages({ findings: first }, response)).rejects.toThrow(
      error,
    );
  }
});

test("detects removals before the next offset even when no finding ID repeats", async () => {
  // Finding 1 disappears after the first page. Finding 101 shifts into it, so page 1 starts at 102.
  await expect(
    collectPages(
      { findings: first },
      { findings: [platformFinding(102)] },
      { findings: [...first.slice(1), platformFinding(101)] },
    ),
  ).rejects.toThrow("changed across pages");

  const invalid = { ...platformFinding(1), id: null };
  const initial = [invalid, ...first.slice(1)];
  const reread = [
    { id: null, ...Object.fromEntries(Object.entries(invalid).reverse()) },
    ...first
      .slice(1)
      .map((row) => ({ ...row, id: String(row.id), status: "fixed" })),
  ];
  const report = await collectPages(
    { findings: initial },
    { findings: [] },
    { findings: reread.reverse() },
  );
  expect(report.findings).toEqual(initial);
});

test("keeps an operator mapping separate from a URL-less project and its short repository name", async () => {
  const project = { ...platformProject, url: null };
  const finding = { ...platformFinding(1), repository: { name: "project" } };
  const report = await collectProject(project, [finding], platformProject.url);
  expect(report).toMatchObject({
    project,
    sourceRepositoryUrl: platformProject.url,
  });
  const { findings } = normalizeSemgrepPlatformFindings(report);
  expect(findings[0]?.evidence).toMatchObject({
    details: { repository: { url: platformProject.url } },
    source_data: { project, sourceRepositoryUrl: platformProject.url, finding },
  });
  expect(() =>
    normalizeSemgrepPlatformFindings(
      report,
      "https://github.com/other/project",
    ),
  ).toThrow("does not match");
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      findings: [{ ...finding, repository: { name: "other/project" } }],
    }),
  ).toThrow("matching source repository");
});

test("replays only the repository names observed for each collected split project", async () => {
  const project = {
    ...platformProject,
    name: "example/mono/moduleA",
    url: "https://github.com/example/mono.git/",
  };
  // An independently configured name and the physical SCM path can both differ from the selected project.
  const names = ["example/mono", "mono", project.name, "moduleA"];
  const rows = names.map((name, i) => ({
    ...platformFinding(i + 1),
    repository: { name },
  }));
  const customName = "legacy/scanner-repo";
  const report = await collectProject(project, [
    ...rows,
    {
      ...platformFinding(5),
      repository: { name: customName, url: project.url },
    },
  ]);
  expect(report.repositoryAliases).toEqual([...names, customName]);
  expect(normalizeSemgrepPlatformFindings(report).findings).toHaveLength(5);

  const other = { ...project, id: 78, name: "example/mono/moduleB" };
  const foreign = {
    ...platformFinding(6),
    repository: { name: other.name, url: project.url },
  };
  const otherReport = await collectProject(other, [foreign]);
  expect(normalizeSemgrepPlatformFindings(otherReport).findings).toHaveLength(
    1,
  );
  const swapped = {
    ...report,
    findings: otherReport.findings,
    findingCount: 1,
  };
  for (const repository of [
    foreign.repository,
    { name: other.name },
    { name: "mono", url: "https://github.com/other/mono" },
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings({
        ...swapped,
        findings: [{ ...foreign, repository }],
      }),
    ).toThrow("repository");
  }
  // Public v1 exports predate the observation list. They used the URL as the binding when present.
  const legacy = { ...swapped };
  delete legacy.repositoryAliases;
  const normalized = normalizeSemgrepPlatformFindings(legacy);
  expect(normalized.findings[0]?.evidence.source_data).toMatchObject({
    finding: foreign,
  });
  expect(normalized.findings[0]?.evidence.source_data).not.toHaveProperty(
    "repositoryAliases",
  );
});

test.each([
  ["github.com/example/tmp/../repo", "github.com/example/./repo", true],
  ["github.com/example/%2e/repo", "github.com/example/./repo", false],
  ["github.com/example/my-repo", "github.com/example/my%2Drepo", true],
  ["github.com/example/my%2Drepo", "github.com/example/my-repo", true],
  ["github.com/example/nested/repo", "github.com/example/nested%2Frepo", false],
  ["github.com/example/my-repo", "github.com/example/my%252Drepo", false],
  [
    "[2001:db8::1]:8443/org/repo",
    "[2001:0db8:0:0:0:0:0:1]:8443/org/repo",
    true,
  ],
  ["bücher.example.test/Org/Repo", "xn--bcher-kva.example.test/Org/Repo", true],
  [
    "bücher.example.test/Org/Repo",
    "xn--bcher-kva.example.test:443/Org/Repo",
    false,
  ],
] as const)(
  "compares HTTP repositories %s and %s (matches=%s)",
  async (native, path, matches) => {
    const base = "https://";
    const project = { ...platformProject, url: base + native };
    const url = base + path;
    const finding = { ...platformFinding(1), repository: { url } };
    if (!matches) {
      await expect(collectProject(project, [finding])).rejects.toThrow(
        "does not match",
      );
      expect(() =>
        normalizeSemgrepPlatformFindings({
          ...platformReport([finding]),
          project,
        }),
      ).toThrow("does not match");
      return;
    }
    const report = await collectProject(project, [finding], url);
    const replay = normalizeSemgrepPlatformFindings(report, url);
    expect(replay.findings[0]?.evidence.source_data).toMatchObject({
      project,
      sourceRepositoryUrl: url,
      finding,
    });
  },
);

test.each([
  "git@scm.example.test:team/repo.git",
  "https://scm.example.test/team/%72epo",
])(
  "normalizes %s against the caller's identified Enterprise GitHub repository",
  (rowUrl) => {
    const url = "https://scm.example.test/Team/Repo";
    const row = {
      ...platformFinding(1),
      repository: { url: rowUrl },
    };
    const report = {
      ...platformReport([row]),
      project: { ...platformProject, url },
    };
    for (const normalize of [
      normalizeSemgrepFindings,
      normalizeSemgrepPlatformFindings,
    ]) {
      const source = { url: url.toLowerCase(), platform: "github" as const };
      expect(
        normalize(report, { sourceRepositories: [source] }).findings,
      ).toHaveLength(1);
      expect(() =>
        normalize(report, {
          sourceRepositories: [{ ...source, url: source.url + "-other" }],
        }),
      ).toThrow();
      expect(() => normalize(report)).toThrow();
    }
  },
);

test("keeps known non-GitHub URLs case-sensitive during collection", async () => {
  for (const host of [
    "gitlab.com",
    "bitbucket.org",
    "dev.azure.com",
    "example.visualstudio.com",
  ]) {
    const url = `https://${host}/Team/Repo`;
    const finding = {
      ...platformFinding(1),
      repository: { url: url.toLowerCase() },
    };
    await expect(
      collectProject({ ...platformProject, url }, [finding]),
    ).rejects.toThrow("does not match");
  }
});

test("losslessly captures distinct int64 IDs and rejects a truncated saved report", async () => {
  const ids = ["9223372036854775806", "9223372036854775807"];
  const records = ids.map((id) => ({
    ...platformFinding(17),
    id,
    first_seen_scan_id: "9007199254740993",
  }));
  // Emit int64 fields as JSON numbers without rounding them in the fixture.
  const json = JSON.stringify({ findings: records }).replace(
    /"(\d{16,19})"/gu,
    "$1",
  );
  const report = await collectPages(new Response(json));
  expect(report.findings).toEqual(records);
  const parsed = normalizeSemgrepPlatformFindings(
    JSON.parse(JSON.stringify(report)),
  );
  expect(parsed.findings).toHaveLength(2);
  expect(parsed.findings[0]?.source_finding_id).not.toBe(
    parsed.findings[1]?.source_finding_id,
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      findings: [report.findings[0]],
    }),
  ).toThrow("Incomplete");
});

test("rejects wrong repository or ref even on rows otherwise excluded; excludes ambiguous and unsafe integer IDs", async () => {
  const finding = platformFinding(10);
  expect(() =>
    normalizeSemgrepPlatformFindings(
      platformReport([]),
      "https://github.com/other/project",
    ),
  ).toThrow("repository");
  const ambiguousUrl = platformProject.url + "?";
  const ambiguous = {
    ...platformReport([]),
    project: { ...platformProject, url: ambiguousUrl },
  };
  expect(() => normalizeSemgrepPlatformFindings(ambiguous)).toThrow(
    "without credentials, query or fragment",
  );
  for (const wrong of [
    { ...finding, id: null, ref: "main" },
    {
      ...finding,
      repository: { url: "git@[github.com:]:example/project.git" },
    },
    {
      ...finding,
      repository: { url: "git@github.com\x01:example/project.git" },
    },
    {
      ...finding,
      repository: { url: "https://git.example.test/other/project" },
    },
  ])
    expect(() =>
      normalizeSemgrepPlatformFindings(platformReport([wrong])),
    ).toThrow();
  const samePage = await collectPages({ findings: [finding, finding] });
  const duplicate = normalizeSemgrepPlatformFindings(
    platformReport([...samePage.findings, { ...finding, id: 2 ** 53 }]),
  );
  expect(duplicate.excluded).toHaveLength(3);
  expect(duplicate.findings).toHaveLength(0);
  const empty = normalizeSemgrepPlatformFindings(platformReport([]));
  expect(empty).toEqual({
    read: 0,
    excluded: [],
    findings: [],
    sourceRepositoryUrl: platformProject.url,
  });
});

test("maps Supply Chain packages, preserves source-only reachability, and keeps AI SAST in its own namespace", () => {
  const normalizeSupplyChain = (...findings: unknown[]) =>
    normalizeSemgrepPlatformFindings(platformReport(findings, "sca"));
  const finding = platformFinding(21);
  const sca = {
    ...finding,
    vulnerability_identifier: "CVE-2025-0001",
    found_dependency: {
      package: "example-pkg",
      ecosystem: "npm",
      version: "1.0.0",
    },
    fix_recommendations: [
      { package: "other-pkg", version: "2.0.0" },
      { package: "example-pkg", version: "1.1.0" },
    ],
    reachability: "reachable",
    location: { file_path: "../outside", line: 1 },
  };
  const result = normalizeSupplyChain(sca);
  expect(result.findings[0]?.evidence).toMatchObject({
    packages: [
      {
        name: "example-pkg",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.1.0"],
      },
    ],
    advisory_ids: ["CVE-2025-0001"],
    locations: [],
    source_data: { finding: { reachability: "reachable" } },
  });
  for (const metadata of [
    {},
    { found_dependency: {} },
    { found_dependency: { ecosystem: "npm", version: "1.0.0" } },
  ]) {
    const advisoryOnly = {
      ...finding,
      ...metadata,
      vulnerability_identifier: "CVE-2025-0001",
    };
    const result = normalizeSupplyChain(advisoryOnly);
    expect(result.findings[0]?.evidence).toMatchObject({
      advisory_ids: ["CVE-2025-0001"],
      packages: [],
      source_data: { finding: advisoryOnly },
    });
  }
  const ruleOnly = normalizeSupplyChain(finding);
  expect(ruleOnly.findings[0]?.evidence).toMatchObject({
    title: finding.rule.name,
    packages: [],
    advisory_ids: [],
    source_data: { finding },
  });
  const invalid = normalizeSupplyChain(
    {
      ...finding,
      rule: {},
      found_dependency: {},
      vulnerability_identifier: " ",
    },
    { ...sca, id: 22, found_dependency: { package: 42 } },
    { ...sca, id: 23, found_dependency: [] },
  );
  expect(invalid.excluded).toHaveLength(3);
  expect(
    normalizeSemgrepPlatformFindings(platformReport([sca])).excluded,
  ).toHaveLength(1);
  const code = normalizeSemgrepPlatformFindings(platformReport([finding]));
  const ai = normalizeSemgrepPlatformFindings(
    platformReport([finding], "ai_sast"),
  );
  expect(ai.findings[0]?.evidence.details?.kind).toBe("sast");
  expect(ai.findings[0]?.source_finding_id).not.toBe(
    code.findings[0]?.source_finding_id,
  );
});

test("keeps message-only findings and preserves ambiguous hosted paths as native evidence", () => {
  for (const product of ["sast", "ai_sast", "sca"] as const) {
    const description = "Check the unsafe input.";
    const finding = {
      ...platformFinding(42),
      ...(product === "ai_sast"
        ? { rule: {}, rule_message: description }
        : { rule: { message: description } }),
      location: { file_path: "src/rules\\test.py", line: 2, end_line: 4 },
    };
    const report = normalizeSemgrepPlatformFindings(
      platformReport([finding], product),
    );
    expect(report.excluded).toEqual([]);
    expect(report.findings[0]?.evidence).toMatchObject({
      title: description,
      description,
      locations: [],
      source_data: { finding },
      ...(product === "sca"
        ? { packages: [], advisory_ids: [] }
        : { details: { rule: null, code: { end_line: null } } }),
    });
  }
});
