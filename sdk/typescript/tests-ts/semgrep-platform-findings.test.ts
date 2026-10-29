import { expect, test } from "bun:test";
import {
  collectSemgrepPlatformFindings,
  normalizeSemgrepPlatformFindings,
} from "../src/semgrep-platform-findings.js";
import {
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
  const selection = { ...options, sourceRepositoryUrl: platformProject.url };
  const report = await collectSemgrepPlatformFindings(selection, {
    environment,
    fetch: async (url, init) => {
      expect(url.origin).toBe("https://semgrep.dev");
      expect(new Headers(init.headers).get("authorization")).toBe(
        "Bearer synthetic-web-token",
      );
      expect(init.redirect).toBe("error");
      if (url.pathname.includes("/projects/")) {
        expect(decodeURIComponent(url.pathname)).toBe(
          "/api/v1/deployments/example/projects/example/project",
        );
        selection.sourceRepositoryUrl = "https://github.com/other/project";
        return Response.json({ project: platformProject });
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

test("fails before acquisition without opt-in, honors cancellation, and never returns a partial page set", async () => {
  const never = () => {
    throw new Error("unexpected request");
  };
  await expect(
    collectSemgrepPlatformFindings(options, { environment: {}, fetch: never }),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS");
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
    { findings: reread },
  );
  expect(report.findings).toEqual(initial);
});

test("keeps an operator mapping separate from a URL-less project and its short repository name", async () => {
  const project = { ...platformProject, url: null };
  const finding = { ...platformFinding(1), repository: { name: "project" } };
  const responses = [{ project }, { findings: [finding] }];
  const report = await collectSemgrepPlatformFindings(
    { ...options, sourceRepositoryUrl: platformProject.url },
    { environment, fetch: async () => Response.json(responses.shift()) },
  );
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

test("binds URL-less split-project findings to the selected project or physical repository", async () => {
  const project = {
    ...platformProject,
    name: "example/mono/moduleA",
    url: "https://github.com/example/mono.git/",
  };
  const rows = ["example/mono", "mono", project.name, "moduleA"].map(
    (name, i) => ({
      ...platformFinding(i + 1),
      repository: { name },
    }),
  );
  // SEMGREP_REPO_NAME and the selected project's display name can differ even on GitHub.
  const customName = {
    ...platformFinding(5),
    repository: { name: "example/mono/moduleB", url: project.url },
  };
  const responses = [{ project }, { findings: [...rows, customName] }];
  const report = await collectSemgrepPlatformFindings(
    { ...options, project: project.name },
    {
      environment,
      fetch: async () => Response.json(responses.shift()),
    },
  );
  expect(normalizeSemgrepPlatformFindings(report).findings).toHaveLength(5);
  for (const repository of [
    { name: "example/mono/moduleB" },
    { name: "mono", url: "https://github.com/other/mono" },
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings({
        ...report,
        findingCount: 1,
        findings: [{ ...rows[0], repository }],
      }),
    ).toThrow("repository");
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
  const report = platformReport([sca]);
  const result = normalizeSemgrepPlatformFindings({
    ...report,
    product: "sca",
  });
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
    const result = normalizeSemgrepPlatformFindings({
      ...platformReport([advisoryOnly]),
      product: "sca",
    });
    expect(result.findings[0]?.evidence).toMatchObject({
      advisory_ids: ["CVE-2025-0001"],
      packages: [],
      source_data: { finding: advisoryOnly },
    });
  }
  const invalid = normalizeSemgrepPlatformFindings({
    ...platformReport([
      { ...finding, found_dependency: {}, vulnerability_identifier: " " },
      { ...sca, id: 22, found_dependency: { package: 42 } },
      { ...sca, id: 23, found_dependency: [] },
    ]),
    product: "sca",
  });
  expect(invalid.excluded).toHaveLength(3);
  expect(normalizeSemgrepPlatformFindings(report).excluded).toHaveLength(1);
  const code = platformReport([finding]);
  const ai = normalizeSemgrepPlatformFindings({ ...code, product: "ai_sast" });
  expect(ai.findings[0]?.evidence.details?.kind).toBe("sast");
  expect(ai.findings[0]?.source_finding_id).not.toBe(
    normalizeSemgrepPlatformFindings(code).findings[0]?.source_finding_id,
  );
});
