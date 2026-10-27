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

test("collects consecutive authenticated pages for exactly one project, ref and product", async () => {
  const pages: string[] = [];
  const report = await collectSemgrepPlatformFindings(options, {
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
  expect(pages).toEqual(["0", "1"]);
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
  await expect(
    collectSemgrepPlatformFindings(
      { ...options, signal: AbortSignal.abort(new Error("stopped")) },
      { environment, fetch: never },
    ),
  ).rejects.toThrow("stopped");
  await expect(
    collectSemgrepPlatformFindings(
      { ...options, signal: new AbortController().signal },
      {
        environment,
        fetch: never,
        signal: AbortSignal.abort(new Error("dependency canceled")),
      },
    ),
  ).rejects.toThrow("dependency canceled");
  for (const mode of ["repeat", "rate-limit", "malformed"]) {
    const collect = collectSemgrepPlatformFindings(options, {
      environment,
      fetch: async (url) => {
        if (url.pathname.includes("/projects/"))
          return Response.json({ project: platformProject });
        if (url.searchParams.get("page") === "0" || mode === "repeat")
          return Response.json({ findings: first });
        return mode === "rate-limit"
          ? new Response("try later", {
              status: 429,
              headers: { "retry-after": "11" },
            })
          : Response.json({ error: "not a findings page" });
      },
    });
    await expect(collect).rejects.toThrow(
      mode === "repeat"
        ? "repeated"
        : mode === "rate-limit"
          ? "Retry-After: 11"
          : "must be an array",
    );
  }
});

test("losslessly captures distinct int64 IDs and rejects a truncated saved report", async () => {
  const ids = ["9223372036854775806", "9223372036854775807"];
  const report = await collectSemgrepPlatformFindings(options, {
    environment,
    fetch: async (url) => {
      if (url.pathname.includes("/projects/"))
        return Response.json({ project: platformProject });
      const template = JSON.stringify(platformFinding(17)).replace(
        '"id":17',
        '"first_seen_scan_id":9007199254740993,"id":17',
      );
      return new Response(
        '{"findings":[' +
          ids.map((id) => template.replace('"id":17', '"id":' + id)).join(",") +
          "]}",
      );
    },
  });
  const parsed = normalizeSemgrepPlatformFindings(
    JSON.parse(JSON.stringify(report)),
  );
  expect(parsed.findings[0]?.evidence.source_data).toMatchObject({
    finding: { first_seen_scan_id: "9007199254740993" },
  });
  expect(
    parsed.findings.map(
      ({ evidence }) =>
        (evidence.source_data?.["finding"] as { id: string }).id,
    ),
  ).toEqual(ids);
  expect(
    new Set(parsed.findings.map(({ source_finding_id }) => source_finding_id))
      .size,
  ).toBe(2);
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      findings: [report.findings[0]],
    }),
  ).toThrow("Incomplete");
});

test("rejects wrong repository or ref even on rows otherwise excluded; excludes ambiguous and unsafe integer IDs", () => {
  const finding = platformFinding(10);
  expect(() =>
    normalizeSemgrepPlatformFindings(
      platformReport([]),
      "https://github.com/other/project",
    ),
  ).toThrow("repository");
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
  const duplicate = normalizeSemgrepPlatformFindings(
    platformReport([finding, finding, { ...finding, id: 2 ** 53 }]),
  );
  expect(duplicate.excluded).toHaveLength(3);
  expect(duplicate.findings).toHaveLength(0);
  const empty = normalizeSemgrepPlatformFindings(platformReport([]));
  expect(empty).toEqual({ read: 0, excluded: [], findings: [] });
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
  expect(normalizeSemgrepPlatformFindings(report).excluded).toHaveLength(1);
  const code = platformReport([finding]);
  const ai = normalizeSemgrepPlatformFindings({ ...code, product: "ai_sast" });
  expect(ai.findings[0]?.evidence.details?.kind).toBe("sast");
  expect(ai.findings[0]?.source_finding_id).not.toBe(
    normalizeSemgrepPlatformFindings(code).findings[0]?.source_finding_id,
  );
});
