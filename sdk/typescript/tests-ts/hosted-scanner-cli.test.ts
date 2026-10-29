import { expect, spyOn, test } from "bun:test";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import {
  collectSnykIssues,
  type CollectSnykIssuesOptions,
} from "../src/snyk-rest-findings.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import {
  platformProject,
  platformRef,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";
import {
  organizationId,
  projectId,
  snykRestDocument,
  snykRestFixture,
  sourceRepositoryUrl,
} from "./support/snyk-rest-fixtures.js";

const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SEMGREP_APP_TOKEN: "synthetic",
  SNYK_TOKEN: "synthetic",
};

test("both collectors use the SDK caller's transport and environment", async () => {
  using fallback = spyOn(globalThis, "fetch").mockRejectedValue(
    new Error("unexpected global fetch"),
  );
  class Transport {
    environment = {
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
      [process.platform === "win32" ? "Snyk_Token" : "SNYK_TOKEN"]:
        "synthetic-snyk",
      [process.platform === "win32"
        ? "Semgrep_App_Token"
        : "SEMGREP_APP_TOKEN"]: "synthetic-semgrep",
    };
    requests: (string | null)[] = [];
    async fetch(_url: URL, init: RequestInit): Promise<Response> {
      this.requests.push(new Headers(init.headers).get("authorization"));
      throw new Error("injected transport");
    }
  }
  const transport = new Transport();
  const snykOptions: CollectSnykIssuesOptions = Object.create({
    organizationId,
    projectId,
    sourceRepositoryUrl,
    product: "code",
  });
  await expect(collectSnykIssues(snykOptions, transport)).rejects.toThrow(
    "injected transport",
  );
  await expect(
    collectSemgrepPlatformFindings(
      {
        deployment: "example",
        project: platformProject.name,
        ref: platformRef,
      },
      transport,
    ),
  ).rejects.toThrow("injected transport");
  expect(transport.requests).toEqual([
    "token synthetic-snyk",
    "Bearer synthetic-semgrep",
  ]);
  expect(fallback).not.toHaveBeenCalled();
});

test("the Semgrep CLI emits a replayable report without a framework wrapper", async () => {
  const cli = createCliTest(main);
  const report = platformReport();
  const code = await cli.runCli(
    [
      "import",
      "semgrep",
      platformProject.name,
      "--semgrep-deployment",
      "example",
      "--semgrep-ref",
      platformRef,
      "--format",
      "json",
    ],
    {
      ...dependencies({ environment }),
      hostedScannerFetch: async (url) =>
        Response.json(
          url.pathname.includes("/projects/")
            ? { project: report.project }
            : { findings: report.findings },
        ),
    },
  );
  expect({ code, stderr: cli.stderr.text() }).toEqual({ code: 0, stderr: "" });
  expect(JSON.parse(cli.stdout.text())).toEqual(report);
});

test.each(["open-source", "code"] as const)(
  "the Snyk CLI forwards the selected %s project and never emits a partial raw report",
  async (product) => {
    const cli = createCliTest(main);
    const { project } = snykRestFixture(product);
    const code = await cli.runCli(
      [
        "import",
        "snyk",
        projectId,
        "--snyk-org",
        organizationId,
        "--snyk-product",
        product,
        "--source-repository-url",
        sourceRepositoryUrl,
        "--format",
        "json",
      ],
      {
        ...dependencies({ environment }),
        hostedScannerFetch: async (url) => {
          if (
            url.pathname ===
            `/rest/orgs/${organizationId}/projects/${projectId}`
          )
            return Response.json(snykRestDocument(project));
          expect(url.pathname).toBe(`/rest/orgs/${organizationId}/issues`);
          expect(url.searchParams.get("type")).toBe(
            product === "code" ? "code" : "package_vulnerability",
          );
          throw new Error("failed issues page");
        },
      },
    );
    expect(code).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain("failed issues page");
  },
);
