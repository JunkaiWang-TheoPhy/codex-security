import { expect, spyOn, test } from "bun:test";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import {
  collectSnykIssues,
  type CollectSnykIssuesOptions,
} from "../src/snyk-rest-findings.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
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

const transportTest =
  "both collectors use the SDK caller's transport and environment";
test(transportTest, async () => {
  if (runTestInSubprocess(import.meta.path, transportTest)) return;
  process.env["SNYK_TOKEN"] = process.env["SEMGREP_APP_TOKEN"] =
    "synthetic-inherited";
  for (const key of [
    "API_V3_URL",
    "SNYK_API_V3_URL",
    "API_REST_URL",
    "SNYK_API_REST_URL",
    "SNYK_API",
    "SNYK_CFG_ENDPOINT",
    "SEMGREP_URL",
    "SEMGREP_APP_URL",
  ])
    delete process.env[key];
  using fallback = spyOn(globalThis, "fetch").mockRejectedValue(
    new Error("unexpected global fetch"),
  );
  class Transport {
    environment: NodeJS.ProcessEnv = Object.setPrototypeOf(
      {
        CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
        [process.platform === "win32" ? "Snyk_Token" : "SNYK_TOKEN"]:
          "synthetic-snyk",
        [process.platform === "win32"
          ? "Semgrep_App_Token"
          : "SEMGREP_APP_TOKEN"]: "synthetic-semgrep",
      },
      process.env,
    );
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
  const snyk = () => collectSnykIssues(snykOptions, transport);
  const semgrep = (token?: string) =>
    collectSemgrepPlatformFindings(
      {
        deployment: "example",
        project: platformProject.name,
        ref: platformRef,
        token,
      },
      transport,
    );
  await expect(snyk()).rejects.toThrow("injected transport");
  await expect(semgrep()).rejects.toThrow("injected transport");

  transport.environment["SEMGREP_APP_URL"] = "https://example.invalid";
  await expect(semgrep()).rejects.toThrow("SEMGREP_APP_URL");
  await expect(semgrep("explicit")).rejects.toThrow("injected transport");
  transport.environment["SEMGREP_URL"] = "https://semgrep.dev/";
  await expect(semgrep()).rejects.toThrow("injected transport");

  expect(transport.requests).toEqual([
    "token synthetic-snyk",
    "Bearer synthetic-semgrep",
    "Bearer explicit",
    "Bearer synthetic-semgrep",
  ]);
  expect(fallback).not.toHaveBeenCalled();
});

test("Snyk checks the effective REST endpoint before sending an environment token", async () => {
  const eu = "https://api.eu.snyk.io";
  const us = "https://api.us.snyk.io";
  const settings: NodeJS.ProcessEnv = { ...environment };
  const requests: string[] = [];
  const collect = (apiOrigin: string, token?: string) =>
    collectSnykIssues(
      {
        organizationId,
        projectId,
        sourceRepositoryUrl,
        product: "code",
        apiOrigin,
        token,
      },
      {
        environment: settings,
        async fetch(url, init) {
          requests.push(
            `${url.origin} ${new Headers(init.headers).get("authorization")}`,
          );
          throw new Error("requested project");
        },
      },
    );
  // Set each higher-priority setting without removing the shadowed endpoint.
  for (const [name, endpoint, origin] of [
    ["SNYK_CFG_ENDPOINT", "https://app.eu.snyk.io/api/v1", eu],
    ["SNYK_API", "https://us.snyk.io/", us],
    ["SNYK_API_REST_URL", eu + "/rest", eu],
    ["API_REST_URL", us + "/rest", us],
    ["SNYK_API_V3_URL", eu + "/rest", eu],
    ["API_V3_URL", us + "/rest", us],
  ] as const) {
    settings[name] = endpoint;
    await expect(collect(origin === eu ? us : eu)).rejects.toThrow(name);
    await expect(collect(origin)).rejects.toThrow("requested project");
    expect(requests.splice(0)).toEqual([`${origin} token synthetic`]);
  }
  await expect(collect(eu, "explicit")).rejects.toThrow("requested project");
  expect(requests).toEqual([`${eu} token explicit`]);
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
