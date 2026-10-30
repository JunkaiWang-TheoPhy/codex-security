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
  for (const token of ["synthetic\rline", "synthetic\0line"])
    await expect(semgrep(token)).rejects.toThrow("NUL or line break");
  snykOptions.token = "synthetic\0line";
  await expect(snyk()).rejects.toThrow("NUL or line break");
  delete snykOptions.token;
  await expect(snyk()).rejects.toThrow("injected transport");
  await expect(semgrep()).rejects.toThrow("injected transport");

  const eu = "https://api.eu.snyk.io";
  const us = "https://api.snyk.io/rest";
  process.env["Snyk_Api_V3_Url"] = us;
  transport.environment["SNYK_Api_REST_Url"] = us;
  transport.environment[
    process.platform === "win32" ? "Snyk_Cfg_Endpoint" : "SNYK_CFG_ENDPOINT"
  ] = eu;
  await expect(snyk()).rejects.toThrow("SNYK_CFG_ENDPOINT");
  snykOptions.apiOrigin = eu;
  await expect(snyk()).rejects.toThrow("injected transport");
  delete process.env["Snyk_Api_V3_Url"];
  process.env["SNYK_API_V3_URL"] = us;
  await expect(snyk()).rejects.toThrow("SNYK_API_V3_URL");

  transport.environment["SEMGREP_APP_URL"] = "https://example.invalid";
  await expect(semgrep()).rejects.toThrow("SEMGREP_APP_URL");
  await expect(semgrep("explicit")).rejects.toThrow("injected transport");
  transport.environment["SEMGREP_URL"] = "https://semgrep.dev/";
  await expect(semgrep()).rejects.toThrow("injected transport");

  expect(transport.requests).toEqual([
    "token synthetic-snyk",
    "Bearer synthetic-semgrep",
    "token synthetic-snyk",
    "Bearer explicit",
    "Bearer synthetic-semgrep",
  ]);
  expect(fallback).not.toHaveBeenCalled();
});

function snykRequestProbe() {
  const settings: NodeJS.ProcessEnv = { ...environment };
  const requests: string[] = [];
  const collect = (apiOrigin?: string, token?: string) =>
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
  return { collect, requests, settings };
}

test("Snyk checks the effective REST endpoint before sending an environment token", async () => {
  const eu = "https://api.eu.snyk.io";
  const us = "https://api.us.snyk.io";
  const { collect, requests, settings } = snykRequestProbe();
  const region =
    process.platform === "win32" ? "Scanner_Region" : "scanner_region";
  settings[region] = "eu";
  settings["SNYK_API_V3_URL"] = "false";
  settings["SNYK_API_REST_URL"] = "FALSE";
  // Set each higher-priority setting without removing the shadowed endpoint.
  for (const [name, endpoint, origin] of [
    ["SNYK_CFG_ENDPOINT", "https://app.eu.snyk.io/api/v1", eu],
    ["SNYK_API", "https://us.snyk.io/", us],
    ["SNYK_API_REST_URL", "https://api.${scanner_region}.snyk.io/rest", eu],
    ["API_REST_URL", us + "/rest", us],
    ["SNYK_API_V3_URL", "https://api.${scanner_region}.snyk.io/rest", eu],
    ["API_V3_URL", us + "/rest", us],
  ] as const) {
    settings[name] = endpoint;
    await expect(collect(origin === eu ? us : eu)).rejects.toThrow(name);
    await expect(collect(origin)).rejects.toThrow("requested project");
    expect(requests.splice(0)).toEqual([`${origin} token synthetic`]);
  }
  settings["API_V3_URL"] = "false";
  await expect(collect(us)).rejects.toThrow(/^API_V3_URL does not match/u);
  delete settings["API_V3_URL"];
  settings["SNYK_API_V3_URL"] = "${scanner_region}";
  settings[region] = "false";
  await expect(collect(us)).rejects.toThrow("SNYK_API_V3_URL");
  delete settings[region];
  await expect(collect(eu)).rejects.toThrow(
    "missing environment variable scanner_region",
  );
  await expect(collect(eu, "explicit")).rejects.toThrow("requested project");
  expect(requests).toEqual([`${eu} token explicit`]);
});

test("Snyk leaves unterminated endpoint references literal and resumes on the next line", async () => {
  const { collect, settings } = snykRequestProbe();
  settings["SNYK_API_V3_URL"] = "https://api.snyk.io/" + "${a".repeat(16_384);
  await expect(collect("https://api.snyk.io")).rejects.toThrow(
    "requested project",
  );
  settings["SNYK_API_V3_URL"] += "\n${missing}";
  await expect(collect("https://api.snyk.io")).rejects.toThrow(
    "missing environment variable missing",
  );
});

test("Snyk sends access tokens only to their embedded API host", async () => {
  const eu = "https://api.eu.snyk.io";
  const us = "https://api.snyk.io";
  const { collect, requests, settings } = snykRequestProbe();
  for (const [kind, host] of [
    ["uat", "api.eu.snyk.io"],
    ["sat", eu],
  ]) {
    const payload = Buffer.from(JSON.stringify({ h: host })).toString(
      "base64url",
    );
    const token = `snyk_${kind}.12345678.${payload}.synthetic`;
    settings["SNYK_TOKEN"] = token;
    await expect(collect()).rejects.toThrow("access token's API host");
    await expect(collect(eu)).rejects.toThrow("requested project");
    settings["SNYK_API"] = us;
    await expect(collect(us, token)).rejects.toThrow("access token's API host");
    await expect(collect(eu, token)).rejects.toThrow("requested project");
    expect(requests.splice(0)).toEqual([
      `${eu} token ${token}`,
      `${eu} token ${token}`,
    ]);
    delete settings["SNYK_API"];
  }
  settings["SNYK_TOKEN"] = "00000000-0000-4000-8000-000000000001";
  await expect(collect()).rejects.toThrow("requested project");
  expect(requests).toEqual([`${us} token ${settings["SNYK_TOKEN"]}`]);
});

test("hosted collection rejects invalid UTF-8 before it can replace vendor evidence", async () => {
  // The two distinct issue keys would both decode to the same replacement character.
  const malformed = (byte: number) =>
    new Response(
      Buffer.concat([
        Buffer.from('{"key":"'),
        Buffer.from([byte]),
        Buffer.from('"}'),
      ]),
    );
  for (const byte of [0xfe, 0xff]) {
    const transport = { environment, fetch: async () => malformed(byte) };
    await expect(
      collectSnykIssues(
        {
          organizationId,
          projectId,
          sourceRepositoryUrl,
          product: "open-source",
        },
        transport,
      ),
    ).rejects.toThrow("not valid UTF-8");
    await expect(
      collectSemgrepPlatformFindings(
        {
          deployment: "example",
          project: platformProject.name,
          ref: platformRef,
        },
        transport,
      ),
    ).rejects.toThrow("not valid UTF-8");
  }
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
  expect(JSON.parse(cli.stdout.text())).toEqual({
    ...report,
    repositoryAliases: ["project"],
  });
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
