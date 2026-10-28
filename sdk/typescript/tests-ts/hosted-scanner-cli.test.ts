import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import {
  platformFinding,
  platformProject,
  platformRef,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";
import {
  organizationId,
  projectId,
  snykRestDocument,
  snykRestProject,
  sourceRepositoryUrl,
} from "./support/snyk-rest-fixtures.js";

const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SEMGREP_APP_TOKEN: "synthetic",
  SNYK_TOKEN: "synthetic",
};

test("the Semgrep CLI emits a replayable report without a framework wrapper", async () => {
  const cli = createCliTest(main);
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
            ? { project: platformProject }
            : { findings: [platformFinding(12)] },
        ),
    },
  );
  expect({ code, stderr: cli.stderr.text() }).toEqual({ code: 0, stderr: "" });
  expect(JSON.parse(cli.stdout.text())).toEqual(platformReport());
});

test.each(["open-source", "code"])(
  "the Snyk CLI forwards the selected %s project and never emits a partial raw report",
  async (product) => {
    const cli = createCliTest(main);
    const requests: URL[] = [];
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
          requests.push(url);
          if (url.pathname.endsWith("/projects/" + projectId))
            return Response.json(
              snykRestDocument(
                snykRestProject({
                  manager: product === "code" ? "sast" : "npm",
                }),
              ),
            );
          throw new Error("failed issues page");
        },
      },
    );
    expect(requests.map((url) => url.pathname)).toEqual([
      `/rest/orgs/${organizationId}/projects/${projectId}`,
      `/rest/orgs/${organizationId}/issues`,
    ]);
    expect(requests[1]?.searchParams.get("type")).toBe(
      product === "code" ? "code" : "package_vulnerability",
    );
    expect(code).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain("failed issues page");
  },
);
