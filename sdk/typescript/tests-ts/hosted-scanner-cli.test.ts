import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import {
  platformFinding,
  platformProject,
  platformRef,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";

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
      ...dependencies({
        environment: {
          CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
          SEMGREP_APP_TOKEN: "synthetic",
        },
      }),
      collectSemgrepPlatformFindings: (options, hooks) =>
        collectSemgrepPlatformFindings(options, {
          ...hooks,
          fetch: async (url) =>
            Response.json(
              url.pathname.includes("/projects/")
                ? { project: platformProject }
                : { findings: [platformFinding(12)] },
            ),
        }),
    },
  );
  expect({ code, stderr: cli.stderr.text() }).toEqual({ code: 0, stderr: "" });
  expect(JSON.parse(cli.stdout.text())).toEqual(platformReport());
});

test.each(["open-source", "code"])(
  "the Snyk CLI forwards the selected %s project and never emits a partial raw report",
  async (product) => {
    const cli = createCliTest(main);
    let received: unknown;
    const code = await cli.runCli(
      [
        "import",
        "snyk",
        "project-id",
        "--snyk-org",
        "organization-id",
        "--snyk-product",
        product,
        "--source-repository-url",
        platformProject.url,
        "--format",
        "json",
      ],
      {
        ...dependencies({
          environment: {
            CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
            SNYK_TOKEN: "synthetic",
          },
        }),
        collectSnykIssues: async (options) => {
          received = options;
          throw new Error(
            "failed second page (HTTP 429); Retry-After: 20: synthetic-token\n\u001b[31mtry later",
          );
        },
      },
    );
    expect(received).toMatchObject({
      projectId: "project-id",
      organizationId: "organization-id",
      product,
      sourceRepositoryUrl: platformProject.url,
    });
    expect(code).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(
      "failed second page (HTTP 429); Retry-After: 20: synthetic-token  [31mtry later",
    );
  },
);
