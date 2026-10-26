import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import * as rubricSource from "../src/severity-rubric.js";
import { bundledSeverityRubric } from "../src/severity-rubric.js";
import { mockWorkbench } from "./support/api-client.js";
import { codexFactory, scanRuntimeDependencies } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
afterEach(() => mock.restore());

function testClient(
  dependencies: Partial<
    NonNullable<ConstructorParameters<typeof CodexSecurity>[1]>
  >,
) {
  return new CodexSecurity(
    {},
    {
      environment: {},
      createCodex: () => {
        throw new Error("Unexpected model invocation");
      },
      probeCodexSandbox: async () => {},
      prepareScanArtifactRestorer: async () => ({ restore: async () => {} }),
      ...dependencies,
    },
    { surface: "sdk" },
  );
}

test.each(["standard", "deep"] as const)(
  "%s scans retain one resolved policy in the model and persisted worker context",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const scan = join(root, "scan");
    await Promise.all([repository, home, scan].map((path) => mkdir(path)));
    const policy = { ...bundledSeverityRubric, revision: 7 };
    const resolve = spyOn(
      rubricSource,
      "getDefaultSeverityRubric",
    ).mockResolvedValue({ ...policy });
    let registration: any;
    let prompt: string | undefined;
    await using client = testClient({
      ...scanRuntimeDependencies(home, scan),
      canRunDirectDeepScan: () => false,
      runWorkbench: async (_options, args, input) => {
        if (args[0] === "register-cli-scan") registration = JSON.parse(input!);
        return mockWorkbench(args, input);
      },
      createCodex: codexFactory(async (value: string) => {
        prompt = value;
        policy.revision = 8;
        throw new Error("Captured scan policy");
      }),
    });
    await expect(
      client.run(repository, { mode, scanPrompt: "Review authorization." }),
    ).rejects.toThrow("Captured scan policy");
    expect(resolve).toHaveBeenCalledTimes(1);
    const saved = { ...bundledSeverityRubric, revision: 7 };
    expect(registration.recipe.severityRubric).toEqual(saved);
    expect(registration.recipe.requiresScanPrompt).toBe(true);
    expect(registration.userContext.split("\n\n")[0]).toBe(
      "Review authorization.",
    );
    expect(
      JSON.parse(registration.userContext.split("\n").at(-1)!).severityRubric,
    ).toEqual(saved);
    expect(prompt).toContain(JSON.stringify({ severityRubric: saved }));
  },
);

test("explicit scan policy is captured before asynchronous preparation and bypasses defaults", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const home = join(root, "home");
  const scan = join(root, "scan");
  await Promise.all([repository, home, scan].map((path) => mkdir(path)));
  const policy = { ...bundledSeverityRubric, revision: 12 };
  const resolve = spyOn(
    rubricSource,
    "getDefaultSeverityRubric",
  ).mockRejectedValue(new Error("Explicit policy must win"));
  let registration: any;
  const runtime = scanRuntimeDependencies(home, scan);
  await using client = testClient({
    ...runtime,
    prepareRuntime: async () => {
      policy.markdown = "Changed by caller";
      return runtime.prepareRuntime();
    },
    runWorkbench: async (_options, args, input) => {
      if (args[0] === "register-cli-scan") registration = JSON.parse(input!);
      return mockWorkbench(args, input);
    },
    createCodex: codexFactory(async () => {
      throw new Error("Captured scan policy");
    }),
  });
  await expect(
    client.run(repository, { severityRubric: policy }),
  ).rejects.toThrow("Captured scan policy");
  expect(resolve).not.toHaveBeenCalled();
  expect(registration.recipe.severityRubric).toEqual({
    ...bundledSeverityRubric,
    revision: 12,
  });
});
