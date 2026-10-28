import { chmod, mkdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import { validateOutputDir } from "../src/runtime.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const fixtures = createApiTestFixtures("codex-security-cli-output-");
afterEach(fixtures.cleanup);

async function scanFixture() {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const output = join(root, "results");
  await mkdir(repository);
  git(repository, "init", "-q");
  const started = mock();
  const signals = new FakeSignals();
  const deps = dependencies({
    currentDirectory: repository,
    onRun: started,
    signals,
  });
  const createSecurity = deps.createSecurity;
  deps.createSecurity = (config) => {
    const security = createSecurity(config);
    return {
      ...security,
      run: async (target, options) => {
        await validateOutputDir(options?.outputDir, options?.archiveExisting);
        return security.run(target, options);
      },
      preflight: async (target, options) => {
        await validateOutputDir(options?.outputDir, options?.archiveExisting);
        return security.preflight(target, options);
      },
    };
  };
  const confirm = mock(async () => true);
  deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
  return { root, repository, output, started, deps, confirm, signals };
}

describe("CLI output directory permissions", () => {
  test.skipIf(process.platform === "win32").each([
    ["standard", []],
    ["deep", []],
    ["standard", ["--headless"]],
  ] as const)(
    "repairs approved permissions for a %s scan %j",
    async (mode, flags) => {
      const { output, started, deps } = await scanFixture();
      await mkdir(output);
      await chmod(output, 0o755);
      const confirm = mock(
        async (
          question: string,
          defaultValue?: boolean,
          signal?: AbortSignal,
        ) => {
          expect(question).toContain(output);
          expect(question).toContain("700");
          expect(defaultValue).toBe(false);
          expect(signal?.aborted).toBe(false);
          expect((await stat(output)).mode & 0o777).toBe(0o755);
          expect(started).not.toHaveBeenCalled();
          return true;
        },
      );
      deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
      const { runCli } = createCliTest(main, { stderr: true });

      expect(
        await runCli(
          ["scan", ".", "--mode", mode, "--output-dir", output, ...flags],
          deps,
        ),
      ).toBe(0);
      expect(confirm).toHaveBeenCalledTimes(1);
      expect((await stat(output)).mode & 0o777).toBe(0o700);
      expect(started).toHaveBeenCalledTimes(1);
    },
  );

  test.skipIf(process.platform === "win32")(
    "leaves permissions unchanged when the user declines",
    async () => {
      const { output, started, deps } = await scanFixture();
      const initialize = mock(deps.createSecurity);
      deps.createSecurity = initialize;
      await mkdir(output);
      await chmod(output, 0o770);
      const confirm = mock(async () => false);
      deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
      const { runCli, stderr } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(2);
      expect(confirm).toHaveBeenCalledTimes(1);
      expect((await stat(output)).mode & 0o777).toBe(0o770);
      expect(initialize).not.toHaveBeenCalled();
      expect(started).not.toHaveBeenCalled();
      expect(stderr.text()).toContain("chmod 700");
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not prompt or change permissions during non-interactive scans or dry runs",
    async () => {
      for (const scenario of [
        { flags: ["--json"] },
        { flags: ["--format", "jsonl"] },
        { flags: ["--dry-run"] },
        { environment: { CI: "true" } },
        { environment: { TERM: "dumb" } },
        { terminal: false },
        { interactive: false },
      ]) {
        const { output, started, deps, confirm } = await scanFixture();
        await mkdir(output);
        await chmod(output, 0o755);
        deps.environment = scenario.environment ?? {};
        deps.outputDirectoryPrompt = {
          isInteractive: () => scenario.interactive !== false,
          confirm,
        };
        const { runCli } = createCliTest(main, {
          stderr: scenario.terminal !== false,
        });

        expect(
          await runCli(
            ["scan", ".", "--output-dir", output, ...(scenario.flags ?? [])],
            deps,
          ),
        ).toBe(2);
        expect(confirm).not.toHaveBeenCalled();
        expect((await stat(output)).mode & 0o777).toBe(0o755);
        expect(started).not.toHaveBeenCalled();
      }
    },
  );

  test.each(["missing", "private"])(
    "does not prompt for a %s output directory",
    async (state) => {
      const { output, started, deps, confirm } = await scanFixture();
      if (state === "private") await mkdir(output, { mode: 0o700 });
      const { runCli } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(0);
      expect(confirm).not.toHaveBeenCalled();
      expect(started).toHaveBeenCalledTimes(1);
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not repair nonempty or linked directories",
    async () => {
      for (const state of ["nonempty", "symlink"] as const) {
        const { root, output, started, deps, confirm } = await scanFixture();
        const actual =
          state === "symlink" ? join(root, "actual-results") : output;
        await mkdir(actual);
        await chmod(actual, 0o755);
        if (state === "symlink") await symlink(actual, output, "dir");
        else await writeFile(join(output, "previous.txt"), "previous scan\n");
        const { runCli } = createCliTest(main, { stderr: true });

        expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(
          2,
        );
        expect(confirm).not.toHaveBeenCalled();
        expect((await stat(actual)).mode & 0o777).toBe(0o755);
        expect(started).not.toHaveBeenCalled();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not repair output inside the repository or under an unsafe parent",
    async () => {
      for (const state of ["repository", "parent"] as const) {
        const { root, repository, started, deps, confirm } =
          await scanFixture();
        const parent =
          state === "repository" ? repository : join(root, "shared");
        if (state === "parent") {
          await mkdir(parent);
          await chmod(parent, 0o777);
        }
        const output = join(parent, "results");
        await mkdir(output);
        await chmod(output, 0o755);
        const { runCli } = createCliTest(main, { stderr: true });

        expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(
          2,
        );
        expect(confirm).not.toHaveBeenCalled();
        expect((await stat(output)).mode & 0o777).toBe(0o755);
        expect(started).not.toHaveBeenCalled();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not offer to repair a directory owned by another user",
    async () => {
      const { output, started, deps, confirm } = await scanFixture();
      await mkdir(output);
      await chmod(output, 0o755);
      const currentUid = process.geteuid!();
      const effectiveUid = spyOn(process, "geteuid").mockReturnValue(
        currentUid + 1,
      );
      const { runCli, stderr } = createCliTest(main, { stderr: true });

      try {
        expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(
          2,
        );
        expect(confirm).not.toHaveBeenCalled();
        expect((await stat(output)).mode & 0o777).toBe(0o755);
        expect(started).not.toHaveBeenCalled();
        expect(stderr.text()).toContain("owned by the current user");
      } finally {
        effectiveUid.mockRestore();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not follow a directory link substituted during the permission prompt",
    async () => {
      const { root, output, started, deps } = await scanFixture();
      const replacement = join(root, "other-directory");
      await mkdir(output);
      await mkdir(replacement);
      await chmod(output, 0o755);
      await chmod(replacement, 0o755);
      const confirm = mock(async () => {
        await rm(output, { recursive: true });
        await symlink(replacement, output, "dir");
        return true;
      });
      deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
      const { runCli, stderr } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(2);
      expect(confirm).toHaveBeenCalledTimes(1);
      expect((await stat(replacement)).mode & 0o777).toBe(0o755);
      expect(started).not.toHaveBeenCalled();
      expect(stderr.text()).toContain(output);
    },
  );

  test.skipIf(process.platform === "win32")(
    "reports a permission repair failure without starting a scan",
    async () => {
      const { output, started, deps } = await scanFixture();
      await mkdir(output);
      await chmod(output, 0o755);
      const confirm = mock(async () => {
        await rm(output, { recursive: true });
        return true;
      });
      deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
      const { runCli, stderr } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(2);
      expect(confirm).toHaveBeenCalledTimes(1);
      expect(started).not.toHaveBeenCalled();
      expect(stderr.text()).toContain(output);
    },
  );

  test.skipIf(process.platform === "win32")(
    "cancels a pending prompt without changing permissions",
    async () => {
      const { output, started, deps, signals } = await scanFixture();
      await mkdir(output);
      await chmod(output, 0o755);
      const confirm = mock(
        (_question: string, _default?: boolean, signal?: AbortSignal) => {
          signals.emit("SIGINT");
          expect(signal?.aborted).toBe(true);
          return new Promise<boolean>(() => {});
        },
      );
      deps.outputDirectoryPrompt = { isInteractive: () => true, confirm };
      const { runCli } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(
        130,
      );
      expect(confirm).toHaveBeenCalledTimes(1);
      expect((await stat(output)).mode & 0o777).toBe(0o755);
      expect(started).not.toHaveBeenCalled();
    },
  );
});
