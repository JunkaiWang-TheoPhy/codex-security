import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";

const temporary = createTemporaryDirectoriesSync(true);
afterEach(temporary.cleanup);

test("Standard schedules every scoped match once and retains unfinished paths", () => {
  const root = temporary.create("standard-queue-");
  const repo = join(root, "repository");
  const scan = join(root, "scan");
  const context = join(scan, "artifacts", "01_context");
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(context, { recursive: true });
  const matched = Array.from({ length: 6 }, (_, i) => `src/route-${i}.ts`);
  for (const path of [...matched, "outside.ts", "src/example.txt"])
    writeFileSync(join(repo, path), "registerWebhook(handler)");
  for (const path of ["selected.txt", "src/unused.ts"])
    writeFileSync(join(repo, path), "ordinary source");
  writeFileSync(
    join(context, "standard-rules.json"),
    JSON.stringify([
      { path: "[.]ts$", content: "registerWebhook" },
      { path: "^src/route-0" },
    ]),
  );
  const run = (command: string, ...values: string[]) =>
    spawnSync(
      nodeCommand().command,
      [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "standard-queue",
        command,
        scan,
        ...values,
      ],
      { encoding: "utf8" },
    );
  const success = (command: string, ...values: string[]) => {
    const result = run(command, ...values);
    expect(result.status, result.stderr).toBe(0);
    return JSON.parse(result.stdout);
  };

  expect(success("build", repo, "src", "selected.txt")).toEqual({
    files: 7,
    batches: 2,
    reviewed: 0,
    remaining: 7,
  });
  const [first, second] = success("pending", "0", "2").pending;
  expect(first.files).toEqual(["selected.txt", ...matched.slice(0, 4)]);
  expect(second.files).toEqual(matched.slice(4));
  success("reviewed", ...first.files.slice(1), ...second.files);
  expect(success("pending", "0", "2").pending).toEqual([
    { id: 1, files: ["selected.txt"] },
  ]);
  expect(run("check").status).toBe(1);
  expect(run("build", repo, ".").status).toBe(1);
  expect(run("reviewed", "outside.ts").status).toBe(1);
  success("reviewed", "selected.txt");
  expect(success("check").remaining).toBe(0);
});
