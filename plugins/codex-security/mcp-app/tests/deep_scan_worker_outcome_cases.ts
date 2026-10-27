import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import type {
  CodexWorkerRequest,
  CodexWorkerResult,
} from "../src/deep-scan/types.js";
import { readJson } from "./support/json.ts";

export async function testDiscoveryOutcome({
  withWorkerFixture,
  runWorker,
  assertReadOnlyWorkerPolicy,
}: {
  withWorkerFixture: (
    action: (
      fixture: { markerPath: string },
      promptPath: string,
      workingDirectory: string,
    ) => Promise<void>,
  ) => Promise<void>;
  runWorker: (
    promptPath: string,
    workingDirectory: string,
    options?: Partial<CodexWorkerRequest>,
  ) => Promise<CodexWorkerResult>;
  assertReadOnlyWorkerPolicy: (args: readonly string[]) => void;
}) {
  for (const resumeThreadId of [undefined, "fixture-existing-thread"]) {
    await withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
      await writeFile(promptPath, "DISCOVERY_OUTCOME_BLOCKED\n");
      const result = await runWorker(promptPath, workingDirectory, {
        resumeThreadId,
        continuationPrompt: resumeThreadId
          ? "DISCOVERY_OUTCOME_BLOCKED\n"
          : undefined,
      });
      assert.deepEqual(result.outcome, {
        status: "blocked",
        reason: "Source access was rejected before review.",
      });
      const invocation = await readJson(fixture.markerPath);
      assert.ok(invocation.argv.includes("--output-schema"));
      assert.match(invocation.stdin, /blocked/);
      assertReadOnlyWorkerPolicy(invocation.argv);
    });
  }
  await withWorkerFixture(async (_fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, "DISCOVERY_OUTCOME_INVALID\n");
    await assert.rejects(
      runWorker(promptPath, workingDirectory),
      /worker outcome/i,
    );
  });
}
