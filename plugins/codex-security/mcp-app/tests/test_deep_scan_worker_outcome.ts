import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import {
  coordinatorFixture,
  FakeExecutor,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

const blockedReason =
  "Source access was rejected at the approval gate before any source review.";

class OutcomeExecutor extends FakeExecutor {
  private readonly blockedAttempts: number;

  constructor(blockedAttempts: number) {
    super();
    this.blockedAttempts = blockedAttempts;
  }

  override async run(request: CodexWorkerRequest) {
    const result = await super.run(request);
    if (request.kind !== "discovery") return result;
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = JSON.parse(await readFile(resultPath, "utf8"));
    // A well-formed final artifact must not override a blocked audit outcome.
    draft.complete = true;
    draft.reviewState = { surfaces: [], explicitExclusions: [], deferred: [] };
    await writeFile(resultPath, JSON.stringify(draft));
    const blocked = this.discoveryCalls <= this.blockedAttempts;
    return {
      ...result,
      outcome: {
        status: blocked ? ("blocked" as const) : ("completed" as const),
        reason: blocked
          ? blockedReason
          : "The authorized scope has no applicable source.",
      },
      diagnostics: [
        {
          code: "worker_error" as const,
          message: "Synthetic recovered stream error.",
        },
      ],
    };
  }
}

try {
  await test("blocked audit cannot publish a completed empty draft", async () => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new OutcomeExecutor(Infinity);
    let publications = 0;
    const terminal = await runCoordinator(fixture, store, executor, {
      retryDelaysMs: [],
      onComplete: async () => {
        publications += 1;
      },
    });
    assert.equal(terminal?.status, "failed");
    assert.match(terminal.error!, /Source access was rejected/);
    assert.equal(publications, 0);
    assert.equal(executor.dedupCalls, 0);
    assert.ok(
      [...store.workers.values()].every(
        (worker) => worker.status !== "succeeded",
      ),
    );
  });

  await test("completed empty audit survives a recovered diagnostic", async () => {
    const { fixture, store } = await coordinatorFixture();
    let publications = 0;
    const terminal = await runCoordinator(
      fixture,
      store,
      new OutcomeExecutor(0),
      {
        retryDelaysMs: [],
        onComplete: async () => {
          publications += 1;
        },
      },
    );
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(publications, 1);
  });

  await test("blocked audit can complete after a successful retry", async () => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new OutcomeExecutor(1);
    let publications = 0;
    const terminal = await runCoordinator(fixture, store, executor, {
      retryDelaysMs: [0],
      onComplete: async () => {
        publications += 1;
      },
    });
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(executor.discoveryCalls, 2);
    assert.equal(
      executor.discoveryResumeThreadIds[1],
      executor.discoveryThreadIds[0],
    );
    assert.equal(publications, 1);
    assert.ok(
      store.workerUpdates.some((update) =>
        update.error?.includes(blockedReason),
      ),
    );
  });
} finally {
  await temporaryDirectories.cleanup();
}
