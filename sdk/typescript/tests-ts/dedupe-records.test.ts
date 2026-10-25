import { expect, test, mock, onTestFinished, spyOn } from "bun:test";
import { throws } from "node:assert/strict";
import { z } from "zod";
import { InvalidDeduplicationDecision } from "../src/index.js";
import { requireFinding } from "../src/deduplication/finding-schema.js";
import { validateReview } from "../src/deduplication/deduplication-reviewer.js";
import * as records from "../src/deduplication/records.js";
import Ajv2020 from "ajv/dist/2020.js";
import { CodexSecurityError, DeduplicationReviewError } from "../src/errors.js";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import type { Finding, FindingsDocument } from "../src/models.js";
import {
  deduplicateRecords,
  recordsReviewAttribution,
  type DeduplicateRecordsInput,
} from "../src/deduplication/records.js";
import type { DeduplicationReviewRequest } from "../src/deduplication/review.js";
import { runRecordsProtocol } from "../src/deduplication/records-protocol.js";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import attributionFixtures from "./fixtures/records-review-attribution.json";
import { rejecting, throwing } from "./support/errors.js";

test("attribution maps exact structured participants to sorted host identities", () => {
  const references = new Map(
    ["A", "B", "C", "D"].map((id) => [`finding-${id}`, id]),
  );
  for (const fixture of attributionFixtures) {
    const participants = fixture.participants.map((id) => `finding-${id}`);
    expect(
      recordsReviewAttribution(
        [...participants].reverse().concat(participants),
        references,
        new Map(fixture.anchors.map((id) => [id, []])),
      ),
    ).toEqual({ ...fixture.attribution, version: 1 });
  }
});

test("attribution rejects absent, unknown, and context-only participants", () => {
  const references = new Map([
    ["finding-A", "A"],
    ["finding-C", "C"],
  ]);
  const anchors = new Map([["A", ["C"]]]);
  for (const participants of [
    undefined,
    [],
    ["unknown"],
    ["finding-C"],
    ["finding-A", "unknown"],
  ])
    expect(() =>
      recordsReviewAttribution(participants, references, anchors),
    ).toThrow();
});

const document: FindingsDocument = JSON.parse(
  await readFile(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
    "utf8",
  ),
);
function record(id: string, title = id) {
  const finding = structuredClone(document.findings[0]!);
  finding.title = title;
  finding.provenance = {
    source: `synthetic/${id}`,
    revision: "synthetic-revision",
  };
  return { id, finding };
}
function input(): DeduplicateRecordsInput {
  return {
    version: 1,
    observations: [
      record("a", "shared"),
      record("b", "shared"),
      record("c", "existing"),
      record("d", "unique"),
      record("neighbor", "existing"),
    ],
    candidateRelationships: ["a", "b", "c", "d"].map((observationId) => ({
      observationId,
      candidateObservationIds: ["a", "b", "c", "d", "neighbor"].filter(
        (id) => id !== observationId,
      ),
    })),
  };
}
function assigned(review: DeduplicationReviewRequest): Finding[] {
  return JSON.parse(
    review.prompt.slice(review.prompt.lastIndexOf('\n{"findings":')),
  ).findings;
}
function decision(findings: Finding[]) {
  return findings[0]!.title === findings[1]!.title
    ? {
        decision: "SAME",
        rationale: "Synthetic shared correction.",
        canonicalFindingId: findings[0]!.findingId,
        mergedFinding: { ...findings[0]!, extensions: { originals: findings } },
      }
    : { decision: "DISTINCT", rationale: "Synthetic independent corrections." };
}
function answer(review: DeduplicationReviewRequest): unknown {
  const findings = assigned(review);
  return review.stage === "pair-review"
    ? decision(findings)
    : {
        decisions: Object.fromEntries(
          findings.slice(1).map((finding, index) => [
            `pair-${index + 1}`,
            {
              decision: decision([findings[0]!, finding]).decision,
              rationale: "Synthetic pair recommendation.",
            },
          ]),
        ),
      };
}

test("records groups original observations and retrieved neighbors with unique representatives", async () => {
  const original = input();
  const requests: DeduplicationReviewRequest[] = [];
  const result = await deduplicateRecords(original, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        expect(review.trustedInstructions).toContain("approved repository");
        expect(review.findingSchema).toHaveProperty("required");
        const validateFinding = new Ajv2020({ strict: false }).compile(
          JSON.parse(JSON.stringify(review.findingSchema)) as object,
        );
        const finding = original.observations[0]!.finding;
        expect(validateFinding(finding)).toBe(true);
        expect(validateFinding({ ...finding, title: "" })).toBe(false);
        expect(review).not.toHaveProperty("validate");
        expect(review).not.toHaveProperty("findingIds");
        for (const finding of assigned(review))
          expect(finding.provenance).toHaveProperty(
            "revision",
            "synthetic-revision",
          );
        return answer(review);
      },
    },
  });
  expect(result.status).toBe("completed");
  expect(
    result.groups.map((group) => [...group.observationIds].sort()).sort(),
  ).toEqual([["a", "b"], ["c", "neighbor"], ["d"]]);
  for (const group of result.groups)
    expect(group.observationIds).toContain(group.representativeObservationId);
  expect(result.unresolved).toEqual([]);
  expect(new Set(requests.map(({ requestId }) => requestId)).size).toBe(
    requests.length,
  );
  expect(requests.filter(({ stage }) => stage === "pair-review")).toHaveLength(
    2,
  );
  expect(original).toEqual(input());
  for (const request of requests) {
    const participants = assigned(request).map((finding) =>
      finding.provenance!.source!.slice("synthetic/".length),
    );
    expect(request.attribution).toEqual({
      version: 1,
      beneficiaryObservationIds: participants
        .filter((id) => id !== "neighbor")
        .sort(),
      contextObservationIds: participants
        .filter((id) => id === "neighbor")
        .sort(),
    });
  }
});

test("records honors explicit observation neighborhoods and handles empty/isolated inputs without reviews", async () => {
  for (const observations of [[], [record("a")]]) {
    const result = await deduplicateRecords(
      {
        version: 1,
        observations: [...observations, record("unused")],
        candidateRelationships: observations.map(({ id }) => ({
          observationId: id,
          candidateObservationIds: [],
        })),
      },
      {
        reviewRunner: {
          run: rejecting("No model call expected"),
        },
      },
    );
    expect(result.status).toBe("completed");
    expect(result.groups).toHaveLength(observations.length);
  }
});

test("candidate-only observations are grouped without becoming additional anchors", async () => {
  const data: DeduplicateRecordsInput = {
    version: 1,
    observations: [
      record("a", "same"),
      record("b", "same"),
      record("c", "same"),
    ],
    candidateRelationships: [
      { observationId: "a", candidateObservationIds: ["b"] },
    ],
  };
  const requests: DeduplicationReviewRequest[] = [];
  const result = await deduplicateRecords(data, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        return answer(review);
      },
    },
  });
  expect(result.status).toBe("completed");
  expect(
    result.groups.map(({ observationIds }) => observationIds.sort()),
  ).toEqual([["a", "b"]]);
  expect(requests.map(({ stage }) => stage)).toEqual([
    "screening",
    "pair-review",
  ]);
  for (const request of requests)
    expect(request.attribution).toEqual({
      version: 1,
      beneficiaryObservationIds: ["a"],
      contextObservationIds: ["b"],
    });
});

test("records retries in a new invocation preserve membership with fresh review UUIDs", async () => {
  const requests: DeduplicationReviewRequest[] = [];
  const data: DeduplicateRecordsInput = {
    version: 1,
    observations: [record("A", "same"), record("D", "same")],
    candidateRelationships: [
      { observationId: "A", candidateObservationIds: ["D"] },
    ],
  };
  const failed = await deduplicateRecords(data, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        throw new Error("Remote acceptance unknown");
      },
    },
  });
  expect(failed.status).toBe("unresolved");
  const completed = await deduplicateRecords(data, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        return answer(review);
      },
    },
  });
  expect(completed.status).toBe("completed");
  expect(requests).toHaveLength(3);
  expect(new Set(requests.map((request) => request.requestId)).size).toBe(3);
  for (const request of requests) {
    expect(request.requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(request.attribution).toEqual({
      ...attributionFixtures[3]!.attribution,
      version: 1,
    });
  }
});

test.each([
  "malformed",
  "unknown-slot",
  "unknown-canonical",
  "missing-pair",
  "inconclusive",
  "failed",
  "pair-failed",
])(
  "%s review never becomes a unique disposition or retries",
  async (scenario) => {
    const runMock = mock(async (review: DeduplicationReviewRequest) => {
      if (scenario === "pair-failed" && review.stage !== "pair-review")
        return answer(review);
      if (scenario === "failed" || scenario === "pair-failed")
        throw new Error("Remote execution may already have been accepted");
      if (scenario === "malformed") return "not an object";
      if (scenario === "inconclusive") return { decision: "INCONCLUSIVE" };
      if (scenario === "unknown-canonical") {
        if (review.stage === "screening") return answer(review);
        return {
          ...decision(assigned(review)),
          canonicalFindingId: "unknown",
        };
      }
      const valid = answer(review) as {
        decisions: Record<string, unknown>;
      };
      if (scenario === "missing-pair") delete valid.decisions["pair-1"];
      if (scenario === "unknown-slot") {
        valid.decisions["unknown"] = valid.decisions["pair-1"];
        delete valid.decisions["pair-1"];
      }
      return valid;
    });
    const result = await deduplicateRecords(input(), {
      reviewRunner: {
        run: runMock,
      },
    });
    expect(result.status).toBe("unresolved");
    expect(result.groups).toEqual([]);
    expect(result.unresolved.map(({ observationId }) => observationId)).toEqual(
      ["a", "b", "c", "d"],
    );
    expect(runMock).toHaveBeenCalledTimes(
      ["pair-failed", "unknown-canonical"].includes(scenario) ? 3 : 1,
    );
  },
);

test("rejects invalid inputs before calling the host", async () => {
  const cases = [
    { ...input(), version: 2 },
    { ...input(), observations: [record("a"), record("a")] },
    { ...input(), observations: [{ id: "a", finding: {} }] },
    { ...input(), canonicals: [] },
    {
      ...input(),
      candidateRelationships: [{ observationId: "a", canonicalIds: [] }],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["a"] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["b", "b"] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        input().candidateRelationships[0],
        input().candidateRelationships[0],
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "unknown", candidateObservationIds: [] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["unknown"] },
      ],
    },
  ];
  for (const data of cases)
    await expect(
      deduplicateRecords(data as DeduplicateRecordsInput, {
        reviewRunner: {
          run: rejecting("Host must not be called"),
        },
      }),
    ).rejects.toThrow();
});

test("SDK aborts even while a host runner is stuck", async () => {
  const controller = new AbortController();
  await expect(
    deduplicateRecords(input(), {
      signal: controller.signal,
      reviewRunner: {
        async run(_review, options) {
          expect(options?.signal).toBe(controller.signal);
          controller.abort(new Error("Canceled by host"));
          return await new Promise(() => {});
        },
      },
    }),
  ).rejects.toThrow("Canceled by host");
});

type Message = {
  jsonrpc: string;
  id: string | number | null;
  method?: string;
  params: DeduplicationReviewRequest;
  result?: unknown;
  error?: { code: number };
};
function fakeHost(
  onReview: (
    message: Message,
    send: (value: unknown) => void,
    input: PassThrough,
  ) => void,
) {
  const stream = new PassThrough();
  const messages: Message[] = [];
  const send = (value: unknown) => stream.write(`${JSON.stringify(value)}\n`);
  const output = new Writable({
    write(chunk, _encoding, callback) {
      const message = JSON.parse(chunk.toString()) as Message;
      messages.push(message);
      if (message.method === "review.run")
        queueMicrotask(() => onReview(message, send, stream));
      callback();
    },
  });
  return { stream, output, messages, send };
}
const run = { jsonrpc: "2.0", id: "run-1", method: "run", params: input() };

test("CLI records mode uses only the fake host, bypassing saved scans, persistence, auth, and updates", async () => {
  const host = fakeHost((message, send) => {
    expect(message.jsonrpc).toBe("2.0");
    expect(message.id).toBe(message.params.requestId);
    expect(message.params.attribution?.version).toBe(1);
    const participants = assigned(message.params).map((finding) =>
      finding.provenance!.source!.slice("synthetic/".length),
    );
    expect(message.params.attribution).toEqual({
      version: 1,
      beneficiaryObservationIds: participants
        .filter((id) => id !== "neighbor")
        .sort(),
      contextObservationIds: participants
        .filter((id) => id === "neighbor")
        .sort(),
    });
    // An older host can ignore additive metadata and use the original request.
    const { attribution: _attribution, ...legacyRequest } = message.params;
    send({ jsonrpc: "2.0", id: message.id, result: answer(legacyRequest) });
  });
  const deps = dependencies();
  for (const key of Object.keys(deps)) {
    if (typeof deps[key as keyof typeof deps] === "function")
      Object.assign(deps, {
        [key]: throwing(`Unexpected dependency: ${key}`),
      });
  }
  deps.addSignalListener = () => {};
  deps.removeSignalListener = () => {};
  deps.recordsInput = host.stream;
  const stderr = capture(true);
  const done = main(["dedupe", "--records"], host.output, stderr.stream, deps);
  host.send(run);
  expect(await done).toBe(0);
  expect(stderr.text()).toBe("");
  expect(host.messages.at(-1)).toMatchObject({
    jsonrpc: "2.0",
    id: "run-1",
    result: { status: "completed" },
  });
  expect(
    host.messages.filter((message) => message.method === "review.run"),
  ).toHaveLength(6);
  host.stream.destroy();
});

test.each([
  "wrong-id",
  "wrong-type",
  "duplicate",
  "malformed",
  "both",
  "no-result",
  "second-run",
  "unknown-cancel",
  "disconnect",
  "stream-error",
  "cancel",
  "host-error",
])("protocol handles %s without further reviews", async (scenario) => {
  const host = fakeHost((message, send, stream) => {
    if (scenario === "wrong-id")
      send({ jsonrpc: "2.0", id: "wrong", result: answer(message.params) });
    if (scenario === "wrong-type")
      send({ jsonrpc: "2.0", id: 1, result: answer(message.params) });
    if (scenario === "duplicate") {
      send({ jsonrpc: "2.0", id: message.id, result: answer(message.params) });
      send({ jsonrpc: "2.0", id: message.id, result: answer(message.params) });
    }
    if (scenario === "malformed") stream.write("not-json\n");
    if (scenario === "both")
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {},
        error: { code: -1, message: "failed" },
      });
    if (scenario === "no-result") send({ jsonrpc: "2.0", id: message.id });
    if (scenario === "second-run") send(run);
    if (scenario === "unknown-cancel")
      send({ jsonrpc: "2.0", method: "cancel", params: { id: "unknown" } });
    if (scenario === "disconnect") stream.end();
    if (scenario === "stream-error")
      stream.destroy(new Error("Host read failed"));
    if (scenario === "cancel")
      send({ jsonrpc: "2.0", method: "cancel", params: { id: "run-1" } });
    if (scenario === "host-error")
      send({
        jsonrpc: "2.0",
        id: message.id,
        error: {
          code: -32001,
          message: "Inconclusive",
          data: { executionMayHaveBeenAccepted: true },
        },
      });
  });
  const done = runRecordsProtocol(host.stream, host.output);
  host.send(run);
  expect(await done).toBe(scenario === "host-error" ? 1 : 2);
  expect(
    host.messages.filter((message) => message.method === "review.run"),
  ).toHaveLength(1);
  const final = host.messages.at(-1)!;
  expect(final.id).toBe("run-1");
  if (scenario === "host-error")
    expect(final.result).toMatchObject({
      status: "unresolved",
      groups: [],
    });
  else expect(final.error).toBeDefined();
  host.stream.destroy();
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "records mode handles %s and removes handlers",
  async (signal) => {
    const signals = new FakeSignals();
    const host = fakeHost(() => signals.emit(signal));
    const deps = dependencies();
    deps.recordsInput = host.stream;
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    const done = main(
      ["dedupe", "--records"],
      host.output,
      capture().stream,
      deps,
    );
    host.send(run);
    expect(await done).toBe(signal === "SIGINT" ? 130 : 143);
    expect(host.messages.at(-1)?.error?.code).toBe(-32800);
    expect(signals.listeners.get(signal)?.size).toBe(0);
    host.stream.destroy();
  },
);

test("real CLI pipes exit after a fake-host run without local Codex or state writes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "records-cli-"));
  const child = spawn(
    process.execPath,
    [
      fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
      "dedupe",
      "--records",
    ],
    {
      cwd: directory,
      env: {
        ...process.env,
        CODEX_CLI_PATH: join(directory, "no-local-codex"),
        CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        CODEX_HOME: join(directory, "home"),
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const closed = new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  const stderr = capture();
  child.stderr.setEncoding("utf8").on("data", stderr.stream.write);
  child.stdin.on("error", () => {});
  try {
    child.stdin.write(`${JSON.stringify(run)}\n`);
    let final: Message | undefined;
    const reviews: DeduplicationReviewRequest[] = [];
    for await (const line of createInterface({ input: child.stdout })) {
      const message = JSON.parse(line) as Message;
      if (message.method === "review.run") {
        reviews.push(message.params);
        expect(message.jsonrpc).toBe("2.0");
        expect(message.id).toBe(message.params.requestId);
        const participants = assigned(message.params).map((finding) =>
          finding.provenance!.source!.slice("synthetic/".length),
        );
        expect(message.params.attribution).toEqual({
          version: 1,
          beneficiaryObservationIds: participants
            .filter((id) => id !== "neighbor")
            .sort(),
          contextObservationIds: participants
            .filter((id) => id === "neighbor")
            .sort(),
        });
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id: message.id, result: answer(message.params) })}\n`,
        );
      } else final = message;
    }
    expect(
      reviews.filter((review) => review.stage === "screening"),
    ).toHaveLength(4);
    expect(
      reviews.filter((review) => review.stage === "pair-review"),
    ).toHaveLength(2);
    expect(await closed).toBe(0);
    expect(stderr.text()).toBe("");
    expect(final).toMatchObject({
      id: "run-1",
      result: {
        status: "completed",
        groups: expect.arrayContaining([
          {
            representativeObservationId: expect.any(String),
            observationIds: expect.arrayContaining(["c", "neighbor"]),
          },
        ]),
      },
    });
    expect(await readdir(directory)).toEqual([]);
  } finally {
    child.stdin.end();
    if (child.exitCode === null) child.kill();
    await closed;
    await rm(directory, { recursive: true, force: true });
  }
});

test("disconnect before run and a broken output pipe terminate cleanly", async () => {
  const host = fakeHost(() => {});
  const disconnected = runRecordsProtocol(host.stream, host.output);
  host.stream.end();
  expect(await disconnected).toBe(2);
  expect(host.messages).toMatchObject([{ id: null, error: { code: -32000 } }]);
  const input = new PassThrough();
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback(new Error("Broken pipe"));
    },
  });
  const failed = runRecordsProtocol(input, output);
  input.write(`${JSON.stringify(run)}\n`);
  expect(await failed).toBe(2);
  input.destroy();
});

const emptyRecords = {
  version: 1,
  observations: [],
  candidateRelationships: [],
};

test("a disconnect while flushing the final result does not send a second response", async () => {
  const inputStream = new PassThrough();
  const messages: Message[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      messages.push(JSON.parse(chunk.toString()));
      inputStream.end();
      setImmediate(callback);
    },
  });
  const done = runRecordsProtocol(inputStream, output);
  inputStream.write(`${JSON.stringify({ ...run, params: emptyRecords })}\n`);
  expect(await done).toBe(0);
  expect(messages).toMatchObject([
    { id: "run-1", result: { status: "completed" } },
  ]);
  expect(messages).toHaveLength(1);
});

const completed = { result: { status: "completed" } };
for (const trigger of ["signal", "notification"]) {
  test.serial.each([
    ["review request", run.params, { method: "review.run" }],
    ["terminal result", emptyRecords, completed],
    ["terminal result flushed after cancel", emptyRecords, completed],
    ["terminal error", {}, { error: expect.anything() }],
  ] as const)(
    `${trigger} stops a blocked %s`,
    async (stage, params, expected) => {
      const inputStream = new PassThrough();
      const writing = Promise.withResolvers<() => void>();
      const output = new Writable({
        write: (_chunk, _encoding, flush) => writing.resolve(flush),
      });
      const writes = spyOn(output, "write");
      let pendingReview: Promise<unknown> | undefined;
      const dedupe = records.deduplicateRecords;
      const operation =
        stage === "review request"
          ? spyOn(records, "deduplicateRecords").mockImplementationOnce(
              (input, options) =>
                dedupe(input, {
                  ...options,
                  reviewRunner: {
                    run: (...args) =>
                      (pendingReview = options.reviewRunner.run(...args)),
                  },
                }),
            )
          : undefined;
      const controller = new AbortController();
      let finished = false;
      onTestFinished(() => {
        finished = true;
        operation?.mockRestore();
        writes.mockRestore();
        output.destroy();
        inputStream.destroy();
      });
      const done = runRecordsProtocol(inputStream, output, controller.signal);
      inputStream.write(`${JSON.stringify({ ...run, params })}\n`);
      const flush = await writing.promise;
      const signal = operation?.mock.calls[0]?.[1].signal;
      const recordsResult = operation?.mock.results[0]?.value;
      if (trigger === "signal") controller.abort("SIGTERM");
      else
        inputStream.write(
          `${JSON.stringify({ jsonrpc: "2.0", method: "cancel", params: { id: run.id } })}\n`,
        );
      if (stage === "terminal result flushed after cancel") flush();
      const code = await done;
      const settled = signal?.aborted
        ? await Promise.allSettled([pendingReview, recordsResult])
        : [];
      // Destroying the blocked stream can resume a test after it timed out.
      if (finished) return;
      expect(code).toBe(2);
      expect(output.destroyed).toBe(true);
      expect(writes).toHaveBeenCalledTimes(1);
      expect(JSON.parse(writes.mock.calls[0]![0])).toMatchObject(expected);
      if (operation) expect(signal?.aborted).toBe(true);
      for (const result of settled) {
        expect(result).toEqual({
          status: "rejected",
          reason: new Error("Deduplication canceled."),
        });
      }
    },
  );
}

test.each(["screening", "pair-review"] as const)(
  "%s refusal stops further reviews and leaves all records unresolved",
  async (stage) => {
    let refused = false;
    let reviewsAfterRefusal = 0;
    const result = await deduplicateRecords(input(), {
      reviewRunner: {
        async run(review) {
          if (refused) reviewsAfterRefusal++;
          if (review.stage === stage) {
            refused = true;
            throw new DeduplicationReviewError({
              stage,
              model: review.model,
              category: "refusal",
              attempts: 1,
              reason: "Synthetic review refusal.",
            });
          }
          return answer(review);
        },
      },
    });
    expect(refused).toBe(true);
    expect(reviewsAfterRefusal).toBe(0);
    expect(result.status).toBe("unresolved");
    expect(result.groups).toEqual([]);
    expect(result.unresolved.map(({ observationId }) => observationId)).toEqual(
      ["a", "b", "c", "d"],
    );
    expect(
      result.unresolved.every(({ reason }) => reason === "review_failed"),
    ).toBe(true);
  },
);

test("records isolates each host review's finding schema", async () => {
  const data: DeduplicateRecordsInput = {
    version: 1,
    observations: [record("a", "same"), record("b", "same")],
    candidateRelationships: [
      { observationId: "a", candidateObservationIds: ["b"] },
    ],
  };
  const requests: DeduplicationReviewRequest[] = [];
  type FindingSchema = {
    properties: { title: Record<string, unknown> };
  };
  let pristine: FindingSchema | undefined;
  let annotated: Record<string, unknown> | undefined;
  let previous: PropertyDescriptor | undefined;
  try {
    for (let invocation = 0; invocation < 2; invocation++) {
      const result = await deduplicateRecords(data, {
        reviewRunner: {
          async run(review) {
            const schema = review.findingSchema as FindingSchema;
            pristine ??= structuredClone(schema);
            expect(schema).toEqual(pristine);
            requests.push(review);
            if (annotated === undefined) {
              annotated = schema.properties.title;
              previous = Object.getOwnPropertyDescriptor(
                annotated,
                "description",
              );
              annotated["description"] = "Host-local adapter annotation.";
            }
            return answer(review);
          },
        },
      });
      expect(result.status).toBe("completed");
      expect(
        result.groups.map(({ observationIds }) => [...observationIds].sort()),
      ).toEqual([["a", "b"]]);
      expect(result.unresolved).toEqual([]);
    }
    expect(requests.map(({ stage }) => stage)).toEqual([
      "screening",
      "pair-review",
      "screening",
      "pair-review",
    ]);
  } finally {
    if (annotated !== undefined) {
      if (previous) Object.defineProperty(annotated, "description", previous);
      else delete annotated["description"];
    }
  }
});

test.each(["refusal", "cleanup", "decision"])(
  "SDK preserves failure classification and identity: %s",
  async (kind) => {
    const refusal = new DeduplicationReviewError({
      stage: "screening",
      model: "synthetic",
      category: "refusal",
      attempts: 1,
      reason: "Synthetic refusal",
    });
    let expected: Error = refusal;
    if (kind === "cleanup")
      expected = new Error("Cleanup failed", { cause: refusal });
    const runMock = mock(async () => {
      if (kind !== "decision") throw expected;
      return {};
    });
    const failure = await deduplicateRecords(input(), {
      throwReviewErrors: true,
      reviewRunner: { run: runMock },
    }).catch((error: unknown) => error);
    if (kind === "decision") {
      expect(failure).toBeInstanceOf(InvalidDeduplicationDecision);
      expect(failure).toBeInstanceOf(CodexSecurityError);
    } else expect(failure).toBe(expected);
    expect(runMock).toHaveBeenCalledTimes(1);
  },
);

test("SDK validation propagates cancellation even after the runner receives a candidate", async () => {
  const controller = new AbortController();
  const started = Promise.withResolvers<(value: unknown) => void>();
  const finish = Promise.withResolvers<unknown>();
  const reason = new Error("Review deadline expired");
  const done = deduplicateRecords(input(), {
    signal: controller.signal,
    throwReviewErrors: true,
    reviewRunner: {
      run(_request, options) {
        started.resolve(options!.validate!);
        return finish.promise;
      },
    },
  });
  const validate = await started.promise;
  controller.abort(reason);
  await expect(done).rejects.toBe(reason);
  expect(() => validate({})).toThrow(reason);
  finish.resolve({});
  await finish.promise;
  expect(() => validate({})).toThrow(reason);
});

test("Finding feedback identifies the invalid field while legacy failures stay compact", async () => {
  const message =
    "Record must satisfy the Finding schema, including provenance.";
  const result = await deduplicateRecords(input(), {
    reviewRunner: {
      async run(request, options) {
        const value = answer(request) as { mergedFinding?: Finding };
        const finding = value.mergedFinding;
        if (finding) {
          finding.locations[0]!.path = 1 as never;
          throws(() => requireFinding(finding), { message });
          throws(() => validateReview(value, [finding]), { message });
          expect(() => options!.validate!(value)).toThrow("/locations/0/path");
        }
        return value;
      },
    },
  });
  expect(result.status).toBe("unresolved");
  for (const entry of result.unresolved) expect(entry.message).toBe(message);
});

test("repeated invalid entries do not amplify Finding feedback", () => {
  const messages = [1, 2].map((count) => {
    const finding = structuredClone(document.findings[0]!);
    finding.codeEvidence = Array(count).fill({});
    try {
      requireFinding(finding, true);
      throw new Error("Expected invalid finding");
    } catch (error) {
      return (error as Error).message;
    }
  });
  expect(messages[0]).toContain("/codeEvidence/0");
  expect(messages[1]).toBe(messages[0]);
});

test("concurrent SDK invocations retain their starting error policy", async () => {
  const resume = Promise.withResolvers<void>();
  const options = {
    throwReviewErrors: false,
    reviewRunner: {
      async run() {
        await resume.promise;
        return {};
      },
    },
  };
  const legacy = deduplicateRecords(input(), options);
  options.throwReviewErrors = true;
  const typed = deduplicateRecords(input(), options).catch(
    (error: unknown) => error,
  );
  resume.resolve();
  expect((await legacy).status).toBe("unresolved");
  expect(await typed).toBeInstanceOf(InvalidDeduplicationDecision);
});

test.each([
  [false, false],
  [false, true],
  [true, false],
  [true, true],
])(
  "preserves preflight diagnostics (typed: %p, rewritten: %p)",
  async (typed, rewritten) => {
    let failure: Error | undefined;
    const result = await deduplicateRecords(input(), {
      throwReviewErrors: typed,
      reviewRunner: {
        async run(request, options) {
          const candidate = answer(request) as { mergedFinding?: Finding };
          if (!candidate.mergedFinding) return candidate;
          candidate.mergedFinding.title = "";
          try {
            options!.validate!(candidate);
          } catch (error) {
            failure = error as Error;
            if (rewritten) failure.message = "Correction budget exhausted";
            throw error;
          }
          return candidate;
        },
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(InvalidDeduplicationDecision);
    if (typed) expect(result).toBe(failure);
    else {
      const unresolved = (result as { unresolved: Array<{ message: string }> })
        .unresolved;
      expect(unresolved.length).toBeGreaterThan(0);
      for (const entry of unresolved)
        expect(entry.message).toBe(failure!.message);
    }
  },
);

test.each(["valid", "invalid", "adapter error"])(
  "preflight preserves synchronous cancellation (%s)",
  async (kind) => {
    const controller = new AbortController();
    const reason = new Error("Synthetic cancellation");
    const adapterFault = new Error("Synthetic adapter failure");
    let observed: unknown;
    await expect(
      deduplicateRecords(input(), {
        signal: controller.signal,
        reviewRunner: {
          async run(request, options) {
            const candidate = answer(request) as { decisions: unknown };
            try {
              options!.validate!({
                get decisions() {
                  controller.abort(reason);
                  if (kind === "adapter error") throw adapterFault;
                  return kind === "invalid" ? null : candidate.decisions;
                },
              });
            } catch (error) {
              observed = error;
            }
            return candidate;
          },
        },
      }),
    ).rejects.toBe(reason);
    expect(observed).toBe(reason);
  },
);

test.each([false, true])(
  "retained validators close after review (failure: %p)",
  async (fail) => {
    const callbacks: Array<(value: unknown) => void> = [];
    const fault = new Error("Synthetic runner failure");
    await deduplicateRecords(input(), {
      reviewRunner: {
        async run(request, options) {
          callbacks.push(options!.validate!);
          if (fail) throw fault;
          return answer(request);
        },
      },
    });
    expect(callbacks.length).toBeGreaterThan(0);
    for (const validate of callbacks) {
      expect(() => validate({})).toThrow("The review has already ended.");
    }
  },
);

test.each([
  [false, false],
  [false, true],
  [true, false],
  [true, true],
])(
  "settling the runner revokes preflight (signal: %p, rejection: %p)",
  async (withSignal, reject) => {
    const data = input();
    data.observations = data.observations.slice(0, 2);
    data.candidateRelationships = [
      { observationId: "a", candidateObservationIds: ["b"] },
    ];
    const ready = Promise.withResolvers<(value: unknown) => void>();
    const finish = Promise.withResolvers<unknown>();
    const candidate = {
      decisions: {
        "pair-1": { decision: "DISTINCT", rationale: "Synthetic distinction" },
      },
    };
    let finalChecked = false;
    const done = deduplicateRecords(data, {
      signal: withSignal ? new AbortController().signal : undefined,
      reviewRunner: {
        run(_request, options) {
          ready.resolve(options!.validate!);
          return finish.promise;
        },
      },
    });
    const validate = await ready.promise;
    if (reject) finish.reject(new Error("Synthetic runner rejection"));
    else
      finish.resolve({
        get decisions() {
          finalChecked = true;
          expect(() => validate(candidate)).toThrow(
            "The review has already ended.",
          );
          return candidate.decisions;
        },
      });
    const late = Promise.withResolvers<unknown>();
    queueMicrotask(() => {
      try {
        validate(candidate);
        late.resolve(undefined);
      } catch (error) {
        late.resolve(error);
      }
    });
    expect((await done).status).toBe(reject ? "unresolved" : "completed");
    expect(finalChecked).toBe(!reject);
    expect(await late.promise).toBeInstanceOf(Error);
    expect(((await late.promise) as Error).message).toBe(
      "The review has already ended.",
    );
  },
);

test.each([
  ["preflight", "Zod"],
  ["final", "Zod"],
  ["preflight", "import"],
  ["final", "import"],
])("%s preserves adapter %s errors", async (stage, kind) => {
  let fault: unknown = new z.ZodError([]);
  if (kind === "import") {
    try {
      requireFinding({});
    } catch (error) {
      fault = error;
    }
  }
  const candidate = Object.defineProperty({}, "decisions", {
    enumerable: true,
    get() {
      throw fault;
    },
  });
  const result = await deduplicateRecords(input(), {
    throwReviewErrors: true,
    reviewRunner: {
      async run(_request, options) {
        if (stage === "preflight") options!.validate!(candidate);
        return candidate;
      },
    },
  }).catch((error: unknown) => error);
  expect(result).toBe(fault);
});

test.each([false, true])(
  "preflight permits correction without changing final acceptance (throw errors: %p)",
  async (typed) => {
    let calls = 0;
    let preflights = 0;
    const result = await deduplicateRecords(input(), {
      throwReviewErrors: typed,
      reviewRunner: {
        async run(request, options) {
          calls++;
          expect(structuredClone(options)).toEqual({ signal: undefined });
          expect(() => options!.validate!({})).toThrow(
            InvalidDeduplicationDecision,
          );
          const value = answer(request);
          // Existing pair normalization strips extra fields in both error modes.
          const candidate =
            request.stage === "pair-review"
              ? { ...(value as object), extra: true }
              : value;
          expect(options!.validate!(candidate)).toBeUndefined();
          preflights++;
          return candidate;
        },
      },
    });
    expect(result.status).toBe("completed");
    expect(
      result.groups.map((group) => [...group.observationIds].sort()),
    ).toEqual([["a", "b"], ["c", "neighbor"], ["d"]]);
    expect(calls).toBe(6);
    expect(preflights).toBe(calls);
  },
);

test.each([false, true])(
  "final validation rejects an answer changed after preflight (throw errors: %p)",
  async (typed) => {
    const result = await deduplicateRecords(input(), {
      throwReviewErrors: typed,
      reviewRunner: {
        async run(request, options) {
          const candidate = answer(request) as { mergedFinding?: Finding };
          options!.validate!(candidate);
          if (candidate.mergedFinding) candidate.mergedFinding.title = "";
          return candidate;
        },
      },
    }).catch((error: unknown) => error);
    if (typed) {
      expect(result).toBeInstanceOf(InvalidDeduplicationDecision);
      expect((result as Error).message).toContain("/title");
    } else {
      expect(result).toMatchObject({ status: "unresolved", groups: [] });
    }
  },
);

test("Finding feedback reuses its validator after failures and exceptions", () => {
  const valid = document.findings[0]!;
  requireFinding(valid);
  const compile = spyOn(Ajv2020.prototype, "compile");
  try {
    const invalid = { ...valid, title: 1 };
    expect(() => requireFinding(invalid, true)).toThrow("/title");
    const fault = new Error("Synthetic adapter failure");
    const throwing = {
      ...valid,
      get title(): string {
        throw fault;
      },
    };
    throws(
      () => requireFinding(throwing, true),
      (error) => error === fault,
    );
    expect(requireFinding(valid, true)).toBe(valid);
    expect(requireFinding(valid)).toBe(valid);
    expect(compile).not.toHaveBeenCalled();
  } finally {
    compile.mockRestore();
  }
});

test("review-scoped provider getters retain their existing lifecycle", async () => {
  let providers = 0;
  const result = await deduplicateRecords(input(), {
    get reviewRunner() {
      providers++;
      let closed = false;
      return {
        async run(request: DeduplicationReviewRequest) {
          if (closed) throw new Error("Synthetic provider already closed");
          closed = true;
          return answer(request);
        },
      };
    },
  });
  expect(result.status).toBe("completed");
  expect(providers).toBe(6);
});
