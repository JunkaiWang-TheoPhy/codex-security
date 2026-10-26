import { createHash } from "node:crypto";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import {
  bundledSeverityRubric,
  getDefaultSeverityRubric,
  severityRubricSchema,
} from "../src/severity-rubric.js";

const key = createHash("sha256")
  .update("codex_security_default_severity_rubric")
  .digest("base64");

afterEach(() => mock.restore());

function response(value: unknown, hash = "sha256") {
  return Response.json({
    hash_used: hash,
    dynamic_configs: { [key]: { value } },
  });
}

test("resolves the shared config without account credentials and refreshes each operation", async () => {
  const config = {
    markdown: "# Policy\nUse the supplied evidence.\n",
    revision: 8,
  };
  const request = spyOn(globalThis, "fetch").mockResolvedValue(
    response(config),
  );
  const first = await getDefaultSeverityRubric();
  expect(first).toEqual({
    ...config,
    sha256: createHash("sha256").update(config.markdown).digest("hex"),
  });
  const [url, init] = request.mock.calls[0]!;
  expect(url).toBe("https://ab.chatgpt.com/v1/initialize");
  expect(init?.headers).not.toHaveProperty("Authorization");
  expect(JSON.parse(init!.body as string)).toEqual({
    user: {},
    hashAlgorithm: "sha256",
    statsigMetadata: { sdkType: "js-client", sdkVersion: "0.0.0" },
  });
  expect(init?.redirect).toBe("error");
  request.mockResolvedValue(response({ ...config, revision: 9 }));
  expect((await getDefaultSeverityRubric()).revision).toBe(9);
  expect(first.revision).toBe(8);
});

test.each([
  null,
  {},
  { markdown: "", revision: 1 },
  { markdown: " \n", revision: 1 },
  { markdown: false, revision: 1 },
  { markdown: "Policy\0", revision: 1 },
  { markdown: "Policy\ud800", revision: 1 },
  { markdown: "Policy", revision: 0 },
  { markdown: "Policy", revision: 1.5 },
  { markdown: "Policy", revision: Number.MAX_SAFE_INTEGER + 1 },
  { markdown: "Policy", revision: "1" },
  { markdown: "Policy", revision: 1, extra: true },
])("invalid config %j uses the bundled SDK policy", async (config) => {
  spyOn(globalThis, "fetch").mockResolvedValue(response(config));
  expect(await getDefaultSeverityRubric()).toEqual(bundledSeverityRubric);
});

test("oversized UTF-8 Markdown uses the bundled policy", async () => {
  spyOn(globalThis, "fetch").mockResolvedValue(
    response({ markdown: "😀".repeat(196_608 / 4 + 1), revision: 1 }),
  );
  expect(await getDefaultSeverityRubric()).toEqual(bundledSeverityRubric);
});

test.each(["missing", "wrong-hash", "json", "http", "network", "timeout"])(
  "%s runtime failure preserves the bundled default",
  async (scenario) => {
    const request = spyOn(globalThis, "fetch");
    if (scenario === "missing")
      request.mockResolvedValue(
        Response.json({ hash_used: "sha256", dynamic_configs: {} }),
      );
    if (scenario === "wrong-hash")
      request.mockResolvedValue(
        response({ markdown: "Policy", revision: 1 }, "djb2"),
      );
    if (scenario === "json")
      request.mockResolvedValue(new Response("not JSON"));
    if (scenario === "http")
      request.mockResolvedValue(new Response("Unavailable", { status: 503 }));
    if (scenario === "network")
      request.mockRejectedValue(new TypeError("Offline"));
    if (scenario === "timeout") {
      const timeout = AbortSignal.abort(
        new DOMException("Timed out", "TimeoutError"),
      );
      spyOn(AbortSignal, "timeout").mockReturnValue(timeout);
      request.mockRejectedValue(timeout.reason);
    }
    expect(await getDefaultSeverityRubric()).toEqual(bundledSeverityRubric);
  },
);

test("caller cancellation rejects instead of silently selecting a fallback", async () => {
  const controller = new AbortController();
  const reason = new Error("Owner canceled");
  spyOn(globalThis, "fetch").mockRejectedValue(reason);
  queueMicrotask(() => controller.abort(reason));
  await expect(getDefaultSeverityRubric(controller.signal)).rejects.toBe(
    reason,
  );
});

test("explicit snapshots require the exact Markdown hash", () => {
  expect(severityRubricSchema.parse(bundledSeverityRubric)).toEqual(
    bundledSeverityRubric,
  );
  expect(() =>
    severityRubricSchema.parse({
      ...bundledSeverityRubric,
      markdown: "changed",
    }),
  ).toThrow("SHA-256");
});
