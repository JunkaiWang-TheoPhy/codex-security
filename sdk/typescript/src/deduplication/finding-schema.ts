import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import { SchemaEnv } from "ajv/dist/compile/index.js";
import type { Finding } from "../models.js";
import { InvalidDeduplicationDecision } from "./decision-error.js";
export class InvalidFindingError extends Error {
  readonly legacyMessage =
    "Record must satisfy the Finding schema, including provenance.";
}

let schema: object | undefined;
let validator: ValidateFunction<Finding> | undefined;

function clearValidationErrors(validator: ValidateFunction): void {
  const pending = [validator.schemaEnv];
  const visited = new Set<SchemaEnv>();
  while (pending.length) {
    const env = pending.pop()!;
    if (visited.has(env)) continue;
    visited.add(env);
    if (env.validate) env.validate.errors = null;
    pending.push(env.root);
    for (const ref of Object.values(env.refs)) {
      if (ref instanceof SchemaEnv) pending.push(ref);
    }
  }
}

export function findingSchema(): object {
  if (schema) return schema;
  const document = JSON.parse(
    readFileSync(
      new URL(
        "../../_bundled_plugin/schemas/findings.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  return (schema = {
    ...document.properties.findings.items,
    $defs: document.$defs,
  });
}

export function requireFinding(
  value: unknown,
  detailedErrors = false,
  failureKind: "record" | "decision" = "record",
): Finding {
  validator ??= new Ajv2020({ strict: false }).compile<Finding>(
    findingSchema(),
  );
  let valid = false;
  try {
    if (!validator(value)) {
      const failure = new InvalidFindingError(
        "Record must satisfy the Finding schema, including provenance." +
          (detailedErrors
            ? " " +
              (validator.errors ?? [])
                .map(
                  ({ instancePath, message }) =>
                    `${instancePath || "/"}: ${message ?? "invalid value"}`,
                )
                .join("; ")
            : ""),
      );
      if (failureKind === "decision")
        throw new InvalidDeduplicationDecision(failure.message, {
          cause: failure,
        });
      throw failure;
    }
    valid = true;
    return value;
  } finally {
    // Compiled $ref validators retain their own error arrays.
    if (!valid) clearValidationErrors(validator);
  }
}
