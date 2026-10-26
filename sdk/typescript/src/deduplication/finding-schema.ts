import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "../models.js";
import { InvalidDeduplicationDecision } from "../errors.js";
let schema: object | undefined;
let validator: ValidateFunction<Finding> | undefined;

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
  if (!validator(value)) {
    const failure = new Error(
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
  return value;
}
