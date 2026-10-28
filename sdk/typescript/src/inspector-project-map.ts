import { lstat, realpath } from "node:fs/promises";
import { relative } from "node:path";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { validateInspectorProjectMapping } from "./inspector-findings.js";
import { readRegularInputBytes } from "./prompt-files.js";
import { isRecord } from "./record.js";
import { gitProtectionRoots, relativePathIsOutside } from "./targets.js";

/** Read an operator mapping independently of the report and local checkout. */
export async function readInspectorProjectMap(
  path: string,
  report: string,
  localRepository: string | undefined,
  signal: AbortSignal,
): Promise<ReadonlyMap<string, string>> {
  const metadata = await lstat(path, { bigint: true });
  const roots = await gitProtectionRoots(report, signal);
  if (localRepository)
    roots.push(
      await realpath(localRepository),
      ...(await gitProtectionRoots(localRepository, signal)),
    );
  const canonical = await realpath(path);
  if (roots.some((root) => !relativePathIsOutside(relative(root, canonical)))) {
    throw new CodexSecurityError(
      "--inspector-project-map must be outside the selected repository and any checkout containing the repository or report.",
    );
  }
  const bytes = await readRegularInputBytes(path, roots, metadata);
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new CodexSecurityError(
      `--inspector-project-map requires UTF-8 JSON. ${errorMessage(error)}`,
      { cause: error },
    );
  }
  if (!isRecord(data) || Object.keys(data).length === 0) {
    throw new CodexSecurityError(
      "--inspector-project-map requires a nonempty JSON object mapping full project ARNs to canonical repository URLs.",
    );
  }
  return new Map(
    Object.entries(data).map(([arn, url]) => [
      arn,
      validateInspectorProjectMapping(arn, url),
    ]),
  );
}
