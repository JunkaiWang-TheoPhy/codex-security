import { join } from "node:path";
import { writeJsonAtomic } from "../deep-scan/artifacts";
import { loadScopes, scopedSourceFiles } from "./generate-inventory";
import { environmentValue, readFile, resolvedPathText } from "./helper-files";
import { append, exists } from "./inventory-paths";

interface Rule {
  path?: string;
  content?: string;
}

interface Queue {
  rules: Rule[];
  batches: string[][];
  reviewed: string[];
}

const readJson = (file: string) => JSON.parse(readFile(file).toString("utf8"));

export function remainingPaths(queue: Queue): string[] {
  const reviewed = new Set(queue.reviewed);
  return queue.batches.flat().filter((path) => !reviewed.has(path));
}

export function requireEmptyQueue(queue: Queue) {
  const remaining = remainingPaths(queue);
  if (remaining.length)
    throw new Error(
      `${remaining.length} Standard target files still need review. Resume with standard-queue pending.`,
    );
}

export async function standardQueue(args: string[], home?: string) {
  const [command, scanDir, ...values] = args;
  if (!scanDir)
    throw new Error(
      "Expected standard-queue <build|pending|reviewed|check> <scan_dir> [arguments]",
    );
  const context = join(scanDir, "artifacts", "01_context");
  const file = join(context, "standard-queue.json");
  let queue: Queue;
  if (command === "build") {
    if (exists(file))
      throw new Error("Queue already built. Use pending to resume.");
    const [root, ...requested] = values;
    const repo = resolvedPathText(root);
    const scopeFile = environmentValue("CODEX_SECURITY_TARGET_PATHS_FILE");
    const scopes = scopeFile ? loadScopes(scopeFile) : requested;
    if (!scopes.length)
      throw new Error(
        "Supply the registered scopes, or . for a whole repository.",
      );
    const rules: Rule[] = readJson(join(context, "standard-rules.json"));
    if (!Array.isArray(rules) || !rules.length)
      throw new Error("Expected a nonempty array of search rules.");
    const matchers = rules.map(({ path, content }) => {
      if (!path && !content)
        throw new Error("Each search rule needs a path or content pattern.");
      return {
        path: path && new RegExp(path, "u"),
        content: content && new RegExp(content, "mu"),
      };
    });
    const matches = new Set<string>();
    for await (const { name, explicit } of scopedSourceFiles(
      repo,
      scopes,
      home,
    )) {
      if (explicit) matches.add(name);
      if (matches.has(name)) continue;
      let source: string | undefined;
      for (const rule of matchers) {
        if (rule.path && !rule.path.test(name)) continue;
        if (rule.content) {
          source ??= readFile(append(repo, name)).toString("utf8");
          if (!rule.content.test(source)) continue;
        }
        matches.add(name);
        break;
      }
    }
    const paths = [...matches].sort();
    queue = { rules, batches: [], reviewed: [] };
    for (let i = 0; i < paths.length; i += 5)
      queue.batches.push(paths.slice(i, i + 5));
    await writeJsonAtomic(file, queue);
  } else {
    queue = readJson(file);
  }
  const paths = new Set(queue.batches.flat());
  const reviewed = new Set(queue.reviewed);
  if (command === "reviewed") {
    for (const path of values) {
      if (!paths.has(path))
        throw new Error(`File is outside the queue: ${path}`);
      reviewed.add(path);
    }
    queue.reviewed = [...reviewed].sort();
    await writeJsonAtomic(file, queue);
  } else if (!["build", "pending", "check"].includes(command)) {
    throw new Error(`Unknown queue operation: ${command}`);
  }
  const remaining = remainingPaths(queue).length;
  if (command === "check") requireEmptyQueue(queue);
  const summary = {
    files: paths.size,
    batches: queue.batches.length,
    reviewed: reviewed.size,
    remaining,
  };
  if (command !== "pending") return summary;
  const after = Number(values[0] ?? 0);
  const limit = Number(values[1] ?? 1);
  const batches = queue.batches
    .map((batch, i) => ({
      id: i + 1,
      files: batch.filter((path) => !reviewed.has(path)),
    }))
    .filter((batch) => batch.id > after && batch.files.length)
    .slice(0, limit);
  return { ...summary, pending: batches };
}
