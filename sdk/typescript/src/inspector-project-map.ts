import { isUtf8 } from "node:buffer";
import { lstat, readlink, realpath, stat } from "node:fs/promises";
import { format, isAbsolute, join, parse, relative, sep } from "node:path";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { validateInspectorProjectMapping } from "./inspector-findings.js";
import { parentDirectory } from "./windows-path.js";
import { bareMetadataRoots } from "./external-findings-local.js";
import { readRegularInputBytes } from "./prompt-files.js";
import { isRecord } from "./record.js";
import {
  gitMarkerRoot,
  nullIfMissingPath,
  relativePathIsOutside,
} from "./targets.js";

// A directory link can enter a checkout below its root, and a second link can
// leave it before the final report or map is reached.
async function directoriesAlongPath(input: string, signal: AbortSignal) {
  const paths = new Map([[input, input]]);
  const directories = new Set<string>();
  const visited = new Set<string>();
  for (const [path, link] of paths) {
    const metadata = await lstat(path).catch(nullIfMissingPath);
    if (!metadata) {
      // Open file descriptors can name an anonymous pipe or a deleted file.
      await stat(link);
      paths.set(parentDirectory(path), link);
      continue;
    }
    directories.add(
      await realpath(metadata.isDirectory() ? path : parentDirectory(path)),
    );
    for (
      let ancestor = path;
      !visited.has(ancestor);
      ancestor = parentDirectory(ancestor)
    ) {
      visited.add(ancestor);
      // A trailing separator makes lstat follow the link. Keep ".." intact.
      const entry = format(parse(ancestor));
      signal.throwIfAborted();
      if (!(await lstat(entry)).isSymbolicLink()) continue;
      const parent = await realpath(parentDirectory(entry));
      directories.add(parent);
      const bytes = await readlink(entry, { encoding: "buffer" });
      if (!isUtf8(bytes))
        throw new CodexSecurityError(
          "Inspector project-map discovery requires UTF-8 symlink targets.",
        );
      const target = bytes.toString("utf8");
      if (sep === "\\" && !isAbsolute(target)) {
        // Win32 cancels parent components when substituting a relative link.
        paths.set(join(parent, target), entry);
        continue;
      }
      const raw = isAbsolute(target) ? target : `${parent}${sep}${target}`;
      const root = parse(raw).root;
      const components = raw
        .slice(root.length)
        .split(sep === "/" ? "/" : /[\\/]/u);
      let physical = root;
      for (const component of components) {
        if (component === "..") {
          // Keep the traversed checkout before resolving its physical parent.
          paths.set(physical, entry);
          physical = parentDirectory(await realpath(physical));
        } else {
          physical = join(physical, component);
        }
      }
      paths.set(physical, entry);
    }
  }
  return directories;
}

/** Read an operator mapping independently of the report and local checkout. */
export async function readInspectorProjectMap(
  path: string,
  report: string,
  localRepository: string | undefined,
  signal: AbortSignal,
): Promise<ReadonlyMap<string, string>> {
  const metadata = await lstat(path, { bigint: true });
  const mapDirectories = await directoriesAlongPath(path, signal);
  if (localRepository === undefined) {
    for (const directory of mapDirectories) {
      if (
        (await gitMarkerRoot(directory, signal, "outermost")) !== null ||
        (await bareMetadataRoots(directory, signal, true)).length > 0
      )
        throw new CodexSecurityError(
          "--inspector-project-map for Cloud must be outside all Git checkouts and recognizable Git metadata directories.",
        );
    }
  }
  const protectedRoots = new Set<string>();
  if (localRepository !== undefined)
    protectedRoots.add(await realpath(localRepository));
  for (const source of localRepository === undefined
    ? [report]
    : [report, localRepository]) {
    for (const directory of await directoriesAlongPath(source, signal)) {
      const checkout = await gitMarkerRoot(directory, signal, "outermost");
      if (checkout !== null) protectedRoots.add(checkout);
    }
  }
  const roots = [...protectedRoots];
  if (roots.length) {
    for (const directory of mapDirectories)
      if (
        roots.some((root) => !relativePathIsOutside(relative(root, directory)))
      )
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
