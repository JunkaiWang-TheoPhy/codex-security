import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import type { BulkScanPrompt } from "./bulk-scan-discovery.js";
import {
  OutputDirectoryError,
  OutputDirectoryPermissionsError,
} from "./errors.js";
import {
  requireModelSafeOutputDir,
  requireOutputOutsideRepository,
  requirePrivateOutputDirectory,
  requireSecureOutputAncestry,
  validateOutputDir,
} from "./runtime.js";
import {
  abortable,
  enclosingGitWorktreeRoot,
  normalizeRepository,
} from "./targets.js";

export async function promptForPrivateScanOutput(
  options: {
    repository: string;
    outputDir?: string;
    archiveExisting?: boolean;
    signal: AbortSignal;
  },
  prompt: Pick<BulkScanPrompt, "isInteractive" | "confirm">,
): Promise<void> {
  if (
    process.platform === "win32" ||
    options.outputDir === undefined ||
    !prompt.isInteractive()
  )
    return;

  try {
    await validateOutputDir(options.outputDir, options.archiveExisting);
  } catch (error) {
    if (!(error instanceof OutputDirectoryPermissionsError)) throw error;
    const directory = error.directory;
    const metadata = await lstat(directory);
    if (!metadata.isDirectory()) throw error;
    // Check ownership without the permission bits that the prompt will repair.
    requirePrivateOutputDirectory(
      { uid: metadata.uid, mode: 0o700 },
      directory,
    );
    const canonical = await realpath(directory);
    requireModelSafeOutputDir(canonical);
    await requireSecureOutputAncestry(canonical);
    const repository = await normalizeRepository(
      options.repository,
      options.signal,
    );
    requireOutputOutsideRepository(
      (await enclosingGitWorktreeRoot(repository, options.signal)) ??
        repository,
      canonical,
    );
    options.signal.throwIfAborted();
    const accepted = await abortable(
      () =>
        prompt.confirm(
          `Make scan output directory private (chmod 700) and continue? ${directory}`,
          false,
          options.signal,
        ),
      options.signal,
    );
    options.signal.throwIfAborted();
    if (!accepted) throw error;

    try {
      // Do not follow a directory link substituted while the prompt was open.
      const handle = await open(
        directory,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const current = await handle.stat();
        if (!current.isDirectory()) throw error;
        requirePrivateOutputDirectory(
          { uid: current.uid, mode: 0o700 },
          directory,
        );
        await handle.chmod(0o700);
      } finally {
        await handle.close();
      }
    } catch (cause) {
      throw new OutputDirectoryError(
        `Unable to make scan output directory private (chmod 700): ${directory}. ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
    await validateOutputDir(directory, options.archiveExisting);
  }
}
