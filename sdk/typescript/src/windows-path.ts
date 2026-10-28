import { dirname, parse, win32 } from "node:path";

/** Node's namespaced UNC root stops at "UNC", before the server and share. */
export function windowsParentDirectory(path: string): string {
  if (
    /^[/\\]{2}[?.][/\\]UNC[/\\]/iu.test(path) &&
    !win32.parse(`\\\\${path.slice(8)}`).base
  )
    return path;
  return win32.dirname(path);
}

export const parentDirectory =
  process.platform === "win32" ? windowsParentDirectory : dirname;

const UNSAFE_COMPONENT = /[<>:"|?*\u0000-\u001f]|[ .]$/u;
const RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;

export function isWindowsUnsafePathComponent(value: string): boolean {
  return (
    value !== "" &&
    value !== "." &&
    (UNSAFE_COMPONENT.test(value) || RESERVED_COMPONENT.test(value))
  );
}

export function windowsUnsafePathComponent(path: string): string | undefined {
  return path
    .slice(parse(path).root.length)
    .split(/[\\/]/u)
    .find(isWindowsUnsafePathComponent);
}
