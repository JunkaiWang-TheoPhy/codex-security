export interface GitRemote {
  url: URL;
  /** Repository path without a URL's leading slash; SCP paths remain literal. */
  path: string;
  scpStyle: boolean;
}

// Git treats a colon followed by "//" as the start of a URL transport.
const scpRemote = /^(?:([^@/:\s?#]+)@)?(\[[^\]]+\]|[^@/:\s?#]+):(?!\/\/)(.+)$/u;

const sshRemote = /^(?:ssh|git\+ssh|ssh\+git):\/\/([^/]+?)(?:\/|%2[fF])/u;

/** A native file URL or an unambiguous local path. */
export function isLocalGitRemote(remote: string): boolean {
  if (remote.includes("://")) return remote.startsWith("file://");
  const colon = remote.indexOf(":");
  return colon < 0 || remote.slice(0, colon).includes("/");
}

export function isWindowsGitDrive(remote: string): boolean {
  // Git for Windows accepts one character or up to four consecutive non-ASCII bytes before a drive colon.
  return (
    process.platform === "win32" &&
    !remote.includes("://") &&
    /^(?:.|[\u0080-\u07ff]{2}):(?!:)/su.test(remote)
  );
}

function parseScpRemote(remote: string): RegExpExecArray | null {
  return !isLocalGitRemote(remote) &&
    !remote.includes("://") &&
    !/^[a-z\d][a-z\d+.-]*::/iu.test(remote)
    ? scpRemote.exec(remote)
    : null;
}

/** Identify retained SSH selectors without requiring the hostname to be a web URL. */
export function isGitSshRemote(remote: string): boolean {
  return sshRemote.test(remote) || parseScpRemote(remote) !== null;
}

function sshAuthority(host: string): URL | null {
  if (/[\/\\?#@\s\x00-\x1f\x7f]/u.test(host)) return null;
  // Git passes a leading plus on decimal ports through to OpenSSH.
  const parse = (authority: string) =>
    URL.parse("ssh://" + authority.replace(/:\+(\d+)$/u, ":$1"));
  const parsed = parse(host);
  if (parsed) return parsed;
  // Git accepts brackets around DNS names, with an SSH port inside or after the brackets.
  const bracketed = /^\[([^\]]+)\](?::(\+?\d*))?$/u.exec(host);
  // An empty port outside the brackets is ignored, but an inner trailing colon is a hostname byte.
  if (!bracketed || bracketed[1]!.endsWith(":")) return null;
  const [, name, port] = bracketed;
  return parse(name + (port ? `:${port}` : ""));
}

/** Parse transport syntax only; callers decide which hosts and credentials are allowed. */
export function parseGitRemote(remote: string): GitRemote | undefined {
  if (remote.includes("://")) {
    const url = new URL(remote);
    return {
      url,
      path: url.pathname.slice(1),
      scpStyle: false,
    };
  }
  const scp = parseScpRemote(remote);
  if (!scp) return undefined;
  const url = sshAuthority(scp[2]!);
  if (!url?.hostname) throw new TypeError("Invalid Git SCP authority.");
  if (scp[1]) url.username = scp[1];
  return {
    url,
    // An SCP path's ?, #, and dot segments are literal Git path characters.
    path: scp[3]!,
    scpStyle: true,
  };
}

/** Git decodes URI escapes once except for NUL, and sends SCP bytes literally. */
export function gitTransportBytes(raw: string, scpStyle: boolean): string {
  const bytes = Buffer.from(raw).toString("latin1");
  return scpStyle
    ? bytes
    : bytes.replace(/%(?!00)([\da-f]{2})/giu, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
}

/** Decode only URI escapes whose ASCII bytes cannot introduce a delimiter. */
export function decodeUnreserved(value: string): string {
  return value.replace(/%([0-9a-f]{2})/giu, (escape, hex: string) => {
    const byte = String.fromCharCode(parseInt(hex, 16));
    return /^[a-z0-9._~-]$/iu.test(byte) ? byte : escape.toUpperCase();
  });
}

/** Represent upload-pack path bytes relative to an HTTP repository origin. */
export function gitPathToHttpPath(bytes: string): string {
  return bytes
    .replace(/^\//u, "")
    .replace(
      /[%\x00-\x20\x7f-\xff]/gu,
      (byte) =>
        "%" + byte.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"),
    );
}

/** Ignore the optional DNS root dot for provider classification only. */
export function gitServiceHostname(hostname: string): string {
  return hostname.replace(/\.$/u, "");
}

export function isGitHubCloudHost(host: string): boolean {
  return host === "github.com" || host.endsWith(".ghe.com");
}

export function isPublicGitHost(host: string): boolean {
  return (
    isGitHubCloudHost(host) || host === "gitlab.com" || host === "bitbucket.org"
  );
}

/** Public Git service hosts whose HTTPS repository identity is known. */
export function isKnownGitHost(host: string): boolean {
  return (
    isPublicGitHost(host) ||
    host === "dev.azure.com" ||
    /^[a-z\d-]+\.visualstudio\.com$/u.test(host)
  );
}

/** Public SSH-over-443 authorities and their HTTPS repository hosts. */
function publicGitSsh443Host(authority: string): string | undefined {
  switch (authority) {
    case "ssh.github.com:443":
      return "github.com";
    case "altssh.gitlab.com:443":
      return "gitlab.com";
    case "altssh.bitbucket.org:443":
      return "bitbucket.org";
  }
}

function matchesHttpsHost(url: string | undefined, hostname: string): boolean {
  const source = url && URL.parse(url);
  return (
    !!source &&
    source.protocol === "https:" &&
    source.hostname.toLowerCase() === hostname
  );
}

/** Standard public SSH aliases, plus a GitHub host established by the caller. */
export function normalizeHostedGitRepositoryUrl(
  remote: string,
  source: string | undefined,
  github: boolean,
): string {
  // A projected single-project report may retain only its SSH spelling.
  return normalizeGitSshAlias(
    remote,
    (host) =>
      (github || isPublicGitHost(host)) &&
      matchesHttpsHost(source ?? `https://${host}`, host),
  );
}

export function normalizeGitRepositoryUrl(
  repository: string,
  sshAliasUrl?: string,
): string {
  return normalizeGitSshAlias(repository, (host) =>
    matchesHttpsHost(sshAliasUrl, host),
  );
}

function normalizeGitSshAlias(
  repository: string,
  isAliasHost: (host: string) => boolean,
): string {
  const isGitSshUser = (username: string, hostname: string) =>
    (username === "git" && hostname === "github.com") ||
    (isAliasHost(hostname) &&
      (username === "git" ||
        username === /^([^.]+)\.ghe\.com$/u.exec(hostname)?.[1]));
  const hostedAlias = (
    url: URL,
    user: string,
    path: string,
    scpStyle: boolean,
  ) => {
    const hostname = url.hostname.toLowerCase();
    const standard =
      isGitSshUser(user, hostname) && (url.port === "" || url.port === "22");
    const alternate =
      user === "git" && publicGitSsh443Host(url.host.toLowerCase());
    if (!standard && !alternate) return repository;
    const bytes = gitTransportBytes(path, scpStyle);
    if (/[?#\\]/u.test(bytes) || /(?:^|\/)\.{1,2}(?:\/|$)/u.test(bytes))
      return repository;
    return `https://${alternate || hostname}/${gitPathToHttpPath(bytes)}`;
  };
  const scp = parseScpRemote(repository);
  if (scp) {
    if (!scp[1]) return repository;
    const authority = sshAuthority(scp[2]!);
    return authority
      ? hostedAlias(authority, scp[1], scp[3]!, true)
      : repository;
  }
  // Git separates the decoded authority from the path at the first slash.
  const ssh = sshRemote.exec(repository);
  if (ssh && !/[\t\r\n]/u.test(repository)) {
    const authority = gitTransportBytes(ssh[1]!, false);
    const login = /^([^@:]+)@([^@]+)$/u.exec(authority);
    if (!login || /[/\\%?#\s]/u.test(authority)) return repository;
    const url = sshAuthority(login[2]!);
    if (url)
      return hostedAlias(
        url,
        login[1]!,
        "/" + repository.slice(ssh[0].length),
        false,
      );
  }
  return repository;
}
