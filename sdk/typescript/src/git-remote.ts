export interface GitRemote {
  url: URL;
  /** Repository path without a URL's leading slash; SCP paths remain literal. */
  path: string;
  scpStyle: boolean;
}

// Git treats a colon followed by "//" as the start of a URL transport.
const scpRemote = /^(?:([^@/:\s?#]+)@)?(\[[^\]]+\]|[^@/:\s?#]+):(?!\/\/)(.+)$/u;

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
  const scp = scpRemote.exec(remote);
  if (scp === null) return undefined;
  return {
    url: new URL(`ssh://${scp[1] ? `${scp[1]}@` : ""}${scp[2]}`),
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

/** Git decodes the port separator before checking the port number. */
function decodeGitSshAuthority(value: string): string {
  return decodeUnreserved(value).replace(/%3A(?=\d+$)/u, ":");
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
export function publicGitSsh443Host(authority: string): string | undefined {
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
  const httpsAlias = (host: string, rawPath: string, scpStyle: boolean) => {
    const bytes = gitTransportBytes(rawPath, scpStyle);
    if (/[?#\\]/u.test(bytes) || /(?:^|\/)\.{1,2}(?:\/|$)/u.test(bytes))
      return repository;
    return `https://${host}/${gitPathToHttpPath(bytes)}`;
  };
  const scp = scpRemote.exec(repository);
  if (scp?.[1] && isGitSshUser(scp[1], scp[2]!.toLowerCase()))
    return httpsAlias(scp[2]!, scp[3]!, true);
  // Git decodes the authority and passes '?' and '#' to SSH as hostname bytes.
  const ssh =
    /^(?:ssh|git\+ssh|ssh\+git):\/\/([^/@?#]+)@([^/@?#]+)(\/.*)$/u.exec(
      repository,
    );
  if (ssh && !/[\t\r\n]/u.test(repository)) {
    const user = decodeUnreserved(ssh[1]!);
    const authority = decodeGitSshAuthority(ssh[2]!);
    // Other reserved escapes can change where Git separates the host, port and path.
    if (authority.includes("%")) return repository;
    const url = URL.parse(`ssh://${authority}/`);
    if (!url) return repository;
    const hostname = url.hostname.toLowerCase();
    const standardSsh =
      isGitSshUser(user, hostname) && (url.port === "" || url.port === "22");
    const alternate =
      user === "git" && publicGitSsh443Host(url.host.toLowerCase());
    if (alternate || standardSsh)
      return httpsAlias(alternate || hostname, ssh[3]!, false);
  }
  return repository;
}
