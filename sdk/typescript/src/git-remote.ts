export interface GitRemote {
  url: URL;
  /** Repository path without a URL's leading slash; SCP paths remain literal. */
  path: string;
  scpStyle: boolean;
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
  const scp = /^((?:[^@/:\s?#]+@)?(?:\[[^\]]+\]|[^@/:\s?#]+)):(.+)$/u.exec(
    remote,
  );
  if (scp === null) return undefined;
  return {
    url: new URL(`ssh://${scp[1]}`),
    // An SCP path's ?, #, and dot segments are literal Git path characters.
    path: scp[2]!,
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

/** Standard public SSH clone aliases, plus a GitHub host established by the caller. */
export function normalizeHostedGitRepositoryUrl(
  remote: string,
  source: string,
  github: boolean,
): string {
  const host = URL.parse(source)?.hostname ?? "";
  return normalizeGitRepositoryUrl(
    remote,
    github || isPublicGitHost(host) ? source : undefined,
    github || isGitHubCloudHost(host),
  );
}

export function normalizeGitRepositoryUrl(
  repository: string,
  sshAliasUrl?: string,
  githubPath = true,
): string {
  // The caller identifies a host whose standard Git SSH login maps to HTTPS.
  const destination = sshAliasUrl ? URL.parse(sshAliasUrl) : undefined;
  const connectedHost =
    destination?.protocol === "https:"
      ? destination.hostname.toLowerCase()
      : undefined;
  const connectedTenant = /^([^.]+)\.ghe\.com$/u.exec(connectedHost ?? "")?.[1];
  const isGitSshUser = (username: string, hostname: string) =>
    (username === "git" &&
      (hostname === "github.com" || hostname === connectedHost)) ||
    (username === connectedTenant && hostname === connectedHost);
  const httpsAlias = (host: string, rawPath: string, scpStyle: boolean) => {
    const bytes = gitTransportBytes(rawPath, scpStyle);
    if (/[?#\\]/u.test(bytes) || /(?:^|\/)\.{1,2}(?:\/|$)/u.test(bytes))
      return repository;
    const path = `/${gitPathToHttpPath(bytes)}`;
    const declared = destination?.pathname;
    if (declared?.includes("%")) {
      // Only unreserved HTTP escapes identify the same literal path byte.
      const decoded = declared.replace(/%[0-9a-f]{2}/giu, (escape) => {
        const byte = String.fromCharCode(parseInt(escape.slice(1), 16));
        return /^[a-z0-9._~-]$/iu.test(byte) ? byte : escape;
      });
      const pathKey = (value: string) => {
        const bare = value.replace(/(?:\.git)?\/?$/u, "");
        return githubPath ? bare.toLowerCase() : bare;
      };
      if (pathKey(path) === pathKey(decoded))
        return `https://${host}${declared}`;
    }
    return `https://${host}${path}`;
  };
  // Git treats a colon followed by "//" as the start of a URL transport.
  const scp = /^([^@/:]+)@([^/:]+):(?!\/\/)(.+)$/u.exec(repository);
  if (scp && isGitSshUser(scp[1]!, scp[2]!.toLowerCase()))
    return httpsAlias(scp[2]!, scp[3]!, true);
  // Git decodes the authority and passes '?' and '#' to SSH as hostname bytes.
  const ssh =
    /^(?:ssh|git\+ssh|ssh\+git):\/\/([^/@%?#]+)@[^/@%?#]+(\/.*)$/u.exec(
      repository,
    );
  if (ssh) {
    // Git retains these bytes, but URL parsing would erase them from the alias.
    if (/[\t\r\n]/u.test(repository)) return repository;
    const url = URL.parse(repository);
    if (!url) return repository;
    const hostname = url.hostname.toLowerCase();
    const standardSsh =
      isGitSshUser(ssh[1]!, hostname) && (url.port === "" || url.port === "22");
    const alternate =
      ssh[1] === "git" && publicGitSsh443Host(url.host.toLowerCase());
    if (alternate || standardSsh)
      return httpsAlias(alternate || hostname, ssh[2]!, false);
  }
  return repository;
}
