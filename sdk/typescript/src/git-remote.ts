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

export function isGitHubCloudHost(host: string): boolean {
  return host === "github.com" || host.endsWith(".ghe.com");
}

export function normalizeGitRepositoryUrl(
  repository: string,
  selectedGitHubUrl?: string,
): string {
  // A connected Cloud repository or a selected GitHub SCM project identifies
  // which Enterprise host supports GitHub's SSH aliases.
  const destination = selectedGitHubUrl
    ? new URL(selectedGitHubUrl)
    : undefined;
  const connectedHost =
    destination?.protocol === "https:"
      ? destination.hostname.toLowerCase()
      : undefined;
  const connectedTenant = /^([^.]+)\.ghe\.com$/u.exec(connectedHost ?? "")?.[1];
  const isGitHubSshUser = (username: string, hostname: string) =>
    (username === "git" &&
      (hostname === "github.com" || hostname === connectedHost)) ||
    (username === connectedTenant && hostname === connectedHost);
  const scp = /^([^@/:]+)@([^/:]+):(.+)$/u.exec(repository);
  if (scp && isGitHubSshUser(scp[1]!, scp[2]!.toLowerCase()))
    return `https://${scp[2]}/${scp[3]}`;
  // Compare Git's literal SSH userinfo before URL strips tabs or newlines.
  const ssh = /^ssh:\/\/([^/@]+)@[^/@]+(\/.*)$/u.exec(repository);
  if (ssh) {
    // Git retains these bytes, but URL parsing would erase them from the alias.
    if (/[\t\r\n]/u.test(repository)) return repository;
    const url = new URL(repository);
    // Git sends the literal SSH path, including dot segments, query and fragment.
    if (url.pathname !== ssh[2]) return repository;
    const hostname = url.hostname.toLowerCase();
    const githubSsh =
      isGitHubSshUser(ssh[1]!, hostname) &&
      (url.port === "" || url.port === "22");
    const githubSshOverHttps =
      ssh[1] === "git" && hostname === "ssh.github.com" && url.port === "443";
    if (githubSshOverHttps) return `https://github.com${url.pathname}`;
    if (githubSsh) return `https://${hostname}${url.pathname}`;
  }
  return repository;
}
