export interface GitRemote {
  url: URL;
  /** URI-encoded in URLs and literal in SCP syntax. */
  username: string;
  /** Repository path without a URL's leading slash; SCP paths remain literal. */
  path: string;
  scpStyle: boolean;
}

/** Parse transport syntax only; callers decide which hosts and credentials are allowed. */
export function parseGitRemote(remote: string): GitRemote | undefined {
  if (remote.includes("://")) {
    const url = new URL(remote);
    // Git passes the complete SSH login, including a literal colon, to SSH.
    const sshLogin = /^(?:ssh|git\+ssh|ssh\+git):\/\/([^/]*)@/iu.exec(
      remote,
    )?.[1];
    return {
      url,
      username: sshLogin ?? url.username,
      path: url.pathname.slice(1),
      scpStyle: false,
    };
  }
  const scp = /^((?:([^@/:\s?#]+)@)?(?:\[[^\]]+\]|[^@/:\s?#]+)):(.+)$/u.exec(
    remote,
  );
  if (scp === null) return undefined;
  return {
    url: new URL(`ssh://${scp[1]}`),
    username: scp[2] ?? "",
    // An SCP path's ?, #, and dot segments are literal Git path characters.
    path: scp[3]!,
    scpStyle: true,
  };
}

export function isGitHubCloudHost(host: string): boolean {
  return host === "github.com" || host.endsWith(".ghe.com");
}
