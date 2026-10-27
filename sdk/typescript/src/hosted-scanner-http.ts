import { CodexSecurityError } from "./errors.js";

export interface HostedScannerHttpOptions {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
}

export function combineHostedSignals(
  first?: AbortSignal,
  second?: AbortSignal,
): AbortSignal | undefined {
  return first && second ? AbortSignal.any([first, second]) : (first ?? second);
}

export async function getHostedJson(
  url: URL,
  authorization: string,
  options: HostedScannerHttpOptions = {},
  parse?: (body: string) => unknown,
): Promise<unknown> {
  options.signal?.throwIfAborted();
  const response = await (options.fetch ?? fetch)(url, {
    method: "GET",
    headers: {
      accept: "application/vnd.api+json, application/json",
      authorization,
    },
    redirect: "error",
    signal: options.signal,
  });
  if (!response.ok) {
    const retry = response.headers.get("retry-after");
    const detail = await response.text();
    throw new CodexSecurityError(
      `GET ${url.origin}${url.pathname} failed (HTTP ${response.status})${retry ? `; Retry-After: ${retry}` : ""}${detail ? `: ${detail}` : "."}`,
    );
  }
  return parse ? parse(await response.text()) : response.json();
}
