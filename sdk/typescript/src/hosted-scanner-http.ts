import { CodexSecurityError } from "./errors.js";
import { requiredText } from "./scanner-import.js";

export interface HostedScannerHttpOptions {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
}

export function hostedRepositoryUrl(value: unknown, label: string): string {
  const raw = requiredText(value, label);
  const url = URL.parse(raw);
  if (
    !url ||
    url.pathname === "/" ||
    !/^https?:\/\/[^@/?#\\\s]+\/[^?#\\\s]+$/iu.test(raw)
  )
    throw new Error(
      "Select an HTTP(S) source repository URL with a path and without credentials, query or fragment.",
    );
  return raw;
}

export function hostedScannerHttp(
  dependencies: HostedScannerHttpOptions,
  callerSignal?: AbortSignal,
) {
  const { signal: transportSignal } = dependencies;
  const signal =
    callerSignal && transportSignal
      ? AbortSignal.any([callerSignal, transportSignal])
      : (callerSignal ?? transportSignal);
  signal?.throwIfAborted();
  const request = dependencies.fetch?.bind(dependencies) ?? fetch;
  async function getJson(
    url: URL,
    authorization: string,
    parse?: (body: string) => unknown,
  ): Promise<unknown> {
    signal?.throwIfAborted();
    const response = await request(url, {
      method: "GET",
      headers: {
        accept: "application/vnd.api+json, application/json",
        authorization,
      },
      redirect: "error",
      signal,
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
  return { signal, getJson };
}
