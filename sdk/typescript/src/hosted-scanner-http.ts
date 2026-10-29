import { CodexSecurityError } from "./errors.js";
import { importEnvironmentSetting } from "./external-imports-feature.js";
import { decodeScannerJson, requiredText } from "./scanner-import.js";

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

function endpointSetting(environment: NodeJS.ProcessEnv, name: string) {
  if (name === "SNYK_API_V3_URL" || name === "SNYK_API_REST_URL") {
    // snyk-config preserves key case and expands each placeholder once.
    for (const key in environment) {
      if (key !== name) continue;
      return environment[key]?.replace(
        /\$\{(.*?)\}/gu,
        (_, reference: string) => {
          const requested =
            process.platform === "win32" ? reference.toUpperCase() : reference;
          const value = importEnvironmentSetting(environment, requested)?.value;
          if (value === undefined)
            throw new Error(
              `${name} references missing environment variable ${reference}.`,
            );
          return value;
        },
      );
    }
    return undefined;
  }
  return importEnvironmentSetting(environment, name)?.value;
}

/** Use a vendor environment token only at the origin configured for it. */
export function hostedEnvironmentToken(
  environment: NodeJS.ProcessEnv,
  tokenName: string,
  origin: string,
  ...originNames: string[]
): string | undefined {
  const token = importEnvironmentSetting(environment, tokenName)?.value;
  if (token) {
    for (const name of originNames) {
      const configured = endpointSetting(environment, name);
      if (!configured) continue;
      const url = URL.parse(configured);
      // Snyk derives its REST host from the general endpoint (e.g. app.eu.snyk.io).
      if (
        url &&
        (name === "SNYK_API" || name === "SNYK_CFG_ENDPOINT") &&
        !url.hostname.startsWith("api.")
      )
        url.hostname = `api.${url.hostname.replace(/^app\./u, "")}`;
      if (url?.protocol !== "https:" || url.origin !== origin)
        throw new Error(
          `${name} does not match ${origin}. Select a matching API origin and ${tokenName} before collecting findings.`,
        );
      break;
    }
  }
  return token;
}

function preserveLargeNumbers(
  _key: string,
  value: unknown,
  context?: { source?: string },
): unknown {
  if (
    typeof value === "number" &&
    (!Number.isFinite(value) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value)))
  )
    return requiredText(context?.source, "Exact scanner numeric value");
  return value;
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
  async function getJson(url: URL, authorization: string): Promise<unknown> {
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
    return JSON.parse(
      decodeScannerJson(await response.arrayBuffer()),
      preserveLargeNumbers,
    );
  }
  return { signal, getJson };
}
