import { CodexSecurityError } from "./errors.js";
import { importEnvironmentSetting } from "./external-imports-feature.js";
import { isRecord } from "./record.js";
import {
  decodeScannerJson,
  parseHostedScannerJson,
  requiredText,
} from "./scanner-import.js";

export interface HostedScannerHttpOptions {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
}

/** libcurl requires ASCII space and control bytes in HTTP URLs to be percent-encoded. */
export function validateHostedRepositoryBytes(value: string): void {
  if (
    /[\x00-\x20\x7f]/u.test(value) &&
    (/^https?:\/\//iu.test(value) ||
      /^https?:$/u.test(URL.parse(value)?.protocol ?? ""))
  )
    throw new CodexSecurityError(
      "HTTP(S) repository URLs must percent-encode spaces and control characters.",
    );
}

export function hostedRepositoryUrl(value: unknown, label: string): string {
  const raw = requiredText(value, label);
  validateHostedRepositoryBytes(raw);
  const url = URL.parse(raw);
  if (
    !url ||
    url.pathname === "/" ||
    !/^https?:\/\/[^@/?#\\\s]+\/[^?#\\]+$/iu.test(raw)
  )
    throw new Error(
      "Select an HTTP(S) source repository URL with a path and without credentials, query or fragment.",
    );
  return raw;
}

function endpointSetting(environment: NodeJS.ProcessEnv, name: string) {
  if (name === "SNYK_API_V3_URL" || name === "SNYK_API_REST_URL") {
    // snyk-config preserves key case and converts boolean literals before interpolation.
    for (const key in environment) {
      if (key !== name) continue;
      const raw = environment[key];
      if (raw === "false" || raw === "FALSE") return undefined;
      return raw?.replace(/\$\{(.*?)\}/gu, (_, reference: string) => {
        const requested =
          process.platform === "win32" ? reference.toUpperCase() : reference;
        const value = importEnvironmentSetting(environment, requested)?.value;
        if (value === undefined)
          throw new Error(
            `${name} references missing environment variable ${reference}.`,
          );
        return value;
      });
    }
    return undefined;
  }
  return importEnvironmentSetting(environment, name)?.value;
}

function endpointOrigin(value: string, snykBase: boolean): string | undefined {
  const url = URL.parse(value);
  if (url?.protocol !== "https:") return undefined;
  // Snyk derives its REST host from the general endpoint (e.g. app.eu.snyk.io).
  if (snykBase && !url.hostname.startsWith("api."))
    url.hostname = `api.${url.hostname.replace(/^app\./u, "")}`;
  return url.origin;
}

export function checkSnykTokenOrigin(token: string, origin: string): void {
  // Snyk user and service access tokens carry their API hostname in the h claim.
  const payload =
    /^snyk_(?:uat|sat)\.[a-z0-9]{8}\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/u.exec(
      token.trim(),
    )?.[1];
  if (!payload) return;
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return;
  }
  const host = isRecord(claims) ? claims["h"] : undefined;
  if (typeof host !== "string" || !host) return;
  const base = host.startsWith("http") ? host : `https://${host}`;
  if (endpointOrigin(base, true) !== origin)
    throw new Error(
      `The Snyk access token's API host does not match ${origin}. Select its API origin before collecting findings.`,
    );
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
      const snykBase = name === "SNYK_API" || name === "SNYK_CFG_ENDPOINT";
      if (endpointOrigin(configured, snykBase) !== origin)
        throw new Error(
          `${name} does not match ${origin}. Select a matching API origin and ${tokenName} before collecting findings.`,
        );
      break;
    }
  }
  return token;
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
    return parseHostedScannerJson(
      decodeScannerJson(await response.arrayBuffer()),
    );
  }
  return { signal, getJson };
}
