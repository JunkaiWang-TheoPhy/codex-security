import { waitForRetry } from "./deduplication/retry.js";
import { CodexSecurityError } from "./errors.js";

const maxRetryAfterMs = 10_000;

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

function httpDate(hint: string, now: number): number {
  const normalized = hint.replace("23:59:60", "23:59:59");
  const leapSecond = normalized === hint ? 0 : 1000;
  let canonical = normalized;
  const asctime =
    /^(\w{3}) (\w{3}) ( \d|\d{2}) (\d{2}:\d{2}:\d{2}) (\d{4})$/u.exec(
      normalized,
    );
  const rfc850 =
    /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(\w{3})-(\d{2}) (\d{2}:\d{2}:\d{2}) GMT$/u.exec(
      normalized,
    );
  if (asctime) {
    const [, weekday, month, day, time, year] = asctime;
    canonical = `${weekday}, ${day!.replace(" ", "0")} ${month} ${year} ${time} GMT`;
  } else if (rfc850) {
    const [, weekday, day, month, year, time] = rfc850;
    const cutoff = new Date(now);
    cutoff.setUTCFullYear(cutoff.getUTCFullYear() + 50);
    const century = Math.floor(cutoff.getUTCFullYear() / 100) * 100;
    const dateIn = (century: number) =>
      `${weekday!.slice(0, 3)}, ${day} ${month} ${century + Number(year)} ${time} GMT`;
    canonical = dateIn(century);
    if (Date.parse(canonical) + leapSecond > cutoff.getTime())
      canonical = dateIn(century - 100);
  }
  const date = new Date(canonical);
  if (leapSecond && new Date(date.getTime() + leapSecond).getUTCDate() !== 1)
    return NaN;
  return canonical.length === 29 && date.toUTCString() === canonical
    ? date.getTime() + leapSecond
    : NaN;
}

function retryAfterMs(response: Response): number | undefined {
  if (response.status !== 429) return;
  const hint = response.headers.get("retry-after");
  if (!hint) return;
  const now = Date.now();
  const delay = /^\d+$/u.test(hint)
    ? Number(hint) * 1000
    : Math.max(0, httpDate(hint, now) - now);
  return delay <= maxRetryAfterMs ? delay : undefined;
}

export async function getHostedJson(
  url: URL,
  authorization: string,
  options: HostedScannerHttpOptions = {},
  parse?: (body: string) => unknown,
): Promise<unknown> {
  const get = () => {
    options.signal?.throwIfAborted();
    return (options.fetch ?? fetch)(url, {
      method: "GET",
      headers: {
        accept: "application/vnd.api+json, application/json",
        authorization,
      },
      redirect: "error",
      signal: options.signal,
    });
  };
  let response = await get();
  const delay = retryAfterMs(response);
  if (delay !== undefined) {
    void response.body?.cancel().catch(() => undefined);
    if (delay > 0) await waitForRetry(delay, options.signal);
    response = await get();
  }
  if (!response.ok) {
    const retry = response.headers.get("retry-after");
    const detail = await response.text();
    throw new CodexSecurityError(
      `GET ${url.origin}${url.pathname} failed (HTTP ${response.status})${retry ? `; Retry-After: ${retry}` : ""}${detail ? `: ${detail}` : "."}`,
    );
  }
  return parse ? parse(await response.text()) : response.json();
}
