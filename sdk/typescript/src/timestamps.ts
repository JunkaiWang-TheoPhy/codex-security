import { regexes } from "zod/v4/core";

const RFC3339_DATE_TIME = new RegExp(
  regexes.datetime({ offset: true }).source,
  "i",
);

export function validRfc3339DateTime(value: string): boolean {
  return !value.startsWith("0000") && RFC3339_DATE_TIME.test(value);
}

/** Compare timestamps without dropping their sub-millisecond digits. */
export function compareTimestamps(left: string, right: string): number {
  const timestamp = Date.parse(left) - Date.parse(right);
  if (timestamp !== 0) return timestamp;
  const leftFraction = left.match(/\.\d{3}(\d*[1-9])/u)?.[1] ?? "";
  const rightFraction = right.match(/\.\d{3}(\d*[1-9])/u)?.[1] ?? "";
  return leftFraction < rightFraction
    ? -1
    : leftFraction > rightFraction
      ? 1
      : 0;
}
