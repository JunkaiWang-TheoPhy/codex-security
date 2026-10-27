export const platformProject = {
  id: 77,
  name: "example/project",
  url: "https://github.com/example/project",
};
export const platformRef = "refs/heads/main";

export function platformFinding(id: number) {
  return {
    id,
    repository: { name: "project", url: platformProject.url },
    ref: platformRef,
    rule: {
      name: "sample.check",
      message: "Sample issue",
      cwe_names: ["CWE-79: XSS"],
    },
    severity: "medium",
    status: "open",
    location: { file_path: "src/app.ts", line: 3, end_line: 5 },
  };
}

export function platformReport(findings: unknown[] = [platformFinding(12)]) {
  return {
    format: "semgrep-platform-findings/v1" as const,
    deployment: "example",
    project: platformProject,
    ref: platformRef,
    product: "sast" as const,
    findingCount: findings.length,
    findings,
  };
}
