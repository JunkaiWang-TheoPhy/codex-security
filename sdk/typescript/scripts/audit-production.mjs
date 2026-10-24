import { spawnSync } from "node:child_process";

for (const project of ["sdk/typescript", "plugins/codex-security/mcp-app"]) {
  console.log(`Auditing production dependencies in ${project}`);
  const { error, status } = spawnSync("pnpm audit --prod --audit-level high", {
    cwd: new URL(`../../../${project}/`, import.meta.url),
    shell: true,
    stdio: "inherit",
  });
  if (error) throw error;
  if (status !== 0) process.exitCode = status ?? 1;
}
