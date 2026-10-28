# Evaluations

Model-based evaluations live here so they can evolve with the plugin without
being embedded in its source tree or shipped npm runtime.

- [Triage finding](triage-finding/README.md): Promptfoo input contracts, OSS
  calibration, and SastBench. This suite owns its private package and lockfile.
- [Deep reducer](deep-reducer/README.md): optional model evaluation of real IPC
  size-limit recovery, pagination, and finding retention. It reuses the MCP
  test helpers and dependencies.
- [Secret discovery](secret-discovery/README.md): checks whether the production
  core audit finds synthetic credentials in source and keeps them in its final
  findings, with deterministic grading and harness checks.
- [Standard time budget](standard-time-budget/README.md): paired comparison of
  production Standard scans with and without an advisory time allowance on
  synthetic vulnerabilities and safe controls, with source-evidence grading.
- [Workflow routing](workflow-routing/README.md): checks whether repository-installed
  production skills route natural-language requests to the appropriate workflow,
  stopping before workflow execution.
- [Dependency alerts](dependency-alert/README.md): manual behavioral scenarios for
  container package copies, distribution backports, and Operator report identity
  after an image rollout. These use synthetic exported evidence without a scanner
  or cluster connection.

Model runs are opt-in. CI runs the deterministic triage, secret-discovery,
time-budget, and workflow-routing helper checks and the real-IPC reducer
regression through the normal MCP test suite.
