import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import type { JsonObject, JsonValue } from "../src/config.js";
import {
  deepScanParentToolOverrides,
  readDeepScanParentConfig,
  type DirectDeepScanOptions,
} from "../src/deep-scan.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("a colliding MCP server leaves only the original coordinator's namespace direct", () => {
  const owner = "codex-security";
  const alias = "codex.security";
  const bare = "codex_security";
  const prefixed = "mcp__codex_security";
  const servers = { [owner]: { enabled: true }, [alias]: { enabled: true } };
  const selected = (...names: string[]) => ({
    enabled: true,
    server_names: names,
  });
  const direct = (...names: string[]) => ({
    direct_only_tool_namespaces: names,
  });
  const overrides = (
    prefix?: JsonValue,
    existing: string[] = ["audit"],
    registrations: JsonObject = servers,
  ) => {
    const config = {
      mcp_servers: registrations,
      features: {
        ...(prefix === undefined
          ? {}
          : { non_prefixed_mcp_tool_names: prefix }),
        code_mode: direct(...existing),
      },
    };
    return parse(deepScanParentToolOverrides(config, {}).join("\n"))[
      "features"
    ];
  };

  expect(overrides()).toEqual({
    non_prefixed_mcp_tool_names: selected(owner),
    code_mode: direct("audit", bare),
  });
  expect(overrides(selected("retained-tools"))).toEqual({
    non_prefixed_mcp_tool_names: selected("retained-tools", owner),
    code_mode: direct("audit", bare),
  });
  expect(overrides(selected(alias))).toEqual({
    code_mode: direct("audit", prefixed),
  });
  expect(overrides(selected(owner))).toEqual({
    code_mode: direct("audit", bare),
  });
  expect(
    overrides(undefined, ["audit"], {
      ...servers,
      [alias]: { enabled: false },
    }),
  ).toEqual({
    code_mode: direct("audit", prefixed, bare),
  });

  expect(overrides(false)).toBeUndefined();
  expect(overrides(true)).toBeUndefined();
  expect(overrides(undefined, [prefixed])).toBeUndefined();
  expect(
    overrides(undefined, [], { ...servers, [owner]: { enabled: false } }),
  ).toBeUndefined();
  expect(
    overrides(selected(bare), [], { ...servers, [bare]: { enabled: true } }),
  ).toBeUndefined();
});

test("native MCP registrations take precedence over the selected plugin's names and opt-outs", () => {
  const owner = "codex-security";
  const alias = "codex.security";
  const plugin = { [owner]: {}, [alias]: {} };
  const noDirect = { omit_tools_from: ["direct"] };
  const overrides = (servers: JsonObject, selected: JsonObject) =>
    parse(
      deepScanParentToolOverrides({ mcp_servers: servers }, selected).join(
        "\n",
      ),
    )["features"];
  const isolated = {
    non_prefixed_mcp_tool_names: { enabled: true, server_names: [owner] },
    code_mode: { direct_only_tool_namespaces: ["codex_security"] },
  };

  expect(overrides({}, plugin)).toEqual(isolated);
  expect(overrides({ [alias]: { enabled: false } }, plugin)).toEqual({
    code_mode: {
      direct_only_tool_namespaces: ["mcp__codex_security", "codex_security"],
    },
  });
  expect(overrides({}, { [alias]: {} })).toBeUndefined();
  expect(overrides({}, { ...plugin, [owner]: noDirect })).toBeUndefined();
  expect(overrides({ [owner]: noDirect }, plugin)).toBeUndefined();
  expect(overrides({ [owner]: {} }, { ...plugin, [owner]: noDirect })).toEqual(
    isolated,
  );
});

test.each([
  {
    name: "inherited Node override",
    dependencyNode: "configured runtime",
    runtimeNode: "configured runtime",
    route: "parent",
  },
  {
    name: "Node override supplied by the prepared runtime",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "prepared Node override replacing the dependency value",
    dependencyNode: "ambient runtime",
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "dependency Node override absent from the prepared runtime",
    dependencyNode: "unused runtime",
    runtimeNode: null,
    route: "direct",
  },
  {
    name: "no Node override",
    dependencyNode: null,
    runtimeNode: null,
    route: "direct",
  },
  {
    name: "installed plugin excludes the direct surface",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    pluginOmit: ["direct"],
    directOmitted: true,
  },
  {
    name: "configured server permits direct use despite the installed plugin exclusion",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    pluginOmit: ["direct"],
    configuredOmit: [],
  },
  {
    name: "configured server excludes the direct surface",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    configuredOmit: ["direct"],
    directOmitted: true,
  },
  {
    name: "alternate MCP declaration selected by the plugin",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    alternateMcpSource: "./other-servers.json",
    directOmitted: true,
  },
  {
    name: "invalid code mode supplied by the caller",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    codeMode: "mistyped",
  },
])("Deep Scan respects $name", async (scenario) => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const runtime = preparedRuntime(codexHome);
  if (scenario.alternateMcpSource) {
    const selected = join(root, "selected-plugin");
    await cp(PLUGIN_ROOT, selected, { recursive: true, dereference: true });
    const path = join(selected, ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    await writeFile(
      path,
      JSON.stringify({ ...manifest, mcpServers: scenario.alternateMcpSource }),
    );
    await writeFile(
      join(selected, scenario.alternateMcpSource),
      JSON.stringify({
        mcpServers: { "codex-security": { omit_tools_from: ["direct"] } },
      }),
    );
    runtime.plugin.pluginRoot = selected;
    runtime.plugin.installedRoot = selected;
  }
  if (scenario.pluginOmit) {
    runtime.plugin.installedRoot = join(root, "installed-plugin");
    await mkdir(runtime.plugin.installedRoot);
    await writeFile(
      join(runtime.plugin.installedRoot, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          "codex-security": { omit_tools_from: scenario.pluginOmit },
        },
      }),
    );
  }
  const selectedNode =
    scenario.runtimeNode === null
      ? undefined
      : join(root, scenario.runtimeNode, "node");
  const runtimeEnvironment: Record<string, string> =
    selectedNode === undefined ? {} : { CODEX_MCP_NODE_PATH: selectedNode };
  const originalRuntimeEnvironment = { ...runtimeEnvironment };
  const codeMode = scenario.codeMode ?? {
    direct_only_tool_namespaces: ["existing_tools"],
  };
  const parentTurn = mock(async () => {
    throw new Error("parent route reached");
  });
  const directRun = mock(async function* (options: DirectDeepScanOptions) {
    expect(options.codexOptions.env?.["CODEX_MCP_NODE_PATH"]).toBe(
      selectedNode,
    );
    throw new Error("direct route reached");
  });
  const started: CodexOptions[] = [];
  const createCodex = mock((options: CodexOptions) => {
    expect(options.apiKey).toBe("synthetic-routing-key");
    expect(options.env?.["CODEX_MCP_NODE_PATH"]).toBe(selectedNode);
    expect(options.env?.["CODEX_SECURITY_SCAN_DIR"]).toBe(scanDir);
    expect(options.config).toMatchObject({
      model: "gpt-6.1-sol",
      model_reasoning_effort: "high",
      features: {
        shell_tool: false,
        code_mode: codeMode,
      },
    });
    return {
      startThread: () => {
        started.push(options);
        return { id: null, runStreamed: parentTurn };
      },
    };
  });
  const client = new TestClient(
    {
      codexOverrides: {
        ...(scenario.configuredOmit === undefined
          ? {}
          : {
              mcp_servers: {
                "codex-security": {
                  command: "test-server",
                  omit_tools_from: [...scenario.configuredOmit],
                },
              },
            }),
        model: "gpt-6.1-sol",
        model_reasoning_effort: "high",
        features: {
          shell_tool: false,
          code_mode: codeMode,
        },
      },
    },
    {
      ...scanRuntimeDependencies(codexHome, scanDir),
      environment: {
        CODEX_API_KEY: "synthetic-routing-key",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        ...(scenario.dependencyNode === null
          ? {}
          : {
              CODEX_MCP_NODE_PATH: join(root, scenario.dependencyNode, "node"),
            }),
      },
      prepareRuntime: async () => ({
        ...runtime,
        environment: runtimeEnvironment,
      }),
      // Keep the host's Bun fallback and account advisory out of this check.
      canRunDirectDeepScan: () => true,
      createCodex,
      runDeepScan: directRun,
    },
  );
  try {
    await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
      `${scenario.route} route reached`,
    );
    expect(started).toHaveLength(1);
    const overrides = started[0]!.configOverrides?.filter((value) =>
      value.startsWith("features.code_mode.direct_only_tool_namespaces="),
    );
    expect(overrides).toEqual(
      scenario.route === "parent" &&
        typeof codeMode !== "string" &&
        !scenario.directOmitted
        ? [
            'features.code_mode.direct_only_tool_namespaces=["existing_tools","mcp__codex_security","codex_security"]',
          ]
        : [],
    );
    expect(parentTurn).toHaveBeenCalledTimes(
      scenario.route === "parent" ? 1 : 0,
    );
    expect(directRun).toHaveBeenCalledTimes(
      scenario.route === "direct" ? 1 : 0,
    );
    expect(runtimeEnvironment).toEqual(originalRuntimeEnvironment);
  } finally {
    await client.close();
  }
});

test("parent configuration reads inherited namespaces and preserves dotted SDK override order", async () => {
  const home = await temporaryDirectory();
  const scanDir = await temporaryDirectory();
  await writeFile(
    join(home, "config.toml"),
    '[features.code_mode]\ndirect_only_tool_namespaces = ["inherited_tools"]\n',
  );
  const read = (config: CodexOptions["config"]) =>
    readDeepScanParentConfig({
      codexOptions: { config, env: { CODEX_HOME: home } },
      preflightCommand: resolveCodexCommand({}),
      pluginRoot: PLUGIN_ROOT,
      scanDir,
      signal: new AbortController().signal,
    });
  const expected = (name: string) => ({
    features: { code_mode: { direct_only_tool_namespaces: [name] } },
  });
  expect(await read({})).toMatchObject(expected("inherited_tools"));
  expect(
    await read({
      features: { "code_mode.direct_only_tool_namespaces": ["first"] },
      "features.code_mode.direct_only_tool_namespaces": ["last"],
      model_auto_compact_token_limit: 2 ** 53,
    }),
  ).toMatchObject({
    ...expected("last"),
    model_auto_compact_token_limit: 2 ** 53,
  });
  await expect(read({ "features.code_mode": "invalid" })).rejects.toThrow();
});
