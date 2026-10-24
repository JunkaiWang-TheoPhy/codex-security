import { ChildProcess } from "node:child_process";
import { appendFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { inspect } from "node:util";

const spawn = ChildProcess.prototype.spawn;
ChildProcess.prototype.spawn = function (options) {
  const [executable, script] = options.args ?? [];
  if (
    executable !== process.execPath ||
    typeof script !== "string" ||
    basename(script) !== "exit.mjs" ||
    !basename(dirname(script)).startsWith("codex-security-auth-epipe-")
  ) {
    return spawn.call(this, options);
  }
  const events = [];
  const started = performance.now();
  const record = (channel, event, fields = {}) => {
    events.push({
      channel,
      event,
      elapsedMs: performance.now() - started,
      ...fields,
    });
  };
  const errorFields = (error) => ({
    name: error?.name,
    message: error?.message,
    code: error?.code,
    errno: error?.errno,
    syscall: error?.syscall,
    path: error?.path,
    detail: inspect(error, { depth: 5 }),
  });
  const save = () => {
    try {
      appendFileSync(
        process.env.AUTH_STDIN_TRACE,
        JSON.stringify({ executable, script, pid: this.pid, events }) + "\n",
      );
    } catch (error) {
      console.warn("Unable to save a synthetic stdin observation", error);
    }
  };
  const observe = (target, channel) => {
    const emit = target.emit;
    target.emit = function (event, ...values) {
      if (event === "error") record(channel, event, errorFields(values[0]));
      if (event === "spawn" || event === "finish") record(channel, event);
      if (event === "exit" || event === "close") {
        record(channel, event, { values });
      }
      try {
        return emit.call(this, event, ...values);
      } finally {
        if (channel === "child" && event === "close") save();
      }
    };
  };
  observe(this, "child");
  let spawned;
  try {
    spawned = spawn.call(this, options);
  } catch (error) {
    record("child", "spawn threw", errorFields(error));
    save();
    throw error;
  }
  const stdin = this.stdin;
  if (stdin !== null) {
    observe(stdin, "stdin");
    const end = stdin.end;
    stdin.end = function (chunk, ...args) {
      record("stdin", "end", {
        bytes:
          typeof chunk === "string"
            ? Buffer.byteLength(chunk)
            : chunk?.byteLength,
      });
      try {
        return end.call(this, chunk, ...args);
      } catch (error) {
        record("stdin", "end threw", errorFields(error));
        save();
        throw error;
      }
    };
  }
  return spawned;
};
