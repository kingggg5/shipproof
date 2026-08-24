import { spawnSync } from "node:child_process";

let cachedRuntime = null;
let runtimeCachePopulated = false;

export function isSupportedPythonVersion(version) {
  const match = /Python\s+(\d+)\.(\d+)/.exec(version || "");
  return Boolean(match)
    && (Number(match[1]) > 3 || (Number(match[1]) === 3 && Number(match[2]) >= 10));
}

function readExecutableVersion(command, argumentPrefix) {
  const result = spawnSync(command, [...argumentPrefix, "--version"], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (result.status !== 0 || result.error) return null;
  return `${result.stdout || ""}${result.stderr || ""}`.trim();
}

/**
 * Detect a Python 3.10+ runtime once per process. The result is cached because
 * gates and MCP tools used to re-probe (up to four spawns) on every call.
 * Returns null when no supported runtime is available.
 */
export function detectPythonRuntime({ refresh = false } = {}) {
  if (!refresh && runtimeCachePopulated) return cachedRuntime;
  const candidates = [];
  if (process.env.SHIPPROOF_PYTHON) candidates.push([process.env.SHIPPROOF_PYTHON, []]);
  if (process.platform === "win32") candidates.push(["py", ["-3"]]);
  candidates.push(["python3", []], ["python", []]);
  for (const [command, argumentPrefix] of candidates) {
    const version = readExecutableVersion(command, argumentPrefix);
    if (version && isSupportedPythonVersion(version)) {
      cachedRuntime = { command, argumentPrefix, version };
      runtimeCachePopulated = true;
      return cachedRuntime;
    }
  }
  cachedRuntime = null;
  runtimeCachePopulated = true;
  return cachedRuntime;
}

export const internals = {
  resetRuntimeCache() {
    cachedRuntime = null;
    runtimeCachePopulated = false;
  },
};
