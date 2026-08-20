import { readFileSync } from "node:fs";

import { resolveRepositoryPath } from "./safe-path.mjs";

const MAX_POLICY_BYTES = 100_000;
const MAX_POLICY_LINES = 1_000;
const MAX_POLICY_DEPTH = 8;
const SEVERITIES = new Set(["critical", "high", "medium", "low", "none"]);
const CAPACITY_INPUT_FLAGS = Object.freeze({
  dau_ratio: "--dau-ratio",
  peak_hour_ratio: "--peak-hour-ratio",
  actions_per_session: "--actions-per-session",
  requests_per_action: "--requests-per-action",
  burst_multiplier: "--burst-multiplier",
  read_ratio: "--read-ratio",
  cache_hit_ratio: "--cache-hit-ratio",
  queries_per_read: "--queries-per-read",
  queries_per_write: "--queries-per-write",
  p95_latency_ms: "--p95-latency-ms",
  db_time_ms: "--db-time-ms",
  instance_rps: "--instance-rps",
  cpu_ms_per_request: "--cpu-ms-per-request",
  memory_mb_per_instance: "--memory-mb-per-instance",
  headroom: "--headroom",
});

function stripComment(line) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote === '"' && character === "\\" && !escaped) {
      escaped = true;
      continue;
    }
    if ((character === '"' || character === "'") && !escaped) {
      quote = quote === character ? null : quote || character;
    }
    if (character === "#" && !quote && (index === 0 || /\s/.test(line[index - 1]))) {
      return line.slice(0, index);
    }
    escaped = false;
  }
  if (quote) throw new Error("unterminated quoted scalar in policy");
  return line;
}

function parseScalar(value, lineNumber) {
  if (value.length > 4_096) throw new Error(`policy line ${lineNumber}: scalar is too long`);
  if (value.startsWith('"')) {
    try {
      const parsed = JSON.parse(value);
      if (typeof parsed !== "string") throw new Error("quoted scalar must be a string");
      return parsed;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`policy line ${lineNumber}: invalid quoted string: ${message}`);
    }
  }
  if (value.startsWith("'")) {
    if (!value.endsWith("'") || value.length < 2) {
      throw new Error(`policy line ${lineNumber}: invalid single-quoted string`);
    }
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (["true", "false"].includes(value)) return value === "true";
  if (["null", "~"].includes(value)) return null;
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)) {
    const number = Number(value);
    if (!Number.isFinite(number)) throw new Error(`policy line ${lineNumber}: invalid number`);
    return number;
  }
  if (!value || /^[\[\]{}&*!|>@`]/.test(value) || ["---", "..."].includes(value)) {
    throw new Error(`policy line ${lineNumber}: unsupported YAML feature`);
  }
  return value;
}

function tokenizeYaml(source) {
  const rawLines = source.replace(/^\uFEFF/, "").split(/\r?\n/);
  if (rawLines.length > MAX_POLICY_LINES) throw new Error("policy exceeds the 1000 line limit");
  const tokens = [];
  for (let index = 0; index < rawLines.length; index += 1) {
    const rawLine = rawLines[index];
    if (rawLine.includes("\t")) throw new Error(`policy line ${index + 1}: tabs are not allowed`);
    const line = stripComment(rawLine).trimEnd();
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent % 2 !== 0) {
      throw new Error(`policy line ${index + 1}: indentation must use two-space steps`);
    }
    tokens.push({ indent, content: line.trimStart(), lineNumber: index + 1 });
  }
  return tokens;
}

function parseYamlBlock(tokens, startIndex, indent, depth) {
  if (depth > MAX_POLICY_DEPTH) throw new Error("policy nesting exceeds eight levels");
  const sequence = tokens[startIndex].content.startsWith("- ");
  const value = sequence ? [] : {};
  let index = startIndex;
  while (index < tokens.length && tokens[index].indent === indent) {
    const token = tokens[index];
    if (sequence) {
      if (!token.content.startsWith("- ")) {
        throw new Error(`policy line ${token.lineNumber}: cannot mix mapping and sequence`);
      }
      const scalar = token.content.slice(2).trim();
      if (!scalar) throw new Error(`policy line ${token.lineNumber}: empty list items are unsupported`);
      value.push(parseScalar(scalar, token.lineNumber));
      index += 1;
      continue;
    }
    if (token.content.startsWith("- ")) {
      throw new Error(`policy line ${token.lineNumber}: cannot mix mapping and sequence`);
    }
    const match = /^([A-Za-z_][A-Za-z0-9_-]*):(.*)$/.exec(token.content);
    if (!match) throw new Error(`policy line ${token.lineNumber}: expected a mapping key`);
    const [, key, remainder] = match;
    if (Object.hasOwn(value, key)) throw new Error(`policy line ${token.lineNumber}: duplicate key ${key}`);
    const scalar = remainder.trim();
    if (scalar) {
      value[key] = parseScalar(scalar, token.lineNumber);
      index += 1;
      continue;
    }
    const next = tokens[index + 1];
    if (!next || next.indent !== indent + 2) {
      throw new Error(`policy line ${token.lineNumber}: nested value must be indented two spaces`);
    }
    const parsed = parseYamlBlock(tokens, index + 1, indent + 2, depth + 1);
    value[key] = parsed.value;
    index = parsed.nextIndex;
  }
  if (index < tokens.length && tokens[index].indent > indent) {
    throw new Error(`policy line ${tokens[index].lineNumber}: unexpected indentation`);
  }
  return { value, nextIndex: index };
}

export function parsePolicyText(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAX_POLICY_BYTES) {
    throw new Error("policy must be UTF-8 text no larger than 100000 bytes");
  }
  const trimmed = source.trim();
  if (!trimmed) throw new Error("policy is empty");
  if (trimmed.startsWith("{")) {
    const value = JSON.parse(trimmed);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("policy must contain an object");
    }
    return value;
  }
  const tokens = tokenizeYaml(source);
  if (!tokens.length || tokens[0].indent !== 0 || tokens[0].content.startsWith("- ")) {
    throw new Error("policy root must be a mapping at indentation zero");
  }
  const parsed = parseYamlBlock(tokens, 0, 0, 0);
  if (parsed.nextIndex !== tokens.length) throw new Error("policy contains invalid indentation");
  return parsed.value;
}

function requireObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be a mapping`);
  }
  return value;
}

function rejectUnknown(value, allowed, name) {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`unknown ${name} keys: ${unknown.sort().join(", ")}`);
}

function requirePath(value, name) {
  if (typeof value !== "string" || !value || /[\0\r\n]/.test(value)) {
    throw new Error(`${name} must be a non-empty path string`);
  }
  return value;
}

function requireFiniteNumber(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${name} must be a finite number`);
  }
  return value;
}

export function validatePolicy(rawPolicy) {
  const policy = requireObject(rawPolicy, "policy");
  rejectUnknown(policy, new Set(["version", "scan", "security", "performance", "capacity"]), "policy");
  if (policy.version !== 1) throw new Error("policy version must be 1");

  const scan = requireObject(policy.scan || {}, "scan");
  rejectUnknown(scan, new Set(["path", "exclude", "max_file_bytes"]), "scan");
  const exclude = scan.exclude || [];
  if (!Array.isArray(exclude) || exclude.length > 100 || exclude.some((item) => typeof item !== "string")) {
    throw new Error("scan.exclude must be an array of at most 100 strings");
  }
  const maxFileBytes = scan.max_file_bytes ?? 1_000_000;
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > 100_000_000) {
    throw new Error("scan.max_file_bytes must be an integer from 1 through 100000000");
  }

  const security = requireObject(policy.security || {}, "security");
  rejectUnknown(security, new Set(["fail_on"]), "security");
  const failOn = security.fail_on || "high";
  if (!SEVERITIES.has(failOn)) throw new Error("security.fail_on has an unsupported severity");

  let performance = null;
  if (policy.performance !== undefined) {
    const value = requireObject(policy.performance, "performance");
    rejectUnknown(value, new Set(["baseline", "current", "budget"]), "performance");
    performance = {
      baseline: requirePath(value.baseline, "performance.baseline"),
      current: requirePath(value.current, "performance.current"),
      budget: requirePath(value.budget, "performance.budget"),
    };
  }

  let capacity = null;
  if (policy.capacity !== undefined) {
    const value = requireObject(policy.capacity, "capacity");
    rejectUnknown(value, new Set(["config", "target_users", "inputs"]), "capacity");
    const hasConfig = value.config !== undefined;
    const hasUsers = value.target_users !== undefined;
    if (hasConfig === hasUsers) {
      throw new Error("capacity must define exactly one of config or target_users");
    }
    if (hasConfig) {
      if (value.inputs !== undefined) throw new Error("capacity.inputs cannot be used with config");
      capacity = { config: requirePath(value.config, "capacity.config") };
    } else {
      if (!Number.isSafeInteger(value.target_users) || value.target_users <= 0) {
        throw new Error("capacity.target_users must be a positive integer");
      }
      const inputs = requireObject(value.inputs || {}, "capacity.inputs");
      rejectUnknown(inputs, new Set(Object.keys(CAPACITY_INPUT_FLAGS)), "capacity.inputs");
      capacity = { target_users: value.target_users, inputs: {} };
      for (const [name, inputValue] of Object.entries(inputs)) {
        capacity.inputs[name] = requireFiniteNumber(inputValue, `capacity.inputs.${name}`);
      }
    }
  }

  return {
    version: 1,
    scan: {
      path: requirePath(scan.path || ".", "scan.path"),
      exclude,
      max_file_bytes: maxFileBytes,
    },
    security: { fail_on: failOn },
    performance,
    capacity,
  };
}

export function defaultPolicy() {
  return validatePolicy({
    version: 1,
    scan: { path: "." },
    security: { fail_on: "high" },
  });
}

export function loadPolicy(repositoryRoot, requestedPath = ".shipproof.yml", { allowMissing = false } = {}) {
  let path;
  try {
    path = resolveRepositoryPath(repositoryRoot, requestedPath, "file");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (allowMissing && error?.code === "SHIPPROOF_PATH_MISSING") return null;
    throw new Error(`invalid policy file ${requestedPath}: ${message}`);
  }
  return { path, policy: validatePolicy(parsePolicyText(readFileSync(path, "utf8"))) };
}

export function buildPolicyGates(repositoryRoot, policy) {
  const root = resolveRepositoryPath(repositoryRoot, ".", "directory");
  const scanTarget = resolveRepositoryPath(root, policy.scan.path, "directory");
  const scanArguments = [
    scanTarget,
    "--format",
    "json",
    "--fail-on",
    policy.security.fail_on,
    "--max-file-bytes",
    String(policy.scan.max_file_bytes),
  ];
  for (const pattern of policy.scan.exclude) scanArguments.push("--exclude", pattern);
  const gates = [{ name: "scan", command: "scan", argumentsList: scanArguments }];

  if (policy.performance) {
    gates.push({
      name: "performance",
      command: "budget",
      argumentsList: [
        "--baseline",
        resolveRepositoryPath(root, policy.performance.baseline, "file"),
        "--current",
        resolveRepositoryPath(root, policy.performance.current, "file"),
        "--budget",
        resolveRepositoryPath(root, policy.performance.budget, "file"),
        "--format",
        "json",
      ],
    });
  }

  if (policy.capacity?.config) {
    gates.push({
      name: "capacity",
      command: "capacity",
      argumentsList: [
        "--config",
        resolveRepositoryPath(root, policy.capacity.config, "file"),
        "--format",
        "json",
      ],
    });
  } else if (policy.capacity?.target_users) {
    const argumentsList = ["--users", String(policy.capacity.target_users), "--format", "json"];
    for (const [name, value] of Object.entries(policy.capacity.inputs)) {
      argumentsList.push(CAPACITY_INPUT_FLAGS[name], String(value));
    }
    gates.push({ name: "capacity", command: "capacity", argumentsList });
  }
  return gates;
}
