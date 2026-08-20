import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_PATH = join(ROOT, "packaging", "approved-files.json");
const DENIED_PATHS = [
  /(^|\/)\.env(?:\.|$)/i,
  /^(?:\.git|\.github|coverage|node_modules|research|tests?)(?:\/|$)/i,
  /(^|\/)(?:id_rsa|id_ed25519|secrets?)(?:\.|$)/i,
  /\.(?:jks|key|keystore|p12|pem|pfx)$/i,
  /(^|\/)\.npmrc$/i,
];

function normalizePath(path) {
  if (typeof path !== "string" || path.length === 0) throw new Error("package path is invalid");
  const normalized = path.replaceAll("\\", "/").normalize("NFC");
  if (
    normalized.startsWith("/") ||
    normalized.startsWith("../") ||
    normalized.includes("/../") ||
    normalized.includes("\0")
  ) {
    throw new Error(`package path escapes the artifact: ${JSON.stringify(path)}`);
  }
  return normalized;
}

export function validatePackageMetadata(metadata, manifest) {
  if (!metadata || typeof metadata !== "object" || !Array.isArray(metadata.files)) {
    throw new Error("npm pack returned invalid package metadata");
  }
  if (!manifest || manifest.schema_version !== 1 || !Array.isArray(manifest.files)) {
    throw new Error("approved package manifest is invalid");
  }
  const actual = metadata.files.map((entry) => normalizePath(entry.path)).sort();
  const approved = manifest.files.map(normalizePath).sort();
  if (new Set(actual).size !== actual.length) throw new Error("package contains duplicate paths");
  const folded = actual.map((path) => path.toLowerCase());
  if (new Set(folded).size !== folded.length) {
    throw new Error("package contains paths that collide on case-insensitive filesystems");
  }
  const denied = actual.filter((path) => DENIED_PATHS.some((pattern) => pattern.test(path)));
  if (denied.length > 0) throw new Error(`package contains denied paths:\n${denied.join("\n")}`);

  const actualSet = new Set(actual);
  const approvedSet = new Set(approved);
  const added = actual.filter((path) => !approvedSet.has(path));
  const removed = approved.filter((path) => !actualSet.has(path));
  if (added.length > 0 || removed.length > 0) {
    const details = [
      ...(added.length > 0 ? [`unapproved files:\n${added.join("\n")}`] : []),
      ...(removed.length > 0 ? [`approved files missing:\n${removed.join("\n")}`] : []),
    ];
    throw new Error(`package file set differs from packaging/approved-files.json\n${details.join("\n")}`);
  }
  if (!Number.isInteger(metadata.size) || metadata.size > manifest.max_packed_bytes) {
    throw new Error(
      `packed size ${metadata.size} exceeds the ${manifest.max_packed_bytes}-byte budget`,
    );
  }
  if (
    !Number.isInteger(metadata.unpackedSize) ||
    metadata.unpackedSize > manifest.max_unpacked_bytes
  ) {
    throw new Error(
      `unpacked size ${metadata.unpackedSize} exceeds the ${manifest.max_unpacked_bytes}-byte budget`,
    );
  }
  return { files: actual.length, packedBytes: metadata.size, unpackedBytes: metadata.unpackedSize };
}

export function checkPackageManifest() {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
  const bundledNpmCli = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  const npmCli = process.env.npm_execpath || (existsSync(bundledNpmCli) ? bundledNpmCli : "");
  const npmCommand = npmCli ? process.execPath : "npm";
  const npmArguments = [
    ...(npmCli ? [npmCli] : []),
    "pack",
    "--json",
    "--dry-run",
    "--ignore-scripts",
  ];
  const result = spawnSync(npmCommand, npmArguments, {
    cwd: ROOT,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim() || `npm pack exited ${result.status}`);
  let reports;
  try {
    reports = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`npm pack did not return JSON: ${error.message}`);
  }
  if (!Array.isArray(reports) || reports.length !== 1) {
    throw new Error("npm pack must return exactly one package report");
  }
  return validatePackageMetadata(reports[0], manifest);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const summary = checkPackageManifest();
    console.log(
      `package manifest verified: ${summary.files} files, ${summary.packedBytes} packed bytes, ${summary.unpackedBytes} unpacked bytes`,
    );
  } catch (error) {
    console.error(`shipproof package check: ${error.message}`);
    process.exitCode = 1;
  }
}
