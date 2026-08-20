import { lstatSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

function isInside(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (
    pathFromRoot !== ".."
    && !pathFromRoot.startsWith(`..${sep}`)
    && !isAbsolute(pathFromRoot)
  );
}

function createPathError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function resolveRepositoryPath(repositoryRoot, requestedPath, expectedType = "either") {
  const root = realpathSync.native(resolve(repositoryRoot));
  const candidate = resolve(root, requestedPath || ".");
  try {
    lstatSync(candidate);
  } catch (error) {
    if (error?.code === "ENOENT") throw createPathError("SHIPPROOF_PATH_MISSING", "requested path does not exist");
    throw error;
  }
  let resolvedCandidate;
  try {
    resolvedCandidate = realpathSync.native(candidate);
  } catch {
    throw createPathError("SHIPPROOF_PATH_INVALID", "requested path cannot be resolved");
  }
  if (!isInside(root, resolvedCandidate)) {
    throw createPathError("SHIPPROOF_PATH_ESCAPE", "requested path escapes the repository");
  }
  const stats = statSync(resolvedCandidate);
  if (expectedType === "file" && !stats.isFile()) {
    throw createPathError("SHIPPROOF_PATH_TYPE", "requested path is not a file");
  }
  if (expectedType === "directory" && !stats.isDirectory()) {
    throw createPathError("SHIPPROOF_PATH_TYPE", "requested path is not a directory");
  }
  return resolvedCandidate;
}
