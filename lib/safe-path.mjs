import { existsSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

function isInside(root, candidate) {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (
    pathFromRoot !== ".."
    && !pathFromRoot.startsWith(`..${sep}`)
    && !isAbsolute(pathFromRoot)
  );
}

export function resolveRepositoryPath(repositoryRoot, requestedPath, expectedType = "either") {
  const root = realpathSync.native(resolve(repositoryRoot));
  const candidate = resolve(root, requestedPath || ".");
  if (!existsSync(candidate)) throw new Error("requested path does not exist");
  const resolvedCandidate = realpathSync.native(candidate);
  if (!isInside(root, resolvedCandidate)) throw new Error("requested path escapes the repository");
  const stats = statSync(resolvedCandidate);
  if (expectedType === "file" && !stats.isFile()) throw new Error("requested path is not a file");
  if (expectedType === "directory" && !stats.isDirectory()) {
    throw new Error("requested path is not a directory");
  }
  return resolvedCandidate;
}
