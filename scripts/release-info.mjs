import { appendFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { PACKAGE_ROOT, VERSION } from "../lib/package-info.mjs";

const rawRef = process.env.GITHUB_REF_NAME || "";
const expectedTag = `v${VERSION}`;

if (
  rawRef.startsWith("v") &&
  (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(rawRef) || rawRef !== expectedTag)
) {
  throw new Error(
    `release tag ${JSON.stringify(rawRef)} must exactly match package version ${expectedTag}`
  );
}
const notes = `docs/releases/${expectedTag}.md`;
if (!existsSync(join(PACKAGE_ROOT, notes))) throw new Error(`missing release notes: ${notes}`);
const major = Number(VERSION.split(".", 1)[0]);
const values = {
  version: VERSION,
  notes,
  prerelease: String(major === 0 || VERSION.includes("-")),
};
if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
for (const [name, value] of Object.entries(values)) {
  if (/[\r\n]/.test(value)) throw new Error(`unsafe release output: ${name}`);
  appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, "utf8");
}
