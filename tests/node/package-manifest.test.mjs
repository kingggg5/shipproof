import assert from "node:assert/strict";
import test from "node:test";

import { validatePackageMetadata } from "../../scripts/check-package-manifest.mjs";

const manifest = {
  schema_version: 1,
  max_packed_bytes: 100,
  max_unpacked_bytes: 200,
  files: ["package.json"],
};

test("package manifest requires an exact safe file set and size budget", () => {
  assert.deepEqual(
    validatePackageMetadata(
      { size: 80, unpackedSize: 160, files: [{ path: "package.json" }] },
      manifest,
    ),
    { files: 1, packedBytes: 80, unpackedBytes: 160 },
  );
  assert.throws(
    () =>
      validatePackageMetadata(
        {
          size: 80,
          unpackedSize: 160,
          files: [{ path: "package.json" }, { path: "docs/new.md" }],
        },
        manifest,
      ),
    /unapproved files/,
  );
  assert.throws(
    () =>
      validatePackageMetadata(
        { size: 80, unpackedSize: 160, files: [{ path: "research/private.json" }] },
        { ...manifest, files: ["research/private.json"] },
      ),
    /denied paths/,
  );
  assert.throws(
    () =>
      validatePackageMetadata(
        { size: 101, unpackedSize: 160, files: [{ path: "package.json" }] },
        manifest,
      ),
    /packed size/,
  );
});
