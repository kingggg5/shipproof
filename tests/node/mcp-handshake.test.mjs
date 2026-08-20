import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_ENTRY = process.env.SHIPPROOF_MCP_SERVER_ENTRY || join(ROOT, "lib", "mcp-server.mjs");
let Client;
let StdioClientTransport;
let unavailable = "";
try {
  ({ Client } = await import("@modelcontextprotocol/sdk/client/index.js"));
  ({ StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js"));
} catch (error) {
  unavailable = error instanceof Error ? error.message : String(error);
}

test(
  "MCP SDK handshake lists strict schemas and validates real structured output",
  { skip: unavailable ? `optional MCP peers are not installed: ${unavailable}` : false },
  async () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), "shipproof-mcp-handshake-"));
    const unicodeSubdirectory = join(repositoryRoot, "โฟลเดอร์ space");
    mkdirSync(unicodeSubdirectory);
    writeFileSync(join(unicodeSubdirectory, "safe.js"), "const value = 1;\n", "utf8");
    const environment = Object.fromEntries(
      Object.entries({ ...process.env, SHIPPROOF_MCP_ROOT: repositoryRoot }).filter(
        (entry) => typeof entry[1] === "string",
      ),
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [SERVER_ENTRY],
      cwd: ROOT,
      env: environment,
      stderr: "pipe",
    });
    const client = new Client({ name: "shipproof-contract-test", version: "1.0.0" });
    try {
      await client.connect(transport, { timeout: 10_000 });
      const { tools } = await client.listTools();
      assert.deepEqual(
        tools.map((tool) => tool.name).sort(),
        [
          "shipproof_budget",
          "shipproof_capacity",
          "shipproof_explain",
          "shipproof_lint_snippet",
          "shipproof_scan",
        ],
      );

      const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));
      assert.ok(byName.shipproof_scan.outputSchema.properties.root);
      assert.ok(byName.shipproof_scan.outputSchema.properties.summary);
      assert.ok(byName.shipproof_capacity.outputSchema.properties.inputs);
      assert.ok(byName.shipproof_explain.outputSchema.properties.details);
      for (const tool of tools) {
        assert.equal(tool.outputSchema.additionalProperties, false, tool.name);
      }

      const capacity = await client.callTool({
        name: "shipproof_capacity",
        arguments: { users: 100 },
      });
      assert.equal(capacity.isError, undefined);
      assert.equal(capacity.structuredContent.tool.command, "capacity");
      assert.equal(capacity.structuredContent.inputs.users, 100);

      const nestedScan = await client.callTool({
        name: "shipproof_scan",
        arguments: { path: "โฟลเดอร์ space", fail_on: "high" },
      });
      assert.equal(nestedScan.isError, undefined);
      assert.equal(nestedScan.structuredContent.root, realpathSync.native(unicodeSubdirectory));
      assert.equal(nestedScan.structuredContent.summary.files_scanned, 1);

      const explanation = await client.callTool({
        name: "shipproof_explain",
        arguments: { rule_id: "SP108", format: "json", context_level: "summary" },
      });
      assert.equal(explanation.isError, undefined);
      assert.equal(explanation.structuredContent.details.rule_id, "SP108");
      assert.equal(explanation.structuredContent.context_level, "summary");
      assert.equal(explanation.structuredContent.details.context_level, "summary");
      assert.equal(explanation.structuredContent.details.attack, undefined);

      const snippet = await client.callTool({
        name: "shipproof_lint_snippet",
        arguments: {
          filename: "large.js",
          code: "const value = 1; // safe fixture\n".repeat(1_250),
        },
      });
      assert.equal(snippet.isError, undefined);
      assert.equal(snippet.structuredContent.root, realpathSync.native(repositoryRoot));
      assert.equal(snippet.structuredContent.summary.files_scanned, 1);
    } finally {
      await client.close().catch(() => {});
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  },
);
