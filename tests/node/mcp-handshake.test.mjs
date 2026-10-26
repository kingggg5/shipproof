import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
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
if (process.env.SHIPPROOF_MCP_REQUIRE_PEERS === "1" && unavailable) {
  throw new Error(`required MCP test peers are unavailable: ${unavailable}`);
}
if (process.env.SHIPPROOF_MCP_EXPECT_ZOD) {
  const require = createRequire(import.meta.url);
  assert.equal(require("zod/package.json").version, process.env.SHIPPROOF_MCP_EXPECT_ZOD);
}

test(
  "MCP scan evidence refreshes after same-size same-mtime edits and deletion even with legacy cache enabled",
  { skip: unavailable ? `optional MCP peers are not installed: ${unavailable}` : false },
  async () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), "shipproof-mcp-freshness-"));
    const filename = join(repositoryRoot, "sample.py");
    const safe = "value = 1\n".padEnd(128, " ");
    // High-entropy secret stays L0-allowlisted so the freshness probe still BLOCKs
    // after the default proof floor moved to L1.
    const risky = ("api_" + "key = '" + "K7mQ2xR9" + "nP4wL8sT3vY1'\n").padEnd(128, " ");
    writeFileSync(filename, safe, "utf8");
    const fixedTime = new Date("2020-01-01T00:00:00Z");
    utimesSync(filename, fixedTime, fixedTime);
    const original = statSync(filename);
    const environment = Object.fromEntries(
      Object.entries({
        ...process.env,
        SHIPPROOF_MCP_ROOT: repositoryRoot,
        SHIPPROOF_MCP_CACHE_MS: "60000",
      }).filter((entry) => typeof entry[1] === "string"),
    );
    const transport = new StdioClientTransport({
      command: process.execPath, args: [SERVER_ENTRY], cwd: ROOT, env: environment, stderr: "pipe",
    });
    const client = new Client({ name: "shipproof-freshness-test", version: "1.0.0" });
    const scan = async () => {
      const result = await client.callTool({ name: "shipproof_scan", arguments: { path: ".", fail_on: "high" } });
      assert.equal(result.isError, undefined);
      return result.structuredContent;
    };
    try {
      await client.connect(transport, { timeout: 10_000 });
      assert.equal((await scan()).verdict, "PASS_WITH_EVIDENCE");
      writeFileSync(filename, risky, "utf8");
      utimesSync(filename, original.atime, original.mtime);
      assert.equal(statSync(filename).size, original.size);
      assert.equal(statSync(filename).mtimeMs, original.mtimeMs);
      const failed = await scan();
      assert.equal(failed.verdict, "BLOCK");
      assert.ok(failed.findings.some((finding) => ["critical", "high"].includes(finding.severity)));
      writeFileSync(filename, safe, "utf8");
      utimesSync(filename, original.atime, original.mtime);
      assert.equal((await scan()).verdict, "PASS_WITH_EVIDENCE");
      rmSync(filename);
      assert.equal((await scan()).summary.files_scanned, 0);
    } finally {
      await client.close();
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  },
);

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

      // Use fixtures from the actual server package, also in a fresh packed consumer.
      const packageRoot = join(dirname(SERVER_ENTRY), "..");
      for (const name of ["baseline", "current", "budget"]) {
        copyFileSync(
          join(packageRoot, "examples", "performance", `${name}.json`),
          join(repositoryRoot, `${name}.json`),
        );
      }
      const budget = await client.callTool({
        name: "shipproof_budget",
        arguments: { baseline: "baseline.json", current: "current.json", budget: "budget.json" },
      });
      assert.equal(budget.isError, undefined);
      assert.equal(budget.structuredContent.passed, true);

      const nestedScan = await client.callTool({
        name: "shipproof_scan",
        arguments: { path: "โฟลเดอร์ space", fail_on: "high" },
      });
      assert.equal(nestedScan.isError, undefined);
      assert.equal(nestedScan.structuredContent.root, realpathSync.native(unicodeSubdirectory));
      assert.equal(nestedScan.structuredContent.summary.files_scanned, 1);

      const coverageInput = byName.shipproof_scan.inputSchema.properties.fail_on_incomplete;
      assert.equal(coverageInput.type, "boolean");
      assert.equal(coverageInput.default, true);
      writeFileSync(join(repositoryRoot, "bundle.zip"), "uninspected container", "utf8");
      const incompleteScan = await client.callTool({
        name: "shipproof_scan",
        arguments: { path: ".", fail_on: "none", fail_on_incomplete: true },
      });
      assert.equal(incompleteScan.isError, undefined);
      assert.equal(incompleteScan.structuredContent.verdict, "CONDITIONAL");
      assert.equal(incompleteScan.structuredContent.summary.completeness.is_complete, false);
      assert.equal(incompleteScan.structuredContent.decision_trace.gate.failed, true);
      const invalidCoverage = await client.callTool({
        name: "shipproof_scan",
        arguments: { fail_on_incomplete: "true" },
      });
      assert.equal(invalidCoverage.isError, true);

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

      for (const [code, expectedRule] of [["24.22.0", "SP684"], ["20.19.0", "SP685"], ["24.22.1", null]]) {
        const result = await client.callTool({
          name: "shipproof_lint_snippet",
          arguments: { filename: ".nvmrc", code },
        });
        assert.equal(result.isError, undefined);
        const advisories = result.structuredContent.findings.filter((finding) => ["SP684", "SP685"].includes(finding.rule_id));
        assert.deepEqual(advisories.map((finding) => finding.rule_id), expectedRule ? [expectedRule] : []);
        assert.ok(advisories.every((finding) => finding.tier === "advisory"));
      }

      for (const [filename, code, expectedRules] of [
        ["transport.ts", "import tls from 'node:tls'; tls.createSecureContext({minVersion:'TLSv1'});", ["SP686"]],
        ["socket.ts", "import {WebSocketServer} from 'ws'; new WebSocketServer({noServer:true,maxPayload:4294967296});", ["SP687"]],
        ["socket.ts", "import {WebSocketServer} from 'ws'; new WebSocketServer({noServer:true,maxPayload:65536});", []],
        ["cookies.cs", 'using Microsoft.AspNetCore.Http; void Set(IResponseCookies cookies, string value) { cookies.Append("session", value, new CookieOptions { HttpOnly = false, Secure = false }); }', ["SP056", "SP084"]],
        ["cookies.cs", 'using Microsoft.AspNetCore.Http; var set = (HttpContext context, string value) => { context.Response.Cookies.Append("session", value, new CookieOptions() { HttpOnly = false, Secure = false }); };', ["SP056", "SP084"]],
        ["next.config.ts", "export default {images:{dangerouslyAllowSVG:true,contentDispositionType:'inline',contentSecurityPolicy:''}};", ["SP688"]],
        ["server.cs", "using Microsoft.AspNetCore.Server.Kestrel.Core; void Configure(KestrelServerOptions options) { options.Limits.MaxRequestBodySize = null; }", ["SP689"]],
        ["client.dart", "import 'package:http/http.dart' as http; Future<void> send(String bearer) async { await http.get(Uri.parse('http://service.example.org'), headers: {'Authorization': bearer}); }", ["SP170"]],
        ["client.dart", "import 'package:http/http.dart' as http; Future<void> send(String bearer) async { await http.get(Uri.parse('https://service.example.org'), headers: {'Authorization': bearer}); }", []],
        ["modules.luau", 'local remote = Instance.new("RemoteFunction")\nremote.OnServerInvoke = function(player: Player, data: number) return require(data) end', ["SP690"]],
        ["delete.lua", 'local remote = Instance.new("RemoteEvent")\nremote.OnServerEvent:Connect(function(player, data) data:Destroy() end)', ["SP691"]],
        ["delete.luau", 'local remote = Instance.new("RemoteEvent")\nremote.OnServerEvent:Connect(function(player, data) if not owns(player, data) then return end data:Destroy() end)', []],
        ["execute.luau", 'remote.OnServerInvoke = function(player: Player, data: string) return loadstring(data)() end', ["SP672"]],
        ["sign.ts", "import {sign} from 'jsonwebtoken'; sign(payload,key,{algorithm:'RS256',allowInsecureKeySizes:true});", ["SP692"]],
        ["sign.ts", "import {sign} from 'jsonwebtoken'; sign(payload,key,{algorithm:'RS256',allowInvalidAsymmetricKeyTypes:true});", ["SP676"]],
        ["http.ts", "import {createServer} from 'node:http'; createServer({httpValidation:'insecure'},handler);", ["SP679"]],
        ["deadlines.ts", "import {createServer} from 'node:http'; createServer({requestTimeout:0,headersTimeout:0});", ["SP693"]],
        ["wait.ts", "async function wait() { await Promise.race([]); }", ["SP694"]],
        ["wait.dart", "import 'dart:async'; void main() async { await Future.any([]); }", ["SP694"]],
        ["sort.ts", "const sorted = [3,1,2].sort((a,b)=>a>b);", ["SP695"]],
        ["reader.cs", "using System.Xml; XmlReader.Create(input,new XmlReaderSettings{DtdProcessing=DtdProcessing.Parse,MaxCharactersFromEntities=0});", ["SP696"]],
        ["listener.py", "import logging.config\nlogging.config.listen(9030,verify=None).start()", ["SP697"]],
        ["compression.ts", "import {gzipSync} from 'node:zlib'; async function pack(data) { return await gzipSync(data); }", ["SP698"]],
        ["value.rs", "fn build() { let value = unsafe { std::num::NonZeroU32::new_unchecked(0) }; }", ["SP699"]],
        ["timer.ts", "import {setTimeout} from 'node:timers'; setTimeout(tick,30*24*60*60*1000);", ["SP700"]],
        ["pool.py", "from sqlalchemy.pool import QueuePool\npool=QueuePool(connect,max_overflow=-1)", ["SP701"]],
        ["kick.luau", 'local remote = Instance.new("RemoteEvent")\nremote.OnServerEvent:Connect(function(player, target) target:Kick() end)', ["SP691"]],
        ["effect.tsx", "import {useEffect} from 'react'; function useRefresh() { useEffect(async () => { await refresh(); }, []); }", ["SP702"]],
        ["pipeline.ts", "import {pipeline} from 'node:stream'; async function transfer(source,destination) { await pipeline(source,destination,(error)=>{report(error);}); }", ["SP703"]],
        ["database.ts", "import {Client} from 'pg'; const db = new Client({connectionString:'postgresql://db.example/app?sslmode=require',ssl:{ca:trustedCA}});", ["SP704"]],
        ["migration.sql", "BEGIN; CREATE INDEX CONCURRENTLY idx ON accounts(id); COMMIT;", ["SP705"]],
        ["definer.sql", "CREATE FUNCTION lookup_setting() RETURNS text LANGUAGE SQL SECURITY DEFINER SET search_path=pg_temp,private AS $$ SELECT value FROM settings $$;", ["SP706"]],
        ["stream.ts", "import {createReadStream,createWriteStream} from 'node:fs'; createReadStream(input).pipe(createWriteStream(output));", ["SP336"]],
        ["read.ts", "import {readFile} from 'node:fs'; async function load(path) { return await readFile(path,(error,data)=>{report(error,data);}); }", ["SP703"]],
        ["write.ts", "import {writeFile} from 'node:fs'; async function save(path,data) { await writeFile(path,data,error=>report(error)); }", ["SP703"]],
        ["drop.sql", "BEGIN; DROP INDEX CONCURRENTLY idx; COMMIT;", ["SP705"]],
        ["reindex.sql", "BEGIN; REINDEX INDEX CONCURRENTLY idx; COMMIT;", ["SP705"]],
        ["store.server.luau", "local remote=Instance.new('RemoteEvent')\nremote.OnServerEvent:Connect(function(player,key,value) game:GetService('DataStoreService'):GetDataStore('Profiles'):SetAsync(key,value) end)", ["SP707"]],
        ["reference.rs", "unsafe fn build() { let value = std::mem::uninitialized::<&u32>(); }", ["SP673"]],
        ["tls.cs", "using System.Net.Security; async System.Threading.Tasks.Task Connect(SslStream tls) { await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost=host, RemoteCertificateValidationCallback=(_,_,_,_)=>true }); }", ["SP104"]],
      ]) {
        const result = await client.callTool({ name: "shipproof_lint_snippet", arguments: { filename, code } });
        assert.equal(result.isError, undefined);
        const findings = result.structuredContent.findings.filter((finding) => ["SP056", "SP084", "SP104", "SP170", "SP336", "SP672", "SP673", "SP676", "SP679", "SP686", "SP687", "SP688", "SP689", "SP690", "SP691", "SP692", "SP693", "SP694", "SP695", "SP696", "SP697", "SP698", "SP699", "SP700", "SP701", "SP702", "SP703", "SP704", "SP705", "SP706", "SP707"].includes(finding.rule_id));
        assert.deepEqual(findings.map((finding) => finding.rule_id).sort(), expectedRules);
        assert.ok(findings.every((finding) => finding.tier === "advisory" && finding.proof_level === "L1"));
      }

      for (const [filename, code] of [
        ["task.py", "import asyncio\nasync def run():\n    await asyncio.create_task(work())\n"],
        ["pool.py", "from concurrent.futures import ThreadPoolExecutor\npool=ThreadPoolExecutor()"],
        ["pool.go", 'package pool\nimport "database/sql"\nfunc configure(db *sql.DB) { db.SetMaxIdleConns(0) }'],
        ["gather.py", "import asyncio\nasync def run():\n    return await asyncio.gather(work())"],
        ["engine.py", "from sqlalchemy import create_engine\nengine=create_engine(url)"],
      ]) {
        const result = await client.callTool({ name: "shipproof_lint_snippet", arguments: { filename, code } });
        assert.equal(result.isError, undefined);
        assert.ok(result.structuredContent.findings.every((finding) => !["SP346", "SP347", "SP348", "SP350", "SP375"].includes(finding.rule_id)));
      }

      for (const [name, argumentsValue] of [
        ["shipproof_scan", { path: 42 }],
        ["shipproof_budget", { baseline: 42, current: "current.json", budget: "budget.json" }],
        ["shipproof_capacity", { users: "100" }],
        ["shipproof_capacity", { users: Number.MAX_SAFE_INTEGER + 1 }],
        ["shipproof_explain", { rule_id: 42 }],
        ["shipproof_lint_snippet", { code: 42 }],
        ["shipproof_lint_snippet", { code: "", filename: "../outside.py" }],
        ["shipproof_lint_snippet", { code: "ก".repeat(70_000), filename: "large.txt" }],
        ["shipproof_scan", { path: ".." }],
        ["shipproof_budget", { baseline: "../outside.json", current: "current.json", budget: "budget.json" }],
      ]) {
        const rejected = await client.callTool({ name, arguments: argumentsValue });
        assert.equal(rejected.isError, true, `${name} must reject invalid or out-of-root input`);
      }
    } finally {
      await client.close().catch(() => {});
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  },
);
