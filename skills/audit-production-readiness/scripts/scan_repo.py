#!/usr/bin/env python3
"""Fast, local-first production risk scanner with JSON, Markdown, and SARIF output."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.5.1"

SEVERITY = {"none": 99, "critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE = {"high": 0, "medium": 1, "low": 2}
SEVERITY_ICON = {
    "critical": "\U0001f534",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
}
CONFIDENCE_LABEL = {"high": "CONFIRMED", "medium": "LIKELY", "low": "NEEDS_REVIEW"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    ".work",
    "benchmarks",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "fixtures",
    ".next",
    ".nuxt",
    ".cache",
    ".npm-cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "__pycache__",
}
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".graphql",
    ".gql",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".properties",
    ".env",
    ".xml",
    ".tf",
    ".hcl",
    ".md",
    ".rst",
    ".txt",
}
DOCUMENT_SUFFIXES = {".md", ".rst", ".txt"}
TEXT_NAMES = {
    "dockerfile",
    "containerfile",
    "makefile",
    "procfile",
    ".dockerignore",
    ".env",
    ".gitignore",
    ".netrc",
    ".npmrc",
    ".pypirc",
}
SECRET_RULE_IDS = {"SP001", "SP002", "SP003"}
PLACEHOLDERS = re.compile(
    r"(?i)(example|sample|placeholder|dummy|changeme|replace[_-]?me|your[_-]?|test[_-]?only|"
    r"not[_-]?a[_-]?real|fake|redacted|xxxx|<[^>]+>|\$\{|process\.env|os\.environ)"
)
INLINE_IGNORE = re.compile(r"shipproof-ignore(?:\s+|:)(SP\d+)")

RULE_EXPLANATIONS: dict[str, dict[str, str]] = {
    "SP001": {
        "why": "A private key in source control lets anyone who clones the repo impersonate the service, decrypt traffic, or sign artifacts.",
        "attack": "Attacker clones the repo (or reads a cached CI log), extracts the key, and authenticates as the service to access internal APIs or sign malicious releases.",
        "false_positive": "Test/example keys clearly marked as non-production (e.g. in a fixture directory with placeholder names) may be safe to suppress.",
        "test": "Add a pre-commit hook or CI step that scans for PEM headers. Verify the key is revoked and rotated.",
    },
    "SP002": {
        "why": "An AWS access key in source control can be scraped by bots within minutes of being pushed.",
        "attack": "Automated scanners find the key on GitHub, use it to spin up crypto-mining instances or exfiltrate S3 data.",
        "false_positive": "Keys starting with AKIA are always real key IDs. If the key is disabled/deleted, suppress via baseline.",
        "test": "Rotate the key immediately. Check CloudTrail for unauthorized usage. Add a secrets scanner to CI.",
    },
    "SP003": {
        "why": "Hardcoded credentials bypass secret rotation, audit logging, and access control provided by secret managers.",
        "attack": "Attacker reads the credential from source, uses it directly against the target service.",
        "false_positive": "Configuration examples, mock values, and test-only constants may trigger this. Check if the value is a real credential.",
        "test": "Move the credential to a secret manager. Add a test that verifies the config key is loaded from the environment.",
    },
    "SP101": {
        "why": "eval/exec turns untrusted input into arbitrary code execution with the application's full privileges.",
        "attack": "Attacker sends crafted input that gets dynamically evaluated, executing arbitrary Python/JS in the server process.",
        "false_positive": "Code generators, template engines, or REPL tools may use eval legitimately. Verify input is never user-controlled.",
        "test": "Replace dynamic evaluation with a safe parser (e.g. ast.literal_eval, JSON.parse). Add a test with malicious input.",
    },
    "SP102": {
        "why": "Enabling shell execution passes the command through a shell interpreter, enabling injection via metacharacters (;, |, $()).",
        "attack": "Attacker injects shell metacharacters into a parameter that reaches subprocess with shell enabled.",
        "false_positive": "Commands with fully hardcoded strings (no user input) are lower risk but still bad practice.",
        "test": "Pass an argument list without the shell flag. Add a test with input containing semicolons and pipes.",
    },
    "SP103": {
        "why": "String-interpolated SQL lets attackers inject arbitrary queries, bypassing authentication and extracting data.",
        "attack": "Attacker sends ' OR 1=1 -- as input, modifying the query to return all rows or execute subqueries.",
        "false_positive": "Dynamic table/column names (not values) may be safe if validated against an allowlist.",
        "test": "Use parameterized queries. Add a test with SQL injection payloads to verify they are escaped.",
    },
    "SP104": {
        "why": "Disabling TLS verification allows man-in-the-middle attacks on any connection.",
        "attack": "Attacker intercepts the connection, reads credentials and data, or modifies responses.",
        "false_positive": "Local development against self-signed certs. Should never appear in production code paths.",
        "test": "Restore verification. Configure the correct CA bundle. Test that connections reject invalid certificates.",
    },
    "SP105": {
        "why": "Without signature verification, anyone can forge JWT tokens and bypass authentication entirely.",
        "attack": "Attacker creates a JWT with algorithm=none or a forged signature, gaining arbitrary access.",
        "false_positive": "Very unlikely to be a false positive. This is almost always a critical vulnerability.",
        "test": "Require a specific algorithm. Test that tokens with wrong algorithm or modified payload are rejected.",
    },
    "SP106": {
        "why": "Unsafe deserialization (pickle, yaml.load) can execute arbitrary code embedded in the serialized data.",
        "attack": "Attacker sends a crafted pickle/YAML payload that executes system commands when deserialized.",
        "false_positive": "Internal-only data that never accepts external input. Still risky if any input path is overlooked.",
        "test": "Use yaml.safe_load or JSON. Add a test with a malicious serialized object.",
    },
    "SP107": {
        "why": "Wildcard CORS with credentials lets any website make authenticated requests to your API.",
        "attack": "Malicious website makes cross-origin requests with the user's cookies, accessing private data.",
        "false_positive": "Rare. If you need credentials, you must specify exact allowed origins.",
        "test": "Allowlist specific origins. Test that requests from unauthorized origins are rejected.",
    },
    "SP108": {
        "why": "An admin route without authorization lets any authenticated (or unauthenticated) user perform privileged actions.",
        "attack": "Normal user calls the admin endpoint directly, bypassing UI restrictions to delete data or modify settings.",
        "false_positive": "Authorization might be handled by middleware not visible in the route decorator. Verify and document.",
        "test": "Add a Depends(require_admin) or equivalent. Test that non-admin users receive 403.",
    },
    "SP201": {
        "why": "Debug mode exposes stack traces, internal state, and sometimes interactive debuggers to end users.",
        "attack": "Attacker triggers an error to see internal paths, database schemas, or get a debug console.",
        "false_positive": "Debug flags in test configuration or local-only settings files.",
        "test": "Make debug mode conditional on an environment variable. Test that production mode hides error details.",
    },
    "SP202": {
        "why": "A floating base image tag means builds are not reproducible and may silently include supply-chain compromises.",
        "attack": "Attacker compromises the tag (e.g. latest) on the registry; all subsequent builds inherit the malicious image.",
        "false_positive": "Development-only Dockerfiles that are never deployed. Pin by digest for any production image.",
        "test": "Pin the image to a sha256 digest. Set up automated digest update with review.",
    },
    "SP203": {
        "why": "A mutable GitHub Action tag can be force-pushed to inject malicious code into your CI pipeline.",
        "attack": "Attacker compromises the action repo and pushes malicious code to the v1 tag. Your CI runs it.",
        "false_positive": "Very unlikely. Always pin to a full 40-character commit SHA.",
        "test": "Replace the tag with the full commit SHA. Add a comment with the original version for reference.",
    },
    "SP301": {
        "why": "Redis KEYS scans the entire keyspace, blocking all other operations on a single-threaded server.",
        "attack": "Attacker triggers a feature using KEYS on a large dataset, causing multi-second latency spikes for all users.",
        "false_positive": "Admin CLI scripts run during maintenance windows with no live traffic.",
        "test": "Use SCAN with a cursor instead of KEYS. Test that pagination works across key batches.",
    },
    "SP302": {
        "why": "A SELECT query without LIMIT returns all matching rows, which can exhaust memory when tables grow.",
        "attack": "Attacker requests an unbounded listing endpoint, causing the server to load millions of rows and run out of memory.",
        "false_positive": "Queries on tables with guaranteed small row counts (e.g., system settings, lookup tables with < 10 rows).",
        "test": "Add a LIMIT clause. Test that the endpoint returns at most the page limit even with large datasets.",
    },
    "SP303": {
        "why": "time.sleep in an async function blocks the entire event loop thread, freezing all concurrent requests.",
        "attack": "Attacker sends multiple requests to a route with blocking sleep, exhausting all event loop capacity.",
        "false_positive": "Sync worker functions executed via run_in_executor or background thread pools.",
        "test": "Replace time.sleep with asyncio.sleep. Test that concurrent requests complete without blocking each other.",
    },
    "SP304": {
        "why": "Outbound HTTP requests without timeouts can hang indefinitely if the remote server becomes unresponsive.",
        "attack": "Remote service degrades or hangs; your server's workers stay blocked waiting for responses until the pool is exhausted.",
        "false_positive": "Requests wrapped in an external timeout mechanism (e.g., asyncio.wait_for, signal-based timeout).",
        "test": "Set timeout=(connect_timeout, read_timeout). Test behavior when remote service hangs.",
    },
    "SP305": {
        "why": "Accepting a page size parameter without an upper bound lets users request 1,000,000 items in a single query.",
        "attack": "Attacker sends ?limit=999999999 to crash the server with an out-of-memory error.",
        "false_positive": "Validation performed in custom validator functions not visible in the parameter declaration.",
        "test": "Add le=100 (FastAPI Query) or maximum constraint. Test that ?limit=999999 returns 422/400.",
    },
    "SP401": {
        "why": "Express apps without helmet lack standard security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
        "attack": "Attacker exploits clickjacking (missing X-Frame-Options) or MIME-sniffing vulnerabilities.",
        "false_positive": "Security headers set at a reverse proxy (nginx, Cloudflare) rather than in Express middleware.",
        "test": "Add app.use(helmet()). Verify response headers contain X-Frame-Options and X-Content-Type-Options.",
    },
    "SP402": {
        "why": "Express without rate limiting allows brute force and credential stuffing attacks.",
        "attack": "Attacker sends thousands of login attempts per second without being throttled.",
        "false_positive": "Rate limiting handled by a reverse proxy, API gateway, or CDN in front of Express.",
        "test": "Add express-rate-limit or similar middleware. Test that excessive requests return 429.",
    },
    "SP403": {
        "why": "NEXT_PUBLIC_ env vars are inlined into client-side JavaScript and visible to all users.",
        "attack": "Developer puts a secret API key in a NEXT_PUBLIC_ variable; anyone can read it from the JS bundle.",
        "false_positive": "Values that are intentionally public (e.g., analytics IDs, public API endpoints).",
        "test": "Move secrets to server-only env vars. Audit NEXT_PUBLIC_ vars for sensitive values.",
    },
    "SP404": {
        "why": "Django SECRET_KEY hardcoded in settings can be extracted from source to forge sessions and CSRF tokens.",
        "attack": "Attacker reads SECRET_KEY from source, forges session cookies, and impersonates any user.",
        "false_positive": "Development-only settings files with non-production keys.",
        "test": "Load SECRET_KEY from an environment variable. Test that the app fails to start without it.",
    },
    "SP405": {
        "why": "Django ALLOWED_HOSTS accepting any host disables host header validation, enabling cache poisoning and SSRF.",
        "attack": "Attacker sends a request with a malicious Host header; Django accepts it and generates URLs with the attacker's domain.",
        "false_positive": "Local development settings. Should never appear in production.",
        "test": "Set ALLOWED_HOSTS to explicit domains. Test that requests with unknown Host headers return 400.",
    },
    "SP406": {
        "why": "Express error handler that sends the raw error object to clients leaks stack traces and internal details.",
        "attack": "Attacker triggers an error to see file paths, database connection strings, or internal logic in the response.",
        "false_positive": "Custom error serializers that explicitly filter what is sent.",
        "test": "Return only a status code and generic message. Log the full error server-side.",
    },
    "SP407": {
        "why": "Missing CSRF protection on state-changing routes allows cross-site request forgery.",
        "attack": "Malicious website submits a form to your app using the victim's session cookies.",
        "false_positive": "API-only services using token auth (not cookies). SPA apps with CORS + token auth.",
        "test": "Enable csurf or csrf middleware. Test that POST requests without a valid token are rejected.",
    },
    "SP408": {
        "why": "Serving a Next.js or Nuxt app without CSP headers allows XSS payloads to execute freely.",
        "attack": "Attacker injects a script tag; without CSP, the browser executes it with full page access.",
        "false_positive": "CSP set at the reverse proxy or CDN level rather than in the app config.",
        "test": "Add Content-Security-Policy header in next.config.js or middleware. Test with a CSP evaluator.",
    },
    "SP004": {
        "why": "Providing a hardcoded default value when an environment secret is missing lets the app run with known, vulnerable keys in production.",
        "attack": "Attacker relies on production omitting the env var, then uses the known default secret to sign JWTs or decrypt data.",
        "false_positive": "Mock secrets in dedicated test suites or local documentation.",
        "test": "Remove the default fallback string; ensure the application fails closed at startup if required secrets are absent.",
    },
    "SP109": {
        "why": "Unvalidated outbound HTTP requests allow Server-Side Request Forgery (SSRF) to private networks and cloud metadata.",
        "attack": "Attacker supplies internal endpoints or metadata addresses to extract IAM cloud credentials.",
        "false_positive": "Fixed, allowlisted external service URLs not controlled by user input.",
        "test": "Validate target URLs against an explicit domain allowlist and reject requests resolving to private IP ranges.",
    },
    "SP110": {
        "why": "Constructing filesystem paths directly from user input allows path traversal to read or overwrite arbitrary files.",
        "attack": "Attacker supplies ../../../etc/shadow or ..\\..\\windows\\system32 to access sensitive host files.",
        "false_positive": "Paths verified with realpath/resolve and confirmed to stay inside an authorized base directory.",
        "test": "Pass traversal sequences (../, ..\\) and verify that the application returns 400 or rejects the path.",
    },
    "SP204": {
        "why": "Logging raw credentials, tokens, or request payloads writes sensitive data to persistent log stores.",
        "attack": "Attacker with log read access (or third-party log provider compromise) extracts user credentials and tokens.",
        "false_positive": "Sanitized or masked debug messages where secrets have been stripped.",
        "test": "Audit logger output during login/auth flows and verify sensitive keys are masked or omitted.",
    },
    "SP306": {
        "why": "Unbounded concurrent iterations (Promise.all or asyncio.gather over large arrays) cause sudden CPU, memory, and connection pool exhaustion.",
        "attack": "Attacker submits a large payload or triggers batch actions that spawn thousands of concurrent tasks, crashing the server.",
        "false_positive": "Fixed small arrays with guaranteed upper limits (e.g. max 5 items).",
        "test": "Process 10,000 items and verify execution is throttled with a semaphore or bounded worker pool.",
    },
    "SP501": {
        "why": "Unmetered AI/LLM API calls in public HTTP endpoints allow malicious actors or bots to run up massive cloud bills through automated requests.",
        "attack": "Attacker loops against an unmetered chat/generation endpoint, draining the organization's LLM credits and incurring thousands of dollars in fees.",
        "false_positive": "Internal cron scripts, offline evaluators, or administrative tasks not exposed to public web traffic.",
        "test": "Simulate 50 rapid requests and verify the endpoint responds with 429 Too Many Requests or requires user authentication.",
    },
    "SP502": {
        "why": "Processing payment webhooks without verifying the cryptographic signature lets anyone send fake success events and unlock paid features for free.",
        "attack": "Attacker crafts and sends a counterfeit checkout.session.completed POST payload to receive premium subscription access.",
        "false_positive": "Local test fixtures or mock payment handlers.",
        "test": "Send a mock webhook with an invalid signature and verify the endpoint rejects it with a 400 Bad Request error.",
    },
    "SP503": {
        "why": "Exposing SUPABASE_SERVICE_ROLE_KEY in frontend environment variables or client builds bypasses all Row Level Security (RLS) policies.",
        "attack": "Attacker extracts the service role key from the browser bundle and reads, alters, or drops any table in the database.",
        "false_positive": "Strictly server-side environment variables without frontend exposure prefixes.",
        "test": "Inspect the client build bundle and verify that only anon public keys are present.",
    },
    "SP313": {
        "why": "Instantiating database clients (e.g. new PrismaClient()) inside serverless handlers opens a new connection on every invocation, rapidly exhausting database slots.",
        "attack": "Surges in incoming traffic spawn new serverless functions that saturate the database connection pool, causing connection refusal errors across all endpoints.",
        "false_positive": "Long-running daemon processes or containerized singletons.",
        "test": "Execute 50 concurrent requests and verify active database connections remain bounded by connection pooling.",
    },
    "SP307": {
        "why": "Executing database queries inside iteration loops (N+1 query problem) multiplies latency and database CPU load proportionally to the collection size.",
        "attack": "A request for a page with hundreds of items triggers hundreds of round-trip database queries, leading to severe latency degradation.",
        "false_positive": "Loops with statically guaranteed iteration counts of 1 or 2 items.",
        "test": "Query a list of 100 items and verify the total number of database queries remains constant (O(1)) rather than scaling linearly.",
    },
    "SP112": {
        "why": "SVG files can contain embedded XML and JavaScript scripts. Serving un-sanitized user-uploaded SVGs directly in browsers leads to Stored XSS.",
        "attack": "Attacker uploads a malicious SVG containing a script tag that executes in other users' browsers to steal authentication tokens.",
        "false_positive": "Upload pipelines that explicitly sanitize SVGs (e.g. using DOMPurify) or serve them with Content-Disposition: attachment.",
        "test": "Upload an SVG containing a test script and verify scripts are sanitized or the file is served as a downloadable attachment.",
    },
    "SP113": {
        "why": "PHP unserialize() can execute magic methods and construct arbitrary object injection chains leading to remote code execution.",
        "attack": "Attacker sends a serialized object payload in a cookie or parameter that instantiates gadget classes to execute shell commands.",
        "false_positive": "Strictly authenticated, signature-verified cryptographic payloads.",
        "test": "Pass a serialized test payload and verify the application rejects it or uses json_decode instead.",
    },
    "SP114": {
        "why": "Regular expressions with nested quantifiers suffer from exponential backtracking (ReDoS) that freezes the CPU and starves the event loop.",
        "attack": "Attacker sends an input of 30 characters that forces the regex engine to test billions of permutations, pinning the CPU at 100%.",
        "false_positive": "Non-backtracking linear-time regex engines.",
        "test": "Pass a non-matching string of repeating characters and verify execution finishes in under 10ms.",
    },
    "SP115": {
        "why": "lxml's default parser resolves entities, so parsing untrusted XML can read local files or expand entities into a denial of service.",
        "attack": "Attacker uploads an XML document with an external entity pointing at /etc/passwd or a billion-laughs payload.",
        "false_positive": "Repositories that only parse trusted, internally generated XML, or that already configure a hardened parser elsewhere.",
        "test": "Parse an XML payload containing an external entity and verify the parser rejects entity resolution.",
    },
    "SP116": {
        "why": "dangerouslySetInnerHTML bypasses React's escaping, so a dynamic value rendered as raw HTML executes injected scripts.",
        "attack": "Attacker stores <img src=x onerror=...> in a field that later reaches __html, running script in every visitor's session.",
        "false_positive": "Static, developer-authored HTML strings that never mix with user data.",
        "test": "Render a value containing a script tag through __html and verify it is sanitized or blocked.",
    },
    "SP117": {
        "why": "new Function() compiles a string into executable code with full program access, exactly like eval.",
        "attack": "Attacker controls part of the compiled string and appends code that exfiltrates data or alters application behavior.",
        "false_positive": "Build-time tooling that compiles known developer-authored templates.",
        "test": "Pass input containing }; StealData(); and verify it is not executed.",
    },
    "SP118": {
        "why": "A string passed to setTimeout or setInterval is compiled and executed like eval, so interpolated input becomes code.",
        "attack": "Attacker controls part of the timer string and appends a payload that runs with the page's privileges.",
        "false_positive": "Static developer-authored strings that never mix with user data are still better replaced by functions.",
        "test": "Pass user input inside the timer string and verify it is not executed.",
    },
    "SP119": {
        "why": "Joining request-controlled segments into a filesystem path lets ../ sequences escape the intended directory.",
        "attack": "Attacker passes ../../../../etc/passwd as a filename and reads arbitrary server files.",
        "false_positive": "Values validated against a strict allowlist before the join.",
        "test": "Submit traversal sequences and verify the resolved path stays inside the base directory.",
    },
    "SP120": {
        "why": "node-serialize's unserialize() executes functions embedded in the payload, giving direct remote code execution.",
        "attack": "Attacker sends a serialized object containing an IIFE that runs a reverse shell on deserialize.",
        "false_positive": "None: this library cannot be used safely on untrusted input.",
        "test": "Send a payload containing an embedded function and verify it is rejected before deserialization.",
    },
    "SP121": {
        "why": "Redirecting to a request-supplied URL lets attackers craft convincing phishing links on your domain.",
        "attack": "Attacker emails https://your-app/logout?next=https://evil.test/login and harvests credentials.",
        "false_positive": "Redirect targets validated against a strict allowlist or built from server-side constants only.",
        "test": "Submit an absolute external URL and verify the application refuses to redirect.",
    },
    "SP122": {
        "why": "Math.random and the random module are predictable PRNGs, so tokens built from them can be guessed.",
        "attack": "Attacker reconstructs the PRNG state from a few observed values and predicts the next session token.",
        "false_positive": "Non-security uses such as UI shuffling, dice rolls, or test fixtures.",
        "test": "Verify generated tokens use the Web Crypto API or the secrets module and have sufficient entropy.",
    },
    "SP123": {
        "why": "Reusing a hardcoded IV with CBC/CTR leaks equality patterns across ciphertexts and enables block-reordering attacks.",
        "attack": "Attacker observes repeated IV/ciphertext prefixes, infers plaintext structure, and replays reordered blocks.",
        "false_positive": "Cipher modes that do not use an IV.",
        "test": "Encrypt the same message twice and verify the IVs and ciphertexts differ.",
    },
    "SP124": {
        "why": "Fetching a URL taken from request input lets attackers reach internal services and cloud metadata endpoints.",
        "attack": "Attacker supplies a metadata-service address (link-local 169"
        + ".254."
        + "169"
        + ".254) and extracts cloud credentials from the response.",
        "false_positive": "URLs assembled entirely from server-side configuration with validated user-selected path segments.",
        "test": "Submit internal and metadata URLs and verify the request is refused before it leaves the service.",
    },
    "SP125": {
        "why": "DomSanitizer bypass methods mark content as trusted, skipping the escaping Angular would otherwise apply.",
        "attack": "Attacker stores a payload that reaches a bypassed binding and executes as script in other users' sessions.",
        "false_positive": "Static, developer-authored markup never mixed with user data.",
        "test": "Render user HTML through the bypass and verify a script tag is neutralized.",
    },
    "SP126": {
        "why": "Web storage is readable by any script on the page, so stored tokens are stolen by the first XSS.",
        "attack": "One injected script reads localStorage and exfiltrates every session token it finds.",
        "false_positive": "Non-sensitive UI preferences such as theme or layout flags.",
        "test": "Verify after login that no token appears in localStorage or sessionStorage.",
    },
    "SP127": {
        "why": "PHP type juggling makes loose comparisons match unexpected values ('abc' == 0 was true before PHP 8).",
        "attack": "Attacker crafts a magic hash or array input that satisfies a loose password comparison.",
        "false_positive": "Comparisons on validated, non-security values.",
        "test": "Fuzz credential comparisons with edge-type inputs and verify only exact matches pass.",
    },
    "SP128": {
        "why": "Interpolating variables into SQL text hands attackers control of query structure.",
        "attack": "A crafted username closes the string and appends OR 1=1 or a UNION.",
        "false_positive": "Query fragments assembled from server-side constants only.",
        "test": "Submit quotes and comment markers and verify they are bound as data.",
    },
    "SP129": {
        "why": "Echoing request data without htmlspecialchars reflects attacker HTML back to victims.",
        "attack": "A crafted link renders a session-stealing script in the victim's browser.",
        "false_positive": "Values already escaped upstream.",
        "test": "Submit an HTML fragment and verify it renders as text.",
    },
    "SP130": {
        "why": "A redirect target from request input lends your domain to phishing pages.",
        "attack": "Attacker distributes your-domain/login?next=https://evil.test to harvest credentials.",
        "false_positive": "Targets validated against a strict allowlist.",
        "test": "Submit an absolute external URL and verify the redirect is refused.",
    },
    "SP131": {
        "why": "An http.Server without timeouts holds connections open indefinitely, letting slow clients exhaust file descriptors.",
        "attack": "Slowloris-style clients open many connections and never finish requests, starving real traffic.",
        "false_positive": "Servers behind proxies that enforce their own timeouts.",
        "test": "Open partial requests and verify the server closes them within the configured timeout.",
    },
    "SP132": {
        "why": "Blocking on a Task while its continuation needs the same context deadlocks or burns threads.",
        "attack": "Under load, thread pools fill with blocked waiters and the service stops responding.",
        "false_positive": "Console tools and startup paths without a synchronization context.",
        "test": "Call the path concurrently and verify no deadlock or thread starvation.",
    },
    "SP133": {
        "why": "Debug compilation ships verbose errors, stack traces, and debugging behavior to production users.",
        "attack": "Attackers trigger errors to read connection strings and internal paths.",
        "false_positive": "Developer-machine configs never used for deployment.",
        "test": "Deploy with release transforms and verify error pages are generic.",
    },
    "SP134": {
        "why": "assert statements vanish under python -O, silently deleting the authorization check in optimized deployments.",
        "attack": "The production image runs with -O, so the admin route no longer checks the flag at all.",
        "false_positive": "Test-suite assertions, which are the intended use of assert.",
        "test": "Run with python -O and verify unauthorized requests still receive 403.",
    },
    "SP135": {
        "why": "strcpy and friends copy without bounds, overflowing the destination buffer.",
        "attack": "Oversized input overwrites adjacent memory and hijacks control flow.",
        "false_positive": "Fixed-size, compile-time-constant inputs; even then bounded APIs are safer.",
        "test": "Fuzz with oversized inputs under ASan and verify no overflow.",
    },
    "SP136": {
        "why": "Discarding Go return values hides errors until they corrupt state or crash a request far from the cause.",
        "attack": "A failed write is ignored; the request reports success while data was never persisted.",
        "false_positive": "Deliberate discards of non-error values with a comment explaining why.",
        "test": "Force the dependency to fail and verify the error surfaces in logs and responses.",
    },
    "SP318": {
        "why": "Retries without a stop condition amplify load precisely when a dependency is already failing, turning a slowdown into an outage.",
        "attack": "An upstream blip causes every caller to retry indefinitely, multiplying traffic until workers and connections are exhausted.",
        "false_positive": "Retry wrappers that already pass an explicit stop condition or attempt bound.",
        "test": "Force the dependency to fail and verify retry attempts stop at the configured bound with backoff.",
    },
    "SP314": {
        "why": "Committing SQLite database files into git source control risks leaking production user records, passwords, and secrets in history.",
        "attack": "Attacker clones the repository and extracts sensitive credentials directly from the tracked database file.",
        "false_positive": "Empty test fixture schema templates.",
        "test": "Verify .gitignore includes *.sqlite and *.db files, and that no database binaries are tracked by git.",
    },
    "SP315": {
        "why": "Failing to close resp.Body in Go HTTP requests keeps underlying TCP sockets and goroutines alive indefinitely, exhausting file descriptors.",
        "attack": "Sustained outbound requests leave thousands of orphaned goroutines until the Go process crashes with too many open files.",
        "false_positive": "Custom HTTP client wrappers that close the response body internally.",
        "test": "Run pprof goroutine profiler under load and verify persistConn goroutines do not accumulate.",
    },
    "SP316": {
        "why": "Executing outbound HTTP requests inside database transactions holds database connections open for seconds, starving the connection pool.",
        "attack": "Traffic surges lock all database connection slots while waiting on third-party APIs, causing total database outages.",
        "false_positive": "In-memory test mocks or sub-millisecond local network calls.",
        "test": "Simulate third-party latency and verify database transaction duration is not prolonged by network calls.",
    },
    "SP317": {
        "why": "Synchronous blocking operations (e.g. time.sleep or requests.get) inside Python async def coroutines block the single-threaded asyncio event loop.",
        "attack": "A single slow blocking call freezes all other concurrent user requests on the same worker process.",
        "false_positive": "Sub-millisecond CPU operations or explicit multi-threading wrappers (asyncio.to_thread).",
        "test": "Send concurrent requests during a slow operation and verify throughput of unaffected endpoints is maintained.",
    },
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    cwe: str
    owasp: str
    suffixes: frozenset[str] = frozenset()
    redact: bool = False


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    path: str
    line: int
    evidence: str
    message: str
    remediation: str
    cwe: str
    owasp: str
    fingerprint: str
    detection: str = "pattern"
    proof_level: str = "L0"


PROOF_LEVELS = {
    "pattern": "L0",
    "ast": "L1",
    "structural": "L1",
    "artifact": "L1",
}


def compile_pattern(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "SP001",
        "Private key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "A private key appears in source control.",
        "Revoke and rotate the key, remove it from history, and use a secret manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP002",
        "AWS access key committed",
        "security",
        "critical",
        "high",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "An AWS access key ID appears in source control.",
        "Disable and rotate the credential, inspect access logs, and purge it from history.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP003",
        "Credential-like value committed",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']"
        ),
        "A credential-like value is assigned directly in a file.",
        "Confirm it is real, then rotate it and load the replacement from an approved secret store.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP101",
        "Dynamic code execution",
        "security",
        "high",
        "medium",
        compile_pattern(r"(?<![\w.])(?:eval|exec)\s*\("),
        "Dynamic code execution can turn untrusted input into code execution.",
        "Remove dynamic evaluation or constrain input with a safe parser and strict allowlist.",
        "CWE-95",
        "OWASP ASVS V1",
        frozenset({".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".rb"}),
    ),
    Rule(
        "SP102",
        "Shell execution enabled",
        "security",
        "high",
        "high",
        compile_pattern(r"\bshell\s*=\s*(?:true|True)\b"),
        "Shell interpretation expands command-injection exposure.",
        "Pass an argument array without a shell and validate every externally controlled argument.",
        "CWE-78",
        "OWASP ASVS V1",
    ),
    Rule(
        "SP103",
        "SQL built with interpolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:execute|query|raw)\s*\(\s*(?:f[\"']|`[^`]*\$\{|[\"'][^\"']*%[s(]|[^,]+\.format\()"
        ),
        "A database query appears to be built with string interpolation.",
        "Use parameterized queries or the ORM's bound parameters and add an injection regression test.",
        "CWE-89",
        "OWASP ASVS V1",
    ),
    Rule(
        "SP104",
        "TLS verification disabled",
        "security",
        "high",
        "high",
        compile_pattern(r"\b(?:verify|rejectUnauthorized)\s*[:=]\s*(?:false|False)\b"),
        "TLS peer verification is explicitly disabled.",
        "Restore certificate verification and configure the correct trust chain.",
        "CWE-295",
        "OWASP ASVS V12",
    ),
    Rule(
        "SP105",
        "JWT signature verification disabled",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"(?:verify_signature[\"']?\s*[:=]\s*(?:false|False)|algorithms?\s*[:=]\s*\[[\"']none[\"']\])"
        ),
        "JWT signature verification appears disabled.",
        "Require an allowlisted algorithm, issuer, audience, expiry, and a verified signature.",
        "CWE-347",
        "OWASP ASVS V6",
    ),
    Rule(
        "SP106",
        "Unsafe deserialization",
        "security",
        "high",
        "medium",
        compile_pattern(r"\b(?:pickle\.loads?|yaml\.load)\s*\("),
        "Unsafe deserialization can execute attacker-controlled behavior.",
        "Use a safe data format; for YAML use safe_load and constrain accepted types.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".py", ".pyi"}),
    ),
    Rule(
        "SP107",
        "Credentialed wildcard CORS",
        "security",
        "high",
        "high",
        compile_pattern("$^"),
        "Wildcard origins and credentials create an unsafe cross-origin policy.",
        "Allowlist exact trusted origins and test preflight behavior.",
        "CWE-942",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP108",
        "Sensitive route lacks visible authorization",
        "security",
        "high",
        "medium",
        compile_pattern("$^"),
        "An admin or internal route has no visible authorization dependency.",
        "Require an explicit authorization dependency or verify and document an application-wide control.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".py"}),
    ),
    Rule(
        "SP201",
        "Debug mode enabled",
        "security",
        "high",
        "high",
        compile_pattern(r"\b(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)\b"),
        "Debug mode may expose internals or interactive execution in production.",
        "Make production fail closed and enable debug only in an explicit local environment.",
        "CWE-489",
        "OWASP ASVS V13",
    ),
    Rule(
        "SP202",
        "Floating container base image",
        "supply-chain",
        "medium",
        "high",
        compile_pattern(
            r"^\s*FROM\s+(?:(?:--platform=\S+)\s+)?(?!\S+@sha256:[0-9a-f]{64}\b)(?!scratch(?:\s|$))\S+(?:\s+AS\s+\S+)?\s*$"
        ),
        "The container base image is not pinned to an immutable digest.",
        "Pin the reviewed image by digest and update it through an automated, reviewed process.",
        "CWE-1104",
        "NIST SSDF PS.3",
    ),
    Rule(
        "SP203",
        "Unpinned GitHub Action",
        "supply-chain",
        "high",
        "high",
        compile_pattern(r"^\s*-?\s*uses:\s*(?!\./)([^\s@]+)@(?![0-9a-f]{40}\b)[^\s#]+"),
        "A third-party GitHub Action is referenced by a mutable tag or branch.",
        "Pin the action to a reviewed 40-character commit SHA and retain the release tag in a comment.",
        "CWE-829",
        "NIST SSDF PS.3",
        frozenset({".yml", ".yaml"}),
    ),
    Rule(
        "SP301",
        "Redis KEYS in application path",
        "scale",
        "high",
        "medium",
        compile_pattern(r"\b(?:redis|redis_client|r)\.keys\s*\("),
        "Redis KEYS can block the server while scanning the full keyspace.",
        "Use cursor-based SCAN, a purpose-built index, or a bounded key namespace.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP302",
        "Unbounded SQL result",
        "scale",
        "medium",
        "low",
        compile_pattern(r"\bSELECT\s+\*\s+FROM\b(?![^;\n]*\bLIMIT\b)"),
        "A query may return an unbounded, over-wide result set.",
        "Select required columns and enforce pagination or a defensible upper bound.",
        "CWE-400",
        "Capacity",
        frozenset({".sql"}),
    ),
    Rule(
        "SP303",
        "Blocking sleep in async code",
        "correctness",
        "high",
        "high",
        compile_pattern(r"\btime\.sleep\s*\("),
        "Blocking sleep may stall an async event loop.",
        "Use the runtime's non-blocking sleep or move blocking work to a bounded worker.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP304",
        "Outbound request without timeout",
        "correctness",
        "high",
        "high",
        compile_pattern("$^"),
        "An outbound request has no explicit deadline and can exhaust workers or connections.",
        "Set connect and read deadlines, bound retries, and test dependency failure.",
        "CWE-400",
        "Reliability",
    ),
    Rule(
        "SP305",
        "Unbounded pagination input",
        "scale",
        "medium",
        "high",
        compile_pattern("$^"),
        "A route accepts a page-size parameter without a visible upper bound.",
        "Enforce a positive maximum at the request boundary and retain a database LIMIT.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    # --- Framework-specific rules ---
    Rule(
        "SP401",
        "Express app without helmet",
        "security",
        "medium",
        "medium",
        compile_pattern("$^"),
        "Express app is created without security middleware (helmet).",
        "Add app.use(helmet()) to set security headers (CSP, HSTS, X-Frame-Options, etc.).",
        "CWE-693",
        "OWASP ASVS V14",
        frozenset({".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP402",
        "Express auth route without rate limiting",
        "security",
        "medium",
        "low",
        compile_pattern("$^"),
        "An authentication-sensitive Express route is registered without visible rate-limiting middleware.",
        "Add rate-limiting middleware (e.g. express-rate-limit) or verify the gateway throttles these routes.",
        "CWE-307",
        "OWASP ASVS V2",
        frozenset({".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP403",
        "Secret in NEXT_PUBLIC_ env var",
        "security",
        "high",
        "medium",
        compile_pattern(r"NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*[:=]"),
        "A NEXT_PUBLIC_ environment variable name suggests a secret that will be exposed to all users in the client bundle.",
        "Move secret values to server-only environment variables (without the NEXT_PUBLIC_ prefix).",
        "CWE-200",
        "OWASP ASVS V14",
    ),
    Rule(
        "SP404",
        "Django SECRET_KEY hardcoded",
        "security",
        "critical",
        "high",
        compile_pattern(r"SECRET_KEY\s*=\s*[\"'][^\"']{20,}[\"']"),
        "Django SECRET_KEY is hardcoded in a settings file.",
        "Load SECRET_KEY from an environment variable or a secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".py"}),
        redact=True,
    ),
    Rule(
        "SP405",
        "Django ALLOWED_HOSTS accepts all",
        "security",
        "high",
        "high",
        compile_pattern(r"ALLOWED_HOSTS\s*=\s*\[[\"']\*[\"']\]"),
        "Django ALLOWED_HOSTS accepts any hostname, disabling host header validation.",
        "Set ALLOWED_HOSTS to explicit trusted domains.",
        "CWE-20",
        "OWASP ASVS V13",
        frozenset({".py"}),
    ),
    Rule(
        "SP406",
        "Express error sent to client",
        "security",
        "medium",
        "low",
        compile_pattern(r"res\.(?:json|send)\s*\(\s*(?:err|error)\b"),
        "An Express error handler appears to send the raw error object to the client.",
        "Return a generic error message and status code. Log the full error server-side.",
        "CWE-209",
        "OWASP ASVS V7",
        frozenset({".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP407",
        "Cookie session routes without CSRF protection",
        "security",
        "medium",
        "low",
        compile_pattern("$^"),
        "State-changing routes rely on cookie sessions without visible CSRF middleware.",
        "Add CSRF middleware (e.g. csurf) for cookie-authenticated routes or switch to token authentication.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP408",
        "Meta-framework config without CSP header",
        "security",
        "medium",
        "low",
        compile_pattern("$^"),
        "A Next.js or Nuxt configuration file does not set a Content-Security-Policy header.",
        "Add a Content-Security-Policy header in the framework config or verify the proxy sets one.",
        "CWE-693",
        "OWASP ASVS V14",
        frozenset({".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP004",
        "Insecure secret fallback default",
        "security",
        "high",
        "high",
        compile_pattern(
            r"(?:os\.(?:environ\.)?get|getenv|process\.env\.[A-Z0-9_]+)\s*(?:\(\s*[\"'][A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|AUTH|PRIVATE)[A-Za-z0-9_]*[\"']\s*,\s*[\"'][^\"'\s]+[\"']|\|\|\s*[\"'][^\"'\s]+[\"'])"
        ),
        "A hardcoded fallback default is provided for an environment secret.",
        "Remove the hardcoded fallback string; require explicit environment configuration.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP109",
        "SSRF to internal network or metadata",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:https?://(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)|(?:requests|httpx|fetch|axios|http)\.(?:get|post|put|delete|request)\s*\(\s*(?:url|target_url|req\.query|request\.args|req\.body|user_url)\b)"
        ),
        "An outbound HTTP request may target internal endpoints, localhost, or cloud metadata.",
        "Validate destination URLs against an allowlist and block private IP ranges.",
        "CWE-918",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP110",
        "Path traversal in file path",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:open|readFile|readFileSync|createReadStream|unlink|rmSync)\s*\(\s*(?:f[\"'][^\"']*\{|\`[^\`]*\$\{|(?:path\.)?join\s*\([^)]*(?:req\.|params|query|user_input))"
        ),
        "A filesystem operation constructs paths directly from variables without visible normalization.",
        "Normalize with realpath/resolve and verify the path remains inside the base directory.",
        "CWE-22",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP204",
        "Sensitive data or credential logging",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"(?:console\.log|logger\.(?:info|debug|warn|error)|logging\.(?:info|debug|warn|error)|print)\s*\(\s*.*(?:password|user\.password|client_secret|private_key|auth_token)\b"
        ),
        "Sensitive credentials or authentication payloads appear to be logged directly.",
        "Mask or redact sensitive fields before writing messages to logs.",
        "CWE-532",
        "OWASP ASVS V7",
    ),
    Rule(
        "SP306",
        "Unbounded concurrency in collection",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"(?:Promise\.all\s*\(\s*(?:[A-Za-z0-9_]+\.map|items\.map)|asyncio\.gather\s*\(\s*\*\s*\[)"
        ),
        "Unbounded concurrent tasks over a collection may exhaust memory or connection pools.",
        "Throttle concurrent execution using a semaphore, p-limit, or batch queue.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP501",
        "Unmetered AI/LLM API route",
        "scale",
        "high",
        "medium",
        compile_pattern(
            r"(?:openai\.(?:chat\.completions|completions|images)\.create|anthropic\.messages\.create|genai\.generate_content|google\.generativeai)\b"
        ),
        "An AI/LLM API call is executed in application code; ensure it is protected by authentication and rate limiting.",
        "Add user authentication, rate limits (e.g. 5 req/min), and per-user credit quotas before calling LLM endpoints.",
        "CWE-400",
        "Cost & Capacity",
    ),
    Rule(
        "SP502",
        "Insecure payment webhook handler",
        "security",
        "critical",
        "high",
        compile_pattern(r"stripe\.webhooks\.constructEvent\s*\(\s*req\.body\b"),
        "Stripe webhook handler passes parsed JSON body instead of raw buffer, causing verification failure.",
        "Pass the raw request buffer to stripe.webhooks.constructEvent using express.raw({ type: 'application/json' }).",
        "CWE-345",
        "OWASP ASVS V13",
    ),
    Rule(
        "SP503",
        "Leaked Supabase service role key",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"(?:NEXT_PUBLIC_[A-Z0-9_]*SUPABASE_SERVICE_ROLE_KEY|NEXT_PUBLIC_[A-Z0-9_]*SERVICE_ROLE|createClient\s*\([^)]*NEXT_PUBLIC_[^)]*SERVICE)"
        ),
        "A Supabase service_role key is exposed to client-side code, completely bypassing Row Level Security (RLS).",
        "Move the service_role key to a server-only environment variable without any client-side prefix.",
        "CWE-200",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP313",
        "Non-singleton database client in serverless",
        "scale",
        "high",
        "medium",
        compile_pattern(r"new\s+PrismaClient\s*\(\s*\)"),
        "Instantiating database clients inside serverless route files can rapidly exhaust database connection limits.",
        "Use a global singleton instance (e.g. globalThis.prisma) and connect through a connection pooler.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP307",
        "N+1 database query in loop",
        "scale",
        "high",
        "high",
        compile_pattern("$^"),
        "A database query is executed inside an iteration loop, multiplying query volume and latency.",
        "Fetch required rows in a single batch query (e.g. using WHERE id IN (...)) or eager loading before the loop.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP112",
        "Unsanitized SVG upload accepted",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"(?:accept\s*[:=]\s*[\"'][^\"']*image/svg\+xml|\.svg[\"']\s*,\s*[\"']\.(?:png|jpe?g)|allowedExtensions\s*[:=]\s*\[[^\]]*[\"']\.?svg[\"'])"
        ),
        "User file upload allows SVG files without visible sanitization, exposing users to Stored XSS.",
        "Sanitize uploaded SVGs with an XML sanitizer, serve with Content-Disposition: attachment, or convert to PNG.",
        "CWE-79",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP113",
        "PHP object injection via unserialize",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"\bunserialize\s*\(\s*(?:\$_(?:GET|POST|COOKIE|REQUEST|SERVER)|[\$a-zA-Z0-9_]+)"
        ),
        "unserialize() on untrusted input allows object injection and arbitrary code execution.",
        "Replace unserialize() with json_decode() or use an allowlisted, signature-verified parser.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP114",
        "Catastrophic ReDoS nested quantifier",
        "security",
        "medium",
        "medium",
        compile_pattern(r"\([a-zA-Z0-9_\.\-\^\$]+(?:\+|\*)\)(?:\+|\*)"),
        "Nested quantifiers in regular expressions can cause exponential backtracking (ReDoS) and freeze event loops.",
        "Rewrite the regular expression without nested quantifiers or use an atomic group / non-backtracking regex.",
        "CWE-1333",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP115",
        "XXE-capable lxml parser without entity hardening",
        "security",
        "medium",
        "low",
        compile_pattern("$^"),
        "lxml parsing is used without a parser that disables entity resolution, enabling XML external entity attacks.",
        "Construct an etree.XMLParser with resolve_entities=False (and no_network=True) or validate input before parsing.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP116",
        "React dangerouslySetInnerHTML with dynamic value",
        "security",
        "high",
        "medium",
        compile_pattern(r"dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*[^\"'\s}]"),
        "dangerouslySetInnerHTML renders a dynamic value as raw HTML, which becomes XSS when the value carries user input.",
        "Render text normally, or sanitize the HTML with DOMPurify before assigning it to __html.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP117",
        "Dynamic code via new Function",
        "security",
        "high",
        "medium",
        compile_pattern(r"\bnew\s+Function\s*\("),
        "new Function() compiles a string into executable code, turning untrusted input into arbitrary code execution.",
        "Replace dynamic compilation with explicit logic or a safe parser (e.g. JSON.parse).",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP118",
        "Implicit eval via timer string",
        "security",
        "medium",
        "high",
        compile_pattern(r"\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]"),
        "A string passed to setTimeout/setInterval is compiled and executed as code, allowing injection.",
        "Pass a function reference instead of a string of code.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP119",
        "Filesystem path joined from request input",
        "security",
        "high",
        "medium",
        compile_pattern(r"path\s*\.\s*join(?:Sync)?\s*\([^)]*\breq\s*\.\s*(?:params|query|body)"),
        "A filesystem path is joined directly from request data, allowing path traversal outside the intended directory.",
        "Validate the request value against an allowlist and resolve the final path inside a fixed base directory.",
        "CWE-22",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP120",
        "Unsafe JS deserialization via node-serialize",
        "security",
        "critical",
        "high",
        compile_pattern("$^"),
        "node-serialize unserialize() executes arbitrary code embedded in the serialized payload.",
        "Exchange JSON instead of serialized JavaScript objects and reject serialized input entirely.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP121",
        "Open redirect from request value",
        "security",
        "medium",
        "medium",
        compile_pattern(r"redirect\s*\(\s*(?:req|request)\s*\."),
        "A redirect target is taken directly from request input, enabling open-redirect phishing attacks.",
        "Redirect only to validated allowlisted paths or relative URLs.",
        "CWE-601",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".py"}),
    ),
    Rule(
        "SP122",
        "Security value from insecure randomness",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:token|secret|api[_-]?key|password|session\w*|otp|nonce|salt|csrf\w*)\s*[:=]\s*[^;#\n]*(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice|randrange|uniform)\s*\()"
        ),
        "A security-sensitive value is generated from a predictable PRNG instead of a cryptographic source.",
        "Generate tokens and secrets with the Web Crypto API or the Python secrets module.",
        "CWE-338",
        "OWASP ASVS V6",
    ),
    Rule(
        "SP123",
        "Hardcoded initialization vector",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"createCipheriv\s*\([^()]*,[^()]*,\s*[\"'][A-Za-z0-9+/=]{8,}[\"']|AES\.new\s*\([^()]*,\s*[^(),]+,\s*iv\s*=\s*b?[\"'][A-Za-z0-9+/=]{8,}[\"']"
        ),
        "A cipher is used with a hardcoded initialization vector, which defeats CBC/CTR semantic security.",
        "Generate a random IV per message with a cryptographic source and transmit it alongside the ciphertext.",
        "CWE-329",
        "OWASP ASVS V8",
    ),
    Rule(
        "SP124",
        "SSRF via user-controlled request URL",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:\bfetch\s*\(|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\()\s*[^)]*\breq\s*\.\s*(?:query|params|body)"
        ),
        "An outbound HTTP call uses a URL taken from request input, allowing SSRF against internal networks and cloud metadata.",
        "Validate target URLs against an explicit host allowlist and reject private IP ranges.",
        "CWE-918",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP125",
        "Angular sanitizer bypass",
        "security",
        "high",
        "medium",
        compile_pattern(r"bypassSecurityTrust(?:Html|Style|Url|ResourceUrl|Script)"),
        "A DomSanitizer bypass method trusts user-influenced content that Angular would otherwise escape.",
        "Remove the bypass or sanitize the value first; never trust raw user content with these methods.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP126",
        "Auth token stored in web storage",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*[\"'][^\"']*(?:token|auth|jwt|secret|session)"
        ),
        "An authentication token is stored in web storage, readable by any injected script.",
        "Keep tokens in httpOnly cookies or in-memory stores; web storage is script-accessible.",
        "CWE-922",
        "OWASP ASVS V3",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP127",
        "PHP loose comparison on credential",
        "security",
        "high",
        "medium",
        compile_pattern(r"\$(?:password|passwd|secret|token|api[_-]?key)\w*\s*==(?!=)"),
        "PHP type juggling can make loose comparisons behave unexpectedly when validating credentials.",
        "Use === or password_verify for credential checks.",
        "CWE-480",
        "OWASP ASVS V2",
        frozenset({".php"}),
    ),
    Rule(
        "SP128",
        "PHP SQL with interpolated variables",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"(?:mysqli?_query|->query|->exec|->prepare)\s*\([^)]*\$_(?:GET|POST|REQUEST)|[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\$[a-zA-Z_]"
        ),
        "A PHP database call interpolates variables or superglobals into the SQL text.",
        "Use prepared statements with bound parameters.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP129",
        "PHP reflected XSS via echoed superglobal",
        "security",
        "high",
        "medium",
        compile_pattern(r"(?:echo|print)\s+\$_(?:GET|POST|REQUEST)\s*\["),
        "Request data is echoed without htmlspecialchars, reflecting attacker-controlled HTML.",
        "Escape output with htmlspecialchars or render through a template engine.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP130",
        "PHP open redirect via Location header",
        "security",
        "medium",
        "medium",
        compile_pattern(r"header\s*\(\s*[\"']Location\s*:[^)]*\$_(?:GET|POST|REQUEST)"),
        "The redirect target is built from request input, enabling phishing redirects.",
        "Redirect only to allowlisted absolute paths.",
        "CWE-601",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP131",
        "Go HTTP server without timeouts",
        "reliability",
        "medium",
        "low",
        compile_pattern("$^"),
        "An http.Server is configured without read/write timeouts, exposing the service to slow-client resource exhaustion.",
        "Set ReadTimeout, WriteTimeout, ReadHeaderTimeout, and IdleTimeout on every http.Server.",
        "CWE-1088",
        "OWASP ASVS V12",
        frozenset({".go"}),
    ),
    Rule(
        "SP132",
        ".NET sync-over-async blocking",
        "reliability",
        "medium",
        "low",
        compile_pattern(r"GetAwaiter\s*\(\s*\)\s*\.\s*GetResult\s*\(|\.Wait\s*\(\s*\)"),
        "Blocking on a Task in a context with a synchronization context deadlocks or starves threads.",
        "Go async all the way; use await instead of blocking on tasks.",
        "CWE-667",
        "OWASP ASVS V12",
        frozenset({".cs"}),
    ),
    Rule(
        "SP133",
        "ASP.NET debug compilation enabled",
        "security",
        "medium",
        "high",
        compile_pattern(r"debug\s*=\s*[\"']true[\"']"),
        "ASP.NET debug mode ships verbose errors and debugging behavior to production.",
        "Set debug to false and use release configuration transforms.",
        "CWE-489",
        "OWASP ASVS V14",
        frozenset({".config"}),
    ),
    Rule(
        "SP134",
        "Assertion used as authorization",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"assert\s+[^#\n]*(?:is_admin|is_superuser|has_role|has_permission|authorized|is_owner)"
        ),
        "assert statements are stripped under python -O, silently removing the authorization check in production.",
        "Raise an explicit 403 through application logic instead of asserting access.",
        "CWE-863",
        "OWASP ASVS V4",
        frozenset({".py"}),
    ),
    Rule(
        "SP135",
        "Unbounded C string function",
        "security",
        "high",
        "high",
        compile_pattern(r"\b(?:strcpy|strcat|sprintf|gets|stpcpy)\s*\("),
        "A C string function with no bound check allows buffer overflow when input length is uncontrolled.",
        "Use bounded equivalents (strncpy/snprintf/strlcpy) or explicit length-checked copies.",
        "CWE-120",
        "OWASP ASVS V5",
        frozenset({".c", ".h", ".cpp", ".hpp"}),
    ),
    Rule(
        "SP136",
        "Go error explicitly discarded",
        "reliability",
        "medium",
        "low",
        compile_pattern(r"_, _\s*:?=|\b_\s*=\s*err\b"),
        "Return values including errors are discarded, hiding failures until they surface as corruption downstream.",
        "Handle the error or annotate the discard with an explicit reason comment.",
        "CWE-754",
        "OWASP ASVS V7",
        frozenset({".go"}),
    ),
    Rule(
        "SP314",
        "Committed SQLite database file",
        "security",
        "high",
        "high",
        compile_pattern("$^"),
        "An SQLite database file is tracked in source control, which may expose private data or tokens.",
        "Remove the database file from git history, add *.sqlite, *.sqlite3, *.db to .gitignore, and use migrations.",
        "CWE-200",
        "OWASP ASVS V14",
    ),
    Rule(
        "SP315",
        "Go HTTP request missing response body close",
        "correctness",
        "high",
        "medium",
        compile_pattern(r"(?:resp|res),\s*(?:err|_)\s*:=\s*http\.(?:Get|Post|Head)\s*\("),
        "An HTTP response body in Go is not visibly closed, which can leak TCP connections and goroutines.",
        "Add defer resp.Body.Close() immediately after error checking and drain the body if unread.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP316",
        "Outbound HTTP call inside database transaction",
        "scale",
        "high",
        "medium",
        compile_pattern("$^"),
        "An outbound HTTP network call is executed inside a database transaction block, risking connection pool starvation.",
        "Move external network requests outside the database transaction boundary.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP317",
        "Blocking call in async def coroutine",
        "scale",
        "high",
        "high",
        compile_pattern("$^"),
        "A synchronous blocking operation (e.g. time.sleep or requests.get) is called directly inside an async def coroutine.",
        "Use non-blocking async equivalents (e.g. asyncio.sleep, httpx.AsyncClient) or wrap in asyncio.to_thread().",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP318",
        "Retry policy without a stop condition",
        "reliability",
        "medium",
        "medium",
        compile_pattern("$^"),
        "A retry loop is configured without a bound, so a failing dependency amplifies load into a retry storm.",
        "Add an explicit stop condition (tenacity stop_after_attempt, bounded retries) and backoff with jitter.",
        "CWE-770",
        "OWASP ASVS V14",
    ),
)


DATABASE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}


def is_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in TEXT_SUFFIXES or suffix in DATABASE_SUFFIXES or path.name.lower() in TEXT_NAMES


def normalize_exclude_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in patterns:
        pattern = value.replace("\\", "/").removeprefix("./")
        if (
            not pattern
            or pattern.startswith("/")
            or "\x00" in pattern
            or ".." in pattern.split("/")
            or len(pattern) > 512
        ):
            raise ValueError(f"unsafe exclude pattern: {value!r}")
        normalized.append(pattern)
    return tuple(dict.fromkeys(normalized))


def is_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(relative_path, pattern):
            return True
        if pattern.endswith("/**") and relative_path == pattern.removesuffix("/**"):
            return True
    return False


def iter_scannable_files(
    root: Path,
    max_file_bytes: int,
    exclude_patterns: Sequence[str] = (),
) -> Iterable[Path]:
    """Walk deterministically while pruning ignored trees before descending into them."""
    for directory, subdirectories, filenames in os.walk(root, topdown=True, onerror=lambda _: None):
        relative_directory = Path(directory).relative_to(root)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in SKIP_DIRS
            and not is_excluded(
                (relative_directory / name).as_posix().removeprefix("./"),
                exclude_patterns,
            )
        )
        for filename in sorted(filenames):
            path = Path(directory, filename)
            if path.is_symlink():
                continue
            if not is_text_file(path):
                continue
            relative_path = path.relative_to(root).as_posix()
            if is_excluded(relative_path, exclude_patterns):
                continue
            try:
                if path.stat().st_size <= max_file_bytes:
                    yield path
            except OSError:
                continue


def clean_evidence(line: str, redact: bool) -> str:
    compact = line.strip().replace("\t", " ")[:240]
    return "[REDACTED: credential-like material]" if redact else compact


def is_pure_comment(line: str, path: Path) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in {
        ".py",
        ".pyi",
        ".sh",
        ".bash",
        ".ps1",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".env",
        ".rb",
        ".graphql",
        ".gql",
    } or name in {"dockerfile", "containerfile", "makefile", "procfile", ".env"}:
        return stripped.startswith("#")
    if suffix in {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".kt",
        ".kts",
        ".go",
        ".rs",
        ".cs",
        ".php",
    }:
        return stripped.startswith(("//", "/*", "*"))
    if suffix == ".sql":
        return stripped.startswith(("--", "/*", "*"))
    if suffix in {".tf", ".hcl"}:
        return stripped.startswith(("#", "//"))
    return False


def make_finding(
    rule: Rule,
    relative_path: str,
    line_number: int,
    evidence: str,
    detection: str = "pattern",
) -> Finding:
    safe_evidence = clean_evidence(evidence, rule.redact)
    if rule.redact:
        content_hash = hashlib.sha256(evidence.strip().encode("utf-8", "replace")).hexdigest()[:12]
        identity = f"{rule.rule_id}:{relative_path}:{content_hash}"
    else:
        identity = f"{rule.rule_id}:{relative_path}:{safe_evidence}"
    fingerprint = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]
    return Finding(
        rule.rule_id,
        rule.title,
        rule.category,
        rule.severity,
        rule.confidence,
        relative_path,
        line_number,
        safe_evidence,
        rule.message,
        rule.remediation,
        rule.cwe,
        rule.owasp,
        fingerprint,
        detection,
        PROOF_LEVELS[detection],
    )


FILE_LEVEL_RULE_IDS = frozenset(
    {
        "SP107",
        "SP131",
        "SP108",
        "SP115",
        "SP120",
        "SP303",
        "SP304",
        "SP305",
        "SP307",
        "SP314",
        "SP316",
        "SP317",
        "SP318",
        "SP401",
        "SP402",
        "SP407",
        "SP408",
    }
)

APPLICABLE_RULES_CACHE: dict[tuple[str, bool, bool], tuple[tuple[Rule, bool], ...]] = {}


def applicable_line_rules(
    suffix: str, is_document: bool, is_manifest_name: bool
) -> tuple[tuple[Rule, bool], ...]:
    """Resolve the line-scanned rules once per file class instead of per file."""
    cache_key = (suffix, is_document, is_manifest_name)
    cached = APPLICABLE_RULES_CACHE.get(cache_key)
    if cached is not None:
        return cached
    selected = [
        (rule, rule.rule_id in SECRET_RULE_IDS)
        for rule in RULES
        if rule.rule_id not in FILE_LEVEL_RULE_IDS
        and not (rule.rule_id == "SP202" and not is_manifest_name)
        and not (is_document and rule.rule_id not in SECRET_RULE_IDS)
        and not (rule.suffixes and suffix not in rule.suffixes)
    ]
    resolved = tuple(selected)
    APPLICABLE_RULES_CACHE[cache_key] = resolved
    return resolved


def find_regex_issues(path: Path, relative_path: str, source_text: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    lines = source_text.splitlines()
    comment_flags = [is_pure_comment(line, path) for line in lines]
    ignore_rule_ids = [
        match.group(1) if (match := INLINE_IGNORE.search(line)) else None for line in lines
    ]
    applicable_rules = applicable_line_rules(
        suffix,
        suffix in DOCUMENT_SUFFIXES,
        path.name.lower() in {"dockerfile", "containerfile"},
    )
    for rule, rule_is_secret in applicable_rules:
        rule_id = rule.rule_id
        pattern_search = rule.pattern.search
        for index, line in enumerate(lines):
            if not rule_is_secret and comment_flags[index]:
                continue
            if ignore_rule_ids[index] == rule_id:
                continue
            if index >= 1 and ignore_rule_ids[index - 1] == rule_id:
                continue
            if pattern_search(line) and not (rule_is_secret and PLACEHOLDERS.search(line)):
                findings.append(make_finding(rule, relative_path, index + 1, line))

    if (
        suffix == ".py"
        and re.search(r"allow_origins\s*=\s*\[[\"']\*[\"']\]", source_text)
        and re.search(r"allow_credentials\s*=\s*True", source_text)
    ):
        line = next((i for i, value in enumerate(lines, 1) if "allow_origins" in value), 1)
        rule = Rule(
            "SP107",
            "Credentialed wildcard CORS",
            "security",
            "high",
            "high",
            compile_pattern("$^"),
            "Wildcard origins and credentials create an unsafe cross-origin policy.",
            "Allowlist exact trusted origins and test preflight behavior.",
            "CWE-942",
            "OWASP ASVS V3",
        )
        findings.append(
            make_finding(rule, relative_path, line, lines[line - 1] if lines else "", "structural")
        )

    if (
        suffix in {".js", ".mjs", ".cjs", ".ts"}
        and re.search(r"origin\s*:\s*(?:true|[\"']\*[\"'])", source_text)
        and re.search(r"credentials\s*:\s*true", source_text)
    ):
        line = next((i for i, value in enumerate(lines, 1) if "origin" in value), 1)
        rule = Rule(
            "SP107",
            "Credentialed wildcard CORS",
            "security",
            "high",
            "high",
            compile_pattern("$^"),
            "Wildcard origins and credentials create an unsafe cross-origin policy.",
            "Allowlist exact trusted origins and test preflight behavior.",
            "CWE-942",
            "OWASP ASVS V3",
        )
        findings.append(
            make_finding(rule, relative_path, line, lines[line - 1] if lines else "", "structural")
        )

    # Framework-specific: Express without helmet
    if (
        suffix in {".js", ".mjs", ".cjs", ".ts"}
        and "express()" in source_text.lower().replace(" ", "")
        and "helmet" not in source_text.lower()
    ):
        express_line = next(
            (
                i
                for i, v in enumerate(lines, 1)
                if re.search(r"express\s*\(\s*\)", v, re.IGNORECASE)
            ),
            None,
        )
        if express_line:
            line_str = lines[express_line - 1]
            prev_line_str = lines[express_line - 2] if express_line >= 2 else ""
            ignore_curr = INLINE_IGNORE.search(line_str)
            ignore_prev = INLINE_IGNORE.search(prev_line_str)
            if not (
                (ignore_curr and ignore_curr.group(1) == "SP401")
                or (ignore_prev and ignore_prev.group(1) == "SP401")
            ):
                rule = find_rule("SP401")
                findings.append(
                    make_finding(rule, relative_path, express_line, line_str, "structural")
                )

    # Framework-specific: Express auth route without rate limiting
    if (
        suffix in {".js", ".mjs", ".cjs", ".ts"}
        and "express()" in source_text.lower().replace(" ", "")
        and not RATE_LIMIT_MARKERS.search(source_text)
    ):
        route_line = next(
            (i for i, value in enumerate(lines, 1) if AUTH_SENSITIVE_ROUTE.search(value)),
            None,
        )
        if route_line:
            append_file_level_finding(findings, "SP402", relative_path, lines, route_line)

    # Framework-specific: cookie-session routes without CSRF protection
    if (
        suffix in {".js", ".mjs", ".cjs", ".ts"}
        and "express()" in source_text.lower().replace(" ", "")
        and COOKIE_SESSION_MARKERS.search(source_text)
        and not CSRF_MARKERS.search(source_text)
    ):
        route_line = next(
            (i for i, value in enumerate(lines, 1) if STATE_CHANGING_ROUTE.search(value)),
            None,
        )
        if route_line:
            append_file_level_finding(findings, "SP407", relative_path, lines, route_line)

    # Framework-specific: Next.js/Nuxt config without a CSP header
    if META_FRAMEWORK_CONFIG_NAME.match(path.name.lower()) and not CSP_MARKERS.search(source_text):
        append_file_level_finding(findings, "SP408", relative_path, lines, 1)

    # XXE: lxml parsing without entity hardening
    if suffix == ".py" and "lxml" in source_text and "resolve_entities" not in source_text:
        lxml_line = next(
            (i for i, value in enumerate(lines, 1) if LXML_PARSE_CALL.search(value)),
            None,
        )
        if lxml_line:
            append_file_level_finding(findings, "SP115", relative_path, lines, lxml_line)

    # Unsafe JS deserialization: node-serialize
    if NODE_SERIALIZE_REQUIRE.search(source_text) and UNSERIALIZE_CALL.search(source_text):
        unserialize_line = next(
            (i for i, value in enumerate(lines, 1) if UNSERIALIZE_CALL.search(value)),
            None,
        )
        if unserialize_line:
            append_file_level_finding(findings, "SP120", relative_path, lines, unserialize_line)

    # Reliability: retry policy without a stop condition
    if (
        suffix == ".py"
        and TENACITY_RETRY.search(source_text)
        and not STOP_CONDITION_HINT.search(source_text)
    ):
        retry_line = next(
            (i for i, value in enumerate(lines, 1) if TENACITY_RETRY.search(value)),
            None,
        )
        if retry_line:
            append_file_level_finding(findings, "SP318", relative_path, lines, retry_line)
    if UNBOUNDED_JS_RETRIES.search(source_text):
        retry_line = next(
            (i for i, value in enumerate(lines, 1) if UNBOUNDED_JS_RETRIES.search(value)),
            None,
        )
        if retry_line:
            append_file_level_finding(findings, "SP318", relative_path, lines, retry_line)

    # Reliability: Go http.Server without timeouts
    if (
        suffix == ".go"
        and GO_HTTP_SERVER_INIT.search(source_text)
        and "ReadTimeout" not in source_text
    ):
        server_line = next(
            (i for i, value in enumerate(lines, 1) if GO_HTTP_SERVER_INIT.search(value)),
            None,
        )
        if server_line:
            append_file_level_finding(findings, "SP131", relative_path, lines, server_line)

    return findings


def resolve_dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
SENSITIVE_ROUTE_SEGMENTS = frozenset({"admin", "internal", "management"})
AUTHORIZATION_DEPENDENCY_HINTS = ("auth", "admin", "permission", "policy", "role", "scope")
PAGE_SIZE_PARAMETERS = frozenset({"limit", "page_size", "per_page"})
RATE_LIMIT_MARKERS = re.compile(r"rate[-_]?limit|limiter|throttle", re.IGNORECASE)
AUTH_SENSITIVE_ROUTE = re.compile(
    r"\.\s*(?:post|use|all)\s*\(\s*[\"'][^\"']*(?:login|sign-?in|auth|session|token|password)",
    re.IGNORECASE,
)
COOKIE_SESSION_MARKERS = re.compile(
    r"cookie[-_]?parser|express-session|req\.cookies|req\.session", re.IGNORECASE
)
CSRF_MARKERS = re.compile(r"csurf|csrf", re.IGNORECASE)
STATE_CHANGING_ROUTE = re.compile(r"\.\s*(?:post|put|patch|delete)\s*\(", re.IGNORECASE)
CSP_MARKERS = re.compile(r"content[-_]?security[-_]?policy|\bcsp\b", re.IGNORECASE)
META_FRAMEWORK_CONFIG_NAME = re.compile(r"(?:next|nuxt)\.config\.(?:js|mjs|cjs|ts)$")
LXML_PARSE_CALL = re.compile(r"\betree\s*\.\s*(?:parse|fromstring|XML|frombuffer)\s*\(")
NODE_SERIALIZE_REQUIRE = re.compile(r"require\s*\(\s*[\"']node-serialize[\"']\s*\)")
UNSERIALIZE_CALL = re.compile(r"\.\s*unserialize\s*\(")
TENACITY_RETRY = re.compile(r"@retry\s*\(")
STOP_CONDITION_HINT = re.compile(r"\bstop")
UNBOUNDED_JS_RETRIES = re.compile(r"retries\s*:\s*Infinity\b", re.IGNORECASE)
GO_HTTP_SERVER_INIT = re.compile(r"http\.Server\s*\{")


def find_rule(rule_id: str) -> Rule:
    return next(rule for rule in RULES if rule.rule_id == rule_id)


def append_file_level_finding(
    findings: list[Finding],
    rule_id: str,
    relative_path: str,
    lines: Sequence[str],
    line_number: int,
) -> None:
    line_str = lines[line_number - 1] if 1 <= line_number <= len(lines) else ""
    prev_line_str = lines[line_number - 2] if line_number >= 2 else ""
    ignore_curr = INLINE_IGNORE.search(line_str)
    ignore_prev = INLINE_IGNORE.search(prev_line_str)
    if (ignore_curr and ignore_curr.group(1) == rule_id) or (
        ignore_prev and ignore_prev.group(1) == rule_id
    ):
        return
    findings.append(
        make_finding(find_rule(rule_id), relative_path, line_number, line_str, "structural")
    )


def route_decorator_calls(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    route_calls: list[ast.Call] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        method = resolve_dotted_name(decorator.func).rsplit(".", 1)[-1].lower()
        if method in ROUTE_METHODS:
            route_calls.append(decorator)
    return route_calls


def route_path(route_call: ast.Call) -> str | None:
    if not route_call.args:
        return None
    value = route_call.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def find_authorized_routers(tree: ast.AST) -> set[str]:
    authorized_routers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func_name = resolve_dotted_name(node.value.func).rsplit(".", 1)[-1]
            if func_name in {"APIRouter", "FastAPI"}:
                for kw in node.value.keywords:
                    if kw.arg == "dependencies":
                        for child in ast.walk(kw.value):
                            if (
                                isinstance(child, ast.Call)
                                and resolve_dotted_name(child.func).rsplit(".", 1)[-1] == "Depends"
                                and child.args
                                and any(
                                    hint in resolve_dotted_name(child.args[0]).lower()
                                    for hint in AUTHORIZATION_DEPENDENCY_HINTS
                                )
                            ):
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        authorized_routers.add(target.id)
    return authorized_routers


def has_visible_authorization_dependency(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_calls: Sequence[ast.Call],
) -> bool:
    candidates: list[ast.AST] = [
        *node.args.defaults,
        *(value for value in node.args.kw_defaults if value is not None),
        *(
            argument.annotation
            for argument in [*node.args.args, *node.args.kwonlyargs]
            if argument.annotation
        ),
    ]
    for route_call in route_calls:
        candidates.extend(
            keyword.value for keyword in route_call.keywords if keyword.arg == "dependencies"
        )
    for candidate in candidates:
        for child in ast.walk(candidate):
            if not isinstance(child, ast.Call):
                continue
            if resolve_dotted_name(child.func).rsplit(".", 1)[-1] != "Depends" or not child.args:
                continue
            dependency_name = resolve_dotted_name(child.args[0]).lower()
            if any(hint in dependency_name for hint in AUTHORIZATION_DEPENDENCY_HINTS):
                return True
    return False


def parameter_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.AST | None]]:
    positional = [*node.args.posonlyargs, *node.args.args]
    positional_defaults: list[ast.AST | None] = [None] * (
        len(positional) - len(node.args.defaults)
    ) + list(node.args.defaults)
    return [
        *zip(positional, positional_defaults, strict=True),
        *zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True),
    ]


def has_page_size_bound(argument: ast.arg, default: ast.AST | None) -> bool:
    candidates = [value for value in (argument.annotation, default) if value is not None]
    for candidate in candidates:
        for child in ast.walk(candidate):
            if not isinstance(child, ast.Call):
                continue
            validator = resolve_dotted_name(child.func).rsplit(".", 1)[-1]
            if validator not in {"Query", "Field"}:
                continue
            if any(
                keyword.arg == "le" and isinstance(keyword.value, ast.Constant)
                for keyword in child.keywords
            ):
                return True
    return False


def is_interpolated_sql_value(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(
            isinstance(child, ast.Constant) and isinstance(child.value, str)
            for child in ast.walk(node)
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    )


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(
        self,
        relative_path: str,
        source_lines: Sequence[str],
        authorized_routers: set[str] | None = None,
    ) -> None:
        self.relative_path = relative_path
        self.source_lines = source_lines
        self.authorized_routers = authorized_routers or set()
        self.findings: list[Finding] = []
        self.async_function_depth = 0
        self.loop_depth = 0
        self.transaction_depth = 0

    def add_finding(self, rule: Rule, node: ast.AST) -> None:
        line_number = getattr(node, "lineno", 1)
        evidence = (
            self.source_lines[line_number - 1] if 0 < line_number <= len(self.source_lines) else ""
        )
        self.findings.append(make_finding(rule, self.relative_path, line_number, evidence, "ast"))

    def inspect_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        route_calls = route_decorator_calls(node)
        if not route_calls:
            return
        sensitive_route = next(
            (
                route_call
                for route_call in route_calls
                if (path := route_path(route_call))
                and SENSITIVE_ROUTE_SEGMENTS.intersection(path.lower().split("/"))
            ),
            None,
        )
        if sensitive_route:
            caller_name = resolve_dotted_name(sensitive_route.func).split(".", 1)[0]
            is_router_authorized = caller_name in self.authorized_routers
            if not is_router_authorized and not has_visible_authorization_dependency(
                node, route_calls
            ):
                self.add_finding(find_rule("SP108"), sensitive_route)
        for argument, default in parameter_defaults(node):
            if argument.arg in PAGE_SIZE_PARAMETERS and not has_page_size_bound(argument, default):
                self.add_finding(find_rule("SP305"), argument)

    def visit_For(self, node: ast.For) -> None:
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_With(self, node: ast.With) -> None:
        is_tx = any(
            (
                resolve_dotted_name(item.context_expr)
                .lower()
                .endswith((".transaction", ".begin", ".atomic"))
                or (
                    isinstance(item.context_expr, ast.Call)
                    and resolve_dotted_name(item.context_expr.func)
                    .lower()
                    .endswith((".transaction", ".begin", ".atomic"))
                )
            )
            for item in node.items
        )
        if is_tx:
            self.transaction_depth += 1
        self.generic_visit(node)
        if is_tx:
            self.transaction_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        is_tx = any(
            (
                resolve_dotted_name(item.context_expr)
                .lower()
                .endswith((".transaction", ".begin", ".atomic"))
                or (
                    isinstance(item.context_expr, ast.Call)
                    and resolve_dotted_name(item.context_expr.func)
                    .lower()
                    .endswith((".transaction", ".begin", ".atomic"))
                )
            )
            for item in node.items
        )
        if is_tx:
            self.transaction_depth += 1
        self.generic_visit(node)
        if is_tx:
            self.transaction_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.inspect_route(node)
        self.async_function_depth += 1
        self.generic_visit(node)
        self.async_function_depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.inspect_route(node)
        previous_depth = self.async_function_depth
        self.async_function_depth = 0
        self.generic_visit(node)
        self.async_function_depth = previous_depth

    def visit_Call(self, node: ast.Call) -> None:
        name = resolve_dotted_name(node.func)
        method = name.rsplit(".", 1)[-1]
        if (
            method in {"execute", "query", "raw"}
            and node.args
            and is_interpolated_sql_value(node.args[0])
        ):
            self.add_finding(find_rule("SP103"), node.args[0])
        if self.loop_depth > 0:
            receiver = name.split(".", 1)[0].lower() if "." in name else ""
            if method in {"query", "execute", "filter", "filter_by", "find_one", "fetch_one"} or (
                receiver in {"db", "session", "cursor", "repo", "conn", "orm"}
                and method in {"get", "find", "select"}
            ):
                self.add_finding(find_rule("SP307"), node)
        is_http_request = name in {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.patch",
            "httpx.delete",
            "client.get",
            "client.post",
            "client.put",
            "client.delete",
            "session.get",
            "session.post",
            "session.put",
            "session.delete",
            "http_client.get",
            "http_client.post",
        } or (
            method in {"get", "post", "put", "patch", "delete"}
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id.lower()
            in {"client", "session", "http", "http_client", "api_client", "s"}
        )
        if is_http_request and not any(keyword.arg == "timeout" for keyword in node.keywords):
            self.add_finding(find_rule("SP304"), node)
        if self.transaction_depth > 0 and is_http_request:
            self.add_finding(find_rule("SP316"), node)
        if self.async_function_depth > 0:
            if name == "time.sleep":
                self.add_finding(find_rule("SP303"), node)
            elif name in {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.delete",
                "urllib.request.urlopen",
            }:
                self.add_finding(find_rule("SP317"), node)
        self.generic_visit(node)


def find_python_ast_issues(relative_path: str, source_text: str) -> list[Finding]:
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError):
        return []
    authorized_routers = find_authorized_routers(tree)
    visitor = PythonSecurityVisitor(
        relative_path, source_lines=source_text.splitlines(), authorized_routers=authorized_routers
    )
    visitor.visit(tree)
    return visitor.findings


def lint_source_snippet(source_text: str, filename: str = "snippet.py") -> list[Finding]:
    """Lint an in-memory code snippet without reading from disk."""
    path = Path(filename)
    findings = find_regex_issues(path, filename, source_text)
    if path.suffix.lower() == ".py":
        findings.extend(find_python_ast_issues(filename, source_text))
    active, _ = deduplicate_and_suppress_findings(findings)
    return active


def load_baseline_fingerprints(path: Path | None) -> set[str]:
    if path is None:
        return set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = payload.get("fingerprints", [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("baseline must contain a string array named 'fingerprints'")
    return set(values)


def deduplicate_and_suppress_findings(
    findings: Iterable[Finding],
    baseline: set[str] | None = None,
) -> tuple[list[Finding], int]:
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line)
        if key not in unique:
            unique[key] = finding
    active: list[Finding] = []
    suppressed_count = 0
    baseline_set = baseline or set()
    for finding in unique.values():
        if finding.fingerprint in baseline_set:
            suppressed_count += 1
        else:
            active.append(finding)
    active.sort(
        key=lambda item: (
            SEVERITY[item.severity],
            CONFIDENCE[item.confidence],
            item.path,
            item.line,
        )
    )
    return active, suppressed_count


def detect_frameworks(root: Path) -> set[str]:
    """Detect frameworks and runtimes from manifest files in the repository root."""
    frameworks: set[str] = set()

    # 1. Node.js / TypeScript (package.json)
    pkg_path = root / "package.json"
    if pkg_path.is_file():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            all_deps: dict[str, str] = {}
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                val = pkg.get(key)
                if isinstance(val, dict):
                    all_deps.update(val)
            # Fullstack & Frontend
            if "next" in all_deps:
                frameworks.add("nextjs")
            if "nuxt" in all_deps or "nuxt3" in all_deps:
                frameworks.add("nuxt")
            if "@sveltejs/kit" in all_deps:
                frameworks.add("sveltekit")
            if "@remix-run/react" in all_deps or "@remix-run/node" in all_deps:
                frameworks.add("remix")
            if "astro" in all_deps:
                frameworks.add("astro")
            if "vue" in all_deps:
                frameworks.add("vue")
            if "@angular/core" in all_deps:
                frameworks.add("angular")
            if "react" in all_deps and "next" not in all_deps:
                frameworks.add("react")
            if "solid-js" in all_deps:
                frameworks.add("solid")
            # Backend
            if "express" in all_deps:
                frameworks.add("express")
            if "fastify" in all_deps:
                frameworks.add("fastify")
            if "@nestjs/core" in all_deps:
                frameworks.add("nestjs")
            if "koa" in all_deps:
                frameworks.add("koa")
            if "hono" in all_deps:
                frameworks.add("hono")
            if "elysia" in all_deps:
                frameworks.add("elysia")
            # ORMs & DBs
            if "@prisma/client" in all_deps or "prisma" in all_deps:
                frameworks.add("prisma")
            if "drizzle-orm" in all_deps:
                frameworks.add("drizzle")
            if "typeorm" in all_deps:
                frameworks.add("typeorm")
            if "mongoose" in all_deps:
                frameworks.add("mongoose")
            if "@supabase/supabase-js" in all_deps:
                frameworks.add("supabase")
        except (OSError, json.JSONDecodeError):
            pass

    # 2. Python (pyproject.toml, requirements.txt, setup.py, Pipfile, poetry.lock)
    for manifest in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "poetry.lock"):
        manifest_path = root / manifest
        if manifest_path.is_file():
            try:
                text = manifest_path.read_text(encoding="utf-8", errors="replace").lower()
                if "django" in text:
                    frameworks.add("django")
                if "fastapi" in text:
                    frameworks.add("fastapi")
                if "flask" in text:
                    frameworks.add("flask")
                if "starlette" in text and "fastapi" not in text:
                    frameworks.add("starlette")
                if "tornado" in text:
                    frameworks.add("tornado")
                if "litestar" in text:
                    frameworks.add("litestar")
                if "sanic" in text:
                    frameworks.add("sanic")
                if "sqlalchemy" in text:
                    frameworks.add("sqlalchemy")
                if "supabase" in text:
                    frameworks.add("supabase")
            except OSError:
                pass

    # 3. Go (go.mod)
    go_mod = root / "go.mod"
    if go_mod.is_file():
        try:
            text = go_mod.read_text(encoding="utf-8", errors="replace").lower()
            if "gin-gonic/gin" in text:
                frameworks.add("gin")
            if "labstack/echo" in text:
                frameworks.add("echo")
            if "gofiber/fiber" in text:
                frameworks.add("fiber")
            if "go-chi/chi" in text:
                frameworks.add("chi")
        except OSError:
            pass

    # 4. Rust (Cargo.toml)
    cargo_toml = root / "Cargo.toml"
    if cargo_toml.is_file():
        try:
            text = cargo_toml.read_text(encoding="utf-8", errors="replace").lower()
            if "actix-web" in text:
                frameworks.add("actix")
            if "axum" in text:
                frameworks.add("axum")
            if "rocket" in text:
                frameworks.add("rocket")
        except OSError:
            pass

    # 5. PHP (composer.json)
    composer_json = root / "composer.json"
    if composer_json.is_file():
        try:
            text = composer_json.read_text(encoding="utf-8", errors="replace").lower()
            if "laravel" in text:
                frameworks.add("laravel")
            if "symfony" in text:
                frameworks.add("symfony")
        except OSError:
            pass

    # 6. Ruby (Gemfile)
    gemfile = root / "Gemfile"
    if gemfile.is_file():
        try:
            text = gemfile.read_text(encoding="utf-8", errors="replace").lower()
            if "rails" in text:
                frameworks.add("rails")
            if "sinatra" in text:
                frameworks.add("sinatra")
        except OSError:
            pass

    # 7. Java / Kotlin / JVM (pom.xml, build.gradle, build.gradle.kts)
    for jvm_file in ("pom.xml", "build.gradle", "build.gradle.kts"):
        jvm_path = root / jvm_file
        if jvm_path.is_file():
            try:
                text = jvm_path.read_text(encoding="utf-8", errors="replace").lower()
                if "spring-boot" in text or "springframework" in text:
                    frameworks.add("springboot")
                if "quarkus" in text:
                    frameworks.add("quarkus")
                if "micronaut" in text:
                    frameworks.add("micronaut")
            except OSError:
                pass

    # 8. Containers & Infra
    if (
        (root / "Dockerfile").is_file()
        or (root / "docker-compose.yml").is_file()
        or (root / "compose.yaml").is_file()
    ):
        frameworks.add("docker")
    if (root / ".github" / "workflows").is_dir():
        frameworks.add("github-actions")
    if (root / "serverless.yml").is_file() or (root / "serverless.ts").is_file():
        frameworks.add("serverless")

    return frameworks


GIT_REF_PATTERN = re.compile(r"^[A-Za-z0-9._/@][A-Za-z0-9._/@~-]*$")


def changed_files(root: Path, git_ref: str) -> frozenset[str]:
    """Resolve repository-relative paths changed relative to a git ref, failing closed."""
    if not GIT_REF_PATTERN.match(git_ref):
        raise ValueError(f"invalid git ref: {git_ref!r}")
    repository_root = root.resolve()
    commands = (
        ["git", "-C", str(repository_root), "diff", "--name-only", "--diff-filter=ACMR", git_ref],
        ["git", "-C", str(repository_root), "ls-files", "--others", "--exclude-standard"],
    )
    changed: set[str] = set()
    for command in commands:
        completed = subprocess.run(  # noqa: S603 (git ref is validated against GIT_REF_PATTERN above)
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode != 0:
            details = (completed.stderr or completed.stdout or "").strip().splitlines()
            hint = details[0] if details else "git failed"
            raise ValueError(f"cannot resolve git ref {git_ref!r}: {hint}")
        changed.update(line.strip() for line in completed.stdout.splitlines() if line.strip())
    return frozenset(path.removeprefix("./") for path in changed)


def scan_repository(
    root: Path,
    max_file_bytes: int = 1_000_000,
    baseline: set[str] | None = None,
    exclude_patterns: Sequence[str] = (),
    include_paths: frozenset[str] | None = None,
) -> tuple[list[Finding], dict[str, object]]:
    repository_root = root.resolve()
    if not repository_root.is_dir():
        raise ValueError(f"not a directory: {repository_root}")
    findings: list[Finding] = []
    files_scanned = 0
    frameworks = detect_frameworks(repository_root)
    normalized_excludes = normalize_exclude_patterns(exclude_patterns)
    for path in iter_scannable_files(repository_root, max_file_bytes, normalized_excludes):
        relative_path = path.relative_to(repository_root).as_posix()
        if include_paths is not None and relative_path not in include_paths:
            continue
        files_scanned += 1
        if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            try:
                header = path.read_bytes()[:16]
                if header.startswith(b"SQLite format 3") or path.suffix.lower() in {
                    ".sqlite",
                    ".sqlite3",
                }:
                    findings.append(
                        make_finding(
                            find_rule("SP314"),
                            relative_path,
                            1,
                            f"Tracked database file: {relative_path}",
                            "artifact",
                        )
                    )
            except OSError:
                pass
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(find_regex_issues(path, relative_path, text))
        if path.suffix.lower() == ".py":
            findings.extend(find_python_ast_issues(relative_path, text))

    active, suppressed = deduplicate_and_suppress_findings(findings, baseline)
    stats = {
        "files_scanned": files_scanned,
        "suppressed": suppressed,
    }
    if frameworks:
        stats["frameworks"] = sorted(frameworks)
    return active, stats


def determine_verdict(findings: Sequence[Finding]) -> str:
    severities = {item.severity for item in findings}
    if severities & {"critical", "high"}:
        return "BLOCK"
    if severities & {"medium", "low"}:
        return "CONDITIONAL"
    return "PASS_WITH_EVIDENCE"


def build_json_report(
    root: Path, findings: Sequence[Finding], stats: dict[str, int]
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": VERSION, "command": "scan"},
        "root": str(root.resolve()),
        "verdict": determine_verdict(findings),
        "summary": {
            "findings": len(findings),
            **stats,
            "by_severity": dict(Counter(item.severity for item in findings)),
        },
        "findings": [asdict(item) for item in findings],
        "limitations": [
            "Fast heuristic scan; confirm every finding.",
            "No runtime reachability, dependency CVE database, or git-history scan.",
        ],
    }


def render_markdown_report(root: Path, findings: Sequence[Finding], stats: dict[str, int]) -> str:
    counts = Counter(item.severity for item in findings)
    lines = [
        "# ShipProof report",
        "",
        f"**Verdict:** {determine_verdict(findings)}",
        "",
        f"Scanned `{stats['files_scanned']}` files; found `{len(findings)}` active issues; suppressed `{stats['suppressed']}`.",
        "",
        "| Critical | High | Medium | Low |",
        "| ---: | ---: | ---: | ---: |",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
        "",
    ]
    for item in findings:
        lines.extend(
            [
                f"## {item.severity.upper()} · {item.rule_id} · {item.title}",
                "",
                f"`{item.path}:{item.line}` · confidence: `{item.confidence}` · {item.category}",
                "",
                f"> {item.evidence}",
                "",
                item.message,
                "",
                f"**Fix:** {item.remediation}",
                "",
                f"Mapping: `{item.cwe}` · `{item.owasp}` · fingerprint `{item.fingerprint}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Limitations",
            "",
            "This is a fast heuristic scan. Confirm every finding with complete data-flow and runtime context; use dedicated SAST, secret-history, dependency, IaC, and load-testing tools for release evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def read_source_context(
    root: Path,
    relative_path: str,
    target_line: int,
    context: int = 2,
) -> list[tuple[int, str]]:
    """Read surrounding lines from source for terminal display."""
    try:
        source_path = root / relative_path
        text = source_path.read_text(encoding="utf-8", errors="replace")
        source_lines = text.splitlines()
        start = max(0, target_line - 1 - context)
        end = min(len(source_lines), target_line + context)
        return [(i + 1, source_lines[i]) for i in range(start, end)]
    except OSError:
        return []


def render_terminal_report(
    root: Path,
    findings: Sequence[Finding],
    stats: dict[str, int],
) -> str:
    """Render a code-review style terminal report with emoji, context, and evidence."""
    verdict = determine_verdict(findings)
    counts = Counter(item.severity for item in findings)
    lines: list[str] = []

    # Header
    icon = "\u2705" if verdict == "PASS_WITH_EVIDENCE" else "\u274c"
    lines.append(f"\n  {icon} ShipProof: {verdict}")
    lines.append(
        f"  Scanned {stats['files_scanned']} files \u2022 {len(findings)} findings \u2022 {stats['suppressed']} suppressed"
    )
    if counts:
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev, 0) > 0:
                parts.append(f"{SEVERITY_ICON.get(sev, '')} {counts[sev]} {sev}")
        bullet = " \u2022 "
        lines.append(f"  {bullet.join(parts)}")
    lines.append("")

    # Findings
    for item in findings:
        icon = SEVERITY_ICON.get(item.severity, "")
        conf_label = CONFIDENCE_LABEL.get(item.confidence, item.confidence)
        lines.append(f"  {icon} {item.severity.upper()} \u2014 {item.title} ({item.rule_id})")
        lines.append(f"     {item.path}:{item.line}  \u2022  confidence: {conf_label}")
        lines.append("")

        # Source context
        context_lines = read_source_context(root, item.path, item.line)
        if context_lines:
            lines.append("     Evidence:")
            for line_num, line_text in context_lines:
                marker = " >" if line_num == item.line else "  "
                lines.append(f"     {line_num:4d}{marker} {line_text}")
            lines.append("")

        # Why + Fix
        lines.append(f"     Why: {item.message}")
        lines.append(f"     Fix: {item.remediation}")
        lines.append(f"     Ref: {item.cwe} \u2022 {item.owasp}")
        lines.append("")
        lines.append("  " + "\u2500" * 70)
        lines.append("")

    if findings:
        lines.append(
            "  \u2192 Run `shipproof scan --fix-prompt` to generate AI-ready fix instructions"
        )
        lines.append("  \u2192 Run `shipproof scan --format json` for machine-readable output")
        lines.append("")

    return "\n".join(lines)


def render_fix_prompts(
    root: Path,
    findings: Sequence[Finding],
) -> str:
    """Generate AI-ready fix prompts for each finding."""
    if not findings:
        return "No findings to fix.\n"

    lines: list[str] = [
        "# ShipProof Fix Prompts",
        "",
        "Copy any prompt below into your AI coding assistant (Codex, Claude Code, Cursor, etc.)",
        "",
    ]
    for i, item in enumerate(findings, 1):
        lines.append(f"## [{i}] {item.rule_id}: {item.title}")
        lines.append("")
        lines.append("```")
        lines.append(f"Fix {item.rule_id} in {item.path} (line {item.line}).")
        lines.append("")
        lines.append(f"Problem: {item.message}")
        lines.append("")

        # Include source context
        context_lines = read_source_context(root, item.path, item.line)
        if context_lines:
            lines.append("Current code:")
            for line_num, line_text in context_lines:
                marker = ">>>" if line_num == item.line else "   "
                lines.append(f"  {line_num}: {marker} {line_text}")
            lines.append("")

        lines.append(f"Required fix: {item.remediation}")
        lines.append("")
        lines.append("Constraints:")
        lines.append("- Do not change the public API contract")
        lines.append("- Add a regression test that verifies the fix")
        lines.append(f"- Reference: {item.cwe}, {item.owasp}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def render_explain(rule_id: str) -> str:
    """Render a detailed explanation for a single rule."""
    rule = None
    for r in RULES:
        if r.rule_id == rule_id:
            rule = r
            break
    if rule is None:
        return f"Unknown rule: {rule_id}. Valid rules: {', '.join(r.rule_id for r in RULES)}\n"

    explanation = RULE_EXPLANATIONS.get(rule_id, {})
    conf_label = CONFIDENCE_LABEL.get(rule.confidence, rule.confidence)
    lines = [
        "",
        f"  {SEVERITY_ICON.get(rule.severity, '')} {rule.rule_id}: {rule.title}",
        f"  Severity: {rule.severity.upper()} \u2022 Confidence: {conf_label} \u2022 Category: {rule.category}",
        f"  {rule.cwe} \u2022 {rule.owasp}",
        "",
        "  What it detects:",
        f"    {rule.message}",
        "",
    ]
    if explanation.get("why"):
        lines.extend(["  Why this matters:", f"    {explanation['why']}", ""])
    if explanation.get("attack"):
        lines.extend(["  Attack scenario:", f"    {explanation['attack']}", ""])
    if explanation.get("false_positive"):
        lines.extend(
            ["  False-positive possibilities:", f"    {explanation['false_positive']}", ""]
        )
    lines.extend(["  Recommended fix:", f"    {rule.remediation}", ""])
    if explanation.get("test"):
        lines.extend(["  Regression test:", f"    {explanation['test']}", ""])
    return "\n".join(lines)


def build_sarif_report(findings: Sequence[Finding]) -> dict[str, object]:
    rules: dict[str, Finding] = {item.rule_id: item for item in findings}
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShipProof",
                        "version": VERSION,
                        "informationUri": "https://github.com/kingggg5/shipproof",
                        "rules": [
                            {
                                "id": item.rule_id,
                                "name": item.title.replace(" ", "_"),
                                "shortDescription": {"text": item.title},
                                "fullDescription": {"text": item.message},
                                "help": {"text": item.remediation},
                                "properties": {"tags": [item.category, item.cwe, item.owasp]},
                            }
                            for item in rules.values()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": item.rule_id,
                        "level": level[item.severity],
                        "message": {"text": item.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": item.path},
                                    "region": {"startLine": item.line},
                                }
                            }
                        ],
                        "partialFingerprints": {"shipproof/v1": item.fingerprint},
                        "properties": {
                            "severity": item.severity,
                            "confidence": item.confidence,
                            "detection": item.detection,
                            "proof_level": item.proof_level,
                        },
                    }
                    for item in findings
                ],
            }
        ],
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "sarif", "terminal"),
        default=None,
    )
    parser.add_argument("--output", type=Path, help="Write report to a file instead of stdout")
    parser.add_argument(
        "--baseline", type=Path, help="Suppress reviewed fingerprints from this JSON baseline"
    )
    parser.add_argument(
        "--baseline-out", type=Path, help="Write active fingerprints as a reviewable baseline"
    )
    parser.add_argument("--fail-on", choices=tuple(SEVERITY), default="high")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument(
        "--min-confidence",
        choices=("high", "medium", "low"),
        default=None,
        help="Only report findings at or above this confidence level",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a repository-relative glob; repeat for multiple patterns",
    )
    parser.add_argument(
        "--fix-prompt",
        action="store_true",
        default=False,
        help="Generate AI-ready fix prompts for each finding",
    )
    parser.add_argument(
        "--explain",
        metavar="RULE_ID",
        default=None,
        help="Print a detailed explanation for a rule (e.g. --explain SP108)",
    )
    parser.add_argument(
        "--snippet",
        metavar="CODE",
        default=None,
        help="Lint an in-memory code snippet directly without scanning a repository",
    )
    parser.add_argument(
        "--snippet-file",
        metavar="FILENAME",
        default="snippet.py",
        help="Virtual filename for the snippet to guide language detection",
    )
    parser.add_argument(
        "--changed-since",
        metavar="GIT_REF",
        default=None,
        help="Scan only files changed relative to a git ref (also includes untracked files)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    arguments = parse_arguments(argv)

    # Handle --explain mode (no scan needed)
    if arguments.explain:
        print(render_explain(arguments.explain))
        return 0

    # Handle --snippet mode (in-memory linting)
    if arguments.snippet is not None:
        findings = lint_source_snippet(arguments.snippet, arguments.snippet_file)
        payload = build_json_report(Path("."), findings, {"files_scanned": 1, "suppressed": 0})
        print(json.dumps(payload, indent=2))
        return 0 if not findings else 1

    try:
        if arguments.max_file_bytes <= 0:
            raise ValueError("max-file-bytes must be positive")
        include_paths = (
            changed_files(arguments.root, arguments.changed_since)
            if arguments.changed_since
            else None
        )
        findings, stats = scan_repository(
            arguments.root,
            max_file_bytes=arguments.max_file_bytes,
            baseline=load_baseline_fingerprints(arguments.baseline),
            exclude_patterns=arguments.exclude,
            include_paths=include_paths,
        )
        if arguments.changed_since:
            stats["changed_since"] = arguments.changed_since

        # Filter by confidence if requested
        if arguments.min_confidence:
            min_conf = CONFIDENCE[arguments.min_confidence]
            findings = [f for f in findings if CONFIDENCE[f.confidence] <= min_conf]

        payload = build_json_report(arguments.root, findings, stats)
        if arguments.baseline_out:
            arguments.baseline_out.write_text(
                json.dumps(
                    {"version": 1, "fingerprints": [item.fingerprint for item in findings]},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

        # Handle --fix-prompt mode
        if arguments.fix_prompt:
            output = render_fix_prompts(arguments.root, findings)
        else:
            # Determine format: default to terminal if TTY, else markdown
            fmt = arguments.format
            if fmt is None:
                fmt = "terminal" if (sys.stdout.isatty() and not arguments.output) else "markdown"

            if fmt == "terminal":
                output = render_terminal_report(arguments.root, findings, stats)
            elif fmt == "markdown":
                output = render_markdown_report(arguments.root, findings, stats)
            elif fmt == "sarif":
                output = json.dumps(build_sarif_report(findings), indent=2)
            else:
                output = json.dumps(payload, indent=2)

        if arguments.output:
            arguments.output.write_text(
                output + ("" if output.endswith("\n") else "\n"), encoding="utf-8"
            )
        else:
            print(output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2

    if arguments.fail_on != "none" and any(
        SEVERITY[item.severity] <= SEVERITY[arguments.fail_on] for item in findings
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
