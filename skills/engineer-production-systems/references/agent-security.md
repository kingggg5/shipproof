# AI agent, RAG, and MCP security

An agent is an untrusted decision component operating between untrusted content and privileged tools. Natural-language instructions are not an authorization boundary.

## Separate control and data

- Treat prompts, retrieved documents, web pages, emails, tickets, memory, tool descriptions, model output, and other agents' messages as untrusted data.
- Keep system policy outside retrieved content. Delimit provenance and never let documents redefine permissions, destinations, tools, or approval requirements.
- Validate structured output against a closed schema. Reject unknown fields, unsafe URLs/paths, invalid identifiers, excessive sizes, and ambiguous actions.
- Re-authorize every tool call at execution time using the authenticated principal, tenant, target object, action, current state, and fresh policy.

## Tool capability design

- Expose narrow task-oriented tools instead of raw shell, SQL, filesystem, browser session, or cloud-admin access.
- Split read and write capabilities. Require preview plus human confirmation for payments, deletion, publication, identity, permission, production, and other consequential writes.
- Use per-tool scopes, short-lived audience-bound credentials, egress allowlists, sandboxed execution, quotas, deadlines, cancellation, bounded output, and idempotency keys.
- For MCP over HTTP, validate issuer, audience, expiry, and scopes; use OAuth protections appropriate to the client; never pass an inbound token through to an upstream service.
- Bind task/session state to the authorized user or service. Use unpredictable identifiers, TTLs, revocation, and ownership checks on status/result reads.

## RAG and memory

- Enforce document-level and chunk-level tenant/ACL filters before ranking and again before response use.
- Retain source, version, page/section, authorization context, and retrieval score. Refuse unsupported claims and surface precise citations.
- Sanitize active content and never execute retrieved code or follow embedded tool instructions by default.
- Scope memory by user and purpose, minimize sensitive retention, make writes observable, validate before reuse, and support deletion. Test memory poisoning and cross-session leakage.

## Evaluation and operation

Maintain versioned bilingual or domain-relevant golden cases for authorization, prompt injection, data exfiltration, tool misuse, excessive agency, hallucinated citations, unsafe refusal, and recovery. Measure task success separately from policy compliance; a successful forbidden action is a security failure.

Log tamper-evident decisions without secrets: actor, tenant, model/prompt/tool versions, input provenance, policy result, requested arguments after redaction, approval identity, tool outcome, latency, token/cost budget, and trace ID. Provide per-tool disable switches, global kill switch, rate/cost limits, rollback, and incident replay from sanitized evidence.
