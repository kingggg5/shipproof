# ShipProof production engineering playbook

This is ShipProof's owner-authored operating model for building and releasing production systems. It is a decision guide, not a copied standards catalog, a certification, or a promise that one architecture fits every workload.

The focused skill references remain the execution detail. This playbook explains how the pieces fit together and what ShipProof considers non-negotiable.

## Contents

1. [How to use this playbook](#how-to-use-this-playbook)
2. [ShipProof doctrine](#shipproof-doctrine)
3. [Application and API security](#1-application-and-api-security)
4. [Data and concurrency](#2-data-and-concurrency)
5. [Architecture and failure containment](#3-architecture-and-failure-containment)
6. [Capacity and scale](#4-capacity-and-scale)
7. [CPU, memory, and latency](#5-cpu-memory-and-latency)
8. [AI, RAG, and tool execution](#6-ai-rag-and-tool-execution)
9. [Systems software](#7-systems-software)
10. [Supply chain, operations, and release](#8-supply-chain-operations-and-release)
11. [Release record](#release-record)

## How to use this playbook

1. Write a short engineering contract: critical journey, owner, trust boundaries, data, workload, SLO, resource budget, and recovery behavior.
2. Apply only the control planes touched by the change. Do not turn the whole playbook into a generic checklist.
3. Label each material choice:
   - **Required** — a baseline invariant for the scoped system.
   - **Context-dependent** — adopt only when a measured constraint or threat justifies it.
   - **Experimental** — isolate, benchmark, and define an exit path before production use.
4. Collect evidence from the real repository and runtime. A named tool, pattern, or standard is not evidence by itself.
5. End with separate release gates for Security, Correctness, Data & Privacy, Scale, Operability, and Supply Chain.

Use the [engineering skill](../skills/engineer-production-systems/SKILL.md) while changing a system and the [audit skill](../skills/audit-production-readiness/SKILL.md) before release.

## ShipProof doctrine

1. **Start from invariants, not products.** Define who may do what, to which object, in which state, under which workload.
2. **Bound every amplifier.** Cap input, output, concurrency, fan-out, queues, caches, retries, model tokens, logs, and retained state.
3. **Prefer the smallest architecture that meets measured needs.** Distribution must pay for its new failure modes.
4. **Keep policy next to the protected action.** UI visibility, prompts, gateways, and upstream checks are not authorization boundaries.
5. **Separate decisions from effects.** Pure policy is testable; I/O and privileged mutations need explicit adapters and authority.
6. **Treat tools and AI findings as leads.** Confirm reachability and impact with a complete path, reproducer, focused test, or runtime evidence.
7. **Make recovery part of the design.** Timeouts, cancellation, replay, rollback, repair, and ownership are normal paths.
8. **Let evidence decide the release.** Missing evidence stays unknown; it does not become a passing score.

## 1. Application and API security

**Invariant:** authenticate the caller, authorize the exact action and object, validate the allowed shape, and minimize the response at every trust boundary.

- Scope every tenant-owned query and mutation by tenant and object ownership. Prefer a non-enumerating not-found response when policy requires it.
- Parse input into explicit command objects. Never pass raw request, model, webhook, or form payloads to persistence APIs.
- Return intentionally shaped DTOs rather than storage models containing internal or sensitive fiel…77690 tokens truncated…model, config)
        self.assertEqual(first, second)
        self.assertIn('__ENV["SERVICE_URL"]', first)
        self.assertIn('__ENV["LOAD_TOKEN"]', first)
        self.assertIn('executor: "constant-arrival-rate"', first)
        self.assertNotIn("https://", first)

    def test_k6_config_rejects_remote_targets_and_unknown_fields(self):
        with self.assertRaises(ValueError):
            validate_k6_config(
                {"routes": [{"name": "unsafe", "path": "https://example.com/", "script": "x"}]}
            )

    def test_cli_exports_k6_without_overwriting_existing_file(self):
        import contextlib
        import io
        import json
        from unittest.mock import MagicMock, patch

        from capacity_model import main, write_new_file

        config = json.dumps(
            {
                "schema_version": "1.0",
                "capacity": {
                    "inputs": {"users": 10000},
                    "k6": {"routes": [{"name": "health", "path": "/health"}]},
                },
            }
        )
        with (
            patch("capacity_model.Path.read_text", return_value=config),
            patch("capacity_model.write_new_file") as writer,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(["--config", "shipproof.json", "--export-k6", "load.js"]),
                0,
            )
        self.assertIn('executor: "constant-arrival-rate"', writer.call_args.args[1])

        existing_path = MagicMock()
        existing_path.exists.return_value = True
        with self.assertRaises(ValueError):
            write_new_file(existing_path, "content", False)

    def test_checked_in_k6_example_matches_versioned_config(self):
        root = Path(__file__).parents[1]
        inputs, k6 = load_config(root / "examples" / "capacity" / "shipproof.config.json")
        generated = render_k6_script(build_capacity_model(CapacityInputs(**inputs)), k6)
        expected = (root / "examples" / "capacity" / "generated-load-test.js").read_text(
            encoding="utf-8"
        )
        self.assertEqual(generated, expected)


if __name__ == "__main__":
    unittest.main()
