# Alibaba Open Code Review and Zvec: ShipProof adoption decision

Reviewed: 2026-09-15. Scope: source-based adoption review, not a release certification.

Current implementation follow-up (2026-10-28): [bounded host-agent review packets](packet-orchestration-2026-10.md). The identity and anchor work proposed in this historical snapshot has implementation records in the linked quality plan; use the dated follow-up for the current packet behavior and verification limits.

## Decision

**Prioritize Open Code Review's evidence orchestration patterns. Defer Zvec to an optional retrieval experiment.**

สรุป: สิ่งที่คุ้มก่อนคือผูกผลตรวจกับโค้ดและกฎที่ใช้จริง, จัดชุดหลักฐานให้ agent ตรวจต่อ, และตรวจตำแหน่งที่อ้างถึง ส่วน vector search ควรเพิ่มเมื่อการค้นหาแบบง่ายมีข้อจำกัดที่วัดได้แล้ว

Implementation sequence, acceptance criteria, evaluation targets, and rollout decisions: [ShipProof quality plan](shipproof-quality-plan.md).

No upstream code, rule pack, model, or dependency was incorporated. ShipProof's runtime, rules, and release gates were not modified by this review.

## Download and provenance

| Repository | Inspected revision | Local source checkout |
| --- | --- | --- |
| [alibaba/open-code-review](https://github.com/alibaba/open-code-review) | `3d4f364e6a6dda8fec644a56cfc754f80fb432e6` | `.shipproof-research-cache/alibaba-open-code-review` |
| [alibaba/zvec](https://github.com/alibaba/zvec) | `0fd01cf5114b66e79ddccd10eba51228f6a9682d` | `.shipproof-research-cache/alibaba-zvec` |

Both are shallow, detached checkouts in the existing Git-ignored research directory. Checkout hooks were disabled. The Git trees contained no symlink entries; Zvec has 16 submodule entries, which were not downloaded. Neither repository's install scripts, test suites, build scripts, agents, or model providers were executed. Both checkouts were clean after inspection.

ShipProof comparison baseline: `c692cc4548907f3f57aa7e2489edd1278e37f7da`, version 0.11.0; initially clean working tree. Earlier 0.10.0 review counts are historical and were not reused as current verification.

Concurrent release-related edits appeared during the review, including a 0.11.1 release-note file. They were left untouched. The baseline above describes initial inspection, not an immutable snapshot of the entire live workspace; this task wrote only the research report and ignored source checkouts.

Both root LICENSE files identify Apache-2.0; Zvec also has a NOTICE covering third-party material. Any later vendoring needs a component-specific license/notice check. This proposal adapts behavior with original implementations; it does not copy upstream prose into ShipProof's MIT rule catalog.

## Open Code Review: what is worth adapting

### 1. Bind evidence to the exact reviewed input — first priority

The [run identity and resume validation](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/session/resume_identity.go) compare repository, source artifact, mode, and rule configuration. [Artifact hashing](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/agent/agent.go#L1022) frames fields unambiguously before hashing. The [file reader](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/tool/filereader.go) reads the selected Git revision for range/commit reviews.

ShipProof already carries fingerprints, external target/config digests, and coverage. The useful addition is **verification against the current target**, not another digest-shaped field.

Concrete local observation: `scripts/import_external_evidence.py:57` validates digest syntax and parses timestamps, but does not compare them with a current repository/configuration or enforce an age policy. A read-only synthetic probe of `load_envelope` accepted a 2020 timestamp and placeholder digests. This is not evidence of a production-gate exploit: the importer is a standalone normalization script. It means its docstring's stale-envelope rejection claim is not implemented by this function.

Proposed change: introduce explicit expected-target/config identities, computed from the bytes and effective options actually reviewed. Define freshness separately from timestamp age. Reject mismatches for evidence reuse; keep imported model findings identified as external. Hashes establish identity, not trusted authorship or correctness.

Acceptance: same-size edits with restored mtime, moved refs, changed rules/options, foreign roots, and modified dependency context must invalidate reuse. Invalid evidence remains exit 2.

### 2. Build bounded review packets for the user's existing agent

[Delegation mode](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/cmd/opencodereview/delegate_cmd.go) emits selection/rule specifications without an OCR-managed LLM call. [GroupRules](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/delegate/rulegroup.go) groups equal rule text while preserving source and pattern provenance.

Extend ShipProof's existing fix-prompt/context output with bounded packets containing the finding, relevant rule IDs, exact source locations, related callers/tests, and unresolved questions. Start with deterministic import/call relationships and same-component context. Use the existing agent handoff instead of requiring ShipProof to manage another provider credential.

[File grouping](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/agent/grouping.go) is partly model-driven, not wholly deterministic. Its useful engineering guarantees are recovery of omitted files, duplicate rejection, a ten-file group cap, and token-budget splitting. The [tests](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/agent/grouping_test.go) explicitly exercise missing, duplicate, unknown, truncated, and oversized groups.

Acceptance: every selected file has a terminal review status; a budget stop cannot masquerade as completion. Grouping must preserve scope and include dependency context without silently changing which files the gate evaluates.

### 3. Validate comment anchors independently of model output

[ResolveComment and RelocateAcrossFiles](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/diff/resolver.go) match quoted source against hunks/content. Cross-file relocation requires one matching file.

For future imported AI comments, require a valid path, revision, side, range, and matching excerpt. Native scanner findings already have locations; concentrate this feature on external review and future PR comments.

Do not port the resolver verbatim: it accepts already-populated line numbers without revalidation, and within-file matching takes the first occurrence. ShipProof should mark ambiguous locations unresolved, including repeated code within one file. Do not let an LLM invent a replacement excerpt to make an invalid anchor appear valid.

Acceptance: repeated snippets, added/deleted sides, renamed files, Unicode paths, changed source, and out-of-range locations are covered. Unresolved comments remain available for review without a fabricated inline anchor.

### 4. Add a recorded verification pass, not automatic suppression

The upstream [review filter](https://github.com/alibaba/open-code-review/blob/3d4f364e6a6dda8fec644a56cfc754f80fb432e6/internal/agent/agent.go#L1776) can remove comments following a model response. Its prompt favors retaining comments when evidence is insufficient, but this remains model judgment.

ShipProof should preserve the original finding and attach a triage assessment with supporting and contradicting evidence. Use the existing `scripts/finding_labels.py` vocabulary: true positive, false positive, needs context, duplicate. A model assessment must not become a trusted human label or disable a deterministic blocking finding.

For the user's earlier concern: classify evidence by its role and trace execution. A vulnerable example inside a rule string or fixture is different from a reachable dangerous operation in the scanner implementation. A directory name alone cannot settle that distinction.

Acceptance: a test/example label cannot suppress live code in that directory; a failed verification call retains the finding; raw and triaged views can be reconciled exactly.

## Zvec: useful later, with a measured reason

Zvec provides native full-text/vector retrieval, structured filters, and rank fusion. [QueryExecutor](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/python/zvec/executor/query_executor.py) routes single and multiple queries. [RrfReRanker](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/python/zvec/extension/multi_vector_reranker.py) combines ranked result lists. [Hybrid tests](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/python/tests/test_collection_fts_vector_hybrid.py) cover filtering, ranking, and vector results when keyword search finds nothing.

Suitable ShipProof uses:

- Search rule explanations and reviewed remediation examples in English and Thai.
- Retrieve related source fragments for an optional review packet.
- Suggest potentially duplicate research candidates for human comparison.

Start with ID/CWE/ecosystem filters and a simple lexical baseline over the 635 executable rules. Keep research candidates separate. This carries forward the existing [zvec-grep review](zvec-grep-review.md); it is not a second justification for adding the same retrieval subsystem.

Adopt Zvec only if hybrid retrieval improves a held-out task set enough to justify indexing, native binaries, RAM, disk, and model costs. Record retrieval recall@k separately from defect recall; a relevant search hit does not prove a vulnerability. Similarity must not automatically merge rule IDs or suppress findings.

### Integration constraints established from source

- The [Python package](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/pyproject.toml) requires NumPy and a compiled backend. It does not fit ShipProof's dependency-free core. Current README/CI include Windows support, but this checkout was not built or runtime-tested here.
- The optional [Sentence Transformer helper](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/python/zvec/extension/sentence_transformer_function.py#L103) can download models and passes `trust_remote_code=True`. This is a concrete integration boundary, not a claim that the storage core executes remote models. Use operator-provisioned, pinned local embeddings with an explicit loading policy; do not inherit this helper's behavior in the default scan.
- [Collection options](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/src/include/zvec/db/options.h) expose read-only mode and memory mapping. Keep the retrieval index reconstructible and separate from authoritative evidence. Require root/revision/config isolation, deletion propagation, bounded queries and single-writer coordination.
- Upstream includes [crash-recovery tests](https://github.com/alibaba/zvec/blob/0fd01cf5114b66e79ddccd10eba51228f6a9682d/tests/db/crash_recovery/write_recovery_test.cc). Their existence does not establish power-loss durability on this machine; persistence claims need deployment-specific verification.

## Proposed order and decision gates

| Order | Deliverable | Required evidence before enabling |
| --- | --- | --- |
| 1 | Verify imported evidence identity and correct stale-evidence claims | Stale/source/config mismatch tests; unchanged 0/1/2 semantics |
| 2 | Extend existing agent handoff with bounded, revision-bound review packets | Complete selection accounting; bounded size; source/test roles; no default network |
| 3 | Validate imported comment locations and record triage | Ambiguity/rename tests; original findings retained; no automatic gate suppression |
| 4 | Evaluate simple rule search versus optional Zvec retrieval | Fixed held-out Thai/English questions, relevant-source labels, recall@k, end-to-end finding quality, latency/RSS/index size, model identity |

Use the existing real-world evaluator and label infrastructure. Open Code Review's README points to AACR-Bench, but the dataset card could not be retrieved in this review; its license, split, and methodology remain unverified. Do not import it or repeat its headline precision/token figures as measured ShipProof improvements.

## Verification boundary

Executed: source download, exact revision/tree inventory, detached checkout and clean-status checks, ignore checks, and the isolated synthetic probe of ShipProof's existing evidence loader. Inspected the cited source paths and selected tests. No upstream runtime tests, model calls, native benchmarks, scanner false-positive survey, or security certification were performed. This review introduces only this research document and the ignored source checkouts; full application tests are not evidence for these unexecuted integrations.
