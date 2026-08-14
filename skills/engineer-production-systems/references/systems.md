# Kernel, browser-engine, parser, and protocol review

Use this path for privileged, memory-unsafe, parser-heavy, concurrent, or adversarial systems code. Static review alone cannot establish safety.

## Shared invariants

- Validate lengths before pointer arithmetic, allocation, copying, indexing, casting, or nested parsing. Check addition and multiplication overflow before comparing bounds.
- Make ownership, lifetime, aliasing, initialization, cleanup, and error unwinding explicit. Review every early return and partial construction path.
- Treat integer width, signedness, truncation, alignment, endianness, and ABI/layout assumptions as security boundaries.
- Review concurrency with a stated lock/atomic/RCU/refcount protocol. Test cancellation, teardown, callback re-entry, and races between validation and use.
- Cap CPU, memory, recursion, decompression, fragmentation, reassembly, retransmission, and state retained per peer or origin.
- Convert every confirmed crash into a minimized reproducer and permanent regression input.

## Kernel and driver code

Trace user-controlled values through syscalls, ioctl/netlink, filesystems, packets, devices, DMA, eBPF, and firmware boundaries. Check copy-to/from-user results, privilege and namespace assumptions, object reference acquisition/release, lock ordering, sleeping context, interrupt context, allocation flags, error pointers, cleanup labels, and teardown races.

Prioritize use-after-free, double free, out-of-bounds access, uninitialized data exposure, refcount overflow/underflow, integer overflow, race conditions, deadlocks, and confused-deputy paths. When authorized, combine targeted review with KASAN/KMSAN/KCSAN/UBSAN and a kernel-aware fuzzer such as syzkaller in an isolated disposable environment.

## Browser engines and complex content

Review transitions among parser, DOM/layout, JavaScript/Wasm runtime, graphics/media codecs, IPC, sandbox, process isolation, and platform bindings. Look for GC/refcount mismatches, stale wrappers, type confusion, bounds errors, re-entrancy, JIT miscompilation, origin confusion, cross-process validation gaps, and unsafe deserialization.

Preserve origin, site, and process identity across redirects, workers, frames, storage, navigation, and IPC. Validate messages on the receiving side. Fuzz narrow parsers and state transitions with representative valid, invalid, nested, and adversarial corpora under ASan/UBSan/MSan as applicable.

## Network protocols

Implement the protocol as an explicit state machine with legal transitions, message-size limits, deadlines, replay/duplicate handling, version negotiation, and deterministic cleanup. Validate framing before decoding fields. Reject ambiguous encodings, trailing data when forbidden, inconsistent lengths, invalid flags, and unsupported combinations.

Analyze fragmentation/reassembly, amplification, downgrade, reflection, resource pinning, half-open state, retransmission storms, compression bombs, parser differentials, and cross-layer interpretation differences. Bind authentication and authorization to the exact peer, channel, transcript, algorithm, and negotiated parameters. Seed fuzzers with protocol corpora and dictionaries; include sequences, not only single packets.

## Evidence ladder

1. Compiler warnings and type checks.
2. Unit, boundary, property, and state-machine tests.
3. Static and data-flow analysis.
4. Sanitizer builds across relevant configurations.
5. Coverage-guided or structure-aware fuzzing with corpus retention.
6. Concurrency and fault-injection tests.
7. Reproducer, root-cause fix, regression test, and monitored rollout.

No single layer replaces the others. A clean AI review is not evidence that decades-old code contains no hidden vulnerability.

## Authorized defensive reverse engineering

Use reverse engineering only for software, firmware, files, or traffic the user owns or is explicitly authorized to assess. Establish scope, evidence-handling rules, legal constraints, and stop conditions first.

1. Hash and preserve the original artifact; work on isolated copies without live credentials or production connectivity.
2. Identify format, architecture, compiler/runtime clues, imports, capabilities, exposed parsers, and privilege boundaries using passive inspection first.
3. Form one testable hypothesis at a time. Correlate static control/data flow with traces from a sandboxed execution.
4. Minimize the input or sequence that triggers the defect. Confirm root cause under a debugger, sanitizer, emulator, or instrumented build when available.
5. Patch the source-level invariant where possible, add a regression corpus/test, compare behavior and resources, and document residual uncertainty.

Do not provide persistence, credential theft, stealth, evasion, unauthorized access, or destructive deployment workflows. For a suspected malicious artifact, prioritize containment, indicators, behavior, and remediation rather than improving its capability.
