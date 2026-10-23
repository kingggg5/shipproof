# Node runtime update and declaration-rule validation

The Windows x64 MSI installation was upgraded from Node.js **24.15.0** to
**24.22.1**. Fresh shells resolve `C:/Program Files/nodejs/node.exe`; npm reports
**11.19.1**. The MSI registration and running executable agree. The installer
returned zero, and the five existing global npm packages retained their versions.
Already-running Node applications need a new process to use the updated runtime.

The installer matched the official SHA-256
`3bda4baf1ee709b33cf920dd633106ddb23951e322bff9c03ec9f64ab8981b01`
and had a valid OpenJS Foundation Authenticode signature. The installed executable
matched upstream SHA-256
`d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5`.
[Official release and checksums](https://nodejs.org/en/blog/release/v24.22.1).

## Detector behavior

`SP684` reports exact declared pins below the reviewed 22.23.4/24.22.1/26.12.1
security baselines. `SP685` reports known upstream EOL branches 18/20/21/23/25.
The rules are disjoint and advisory. They cover `.nvmrc`, `.node-version`, a single
exact `nodejs` entry in `.tool-versions`, and the final static official Node image
stage, including supported aliases and variant spellings.

Ranges, floating aliases, prereleases, vendor suffixes, custom images, digest
overrides, ambiguous declarations and compatibility CI do not establish these
predicates. Development declarations, API use, actual deployment and vendor patch
status require further evidence. The [authored contracts](../scripts/build_node_runtime_contracts.py)
contain 15 positives, 52 negatives and 9 adversarial cases across both rule IDs.
Negative cases include disjoint-rule checks; they do not assert that every other
rule must be silent. All 76 cases run through the repository walker.

## Compatibility and integrity evidence

| Node runtime | SDK | Zod | Source MCP | Fresh packed MCP |
| --- | --- | --- | --- | --- |
| 24.22.1 | 1.32.1 | 3.25.76 | Passed, no peer skips | Passed, no peer skips |
| 24.22.1 | 1.32.1 | 4.6.7 | Passed, no peer skips | Passed, no peer skips |

The real SDK handshake exercises all five tools, strict output schemas, incorrect
types, unsafe integer inputs, traversal, Unicode byte limits, fresh scans after
same-size/same-mtime changes, and the new Node advisories. Root dependencies were
restored to the lockfile after the Zod 3 run; package metadata did not change.

Local `npm run check` passed with 902 Python tests, three platform-related skips,
two demo tests, the Node suites, package boundaries and installed-tarball smoke.
Self-scan reported zero application findings and complete selected-source coverage;
32 deliberate test findings remain visible. All 654 executable rules have contracts.
The 30-package/867-file paired corpus retained all 54 original high-signature
locations; its remediated leg remained at zero high/critical and 16 gate medium
findings. Existing precision thresholds, source manifest and labels are unchanged.

Version-file review also covers case-sensitive dotfile names and a sparse-input
memory regression. A 100,008-byte `.nvmrc` containing 100,000 blank lines used
9,987,707 peak traced parser bytes before the fix and 801,367 after it. The parser
retains one candidate and rejects a second declaration immediately. A regression
test enforces a four-million-byte allocation ceiling for that input.

## Measured lexer change

The native lexer checks the first character before attempting comment and raw-string
probes. This retains lexical validation and the existing token/nesting limits.
Nine measured samples followed an untimed warm-up for each fixture. Before and
after input hashes, token counts, offsets and token hashes match for all six cases.

| Typical indentation | Before median | After median | Change |
| --- | ---: | ---: | ---: |
| Go | 11.749 ms | 9.794 ms | -16.6% |
| Rust | 9.221 ms | 7.024 ms | -23.8% |
| Luau/Lua | 7.249 ms | 5.943 ms | -18.0% |

Deep-indentation cases improved by 14.8–21.6%. These are lexer measurements on
synthetic fixtures, not a universal scanner throughput claim. The separate
1,000-file clean scan had median 1.0268 → 0.9757 seconds and p95 1.0377 → 1.0824
seconds across five samples, so the tail result does not establish a general
end-to-end speed improvement. Both runs stayed below the existing five-second
budget with zero findings. Environment: Windows 11, Python 3.12.10.

Reproduce the lexer workload with `python scripts/benchmark-native-lexer.py` and
the scanner workload with `python scripts/benchmark-scanner.py --files 1000 --samples 5`.
Baseline source revision: `bb2422173f6b2d7c2f880e542e43f14f8dff1b34`.
Raw [lexer before](node-runtime-benchmark/native-before.json),
[lexer after](node-runtime-benchmark/native-after.json),
[scanner before](node-runtime-benchmark/scanner-before.json) and
[scanner after](node-runtime-benchmark/scanner-after.json) retain every sample.

The maintainer release guide remains in source with public links instead of the
npm artifact, preserving the existing package byte ceilings. No release or
registry publication was performed. Review was primary self-review with bounded
mechanical source/documentation assistance, not independent certification.
