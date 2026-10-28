# ShipProof next development plan

Last reviewed: 2026-10-28 (context-specific taint closeout; dated baselines below remain historical).

สถานะ: แผนหลักสำหรับเปลี่ยน research backlog ให้เป็น production evidence ที่เชื่อถือได้ โดยไม่เปิดกฎจำนวนมากแบบ big-bang และไม่ลดมาตรฐาน false-positive

## เป้าหมาย

ShipProof ต้องรักษาแกนหลักสามข้อพร้อมกัน:

1. คำสั่งและ evidence contracts ต้อง fail closed และให้ผลเหมือนกันทุก adapter
2. กฎ executable ทุกตัวต้องมีหลักฐานทั้ง positive, negative และ adversarial
3. Research candidates จะเลื่อนเป็น detector ได้เฉพาะเมื่อพิสูจน์ semantics และ precision ของ ecosystem นั้นแล้ว

แผนนี้ใช้ร่วมกับ [แผนผู้สมัคร 1,000 รายการ](rule-expansion-1000.md), [ชุดข้อมูลปี 2021–2026](rule-expansion-2021-2026.md) และ [แผนเฉพาะภาษา 5,000 รายการ](rule-expansion-languages-5000.md)

## Baseline snapshot — 2026-08-27

ข้อมูลต่อไปนี้เป็น snapshot วันที่ 2026-08-27 ไม่ใช่ตัวเลขรับประกันในอนาคตหรือผลทดสอบรอบ recheck:

- pre-cohort rule baseline: 656 at `09adda6` (2026-10-23, not the dated August measurement)
- research inventory: 7,800 catalogued candidates plus 1,000 reserved promotion slots (`SP651–SP9450`)
- language-specific research candidates: 5,000 (`SP4451–SP9450`)
- project Python test cases ที่ discover ได้: 636 พร้อม Node, package และ end-to-end suites
- self-scan: 0 active findings ที่ high gate
- reference benchmark: 1,000 clean files, warm pass 0.96 วินาที (~1,040 files/s), peak RSS 26.13 MB บน Windows/Python 3.12.10; harness รายงาน cold และ warm แยกกัน (การเปิดไฟล์ครั้งแรกของ OS ไม่ใช่งาน scanner), รองรับ `--jobs N`, และ fixture/config digest อยู่ใน report
- default path: read-only, offline และไม่มี dependency เพิ่ม

Candidate ID ไม่ได้แปลว่ามี detector แล้ว จำนวน research slots จึงห้ามนำไปรวมกับ executable rule count ในเอกสารหรือการตลาด

## Previous field-cohort status — 2026-10-23

- historical executable scanner rules: 661

The registry then contained 661 executable rules through SP692. The Luau/TypeScript
continuation adds SP690–SP692 and extends SP672/SP676/SP679 without duplicate
IDs; see the [cohort evidence](../research/luau-typescript-cohort-2026-10.md).
The bounded
TypeScript/.NET/Dart cohort adds SP688/SP689, extends SP170 and SP056/SP084,
and narrows SP596. SP688 and SP689 are advisory regardless of their medium
severity. Local pinned-snapshot evaluation and compatibility gates are complete;
the scoped source review is not a universal zero-false-positive or independent
precision claim. See the [cohort evidence and limits](../research/field-cohort-ts-dotnet-dart-2026-10.md).

The failure catalog is maintainer-source-only and excluded from npm to preserve
package ceilings; see the [catalog](knowledge/failure-catalog.md).

## Previous value/default/trust cohort — historical

- previous historical executable scanner rules: 667 through SP701

SP699–SP701 add bounded Rust validity, Node timer-range and explicit QueuePool
capacity checks. SP673/SP104 gain scoped variants; SP347/SP350 are retired because
their default assumptions do not establish a defect. See the
[cohort record](../research/value-cohort-2026-10.md) for evidence and limitations.

## Previous Node/React/Luau/PostgreSQL cohort — historical

- historical executable scanner rules: 667 through SP706
- added SP702–SP706, expanded SP691, and retired SP325/SP334/SP359/SP363/SP423

Earlier Luau/TypeScript, broad-quality, and value/default/trust selections are
reflected in that historical registry. See the
[cohort record](../research/web-database-cohort-2026-10.md).

## Previous I/O ownership cohort — historical

- historical executable scanner rules: 667 through SP707
- repaired SP336, retired SP367, extended SP703/SP705, and added advisory SP707

See the [cohort record](../research/io-ownership-cohort-2026-10.md).

## Current taint-contract closeout — 2026-10-28

แก้การเชื่อชื่อ sanitizer และการใช้ protection ข้ามบริบทแล้ว: แยก provenance
จากค่าที่แปลง ป้องกัน raw sibling/mixed-value หลุด ตรวจ binding/shadowing และ
แยก SQLModel session.exec จาก Python exec. Unknown calls และ query builder
ยังเป็น advisory โดยไม่ลดเกณฑ์ gate หรือแก้ป้ายกำกับ benchmark.

รายละเอียด ข้อจำกัด และผลทดสอบของรอบนี้อยู่ใน
[taint-contract closeout](../research/sanitizer-contracts-2026-10.md).
จำนวน executable ยังเป็น 673 กฎ งานเพิ่มกฎหรือรองรับ semantics ที่ซับซ้อนขึ้น
ต้องผ่านหลักฐานเฉพาะ ecosystem ต่อไป ไม่ถือว่า research candidates ใช้งานแล้ว.

## Previous Luau community cohort — 2026-10-26

- executable scanner rules: 673 through SP713, with deliberate ID gaps
- adds SP708–SP713 and extends SP707 for direct RemoveAsync/IncrementAsync

The [source cohort](../research/luau-community-cohort-2026-10.md) records scope
and source provenance; the [pinned library manifest](../benchmarks/luau-community-cohort-repositories.json)
identifies the two source-only libraries. No test, CI, performance, or precision
result is stated here.

## Previous broad-quality cohort status — 2026-10-23

- historical executable scanner rules: 666

The registry then contained 666 executable rules through SP698. The six additions,
SP693–SP698, are medium advisory checks with bounded source syntax. SP346 now
matches only import-bound standalone `asyncio.create_task` expressions that are
not awaited, returned, or assigned. SP375 no longer treats `SetMaxIdleConns(0)` as
an unlimited open-connection cap. SP348 is retired because the Python executor's
default is bounded; its ID will not be reused.

The cohort record describes its limits and pending verification. No test or
performance metrics are claimed, and the source checks do not establish deployed
impact or a universal false-positive rate. The 2,800 expert/annual and 5,000
language-catalog entries remain non-executable candidates. See the
[broad-quality cohort record](../research/broad-quality-cohort-2026-10.md).

## หลักการตัดสินใจ

- แก้ trust boundary และ contract bug ก่อนเพิ่ม detector
- ใช้ primary sources เช่น CWE, OWASP, CERT และเอกสารเจ้าของ framework
- Community posts ใช้ค้นหาคำถามและจัด priority เท่านั้น
- ห้ามคัดลอก Semgrep rules หรือแหล่งที่มีข้อจำกัดใบอนุญาต
- ไม่ใช้ regex เมื่อ detector ต้องเข้าใจ scope, lifecycle, alias, data flow หรือ reachability
- สิ่งที่ source code พิสูจน์ไม่ได้ต้องไปอยู่ใน dependency, policy, benchmark, load หรือ runtime evidence
- `0` คือผ่าน, `1` คือ gate failure และ `2` คือ invalid/unavailable evidence เสมอ
- การเพิ่ม optional analyzer ห้ามทำให้ default scanner ดาวน์โหลด dependency หรือส่ง source ออกจากเครื่อง

## ลำดับการดำเนินงาน

```text
P0 Contract integrity
  -> P1 Executable-rule assurance
    -> P2 Candidate promotion batches
      -> P3 Language engines and evidence adapters
        -> P4 Scale/performance evidence
          -> P5 Real-world evaluation and 1.0 cleanup
```

P0 และ P1 เป็น release blockers ส่วน P2–P5 ทำเป็นชุดเล็กและต้องผ่าน gate ของชุดก่อนหน้า

## P0 — Contract integrity

### P0.1 MCP contracts

- [x] สร้าง input/output schema แยกสำหรับ MCP tool แต่ละตัว แทน schema envelope แบบกว้าง
- [x] ทดสอบ `tools/list` และ `tools/call` ด้วย official SDK handshake
- [x] ตรวจ child status ก่อน parse JSON และรักษา stderr ที่ใช้แก้ปัญหาได้
- [x] เปลี่ยน snippet transport จาก argv เป็น bounded stdin
- [x] บังคับ repository root ที่ resolve แล้วในทุก tool
- [x] เพิ่ม timeout, output cap, cancellation และ spawn-error handling ให้ `explain`
- [x] ทดสอบ path ที่มี Unicode, spaces, subdirectory และ Windows command-length boundary

Acceptance gate:

- structured content ผ่าน schema ของ tool นั้นจริง
- invalid evidence คืน exit/error class ที่สอดคล้องกัน
- cancellation หยุด child process ได้
- source snippet ไม่ปรากฏใน process arguments

### P0.2 Command evidence schemas

- [x] สร้าง schema เฉพาะสำหรับ `scan`, `check`, `budget`, `capacity`, `cost`, `impact`, `invariants` และ evidence adapters
- [x] เพิ่ม golden JSON fixture ต่อคำสั่ง
- [x] ตรวจ output จริงกับ schema ใน CI ไม่ใช่ตรวจเพียงว่าไฟล์ schema parse ได้
- [x] ระบุ schema version, tool version, verdict, limitations, root และ artifact identity ให้สม่ำเสมอ
- [x] เพิ่ม compatibility fixture ก่อนเปลี่ยนชื่อหรือลบ field

Acceptance gate:

- output ทุก command ผ่าน schema ของตัวเอง
- invalid input คืน `2` และไม่สร้าง PASS-looking artifact
- Node CLI, direct Python และ adapter ให้ semantic result เดียวกัน

### P0.3 Secret-safe capacity and generated artifacts

- [x] ป้องกัน k6 route body ฝังค่าจาก key เช่น password, token, secret, authorization และ api key
- [x] รองรับ environment placeholder สำหรับค่าที่ต้องส่งตอนรันจริง
- [x] เพิ่ม negative fixture ที่มี nested secret และ mixed-case key
- [x] ตรวจ artifact, terminal context และ fix prompt ด้วย redaction contract เดียวกัน

Acceptance gate:

- generated k6 ไม่มี hostname, credential หรือ secret literal
- output deterministic เมื่อ input ที่ไม่ลับเหมือนกัน
- unknown secret-shaped field fail closed หรือถูกแทนด้วย placeholder ที่ชัดเจน

### P0.4 Package and release integrity

- [x] ใช้ `npm pack --json` สร้าง normalized package manifest
- [x] เปรียบเทียบกับ approved file allowlist และ deny patterns
- [x] ตั้ง compressed/unpacked size budget
- [x] smoke test CLI, Action, MCP startup และทั้งสอง skills จาก tarball จริง
- [x] ตรวจ exact release tag, package version และสร้าง artifact digest ก่อนเผยแพร่ release
- [x] แยก already-exists จาก auth/network/validation failure โดยไม่ใช้ failure-masking fallback

Acceptance gate:

- unexpected file ทำให้ CI fail
- release จาก branch หรือ tag ไม่ตรง version ถูกปฏิเสธ
- moving tag เปลี่ยนได้หลัง immutable release สำเร็จเท่านั้น

### P0.5 Documentation truthfulness

- [x] ทำ CI matrix ใน README/AGENTS ให้ตรง workflow จริง
- [x] ทำจำนวน MCP tools, rules, proof levels และ runtime requirements ให้ตรง implementation
- [x] เพิ่ม structure tests สำหรับค่าที่สามารถ derive จาก code/workflows ได้
- [x] บังคับ exact rule count claim ให้ derive/check จาก `RULES`

## P1 — Executable-rule assurance

เป้าหมายคือทำให้กฎ executable ทั้งหมดมี test contract ที่ตรวจโดยเครื่อง ไม่ใช่เพียงมีชื่ออยู่ในตาราง README

### P1.1 Rule inventory

- [x] สร้างรายงาน rule ID ที่ขาด positive, negative, adversarial, CWE, remediation หรือ false-positive analysis
- [x] ขยาย successor manifests ใต้ `tests/rule-contracts/` และ runtime secret fixtures ให้ครอบคลุมทุก executable ID
- [x] แยก fixture ตาม ecosystem และ engine: pattern, AST/structural, artifact และ runtime-secret พร้อม index/digest
- [x] ทำ structure test ให้ fail เมื่อเพิ่ม rule โดยไม่มีสอง polarity (ใช้ transitional debt baseline ที่เพิ่มไม่ได้โดยเงียบและต้องลดลงเมื่อเติม contract สำเร็จ)

### P1.2 Minimum fixture contract

ทุกกฎต้องมีอย่างน้อย:

- positive 1 รายการ
- negative 2 รายการ
- adversarial/evasion 1 รายการ
- high/critical ต้องมี positive และ negative อย่างน้อยฝั่งละ 2 รายการ
- framework/version boundary เมื่อ syntax เปลี่ยนตามเวอร์ชัน
- false-positive note ที่บอก external control หรือ context ที่ scanner มองไม่เห็น

Fixture ต้องตรวจทั้ง rule ID, severity, detection type, proof level, path, line และ fingerprint ที่เกี่ยวข้อง ไม่ตรวจเพียงว่าจำนวน findings มากกว่าศูนย์

### P1.3 Engine regression gates

- [x] multiline detector ต้องมี fixture ที่ข้ามบรรทัดจริง
- [x] suffix routing ต้องผ่าน repository walker ไม่เรียก helper โดยตรงอย่างเดียว
- [x] secret rules ต้องตรวจ redaction ใน JSON, Markdown, terminal และ prompts
- [x] autofix ต้อง re-scan และคืน exit ตาม findings ที่เหลือ
- [x] changed-only scan ต้องครอบคลุม rename, copy, Unicode, subdirectory และ untracked files

Acceptance gate ของ P1:

- executable IDs ทุกตัวมี machine-readable fixture contract
- full suite, golden parity และ package smoke ผ่าน
- self-scan มี 0 findings ที่ high gate

## P2 — Promote research candidates เป็นชุดเล็ก

### P2.1 Candidate lifecycle

ใช้สถานะต่อไปนี้:

```text
research_only -> triaged -> fixture_ready -> shadow -> promoted
                      \-> rejected
```

- `research_only`: มีแหล่งและ taxonomy แต่ยังไม่ใช่ detector
- `triaged`: ยืนยัน ecosystem semantics และ evidence route แล้ว
- `fixture_ready`: มี corpus ครบ แต่ยังไม่เปิดกับผู้ใช้ปกติ
- `shadow`: รัน advisory เพื่อเก็บ precision โดยไม่ block
- `promoted`: เข้า `RULES`, README tables และ release contract แล้ว
- `rejected`: เก็บ ID และเหตุผลไว้ ไม่หมุน ID กลับมาใช้ใหม่

### P2.2 Eligibility filter

Candidate ชุดแรกต้องผ่านทุกข้อ:

- `applicability_tier = direct`
- ไม่ใช่ Deprecated หรือ Obsolete CWE
- มี owning documentation ปัจจุบัน
- syntax/configuration ที่เป็นปัญหาปรากฏใน repository ได้ชัดเจน
- detector ไม่ต้องเดา deployment, reachability หรือ external authorization
- `coverage_gap` หรือมีแผน `extend_or_replace_existing` ที่ไม่สร้าง alert ซ้ำ
- remediation สามารถทดสอบเป็น negative fixture ได้

`language_independent` และ `taxonomy_only` ห้ามเลื่อนเพียงเพราะคะแนนสูง ต้องมี ecosystem-specific source เพิ่มก่อน

### P2.3 Promotion batch A — ภาษาหลัก

เพดาน 25 กฎ ไม่ใช่โควตาที่ต้องฝืนเติม:

| Ecosystem | Maximum | เนื้อหาที่ควรเริ่ม |
| --- | ---: | --- |
| C# | 3 | ASP.NET explicit unsafe configuration, async/resource lifetime |
| TypeScript | 4 | explicit compiler/runtime boundary, unsafe web APIs |
| PHP | 3 | file upload/include/database construction ที่พิสูจน์ได้ |
| React | 2 | effect/subscription lifecycle และ explicit unsafe rendering |
| Go | 3 | timeout, cancellation, body/resource lifecycle |
| C++ | 4 | explicit unsafe memory/container/API calls |
| Angular | 2 | sanitizer bypass, XSRF/Trusted Types configuration |
| JavaScript | 2 | runtime injection และ unbounded event-loop behavior |
| SQL | 2 | explicit dangerous DDL/query patterns ที่มี scope ชัดเจน |

หาก candidate ใดไม่ผ่าน precision gate ให้จำนวน batch ลดลง ห้ามแทนด้วย candidate ที่อ่อนกว่าเพื่อให้ครบ 25

### P2.4 Promotion batch B — ecosystem เพิ่มเติม

หลัง batch A อยู่ใน shadow และไม่มี regression จึงพิจารณา Python, Java, Rust, Kotlin และ Swift รวมไม่เกิน 25 กฎ โดย Kotlin/Swift ต้องมี Android/Apple semantics โดยตรงก่อนเสมอ

สถานะ batch A ณ 2026-08-24: ตรวจครบ 25 candidates ตามเพดานทั้ง 9 ecosystem แล้วใน
[`research/promotion-batch-a.json`](../research/promotion-batch-a.json) — 3 รายการอยู่ที่
`fixture_ready`, 22 รายการถูกปฏิเสธจาก batch เพราะซ้ำกับ detector เดิม, ต้องใช้ data-flow/lifetime
analysis, ขาด framework semantics หรือวาง ecosystem ผิด และ 0 รายการถูก promote. ชุด prototype
ทั้งสามมี executable positive/negative/adversarial cases แต่ยังห้ามเข้า `RULES` จนกว่าจะมี
representative-repository shadow metrics และ benchmark delta. ดังนั้น batch B ยังไม่เริ่มตาม gate
ข้างต้น; นี่เป็น evidence dependency ไม่ใช่จำนวนกฎที่ต้องฝืนเติม.

### P2.5 Promotion gate ต่อกฎ

- source links และวันที่ทบทวน
- CWE/control mapping
- engine และ proof level ที่ไม่กล่าวเกินจริง
- positive/negative/adversarial fixtures
- duplicate comparison กับ rule เดิมทั้ง CWE, suffix, message และ fingerprint
- controlled corpus result
- representative-repository result
- runtime delta
- README และ explanation entry

## P3 — Language engines and evidence adapters

Default scanner ยังคง zero-dependency ส่วน compiler/framework analyzers เป็น optional evidence ที่ต้องตรวจ availability และ trust boundary

| Ecosystem | Default static scope | Optional evidence | สิ่งที่ห้ามเดาจาก regex |
| --- | --- | --- | --- |
| C# | explicit config/API misuse, simple structural scope | .NET build/analyzers | interprocedural async flow, authorization reachability |
| TypeScript/JavaScript | imports, calls, config, bounded structural flow | TypeScript compiler | type narrowing, alias chain, framework-generated behavior |
| React | component/effect structure, explicit sinks | TypeScript + framework tests | real render frequency, ownership across custom hooks |
| Angular | templates/config and direct sanitizer bypass | Angular compiler/test evidence | DI aliases, compiled template behavior |
| PHP | explicit includes/uploads/query construction | PHP lint and reviewed analyzer | dynamic include graph, runtime configuration |
| Go | server/resource patterns and direct error handling | `go vet`, `govulncheck`, tests | whole-program goroutine ownership |
| C++ | dangerous APIs and local bounds | compiler warnings, sanitizers | lifetime, aliasing and memory safety across translation units |
| SQL | statement/token structure and migration risk | plans, lock analysis, database tests | cardinality, production indexes and lock duration |
| Python | AST and local taint | project tests/type checker | dynamic dispatch and external policy |
| Java/Rust/Kotlin/Swift | conservative explicit patterns | owning compiler/analyzer | whole-program lifecycle and platform state |

Adapter acceptance gate:

- executable path และ arguments อยู่ใน allowlist
- project-controlled tool ต้องมี explicit consent
- version probe ถูกต้องสำหรับ tool นั้น
- crash, timeout, unavailable และ findings แยกสถานะกัน
- output ถูก bound และ redact

สถานะ ณ 2026-08-24: acceptance gate ข้างต้นถูกทำเป็น executable contract แล้วสำหรับ
TypeScript, Go และ Rust adapters โดยรายงาน tool version, แยก unavailable/timeout/output-limit/
crash/findings, จำกัด diagnostics และ redact credential-shaped output. Default scanner ยังไม่เรียก
analyzer หรือ network เอง และ compiler ที่อยู่ใน project ต้องใช้ `--allow-project-code` เสมอ.

## P4 — Scale and performance evidence

Security source findings, capacity estimates และ measured performance ต้องไม่ถูกรวมเป็นคำตัดสินเดียว

### P4.1 Static candidates ที่พอพิสูจน์ได้

- locally visible unbounded loop/retry/recursion
- allocation หรือ buffer ที่รับ unbounded input โดยตรง
- query/network call ภายใน loop ที่ระบุได้
- missing timeout/cancellation/cleanup ใน resource owner เดียวกัน
- explicit blocking call ใน async/UI/event-loop context

### P4.2 สิ่งที่ต้องใช้ benchmark/policy/runtime

- N+1 ที่ขึ้นกับ ORM relation และ request shape
- query plan, index quality และ lock duration
- React/Angular render frequency
- queue saturation, connection-pool sizing และ backpressure
- throughput, tail latency, memory growth และ capacity headroom

### P4.3 Required evidence

- baseline และ changed result จาก harness เดียวกัน
- warmup/sample count/percentile ที่ระบุชัดเจน
- machine/runtime identity
- SLO หรือ budget ที่ผู้ใช้กำหนด
- artifact digest และ deterministic configuration
- ไม่มี credential หรือ production target ใน generated script

สถานะ ณ 2026-08-26: benchmark harness บันทึก warmup, samples, median, p95, peak RSS,
runtime/platform, workload bytes และ deterministic digests แล้ว. Clean 1,000-file profile มี p95
0.7744 วินาที; adversarial-regex 250-file profile มี p95 2.3359 วินาที; large-file profile 8 x
512 KiB มี p95 8.3140 วินาทีและใช้ budget แยก 10 วินาที. ตัวเลขนี้เป็นผลบน Windows/Python
3.12.10 ของเครื่องที่ระบุ ไม่ใช่คำรับรองทุกเครื่อง.

## P5 — Real-world evaluation and release readiness

### P5.1 Evaluation corpora

- controlled vulnerable/clean pairs
- generated-code corpus
- polyglot monorepos
- Unicode, worktree, symlink และ nested-root repositories
- representative open-source repositories ที่ตรวจ license และ snapshot revision แล้ว
- framework-version fixtures สำหรับ syntax ที่เปลี่ยนเร็ว

ห้ามดาวน์โหลด repository ใน default scan การสร้าง/refresh corpus เป็น maintainer workflow แยกต่างหาก

### P5.2 Quality metrics

รายงานต่อ batch ต้องมี:

- true positives, false positives, false negatives และ true negatives
- observed precision/recall พร้อมจำนวน sample
- results แยกตาม rule, ecosystem, severity และ engine
- duplicate findings ต่อ root cause
- scan time และ memory delta
- evasion cases ที่รู้แต่ยังตรวจไม่ได้

Blocking high/critical ต้องมี zero observed false positives ใน controlled negative corpus และ representative clean corpus ที่ระบุขนาดไว้ คำว่า zero ต้องเขียนเป็น “zero observed” เสมอ ไม่ใช่รับรองว่าไม่มี false positive ในทุก repository

### P5.3 Performance budgets

- reference 1,000-file scan ต้องไม่เกิน 5 วินาที
- promotion batch ต้องไม่ทำให้ reference runtime แย่ลงเกิน 5% โดยไม่มีเหตุผลและ optimization plan
- report ordering และ fingerprints ต้อง deterministic
- large-file, many-file และ adversarial-regex corpus ต้องมี timeout/memory bounds

สถานะ ณ 2026-08-24: controlled head-to-head labels แยก sink ที่ต้องรายงานออกจาก
context-only source/helper files และรายงาน TP/FP/FN/TN พร้อม corpus digest. Manifest สำหรับ
real-world evaluator มี clean baseline 3 ชุดและ intentionally vulnerable 3 ชุด โดย pin full commit
และ license permalink; evaluator fail closed เมื่อ fetch/revision/license ไม่พร้อม และทุก finding
ยังเป็น `unreviewed` จนกว่าจะมี human labels จึงห้ามใช้ผลดิบกล่าวอ้าง precision. รอบ reviewed
manifest วันที่ 2026-08-24 fetch/verify/scan ผ่านครบ 6 revisions รวม 1,805 files, 732 findings
และ 310 application-scope findings โดยตัวเลขเหล่านี้เป็น inventory ไม่ใช่ precision metric.

## AI extension security track

เป้าหมายของ track นี้คือให้ ShipProof ตรวจ trust boundary รอบ AI agent ได้ดีขึ้น โดยรักษาจุดแข็งเดิม:
default scan ต้อง local, read-only, offline, deterministic และไม่ต้องติดตั้ง service เพิ่ม. จำนวนหมวด
หรือจำนวน signature ไม่ใช่ success metric; ทุก claim ต้องไม่เกินหลักฐานที่ scanner มองเห็นจริง.

### Precision boundary ที่ปิดแล้ว

- `SP096`–`SP100` ทำงานเฉพาะ package ที่ประกาศด้วย `SKILL.md`; README ทั่วไปและ directory ชื่อ
  `skills` ที่ไม่มี descriptor ไม่ถือเป็น Skill package
- changed-only scan ยังคง ownership context จาก `SKILL.md` แม้ descriptor ไม่ได้อยู่ใน diff
- `SP099` รายงานการเข้าถึง environment credential เป็น capability evidence ระดับ medium ไม่อ้างว่า
  มีการขโมยหรือส่งข้อมูลออก
- `SP100` ต้องเห็น POST-capable client ไปยัง webhook-style endpoint; การเรียก API ของ model provider
  ตามปกติและ GET webhook ไม่ใช่ finding
- `SP282` ยอมรับ Ollama bare model, namespace, `library/*` และ default registry; รายงานเฉพาะ host
  ที่ไม่ใช่ default registry และระบุชัดใน model name
- กฎ AI framework ปัจจุบันเป็น source-level posture checks ไม่ใช่ CVE scanner และไม่อ้างว่า
  component ที่ deploy อยู่ตรงกับ vulnerable version

### P0/P1 recheck — 2026-09-04

P0/P1 ในส่วนนี้หมายถึงลำดับงานก่อนปล่อย contract ที่เชื่อถือได้ ไม่ใช่คะแนน CVSS หรือการยืนยันว่า exploit ได้ การตรวจซ้ำพบ implementation ของ completeness/suppression อยู่แล้ว จึงแก้ contract ที่พิสูจน์ว่าผิดก่อนเพิ่ม feature ซ้ำหรือเพิ่มจำนวนกฎ

| Priority | ข้อบกพร่องที่ reproduce ได้ | การแก้และ acceptance |
| --- | --- | --- |
| P0 | changed-only นับ omission นอก scope; ZIP ไม่เคารพ exclude; directory error หาย | เลือก scope ก่อนนับ, แยก policy skip, บันทึก walk errors, ทดสอบทั้ง in-scope/out-of-scope |
| P0 | read limit เช็คเฉพาะก่อนอ่าน; unreadable นับเป็น scanned; fallback นับซ้ำ | bounded descriptor reads, reparse/nonregular guards, UTF-8 omission, reset partial counters, database header only |
| P0 | trace/SARIF/check และ autofix อาจให้ผลขัดกับ incomplete gate | ส่ง completeness ทุก adapter, check ไม่อ้าง complete pass, Action แสดง warning, MCP คืน gate trace, fix/dry-run ไม่ bypass |
| P1 | baseline key สะกดผิดหรือ matcher เป็น null ทำให้ suppress กว้างขึ้น; baseline-out โหลดซ้ำไม่ได้ | strict keys/types/duplicate rejection, bounded reasons/counts/bytes, round-trip tests, review-required default reason |
| P1 | SP631 ตีความ `ledger` เป็น `edge` และแจ้ง Node CLI เป็น critical | ต้องมี literal Edge runtime declaration และ runtime import ใน code; เพิ่ม negative cases สำหรับ Node/comments/strings/type imports |

Scope: implementation เดิม + fixes ข้างต้น; ไม่มี dependency/network default เพิ่ม ไม่มีการ execute SkillSpector หรือคัดลอก detector ของโครงการนั้น Rule IDs/fingerprints เดิมยังคงอยู่ แต่ชื่อและ proof boundary ของ SP631 ถูกแก้ให้ตรงหลักฐาน

หลักฐาน: `tests/test_p0_p1_recheck.py`, `tests/test_coverage_suppression.py`, Node policy/Action/hardening tests, และ MCP SDK handshake ทดสอบ end-to-end การตรวจเป็น self-review พร้อม isolated read-only surface mapping ไม่ใช่ independent security audit การสร้าง symlink จริงขึ้นกับสิทธิ์ OS; มี reparse-point simulation แยกต่างหาก

ผล verification รอบนี้ (Windows, Node 24.15.0, Python 3.12.10):

- `npm run check` ผ่านครบ: Node test suites ผ่านทั้งหมด (skip 1 เคส symlink จริงที่ OS ไม่อนุญาต), Python 684 tests, demo 2 tests, lint, package manifest และ packed-artifact smoke test
- regression suite ใหม่ 25 tests: ผ่าน 24, skip 1; ตรวจทั้ง positive/negative paths รวม 8 false-positive variants ของ SP631
- self-scan `--max-file-bytes 10000000 --fail-on high` exit `0`, verdict `PASS_WITH_EVIDENCE`, 369 files, 0 app findings และ 29 test-scope findings; completeness เป็น `true` (assets 10 รายการเป็น intentional boundary) และไม่มี omission reason
- structural contracts regenerate แล้วและ `--check` ยืนยันว่า current; `git diff --check` ผ่าน

Benchmark แบบ local generated corpus, warm-up 1 pass + 3 measured samples ตาม budget ใน CI (ไม่ใช่ production SLO หรือการเปรียบเทียบกับเครื่องมืออื่น):

| Profile | Files / jobs | Median / p95 (s) | Measured process peak RSS (MB) | Gate |
| --- | --- | --- | --- | --- |
| clean throughput | 1,000 / 4 | 0.7519 / 0.7572 | 28.04 | p95 < 15 s |
| adversarial regex, 4 KiB | 250 / 1 | 2.0974 / 2.1399 | 26.40 | p95 < 5 s; RSS < 256 MB |
| large file, 512 KiB | 8 / 1 | 7.8642 / 7.9444 | 27.17 | p95 < 10 s; RSS < 256 MB |

ทุก profile ผ่านและมี 0 findings; RSS ของ throughput ไม่ใช่ยอดรวม memory ของทุก worker ยังไม่ได้รัน remote CI matrix ของ Node 20/22 หรือ Python versions/OS อื่นในรอบนี้ และยังไม่ได้ release/commit ผล green gate ไม่ใช่การยืนยันว่าไม่มีบัคหรือ false positive นอก corpus ที่ทดสอบ

### ความปลอดภัยของตัว scanner เอง

- [x] **Inspection completeness ledger:** รายงานเฉพาะ selected source scope; unreadable/parser-limit/line-limit (บรรทัดยาวเกิน 8,192 ตัวอักษร)/oversized/container/unknown-binary/symlink ป้องกัน complete pass ส่วน asset/database เป็น intentional scope boundary; dependency/build trees ยัง prune เพื่อ bounded performance แต่ Git-index และ changed-file selections จะพา tracked files ใน tree นั้นกลับมาตรวจ จึงไม่ซ่อน committed payload หลังชื่อ directory ได้ ส่วน untracked members ยังไม่ enumerate; production `check` บังคับ full-root/high-floor/fail-closed policy ห้ามตีความ zero findings หรือ `is_complete` เป็นความปลอดภัย runtime ดู [contract](commands.md#coverage-and-baseline-contracts)
- [x] **Auditable suppression (baseline เวอร์ชัน 2):** fingerprint objects และกฎ glob ต้องมี reason; legacy string fingerprints ยังใช้ได้ JSON/Markdown/terminal รองรับ `--show-suppressed` และ SARIF เก็บ external suppressions baseline ไม่ใช่ signed approval หรือ whole-file/content-bound digest; `scanner_version` เป็นข้อมูลและ major-version warning เท่านั้น
- [x] **Eval-dataset scope:** `evals.json`/`dataset.jsonl` และพี่น้องใต้ `evals/`/`eval/` เป็น test scope โดยอัตโนมัติ — prompt และ ground-truth ไม่ trigger กฎ non-secret แต่ secret ยังถูกรายงาน

Backlog ถัดไป (ปรับลำดับหลัง recheck):

1. **P1 — Capability inventory (AI-A):** opt-in script `scripts/ai_inventory.py` แยก declared / observed-static / unknown และ redact credential แล้ว ยังไม่เป็น blocking rule และยังไม่มี capability graph ครบตาม milestone
2. **P1 — MCP-config posture + metadata:** explicit mutable/unpinned launch settings เป็น advisory; bidi/hidden instructions ต้องมี field-specific context ภาษาไทย/จีน/ญี่ปุ่นหรือ mixed-script อย่างเดียวไม่ใช่ช่องโหว่ ต้องมี benign multilingual corpus ก่อนเพิ่ม severity
3. **P2 — Nested artifact inspection:** `--inspect-archives` เปิด ZIP/Office ในหน่วยความจำด้วยขอบเขต member/byte/ratio แล้ว ค่า default ยัง omit container; `.tar`/`.7z` ยังไม่ตรวจ
4. **P2 — External evidence adapter (AI-B):** `shipproof gate evidence --import` รับ envelope ที่มี version/digest แล้ว exit `2` เมื่อ malformed ไม่เพิ่ม LLM/OSV/network เป็น default
5. **P2 — Least-privilege/change detection:** หลัง inventory และ trusted digest store มี contract แล้วเท่านั้น ต้องนิยาม reviewer, accepted revision และ stale evidence ก่อนอ้างว่า detect rug pull

เลื่อน candidate เป็น blocking rule ได้เมื่อมี primary sources, positive/negative/adversarial fixtures, deduplication และ human-labelled representative results; ไม่ใช้ rule quota หรือ metric ของ SkillSpector มาอ้าง precision ของ ShipProof

### Milestone AI-A — Inventory และ capability graph

1. เพิ่ม opt-in profile สำหรับค้นหา `SKILL.md`, MCP configuration และ agent-workflow manifests
2. สร้าง normalized inventory ของ component, declared tools, filesystem/network/process capability,
   credential access และ remote endpoints โดย redact value ทุกชนิด
3. แยก `declared`, `observed-static` และ `unknown` ให้ชัด ห้ามตีความ absence of evidence เป็น safe
4. แสดงเส้นทาง trust boundary เช่น prompt -> tool -> credential -> network sink โดยใช้ proof level
5. เพิ่ม golden contracts สำหรับ nested package, monorepo, changed-only, Unicode path และ symlink boundary

Acceptance gate:

- inventory เหมือนกันผ่าน Python CLI, Node CLI, MCP และ SARIF adapters
- default scan ไม่มี network/process execution เพิ่มจาก contract ปัจจุบัน
- clean representative corpus มี zero observed high/critical false positives
- finding ทุกตัวอธิบาย observable evidence และ non-claims ได้

### Milestone AI-B — External evidence adapters

1. รับผลจากเครื่องมือภายนอกผ่าน `gate evidence` แบบ opt-in และ schema-versioned
2. require tool identity, version, config digest, target digest, timestamp และ explicit limitations
3. normalize severity/control mapping โดยเก็บ original rule ID และ provenance เสมอ
4. duplicate/correlate กับ ShipProof finding โดยไม่ทำให้ imported claim กลายเป็น native proof
5. แยก unavailable, timeout, malformed, stale และ incompatible evidence เป็น exit `2`

Adapter ต้องไม่ดาวน์โหลดหรือรันเครื่องมือภายนอกเองใน default path. การรองรับเครื่องมือใดจะเริ่ม
หลังมี stable public output schema หรือ pinned fixture ที่ตรวจ license และ provenance แล้วเท่านั้น.

### Milestone AI-C — Agent red-team lab

1. ทำเป็น `labs` แบบ explicit opt-in แยกจาก static gate
2. ใช้ isolated test credentials, deny-by-default tools, bounded requests, timeout และ output caps
3. เริ่มจาก prompt-injection/tool-confusion fixtures ที่ deterministic ก่อนเพิ่ม model-backed evaluation
4. model-backed score ต้องรายงาน model/version, seed หรือ repeat policy, sample count และ variance
5. ห้ามใช้คะแนนชุดเดียวอ้างความปลอดภัยทั่วไป และห้ามส่ง repository source ออกนอกเครื่องโดยปริยาย

Promotion ไปเป็น blocking gate ทำได้เมื่อมี independent labels, reproducible harness, documented
false-positive/false-negative boundary และผู้ใช้อนุมัติ network/cost/external side effects โดยชัดเจน.

## CLI 1.0 cleanup

### คงไว้เป็น public surface

- `check`, `scan`, `explain`
- `gate budget`, `gate evidence`
- `labs impact`, `labs invariants`, `labs cost`, `labs capacity`
- `init`, `config validate`, `doctor`, `mcp`
- `version`, `help`

### ถอดหรือหยุดรองรับ

- `badge`: ถอดแล้ว เพราะ static output ไม่สามารถ attest repository status
- `prompt`: ใช้ `init`
- `install`: ใช้ `init --scope global`
- `hook`: ใช้ pre-commit framework configuration
- top-level `cost`, `impact`, `invariants`, `capacity`: ใช้ `labs`
- legacy budget/evidence aliases: ใช้ `gate`

Migration gate ก่อน 1.0:

- aliases แสดง warning ในรุ่นก่อนถอด
- help ซ่อน legacy surface
- docs ไม่มีตัวอย่างใหม่ที่ใช้ alias
- parser tests ยืนยันว่า 1.0 ปฏิเสธคำสั่งที่ถอดด้วย exit `2`
- release notes มี replacement command ทุกตัว

สถานะ ณ 2026-08-24: parser มี major-version gate และ test ครบทุก hidden alias แล้ว. รุ่น 0.x
ยังแสดง migration warning; การถอดจริงจะเกิดเมื่อออก 1.0 หลัง Milestone C–F ผ่านครบเท่านั้น.

## Milestones และ dependency

| Milestone | Includes | เริ่มได้เมื่อ | Exit evidence |
| --- | --- | --- | --- |
| A — Trustworthy adapters | P0.1–P0.5 | ทันที | schemas, handshake, package manifest, zero-secret artifacts |
| B — Rule assurance | P1 | Milestone A contract รูปแบบคงที่ | every executable ID has fixture contract |
| C — First language cohort | P2 batch A | Milestone B ผ่าน | shadow results และ zero observed FP ตาม gate |
| D — Polyglot evidence | P3 + P2 batch B | adapter trust model จาก A | compiler/analyzer evidence contracts |
| E — Scale proof | P4 | schemas และ artifact identity คงที่ | benchmark/load evidence ตาม SLO |
| F — Stable 1.0 | P5 + CLI cleanup | A–E ผ่าน | consumer matrix, package/release proof, migration complete |

## ลำดับงานสามชุดถัดไป

### ชุดที่ 1 — Shadow evidence ของ prototype

1. เปิด advisory-only lane ให้ `SP5301`, `SP5951` และ `SP6309`
2. รันเฉพาะ revision-pinned representative repositories
3. label findings และ negative files โดยมนุษย์
4. บันทึก duplicate/runtime delta แยกต่อ candidate
5. promote หรือ reject ตามหลักฐาน ห้ามเติมกฎทดแทนเพื่อให้ครบโควตา

### ชุดที่ 2 — Representative corpus review

1. รัน opt-in evaluator จาก reviewed manifest
2. เก็บ corpus/license/tool/environment digests
3. label TP/FP/FN/TN แยก ecosystem, severity และ engine
4. เพิ่ม generated/polyglot/framework-version corpora ที่ยังขาด
5. publish observed metrics พร้อม sample count และ known evasions

### ชุดที่ 3 — 1.0 release gate

1. ปิด Milestone C–E ด้วย shadow, benchmark และ representative labels
2. ทดสอบ consumer matrix และ packed artifact บนทุก runtime ที่รองรับ
3. ถอด legacy aliases และตรวจ replacement ทุกคำสั่ง
4. freeze schema/exit-code compatibility boundary
5. cut 1.0 เฉพาะเมื่อ release proof, migration และ external evidence ครบ

## Candidate review record

ใช้ข้อมูลขั้นต่ำนี้กับทุก candidate ที่เข้าสู่ triage:

```yaml
candidate_id: SPxxxx
ecosystem: typescript
status: triaged
source_revision: "official-document revision or review date"
cwe: CWE-xxx
existing_overlap: []
proof_claim: "สิ่งที่ detector พิสูจน์ได้เท่านั้น"
non_claims:
  - "สิ่งที่ต้องใช้ runtime หรือ data flow"
engine: structural
positive_fixtures: []
negative_fixtures: []
adversarial_fixtures: []
false_positive_analysis: ""
remediation_test: ""
shadow_metrics: null
decision: pending
```

## Definition of done

งานหนึ่งถือว่าเสร็จเมื่อ:

- implementation, tests, schemas และ docs เปลี่ยนพร้อมกัน
- exit-code contract และ redaction ผ่าน
- ไม่มีการเพิ่ม network/dependency ใน default path
- duplicate checker และ golden contracts ผ่าน
- `npm run check` ผ่าน
- self-scan ผ่านด้วย 0 findings ที่ high gate
- benchmark อยู่ใน budget
- limitation และสิ่งที่ยังพิสูจน์ไม่ได้ถูกบันทึก

คำสั่งตรวจขั้นต่ำ:

```bash
npm run check
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
python scripts/benchmark-scanner.py --files 1000
```

หาก gate ใดไม่ผ่าน งานต้องคงสถานะ incomplete แม้ detector จะตรวจ positive fixture ได้แล้ว
