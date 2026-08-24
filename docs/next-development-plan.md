# ShipProof next development plan

Last reviewed: 2026-08-24.

สถานะ: แผนหลักสำหรับเปลี่ยน research backlog ให้เป็น production evidence ที่เชื่อถือได้ โดยไม่เปิดกฎจำนวนมากแบบ big-bang และไม่ลดมาตรฐาน false-positive

## เป้าหมาย

ShipProof ต้องรักษาแกนหลักสามข้อพร้อมกัน:

1. คำสั่งและ evidence contracts ต้อง fail closed และให้ผลเหมือนกันทุก adapter
2. กฎ executable ทุกตัวต้องมีหลักฐานทั้ง positive, negative และ adversarial
3. Research candidates จะเลื่อนเป็น detector ได้เฉพาะเมื่อพิสูจน์ semantics และ precision ของ ecosystem นั้นแล้ว

แผนนี้ใช้ร่วมกับ [แผนผู้สมัคร 1,000 รายการ](rule-expansion-1000.md), [ชุดข้อมูลปี 2021–2026](rule-expansion-2021-2026.md) และ [แผนเฉพาะภาษา 5,000 รายการ](rule-expansion-languages-5000.md)

## Baseline ปัจจุบัน

ข้อมูลต่อไปนี้เป็น snapshot ณ วันที่ทบทวน ไม่ใช่ตัวเลขรับประกันในอนาคต:

- executable scanner rules: 620
- research inventory: 7,800 catalogued candidates plus 1,000 reserved promotion slots (`SP651–SP9450`)
- language-specific research candidates: 5,000 (`SP4451–SP9450`)
- project Python test cases ที่ discover ได้: 564 พร้อม Node, package และ end-to-end suites
- self-scan: 0 active findings ที่ high gate
- reference benchmark: 1,000 ไฟล์ใน 0.6813 วินาที (1,467.7 files/s), peak RSS 24.79 MB บน Windows/Python 3.12; warm pass 1,441.5 files/s
- default path: read-only, offline และไม่มี dependency เพิ่ม

Candidate ID ไม่ได้แปลว่ามี detector แล้ว จำนวน research slots จึงห้ามนำไปรวมกับ executable rule count ในเอกสารหรือการตลาด

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
- [ ] เพิ่ม golden JSON fixture ต่อคำสั่ง
- [x] ตรวจ output จริงกับ schema ใน CI ไม่ใช่ตรวจเพียงว่าไฟล์ schema parse ได้
- [x] ระบุ schema version, tool version, verdict, limitations, root และ artifact identity ให้สม่ำเสมอ
- [ ] เพิ่ม compatibility fixture ก่อนเปลี่ยนชื่อหรือลบ field

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

- [ ] สร้างรายงาน rule ID ที่ขาด positive, negative, adversarial, CWE, remediation หรือ false-positive analysis
- [ ] ขยาย `tests/rule_cases_v2.json` หรือ successor ให้ครอบคลุมทุก executable ID
- [ ] แยก fixture ตาม ecosystem และ engine: regex, AST, structural, artifact และ taint
- [ ] ทำ structure test ให้ fail เมื่อเพิ่ม rule โดยไม่มีสอง polarity

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

### ชุดที่ 1 — Contract closure

1. MCP per-tool schemas และ bounded stdin
2. per-command JSON schemas/golden fixtures
3. secret-safe k6 body
4. package manifest allowlist
5. docs-derived structure tests

### ชุดที่ 2 — Existing rule assurance

1. inventory executable IDs เทียบกับ fixture manifest
2. เติม polarity ให้ high/critical ก่อน
3. เติม walker/suffix/multiline/secret/autofix contracts
4. รัน real negative corpus
5. publish coverage report ที่ derive ได้

### ชุดที่ 3 — Promotion batch A

1. คัด direct candidates ที่ไม่ซ้ำ
2. เขียน ecosystem semantics และ false-positive analysis
3. สร้าง fixtures ก่อนเขียน detector
4. implement engine ที่เล็กที่สุดซึ่งพิสูจน์เงื่อนไขได้
5. เปิด shadow, วัดผล แล้วจึงตัดสิน promote/reject

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
