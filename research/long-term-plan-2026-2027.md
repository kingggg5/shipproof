# ShipProof — Long-term product and engineering plan

วันที่จัดทำ: 2026-09-22 · สถานะ: proposed · Baseline: `dd589b5c4d15b48c58a2bb97022d0bb59b3b54cc`

## 1. ทิศทางที่เลือก

อัปเดตการดำเนินงาน 2026-10-22: แก้ precision/eligibility ใน LT-01–LT-06 แล้ว
ตามขอบเขตที่ทดสอบใน [รายงาน 0.12.0](release-0.12.0-report.md) รวม syslog และ
DTD/resolver semantics; ไม่ได้พิสูจน์ native runtime exploitability. LT-07 ยัง
ไม่ถือว่าทำ profiling/optimization ครบเพียงเพราะ benchmark ผ่าน และ LT-08
เรื่อง semantic catalog triage ยังเปิดอยู่. แผนระยะยาวทั้งฉบับยังไม่ถือว่าเสร็จ

ทำให้ ShipProof เป็น production gate ที่ติดตั้งง่าย ตรวจเร็ว อธิบายปัญหาได้ตรง และให้ผลซ้ำได้ จุดแข็งระยะยาวคือ **ความแม่นยำของกฎ + หลักฐานที่ตรวจย้อนกลับได้ + ประสบการณ์แก้บัคที่ดี**

เป้าหมาย 5,000 executable rules ยังคงเป็นเป้าหมายขยายผลิตภัณฑ์ แต่การปล่อยขึ้นกับกฎที่มี semantics ต่างกันและผ่านการวัดผลจริง จำนวน research rows, test cases, syntax variants และ imported findings ต้องรายงานแยกกัน

ใช้เอกสารนี้จัดลำดับงานใหม่ร่วมกับ [rule plan](rule-plan-2026-2027.md) แผนเก่า เช่น [quality plan](shipproof-quality-plan.md) และ [development plan](../docs/next-development-plan.md) ใช้อ้างอิงประวัติและงานที่มีแล้ว สถานะ checked ในแผนเก่าต้องยืนยันกับ commit/ผลตรวจอีกครั้งก่อนนับว่าเสร็จ

เอกสารนี้เป็นแผนที่สร้างเสร็จแล้ว งาน implementation ในตารางยังไม่ได้ดำเนินการหรือรับรองจากการสร้างแผน

## 2. Baseline ที่ตรวจจาก checkout

| สิ่งที่ตรวจ | ผลวันที่ 2026-09-22 | ความหมายต่อแผน |
| --- | --- | --- |
| Working tree ก่อนเขียนแผน | สะอาด; HEAD `dd589b5` | แผนยึด revision นี้ ไม่อนุมานสถานะ remote ปัจจุบัน |
| Registry / assurance | 640 executable; 640 complete ตาม minimum; partial/uncontracted/metadata debt = 0 | ตัวเลข complete เป็นความครบของ manifest ไม่ใช่ precision |
| Realistic negative inventory | 81 rules มีอย่างน้อยหนึ่ง realistic negative; 559 มีเฉพาะ near-miss; 423 high/critical ขาด realistic negatives | ต้องลงทุนกับ corpus และ semantics พร้อมเพิ่มกฎ |
| Research | language 5,000 + annual 1,800 + expert 1,000 = 7,800 records | ชื่อ CWE ข้ามภาษาไม่เท่ากับ unique detector; Dart ยังไม่อยู่ใน allocation 14 ecosystems |
| Default gate timeout | 120s; coverage CI override 180s | เป็น execution ceiling; ยังไม่มีหลักฐานว่า throughput ดีขึ้นจากการเพิ่ม timeout |
| Architecture | scanner registry/engines หลักอยู่ใน `scan_repo.py`; Node adapters และ precision policy แยกแล้ว | เริ่มแยก registry/engines ทีละส่วนด้วย output parity |
| Released version | package metadata 0.11.2; มี commits เพิ่มกฎหลัง tag | ต้องแยก released artifact ออกจาก current main inventory |

หลักฐาน inventory: `scripts/rule_assurance_report.py::build_report`, `precision.py`, `scan_repo.py`, `tests/test_rule_quality.py`, `tests/test_structure.py`, research JSON และ release docs ใน checkout

## 3. งานด่วนก่อนขยายกฎรอบถัดไป

Priority ในแผนหมายถึงลำดับงาน ไม่ใช่คะแนนความรุนแรงช่องโหว่

| ID | Priority / ปัญหาที่ตรวจพบ | งานและ acceptance |
| --- | --- | --- |
| LT-01 | P0: SP104 แจ้ง `SecurityContext(withTrustedRoots: false)` เป็น TLS verification disabled | แก้ interpretation; empty/custom trust store ต้องไม่เป็น bypass; unconditional acceptance ยังถูกตรวจได้; เพิ่ม official-safe regression |
| LT-02 | P0: docs เรียก SP666–SP670 ว่า advisory แต่ `ADVISORY_RULE_IDS` มีเพียง SP061 | กำหนด eligibility จาก metadata ที่ runtime ใช้จริง; probe SP669/SP670 ปัจจุบันได้ `tier=gate` และ block ที่ medium/L0; test ทุก adapter/threshold ต้องตรง contract |
| LT-03 | P1: SP670 รวม DTD parsing, resolver construction และ XXE เข้าด้วยกัน | แยก posture, resource exhaustion และ external resolution; ตรวจ target framework/object lifecycle; `Parse + null resolver` ไม่ใช่หลักฐาน external fetch |
| LT-04 | P1: SP668 พลาด `syslog(LOG_ERR, argv[1])` | ใช้ sink argument index ตาม API; format ของ syslog อยู่ argument ที่สอง; positive/negative พร้อม boundary ของทุก sink |
| LT-05 | P1: release notes 0.10–0.11.2 ถูกเปลี่ยนจำนวนกฎตาม main | คืนข้อมูลจาก tagged snapshots; structure tests ของ release ต้องเทียบ tag/version snapshot ไม่บังคับเท่ากับ live RULES |
| LT-06 | P1: test helper `ScanRepoTests.findings()` เรียก detector ตรง ไม่ได้เดิน filesystem | แยก matcher tests กับ walker tests; กฎใหม่ทุกตัวต้องผ่าน temp-repo scan, suffix, manifest, scope และ CLI parity |
| LT-07 | P1: timeout CI เคยถูกแก้โดยขยายเวลา | profile clean checkout กับ working tree; จับเวลาช่วง walk/read/match/structural/serialization; จัด performance regression แยกจาก functional coverage |
| LT-08 | P1: catalog triage ใช้ title keywords และ CWE overlap เป็นตัวแทน coverage | เปลี่ยนเป็น signature/semantic evidence; similarity ใช้เสนอคู่ให้ review; ไม่ตัด candidate เพราะ CWE เดียวกันอย่างเดียว |

ข้อ LT-01 ยืนยันกับ [Dart SecurityContext](https://api.dart.dev/dart-io/SecurityContext/SecurityContext.html): flag ควบคุมการเติม root certificates ให้ context ไม่ใช่การยอมรับ certificate ทุกใบ ตรวจ source/test ของ SDK ผ่าน Context7 เพิ่มด้วย

ข้อ LT-03 ต้องอ้าง [Microsoft CA3075](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075) และ target framework: null resolver ป้องกันการเปิด external resources แต่ยังต้องพิจารณา entity expansion และขอบเขต input แยกกัน ส่วนข้อ LT-04 อ้าง [POSIX syslog](https://pubs.opengroup.org/onlinepubs/9699919799/functions/syslog.html) ทั้งหมดเป็น original detector work

## 4. Roadmap 12 เดือน

ระยะเวลาเป็น planning estimate สำหรับหนึ่ง primary implementer กับผู้ตรวจ domain แบบ part-time เริ่มนับจากวันที่เริ่ม implementation; ถ้าผู้ตรวจไม่พร้อม ให้คงงานไว้ที่ shadow/review และปรับ throughput

| ระยะ | งานหลักและเจ้าของบทบาท | ส่งมอบ | เกณฑ์จบ |
| --- | --- | --- | --- |
| 0–2 สัปดาห์ | LT-01–LT-08; core maintainer + QA reviewer | precision fixes, inventory ที่ truthful, profiles, regression cases | ไม่มี known contradiction ใน eligibility; official-safe cases ผ่าน; historical release data ถูกต้อง |
| สัปดาห์ 3–6 | core maintainer: registry/metadata boundary; corpus maintainer: corpus v1 | schema สำหรับ rule revision/lifecycle; deterministic docs; parsing context reuse | unchanged rules ให้ IDs, anchors, fingerprints, verdicts เหมือนเดิมบน golden corpus |
| สัปดาห์ 7–12 | Dart/.NET/C reviewers: language cohorts; core maintainer: execution budget | first validated cohorts + pinned corpus + native evidence design | release batch มี labels, FP/FN review, duplicate analysis และ runtime delta |
| เดือน 4–6 | language engines + adoption | bounded syntax/object flow; contributor templates; partner feedback | cohort metrics ผ่าน rule plan; clean install/upgrade/rollback ผ่าน; debt ลดตาม milestone |
| เดือน 7–9 | integration + stable API | CLI/Action/MCP parity, release candidate 1.0 เมื่อพร้อม | migration examples, source-to-artifact traceability, measured compatibility matrix |
| เดือน 10–12 | expand validated ecosystems | เปิด cohorts ภาษาอื่นตาม user evidence; rule maintenance automation | dashboard แยก measured/unknown; กฎ stale ถูก review/deprecate; capacity model ระบุเวลาไปถึง 5,000 ใหม่ |

1.0 เป็น compatibility milestone; ไม่ผูกกับจำนวนกฎ และไม่ออก tag เพียงเพราะครบวัน

## 5. Architecture ที่จะลงทุน

รักษา `check`, `scan`, `explain` เป็นทางหลัก ส่วน `labs` ใช้สำหรับงานทดลอง; CLI, Action และ MCP รับผลจาก decision policy เดียวกัน

1. ย้าย rule metadata/คำอธิบายออกจากไฟล์ engine เป็น modules ตาม ecosystem โดยรักษา import path และ CLI entry เดิมช่วง migration
2. เพิ่ม immutable per-file context: suffix, source role, lexical tokens, line offsets, framework/target hints; สร้าง context ครั้งเดียวแล้วแชร์ให้ applicable rules
3. แยก detectors เป็น literal/config, bounded structural และ data-flow; แต่ละ detector ประกาศ input ที่ต้องใช้และ proof claim
4. ตัดสิน gate หลังรวบรวม findings ผ่าน policy กลาง; lifecycle, severity, proof, eligibility และ human triage เป็นคนละ field
5. ใช้ content digest, rule-set digest และ effective policy digest สำหรับ evidence identity; cache ที่เริ่มก่อนคือ parsed context แบบขอบเขตชัด ยังไม่ reuse verdict จาก mtime อย่างเดียว
6. ขยาย existing external evidence importer ก่อนสร้าง compiler ของเราเอง; analyzer opt-in ต้องระบุ version, configuration, scope, timeout, source digest และ failure status

ลำดับ native evidence ที่เสนอ: รับ SARIF/JSON ที่ผู้ใช้สร้างไว้ → validate/map results → จึงเพิ่มการเรียก local tool โดย explicit consent. Dart analyzer, Roslyn/.NET และ Clang เป็น candidates; ความพร้อม/version/schema ต้องตรวจขณะ implementation. Build หรือ analyzer plugin อาจ execute project code จึงห้ามเป็นส่วนของ default offline scan

ยังไม่ลงทุนใน custom LLM training, vector database, managed red-team platform หรือ cloud code upload จนมี workload ที่ lexical search, host agent และ local evidence ตอบไม่ได้และมี benchmark ยืนยัน

## 6. ทำให้พัฒนาเร็วขึ้นและสแกนเร็วขึ้น

### Development throughput

- จำกัด WIP 1 engine change + 1 cohort เพื่อให้ review ทัน; cohort เปิด 10–25 proposals แต่ integration batch 3–10 unique detectors
- ใช้ schema เดียวสร้าง rule docs/inventory/fixture checks; ผู้เขียนกำหนด semantics และ labels ก่อน matcher
- รัน focused tests ตอนแก้แต่ละ detector; full checks หนึ่งครั้งต่อ integrated batch; รันซ้ำเมื่อมี diff/failure ใหม่
- เก็บ CI logs และ failure artifact แบบ bounded/redacted; ผูก run กับ commit ให้ชัดก่อนประกาศผ่าน
- แยก review roles: implementer, ecosystem reviewer, corpus labeler; ถ้าเป็นคน/agent เดียวกันระบุ self-review

### Runtime budgets ที่เสนอ

ตัวเลขต่อไปนี้เป็น target สำหรับ fixed benchmark runner หลังเก็บ baseline ไม่ใช่ผลวัดปัจจุบัน

| Workload | Target | วิธีวัด / หลักฐาน |
| --- | --- | --- |
| 1,000 small clean source files | warm p95 ≤ 3s; peak RSS ≤ 256 MiB | warm-up 1 + อย่างน้อย 10 measured samples; รายงาน cold start แยก |
| เพิ่มกฎ cohort เดียว | p95 และ RSS delta ≤ 10% บน corpora ที่ได้รับผล | baseline/candidate บนเครื่องและ corpus เดียวกัน; หาก variance ทับ threshold ให้เพิ่ม samples |
| Real-repo self-check | median ลด ≥ 30% จาก LT-07 baseline | รายงานไฟล์/bytes/ขนาดบรรทัดตามภาษา พร้อม breakdown; ห้ามอ้างจาก timeout ceiling |
| Hostile/minified input | อยู่ใน budget fixture ปัจจุบันและมี omission ledger | รายงาน worst case; truncation/timeout ต้องไม่เป็น PASS ที่ดูครบ |
| Package | ceiling ปัจจุบัน 500,000 packed / 1,870,000 unpacked bytes | planned growth ของ rules ต้อง review ก่อน; ไม่เพิ่มเพดานหลัง fail โดยไม่มีเหตุผลและ measurement |

หาก engine โตจน budget ไม่เหมาะ ให้เสนอ ADR เรื่อง optional packs/lazy loading พร้อม consumer tests และตัวเลข ก่อนเปลี่ยน contract

## 7. Quality และ adoption milestones

- ภายในสัปดาห์ 2: official-safe regressions สำหรับกฎที่พบผิด; dashboard แยก manifest completeness กับ detection quality
- ภายในสัปดาห์ 6: ลด high/critical realistic-negative debt จาก baseline 423 อย่างน้อย 50 กฎ ผ่าน semantic review ไม่เติม prose ให้ครบความยาว
- ภายในสัปดาห์ 12: ลดอย่างน้อย 150 กฎจาก baseline; candidate ใหม่ทุกตัวมี realistic negatives ครบตาม rule plan
- ภายในเดือน 6: high/critical ที่ยัง default-gate eligible มี realistic-negative review ครบ; กฎที่พิสูจน์ไม่ได้เปลี่ยน lifecycle พร้อม migration note
- เชิญ 5 pilot repositories ที่เจ้าของยินยอม: Flutter app, Dart service/CLI, ASP.NET API, .NET worker และ C utility. ขอ findings disposition และเวลา triage; default scanner ไม่เก็บ telemetry
- ขยายเป็น 15 representative repos (อย่างน้อยภาษาเป้าหมายละ 5) หลัง pilot; ต้องมี library และ application, safe patterns และ intentionally vulnerable fixtures
- วัดผู้ใช้ติดตั้งจนได้ first useful result, unreviewed findings, suppressions พร้อม reason, repeated false positives และ median triage time; เริ่มจาก consented/manual feedback

## 8. Release และ maintenance

ทุก integration batch: focused tests, assurance, same-input parity, required full check/self-scan, pack smoke และ applicable performance gate. ก่อน release ให้ CI matrix ของ commit ที่จะ tag ผ่านและตรวจ artifact metadata เทียบ main อย่างชัดเจน

Tag notes คงข้อมูลของ release นั้น; main docs แสดง unreleased changes. Breaking fingerprint/schema/exit behavior ต้องมี migration และ version decision. Existing IDs ที่เลิกใช้เก็บ tombstones; ห้าม reuse เป็นคนละ root cause

ทบทวน rule sources ทุก 90 วันหรือทันทีเมื่อ upstream มี semantic/version change; กฎที่ source หมดอายุไม่ได้กลายเป็น unsafe โดยอัตโนมัติ ให้ review applicability. หยุด cohort ที่เปิดใช้แล้วสร้าง confirmed false positives กระทบ gate; ทำ regression และออก patch

รองรับ runtimes ตาม product policy ที่ตรวจ official support schedule รายไตรมาส. Baseline CI มี Node 20/22/24 และ Python 3.10–3.14; ตารางที่มีอยู่ไม่ใช่ข้ออ้างว่าทุกรุ่นยังได้รับ upstream security support

## 9. Definition of done และลำดับเริ่มงาน

แผน implementation เริ่ม **LT-01 → LT-02 → LT-03/LT-04 → LT-05/LT-06 → LT-07/LT-08 → registry/cohorts**

งานจะปิดได้เมื่อมี trigger ที่ยืนยันได้, safe counterexample, measured result, updated contract/docs, trace ถึง source revision และความเสี่ยงที่เหลือ. Green CI อย่างเดียวไม่ปิด precision review. เป้าหมาย 5,000 ยัง open จน runtime registry แสดง unique enabled rules ครบและ promotion records ผ่านทุกตัว

เมื่อครบ timebox ให้บันทึก elapsed time จริง, commit, งานเสร็จ/ค้าง และ next action; อย่าอ้างทำครบสองชั่วโมงหากไม่มี clock evidence. เอกสารแผนนี้ไม่เริ่ม background automation หรือ release โดยอัตโนมัติ
