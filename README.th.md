# ShipProof

**ระบบตรวจสอบและพิสูจน์ความพร้อมของโค้ดก่อนปล่อยขึ้น Production**

[English](README.md) · [ภาษาไทย](README.th.md)

ความปลอดภัย · ความถูกต้องของโค้ด · การรองรับการสเกล · ประสิทธิภาพ · ความพร้อมสำหรับ Production

รองรับการทำงานร่วมกับ **Codex**, **Claude Code**, **Cursor**, **Gemini**, **Grok**, Terminal ทั่วไป, Pre-commit และ GitHub Actions

[![CI](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml)
[![Security](https://github.com/kingggg5/shipproof/actions/workflows/security.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/security.yml)
[![Public beta](https://img.shields.io/badge/public_beta-v0.5.1-2563eb)](CHANGELOG.md)
[![Coverage gates](https://img.shields.io/badge/coverage-Python_80%25_%7C_Node_core_70%25-0f766e)](.github/workflows/ci.yml)
[![Codex](https://img.shields.io/badge/Codex-skill%20%2B%20plugin-111827)](https://learn.chatgpt.com/docs/build-skills)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-skill%20%2B%20plugin-D97757)](https://code.claude.com/docs/en/skills)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ShipProof คือเกตตรวจสอบความพร้อม (Production Gate) สำหรับโปรเจกต์ที่เขียนโค้ดด้วยตนเองหรือใช้ AI ช่วยเขียน (Vibe Coding) เครื่องมือจะตรวจสอบโค้ดแบบ Static Analysis โดยไม่ต้องรันโค้ดจริง, วัดและเปรียบเทียบการใช้ CPU/RAM/Latency ตามงบประมาณที่กำหนด, จำลองการรองรับโหลดและคอขวดเมื่อมีผู้ใช้เพิ่มขึ้น และสร้าง Prompt คำแนะนำให้ AI นำไปแก้ไขโค้ดได้อย่างตรงจุด

ShipProof ไม่ได้สัญญาคำว่า "สมบูรณ์แบบ 100%" หรือ "ไม่มีวันถูกแฮก" จากการสแกนโค้ดเพียงอย่างเดียว แต่ช่วยให้เรามองเห็นสมมติฐานและจุดบกพร่องที่ซ่อนอยู่ นำหลักฐานจริงมาพิสูจน์ และคงอำนาจการตัดสินใจขั้นสุดท้ายไว้ที่นักพัฒนาและทีมงาน

<p align="center">
  <img src="docs/assets/terminal-demo.svg" width="100%" alt="ShipProof terminal demo" />
</p>

## ทำความเข้าใจใน 30 วินาที

ในไดเรกทอรีตัวอย่าง [demo API](examples/demo-api/README.md) มีการจำลองโค้ดที่มีช่องโหว่จริง 5 ประการ: ไม่มีระบบยืนยันสิทธิ์ใน Route แอดมิน, ต่อ String ในคำสั่ง SQL โดยตรง, การแบ่งหน้าข้อมูล (Pagination) ที่ไม่จำกัดจำนวนสูงสุด, การยิง HTTP Request ภายนอกโดยไม่มี Timeout และการเปิด Debug Mode ค้างไว้ใน Production

```bash
shipproof scan examples/demo-api/fixtures/before --fail-on high
# ผลลัพธ์: BLOCK · พบ 5 ปัญหาความเสี่ยงสูง

python -m unittest discover -s examples/demo-api/fixtures/after/tests -v
shipproof scan examples/demo-api/fixtures/after --fail-on high
# ผลลัพธ์: PASS_WITH_EVIDENCE · ไม่พบปัญหา (0 findings)
```

ชุดทดสอบจะยืนยันความถูกต้องระหว่างก่อนและหลังการแก้โค้ด พร้อมทั้งมี [Node.js, Python และ Performance Fixtures](fixtures/README.md) เพื่อป้องกันการแจ้งเตือนที่ผิดพลาด (False Positives)

## เริ่มต้นใช้งานทันที (ไม่ต้องตั้งค่าไฟล์ล่วงหน้า)

สามารถรันคำสั่งตรวจสอบในโปรเจกต์ใดก็ได้ทันที:

```bash
npx github:kingggg5/shipproof check
```

รูปแบบ git นี้ใช้ได้โดยไม่ต้องมีบัญชีหรือ Token ใด ๆ (GitHub Packages บังคับให้ authenticate แม้จะเป็นแพ็กเกจสาธารณะ จึงไม่ใช้รูปแบบ `npx @kingggg5/shipproof` ไว้ตอนนี้ — เมื่อประกาศบน npm registry สาธารณะแล้วคำสั่งสั้นดังกล่าวจะใช้ได้ทันที)

หรือติดตั้งแบบ Global ลงในเครื่อง:

```bash
npm install --global github:kingggg5/shipproof
shipproof doctor .
shipproof init . --target both
shipproof check .
```

คำสั่ง `init` จะเพิ่มชุดคำสั่ง (Skills) ให้กับ Codex ในโฟลเดอร์ `.agents/skills` และ Claude Code ในโฟลเดอร์ `.claude/skills` โดยจะไม่เขียนทับโฟลเดอร์เดิมที่มีอยู่แล้ว เว้นแต่จะระบุตัวเลือก `--force`

ความต้องการของระบบ: Node.js 20+ สำหรับการเรียกใช้งาน CLI และ Python 3.10+ สำหรับคำสั่ง `scan`, `check`, `budget`, `capacity` และระบบ MCP ตัวระบบหลักไม่มี Runtime Dependency ภายนอก ทำให้ติดตั้งและทำงานได้อย่างรวดเร็ว

## สร้างมาเพื่อยุค Vibe Coding

งานวิจัยสนามจริงปี 2025–2026 ชี้ตรงกันว่าเกิดอะไรเมื่อโค้ดถูก ship เร็วกว่าที่จะตรวจสอบ: การสแกนแอป vibe-coded 5,200 ตัว เจอช่องโหว่กว่า 2,000 จุดและ secrets หลุดกว่า 400 รายการ ราว 20% ของแอป vibe-coded มีข้อบกพร่องร้ายแรง และ 62% ของโซลูชันที่ AI สร้างมีข้อบกพร่องเชิงดีไซน์หรือความปลอดภัย โดยมี 74 AI-linked CVEs ที่ถูกบันทึกไว้แล้ว ShipProof เกิดมาเพื่อช่องว่างนี้: เป็น "ดวงตาคู่ที่สอง" แบบออฟไลน์และ deterministic ที่รันในไม่กี่วินาทีหลัง agent ทำงานแต่ละรอบ ด้วย 200 detectors ที่เล็งไปที่กลุ่มความล้มเหลวที่ AI เขียนบ่อยที่สุด (ลืม authorization, SQL แบบต่อ string, secrets หลุด, AI endpoint ไม่จำกัด, retry storm, debug ติดค้าง) พร้อม proof levels ที่ซื่อสัตย์ — ไม่อ้างหลักฐานมากกว่าที่ engine ตรวจได้จริง

## รูปแบบการรายงานผลใน Terminal

ShipProof ออกแบบการรายงานผลให้เข้าใจง่ายเหมือนได้รับการตรวจโค้ด (Code Review) จาก Senior Engineer โดยระบุบรรทัดที่พบปัญหา, ระดับความมั่นใจ, เหตุผลว่าทำไมจุดนี้จึงอันตราย และแนวทางการแก้ไขที่ถูกต้อง:

```text
  [BLOCK] ShipProof: BLOCK
  Scanned 24 files | 1 blocking issue | 0 suppressed
  HIGH: 1

  [HIGH] Sensitive route lacks visible authorization (SP108)
     src/routes/admin.py:42  |  confidence: LIKELY

     Evidence:
       40   
       41   @app.post("/admin/users/{user_id}/ban")
       42 > def ban_user(user_id: str):
       43       return db.ban(user_id)

     Why: เส้นทาง API สำหรับผู้ดูแลระบบไม่มีการตรวจสอบสิทธิ์ ทำให้ผู้ใช้ทั่วไปสามารถเรียกคำสั่งได้
     Fix: เพิ่ม Dependency ในการตรวจสอบสิทธิ์ เช่น Depends(require_admin)
     Ref: CWE-862 | OWASP ASVS V4

  ----------------------------------------------------------------------

  -> รัน `shipproof scan --fix-prompt` เพื่อสร้าง Prompt สำหรับสั่งให้ AI แก้โค้ด
  -> รัน `shipproof explain SP108` เพื่อดูรายละเอียดและตัวอย่างการเขียน Test
```

## กระบวนการพัฒนาแบบวงปิดร่วมกับ AI (Closed-Loop Workflow)

ShipProof เปลี่ยนการเขียนโค้ดร่วมกับ AI ให้เป็นวงรอบที่มีการตรวจสอบหลักฐานอย่างรัดกุม: AI เขียนโค้ด -> ShipProof ตรวจพบความเสี่ยง -> สร้างคำสั่งแก้ไขพร้อมเงื่อนไข -> AI แก้โค้ดและเพิ่ม Regression Test -> ShipProof ตรวจสอบซ้ำจนกว่าจะผ่านเกณฑ์

<p align="center">
  <img src="docs/assets/architecture-workflow.svg" width="100%" alt="ShipProof verification pipeline" />
</p>

```mermaid
flowchart LR
    A["AI เขียนโค้ด"] --> B["ShipProof ตรวจพบความเสี่ยง"]
    B --> C["shipproof scan --fix-prompt"]
    C --> D["AI แก้ไขโค้ดพร้อมเขียน Regression Test"]
    D --> E["ShipProof ตรวจสอบหลักฐานยืนยันความปลอดภัย"]
```

### การสร้าง Prompt สำหรับส่งต่อให้ AI

```bash
shipproof scan --fix-prompt
```

คำสั่งนี้จะสร้างข้อความคำสั่งที่มีบริบทของโค้ด, ข้อจำกัด และเงื่อนไขการเขียน Test เพื่อนำไปวางใน **Codex**, **Claude Code**, **Cursor**, **Gemini**, **Grok** หรือ **Copilot**:

```text
Fix SP108 in src/routes/admin.py (line 42).

Problem:
An admin route has no visible authorization dependency.

Required fix:
Add Depends(require_admin) to route dependencies.

Engineering Dimensions:
- [x] Object-Level Authorization & IDOR Protection
- [x] Tenant Boundary Isolation
- [x] Least Privilege & Default-Deny Policy
- [x] Token Lifecycle & Invalidation

Implicit Requirements:
- Enforce authorization before executing any business logic or state modification.
- Return 403 Forbidden for authenticated non-authorized users, 401 for unauthenticated.
- Preserve legitimate user access paths while closing escalation routes.

Failure Scenarios to Guard Against:
- Regular authenticated user submits payload to target endpoint and modifies elevated resource.
- Missing tenant scoping allows user in Organization A to access records belonging to Organization B.

Constraints:
- Do not change the public API contract
- Add a regression test that verifies the fix
- Reference: CWE-862, OWASP ASVS V4
```

### การวิเคราะห์ผลกระทบและการกระจายความเสี่ยง (Change Impact Analysis)

ตรวจสอบ Callers, ฐานข้อมูล/State ที่แตะต้อง และชุด Regression Test ที่เกี่ยวข้องโดยตรงก่อนลงมือแก้โค้ด:

```bash
shipproof impact src/routes/admin.py
```

### การตรวจสอบ System Invariants ระดับสถาปัตยกรรม

ตรวจสอบ Invariants ของระบบ เช่น เส้นแบ่งสิทธิ์ (Auth Boundary), Tenant Isolation และ Transaction Safety:

```bash
shipproof invariants .
```

### การคำนวณ Token และงบประมาณ AI Agent (Cost & Token Budgeting)

ประเมิน Token และค่าใช้จ่ายของ AI Agent แบบออฟไลน์ 100% พร้อมคำนวณส่วนลด Prompt Caching สำหรับโมเดลปี 2026 (Claude 3.5/3.7, GPT-4o, Gemini 2.0, DeepSeek R1):

```bash
shipproof cost . --model claude-3-5-sonnet --iterations 3
shipproof cost . --model deepseek-r1 --cadence per-pr --budget-usd 0.50
```

### การรัน Agent บน Git Worktree แยกต่างหาก (Worktree Sandbox)

แยกโฟลเดอร์ทำงานของ AI Agent ไว้ใน `.work/<task>` โดยไม่กระทบ Branch หลัก และตรวจสอบ Gate ก่อน Merge อัตโนมัติ:

```bash
shipproof worktree create fix-auth
# Agent ทำงานในโฟลเดอร์ .work/fix-auth อย่างปลอดภัย
shipproof worktree check fix-auth
shipproof worktree merge fix-auth
```

### การสร้าง Status Badge สำหรับ README

สร้าง Markdown Badge แสดงสถานะความพร้อมส่งมอบขึ้น Production:

```bash
shipproof badge .
```

### การดูคำอธิบาย Rule อย่างละเอียด

สามารถตรวจสอบเหตุผลเบื้องหลัง, รูปแบบการโจมตี, ข้อควรระวังเรื่อง False Positive และวิธีเขียน Test ยืนยันผล:

```bash
shipproof explain SP108
```

## การตรวจจับที่ปรับตาม Framework อัตโนมัติ

ShipProof จะตรวจสอบไฟล์โครงสร้างของโปรเจกต์และเปิดใช้งานกฎการตรวจสอบที่เหมาะสมกับ Framework และ Runtime นั้นๆ โดยอัตโนมัติ:

| กลุ่มเทคโนโลยี / Framework | การตรวจจับ | รายการที่ตรวจสอบเจาะจง |
| :--- | :--- | :--- |
| **Next.js, Nuxt, SvelteKit, Remix, Astro** | `package.json` (`next`, `nuxt`, `@sveltejs/kit`, `@remix-run/*`, `astro`) | ป้องกัน Secret หลุดใน `NEXT_PUBLIC_` (`SP403`), ตรวจสอบนโยบาย CSP (`SP408`), ป้องกัน Connection รั่วใน Serverless DB (`SP313`), ตรวจสอบ Middleware Static Asset Matcher (`SP413`), ตรวจสอบการตรวจสิทธิ์ใน Server Action (`SP420`) |
| **React, Vue, Angular, SolidJS** | `package.json` (`react`, `vue`, `@angular/core`, `solid-js`) | ป้องกัน Supabase `service_role` key หลุดฝั่ง Client (`SP503`), ป้องกันการ Log Credential ใน Client Bundle (`SP204`), ป้องกัน SVG XSS (`SP112`), ป้องกัน Raw HTML Injection (`SP116`), ป้องกัน Angular Sanitizer Bypass (`SP125`), ป้องกัน Vue `v-html` (`SP415`), ตรวจสอบ Array Index Key (`SP414`) |
| **Express, Fastify, NestJS, Koa, Hono, Elysia** | `package.json` (`express`, `fastify`, `@nestjs/core`, `koa`, `hono`, `elysia`) | ตรวจสอบ Security Headers (`SP401`), ตรวจสอบ Rate Limit ใน Auth Route (`SP402`), ตรวจสอบ CSRF ใน Cookie Session (`SP407`), ป้องกัน Open Redirect (`SP121`), ป้องกัน SSRF จาก URL ของ Request (`SP124`), ป้องกัน Raw Error Object หลุด (`SP406`), ตรวจสอบ Body Parser Limits (`SP412`), ป้องกัน Stream Pipe Error (`SP336`), ป้องกัน In-Memory Session รั่ว (`SP337`), ป้องกัน Sync Crypto ใน Event Loop (`SP339`), ป้องกัน `process.exit` ใน Handler (`SP343`), ป้องกัน Stripe Webhook ปลอม (`SP502`), ตรวจสอบ Rate Limit ใน AI Route (`SP501`) |
| **Prisma, Drizzle, TypeORM, Mongoose, Supabase** | `package.json` (`@prisma/client`, `drizzle-orm`, `typeorm`, `mongoose`, `@supabase/*`) | ป้องกัน Raw SQL Interpolation (`SP103`), ป้องกันการสร้าง DB Client ซ้ำซ้อนใน Serverless (`SP313`), ป้องกัน Supabase RLS Bypass (`SP503`), ป้องกัน Unbounded Query (`SP302`), ตรวจสอบ Connection Pool Limits (`SP328`), ป้องกัน Per-Row Commit Lock (`SP326`) |
| **FastAPI, Starlette, Litestar, Sanic** | `pyproject.toml`, `requirements.txt` | ตรวจสอบสิทธิ์ Route แอดมิน (`SP108`), ตรวจสอบ `response_model` (`SP409`), ป้องกัน Wildcard CORS Credentials (`SP419`), ตรวจสอบ N+1 Query ใน Loop (`SP307`), ตรวจสอบ Limit ของ Pagination (`SP305`), ตรวจสอบ Timeout (`SP304`), ป้องกัน Asyncio Task หลุด (`SP335`), ป้องกัน ThreadPool ต่อ Request (`SP344`) |
| **Django & Flask** | `pyproject.toml`, `requirements.txt` | ป้องกัน Hardcoded `SECRET_KEY` (`SP404`), ตรวจสอบ Wildcard `ALLOWED_HOSTS` (`SP405`), ป้องกัน Debug Mode (`SP201`, `SP411`), ป้องกัน Flask Hardcoded `secret_key` (`SP410`), ป้องกัน SQL Interpolation (`SP103`), ป้องกัน SSTI ใน `render_template_string` (`SP137`) |
| **Go (Gin, Echo, Fiber, Chi)** | `go.mod` | ตรวจสอบ Server Timeout (`SP131`), ป้องกันการละเลย Error (`SP136`), ป้องกัน Response Body Leak (`SP315`), ป้องกัน Goroutine Context Leak (`SP309`), ป้องกัน Unbuffered Channel Deadlock (`SP332`), ป้องกัน WaitGroup Race Condition (`SP333`), ป้องกัน Insecure Secret Fallback (`SP004`), ตรวจสอบ Outbound Request Timeout (`SP304`), ป้องกัน Unbounded Concurrency (`SP306`) |
| **Rust (Actix-web, Axum, Rocket)** | `Cargo.toml` | ป้องกัน Secret / Token หลุด (`SP001`, `SP002`, `SP003`), ป้องกันการปิด TLS Verification (`SP104`), ป้องกัน SSRF สู่ Cloud Metadata (`SP109`), ป้องกันการ Log ข้อมูลลับ (`SP204`) |
| **PHP (Laravel, Symfony)** | `composer.json` | ป้องกัน Dynamic Code Execution (`SP101`), ป้องกัน SQL Injection (`SP103`, `SP128`), ป้องกัน Path Traversal (`SP110`), ป้องกัน Loose Equality Credential Comparison (`SP127`), ป้องกัน Reflected XSS (`SP129`), ป้องกัน Open Redirect (`SP130`), ป้องกัน Object Injection (`SP113`) |
| **Ruby (Rails, Sinatra)** | `Gemfile` | ป้องกัน Secret Key รั่วไหล (`SP003`), ป้องกัน Unsafe Deserialization ผ่าน Marshal/YAML (`SP106`), ป้องกันการเปิด Debug Mode (`SP201`), ป้องกันการปิด CSRF (`SP417`), ป้องกัน Dynamic Code Execution (`SP101`), ตรวจสอบ Payment Idempotency (`SP504`) |
| **Java / Kotlin (Spring Boot, Quarkus, Micronaut)** | `pom.xml`, `build.gradle`, `build.gradle.kts` | ป้องกัน Secret / Token หลุด (`SP001`, `SP002`, `SP003`), ป้องกัน Wildcard CORS พร้อม Credentials (`SP107`), ป้องกัน Path Traversal (`SP110`), ป้องกัน Spring Boot Actuator หลุดสาธารณะ (`SP416`), ป้องกัน Binary ObjectInputStream Deserialization (`SP168`) |
| **C# / .NET (ASP.NET Core, Web API)** | `*.csproj`, `packages.config` | ป้องกัน Sync-over-Async Thread Starvation (`SP132`), ป้องกัน `debug="true"` ใน Config (`SP133`), ป้องกัน Unconditional `UseDeveloperExceptionPage` (`SP418`), ป้องกัน Insecure Deserialization (`SP106`) |
| **C / C++** | `CMakeLists.txt`, `Makefile` | ป้องกัน Unbounded String Functions `strcpy`/`gets` (`SP135`), ป้องกัน File Permission แบบ World-Writable (`SP139`, `SP169`) |
| **Containers, Serverless & CI/CD** | `Dockerfile`, `compose.yaml`, `serverless.yml`, `.github/workflows` | ป้องกันการรันเป็น Root (`SP205`), ป้องกัน Pipe curl to shell (`SP206`), ป้องกัน Copy `.env` (`SP207`), ป้องกัน Expose Low Port (`SP208`), ป้องกัน PR Target Checkout (`SP209`), ป้องกัน CI Script Injection (`SP210`), ตรวจสอบ CI Permissions (`SP211`), ป้องกัน Secret Log ใน CI (`SP212`), ตรวจสอบการ Pin SHA ใน GitHub Actions (`SP203`), ตรวจสอบ Base Image Digest (`SP202`), ป้องกัน Docker Socket Mount (`SP222`), ตรวจสอบ Nginx TLS (`SP223`) |

## การควบคุม False Positive (ความแม่นยำสูง)

ShipProof เน้นความแม่นยำสูงเพื่อไม่ให้เกิดการแจ้งเตือนรบกวน:

- **Inline suppression:** ใส่คอมเมนต์ `# shipproof-ignore SP101` หรือ `// shipproof-ignore SP101` ไว้ที่บรรทัดนั้นหรือบรรทัดก่อนหน้าโดยตรง
- **Confidence filtering:** รันด้วยตัวเลือก `--min-confidence high` เพื่อดูเฉพาะรายการที่มีความมั่นใจสูง
- **Reviewed baselines:** บันทึกรายการหนี้ทางเทคนิคที่มีอยู่เดิมไว้ใน `.shipproof-baseline.json` ด้วยคำสั่ง `shipproof scan --baseline-out .shipproof-baseline.json`

## การใช้งานบน GitHub Actions

เพิ่มเกตตรวจสอบอัตโนมัติในทุก Pull Request:

```yaml
name: ShipProof
on: [pull_request]
permissions:
  contents: read
jobs:
  production-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kingggg5/shipproof@v0.5.1
        with:
          fail-on: high
```

Action จะสร้างการ์ดสรุปสถานะแบบ Markdown สวยงามลงใน GitHub Step Summary อัตโนมัติ

สำหรับ Pull Request ใน Repository ขนาดใหญ่ สามารถสแกนเฉพาะไฟล์ที่เปลี่ยนแปลงเทียบกับ Branch หลักได้:

```yaml
      - uses: kingggg5/shipproof@v0.5.1
        with:
          fail-on: high
          changed-since: origin/main
```

Scanner จะหาไฟล์จาก git diff (ไฟล์ที่เพิ่ม/คัดลอก/แก้ไข/เปลี่ยนชื่อ รวมถึงไฟล์ใหม่ที่ยังไม่ track) และระบุ ref ไว้ใน `changed_since` ของ JSON output การสแกนรอบนั้นจะไม่รายงาน findings นอก diff — ควรคง scheduled full scan ไว้เป็น Safety Net

## นโยบายเดียว คำสั่งเดียว

สร้างไฟล์คอนฟิก [`.shipproof.yml`](.shipproof.yml) ไว้ที่ Root ของโปรเจกต์ จากนั้นสั่งรันตรวจสอบทุกเกตได้ด้วยคำสั่งเดียว:

```yaml
version: 1
scan:
  path: .
  exclude:
    - vendor/**
security:
  fail_on: high
performance:
  baseline: perf/baseline.json
  current: perf/current.json
  budget: perf/budget.json
capacity:
  config: capacity.json
```

สั่งตรวจสอบทั้งหมด:

```bash
shipproof check
```

## สรุปคำสั่งทั้งหมดของ CLI

```text
shipproof check [path] [--config <file>]     รันทุกเกตตามที่ตั้งค่าไว้ (หรือรันได้ทันทีแม้ไม่มีไฟล์คอนฟิก)
shipproof scan [path] [options]              สแกนโค้ดในโปรเจกต์ (--format terminal|json|sarif|markdown)
shipproof explain <rule-id>                  แสดงคำอธิบายกฎอย่างละเอียด (เช่น explain SP108)
shipproof doctor [path] [--json]             ตรวจสอบความพร้อมของ Environment และ Runtime ในเครื่อง
shipproof init [path] [--target <host>]      ติดตั้ง Skills สำหรับ Codex (.agents) และ Claude (.claude)
shipproof install [--target <host>]          ติดตั้ง Skills สำหรับใช้งานส่วนตัวใน Codex/Claude
shipproof prompt <name|list>                 แสดงข้อความ Prompt มาตรฐานสำหรับงาน Production Engineering
shipproof budget [budget options]            ตรวจสอบการถดถอยของ CPU, RAM, Latency เทียบกับ Baseline
shipproof capacity [capacity options]        วิเคราะห์การรองรับโหลดและส่งออกเป็นสคริปต์ทดสอบ k6
shipproof evidence [path] [options]          รันตัววิเคราะห์ภาษาเฉพาะทาง (TypeScript, Go, Rust)
shipproof hook <install|remove>              ติดตั้งหรือถอด Git Pre-commit Hook อัตโนมัติ
shipproof mcp                                เริ่มต้นการทำงานของ MCP Server แบบ Read-Only
shipproof help                               แสดงคำแนะนำการใช้งาน
shipproof version                            แสดงเวอร์ชันปัจจุบัน
```

รายละเอียดเพิ่มเติมเกี่ยวกับ Parameter และ Exit Code สามารถอ่านได้ที่ [docs/commands.md](docs/commands.md)

## การติดตั้งจากการ Clone โค้ด

```bash
git clone https://github.com/kingggg5/shipproof.git
cd shipproof
npm install --global .
```

จากนั้นเรียกใช้งาน Skill ในระหว่างพัฒนา:

```text
Use $engineer-production-systems to implement this feature with explicit security,
CPU, RAM, latency, and failure budgets.
```

ก่อนปล่อยโค้ดขึ้น Production:

```text
Use $audit-production-readiness to audit this repository for production.
```

สำหรับ Claude Code สามารถโหลดโปรเจกต์เป็น Plugin ได้โดยตรง:

```bash
claude --plugin-dir .
```

## การควบคุมงบประมาณทรัพยากร (Resource Budgets)

ผลการทดสอบ Benchmark จะยังคงอยู่ในโปรเจกต์ของคุณ โดย ShipProof จะทำหน้าที่ประเมินตัวเลขเพื่อความรวดเร็วและไม่ขึ้นกับ Cloud Provider ใดๆ

ตัวอย่าง `perf-baseline.json`:

```json
{"metrics":{"p95_latency_ms":120,"cpu_ms":8.5,"rss_mb":180,"throughput_rps":850}}
```

กำหนดเพดานที่ยอมรับได้ใน `perf-budget.json`:

```json
{
  "metrics": {
    "p95_latency_ms": {"direction":"lower","max_regression_percent":10,"max":160},
    "cpu_ms": {"direction":"lower","max_regression_percent":8},
    "rss_mb": {"direction":"lower","max_regression_percent":5,"max":220},
    "throughput_rps": {"direction":"higher","max_regression_percent":5,"min":750}
  }
}
```

สั่งตรวจสอบเกต:

```bash
shipproof budget \
  --baseline perf-baseline.json --current perf-current.json \
  --budget perf-budget.json --format markdown
```

ตัวอย่างไฟล์ที่พร้อมทดลองรันอยู่ที่ [`examples/performance`](examples/performance)

## เครื่องมือวิเคราะห์โหลดและการสเกล (Capacity Modeling)

สแกนโค้ดและส่งออกผลลัพธ์เป็น SARIF 2.1.0 สำหรับ GitHub Code Scanning:

```bash
shipproof scan . --format sarif --output shipproof.sarif --fail-on high
```

<p align="center">
  <img src="docs/assets/capacity-demo.svg" width="100%" alt="ShipProof capacity planning demo" />
</p>

จำลองความต้องการของระบบเมื่อมีผู้ใช้ลงทะเบียน 100,000 ถึง 1,000,000 คน พร้อมคำนวณการใช้ CPU, Memory และ Database Connection Pool:

```bash
shipproof capacity \
  --users 100000 --dau-ratio 0.25 --peak-hour-ratio 0.15 \
  --actions-per-session 10 --requests-per-action 2 --burst 2.5 --format markdown
```

ส่งออกเป็นสคริปต์ k6 สำหรับนำไปรัน Load Test จริง:

```bash
shipproof capacity --config examples/capacity/shipproof.config.json \
  --export-k6 load-test.js --format json
BASE_URL=https://staging.example.test LOAD_TEST_TOKEN=replace-me k6 run load-test.js
```

## การเชื่อมต่อผ่าน MCP และการตรวจภาษาเฉพาะทาง

ติดตั้ง Dependency เพิ่มเติมสำหรับ MCP แล้วเริ่มการทำงานของ Server:

```bash
npm install --save-dev github:kingggg5/shipproof @modelcontextprotocol/sdk@1.29.0 zod@3.25.76
npx shipproof mcp
```

ตรวจสอบเครื่องมือเฉพาะภาษาที่พร้อมใช้งาน:

```bash
shipproof evidence . --list --format json
shipproof evidence . --adapter typescript --format json
shipproof evidence . --adapter go --format json
shipproof evidence . --adapter rust --allow-project-code --format json
```

## ตารางกฎการตรวจสอบ (Detection Rules Reference)

รหัส `SP111` และ `SP308`–`SP312` เป็นรหัสสงวนไว้สำหรับกฎในอนาคต (ยังไม่ถูกใช้งาน)

ทุก finding มี `proof_level` ระบุระดับหลักฐาน: `L0` คือการ match ด้วย pattern, `L1` คือหลักฐานเชิงโครงสร้าง (Python AST, การวิเคราะห์ทั้งไฟล์ หรือการตรวจ artifact เช่น header ของไฟล์ SQLite) — ทั้งสองระดับนี้คือสิ่งที่ ShipProof พิสูจน์ได้จริงในวันนี้ ระดับที่สูงกว่าที่ต้องใช้ data-flow ข้ามไฟล์ หรือ runtime evidence จะไม่ถูกอ้างจนกว่า engine จะรองรับจริง

| รหัส Rule | คำอธิบายปัญหา | ระดับความรุนแรง | การตรวจจับ |
| :--- | :--- | :--- | :--- |
| **SP001** | Private key committed | CRITICAL | Regex |
| **SP002** | AWS access key committed | CRITICAL | Regex |
| **SP003** | Credential-like value committed | HIGH | Regex |
| **SP004** | Insecure secret fallback default | HIGH | Regex |
| **SP005** | GCP service account private key committed | CRITICAL | Regex |
| **SP006** | GitHub access token committed | CRITICAL | Regex |
| **SP007** | AWS session token or secret key committed | CRITICAL | Regex |
| **SP008** | Slack bot token or webhook committed | CRITICAL | Regex |
| **SP009** | Stripe live secret key committed | CRITICAL | Regex |
| **SP010** | OpenAI or Anthropic API key committed | CRITICAL | Regex |
| **SP011** | SendGrid or Twilio API key committed | CRITICAL | Regex |
| **SP012** | Mailgun or Postmark API token committed | CRITICAL | Regex |
| **SP013** | Discord bot token or webhook committed | CRITICAL | Regex |
| **SP014** | Square or PayPal credentials committed | CRITICAL | Regex |
| **SP015** | HuggingFace or Replicate token committed | CRITICAL | Regex |
| **SP016** | Hardcoded Bearer JWT token | HIGH | Regex |
| **SP017** | Package registry publish token committed | CRITICAL | Regex |
| **SP018** | Kubernetes service account token committed | CRITICAL | Regex |
| **SP019** | Database connection string with password | HIGH | Regex |
| **SP020** | Redis connection URI with password | HIGH | Regex |
| **SP021** | MongoDB connection string with password | HIGH | Regex |
| **SP022** | Cloudflare API token committed | CRITICAL | Regex |
| **SP023** | Datadog or New Relic key committed | HIGH | Regex |
| **SP024** | Sentry auth token or secret DSN committed | HIGH | Regex |
| **SP025** | Hardcoded encryption passphrase or static salt | CRITICAL | Regex |
| **SP026** | Anthropic API key committed | CRITICAL | Regex |
| **SP027** | Hugging Face user access token committed | CRITICAL | Regex |
| **SP028** | Pinecone API key committed | CRITICAL | Regex |
| **SP029** | Cohere API key committed | CRITICAL | Regex |
| **SP030** | Datadog API or application key committed | CRITICAL | Regex |
| **SP031** | New Relic license or ingest key committed | CRITICAL | Regex |
| **SP032** | Sentry DSN authentication token committed | HIGH | Regex |
| **SP033** | Postman API key committed | CRITICAL | Regex |
| **SP034** | Shopify access token or private app secret committed | CRITICAL | Regex |
| **SP035** | Square OAuth or access token committed | CRITICAL | Regex |
| **SP036** | Algolia admin API key committed | CRITICAL | Regex |
| **SP037** | Vault root or client token committed | CRITICAL | Regex |
| **SP038** | Pulumi access token committed | CRITICAL | Regex |
| **SP039** | Grafana service account or API token committed | CRITICAL | Regex |
| **SP040** | Discord bot token committed | CRITICAL | Regex |
| **SP041** | Telegram bot API token committed | CRITICAL | Regex |
| **SP042** | Slack incoming webhook URL committed | HIGH | Regex |
| **SP043** | Linear personal access token committed | CRITICAL | Regex |
| **SP044** | Notion internal integration token committed | CRITICAL | Regex |
| **SP045** | Airtable personal access token committed | CRITICAL | Regex |
| **SP046** | Resend API key committed | CRITICAL | Regex |
| **SP047** | Twilio Account SID and Auth Token committed together | CRITICAL | Regex |
| **SP048** | Firebase service account JSON committed | CRITICAL | Regex |
| **SP049** | Age encryption identity secret key committed | CRITICAL | Regex |
| **SP050** | PyPI upload token committed | CRITICAL | Regex |
| **SP101** | Dynamic code execution | HIGH | Python AST |
| **SP102** | Shell execution enabled | HIGH | Python AST |
| **SP103** | SQL built with interpolation | HIGH | Python AST |
| **SP104** | TLS verification disabled | HIGH | Regex |
| **SP105** | JWT signature verification disabled | CRITICAL | Regex |
| **SP106** | Unsafe deserialization | HIGH | Regex |
| **SP107** | Credentialed wildcard CORS | HIGH | Regex |
| **SP108** | Sensitive route lacks visible authorization | HIGH | Regex |
| **SP109** | SSRF to internal network or metadata | HIGH | Regex |
| **SP110** | Path traversal in file path | HIGH | Regex |
| **SP111** | Zip-Slip unsafe archive extraction | HIGH | Regex |
| **SP112** | Unsanitized SVG upload accepted | MEDIUM | Regex |
| **SP113** | PHP object injection via unserialize | CRITICAL | Regex |
| **SP114** | Catastrophic ReDoS nested quantifier | MEDIUM | Regex |
| **SP115** | XXE-capable lxml parser without entity hardening | MEDIUM | Regex |
| **SP116** | React dangerouslySetInnerHTML with dynamic value | HIGH | Regex |
| **SP117** | Dynamic code via new Function | HIGH | Regex |
| **SP118** | Implicit eval via timer string | MEDIUM | Regex |
| **SP119** | Filesystem path joined from request input | HIGH | Regex |
| **SP120** | Unsafe JS deserialization via node-serialize | CRITICAL | Regex |
| **SP121** | Open redirect from request value | MEDIUM | Regex |
| **SP122** | Security value from insecure randomness | HIGH | Regex |
| **SP123** | Hardcoded initialization vector | HIGH | Regex |
| **SP124** | SSRF via user-controlled request URL | HIGH | Regex |
| **SP125** | Angular sanitizer bypass | HIGH | Regex |
| **SP126** | Auth token stored in web storage | MEDIUM | Regex |
| **SP127** | PHP loose comparison on credential | HIGH | Regex |
| **SP128** | PHP SQL with interpolated variables | HIGH | Regex |
| **SP129** | PHP reflected XSS via echoed superglobal | HIGH | Regex |
| **SP130** | PHP open redirect via Location header | MEDIUM | Regex |
| **SP131** | Go HTTP server without timeouts | MEDIUM | Regex |
| **SP132** | .NET sync-over-async blocking | MEDIUM | Regex |
| **SP133** | ASP.NET debug compilation enabled | MEDIUM | Regex |
| **SP134** | Assertion used as authorization | HIGH | Regex |
| **SP135** | Unbounded C string function | HIGH | Regex |
| **SP136** | Go error explicitly discarded | MEDIUM | Regex |
| **SP137** | Server-side template injection | HIGH | Python AST |
| **SP138** | Timing-attack vulnerable comparison | HIGH | Regex |
| **SP139** | Insecure temporary file creation | HIGH | Regex |
| **SP140** | Insecure cryptographic hash algorithm (MD5/SHA1) | HIGH | Regex |
| **SP141** | Weak PRNG seeded with timestamp | HIGH | Regex |
| **SP142** | AES cipher in ECB mode | HIGH | Regex |
| **SP143** | Static salt in password hashing | HIGH | Regex |
| **SP144** | JWT verification bypassed | CRITICAL | Regex |
| **SP145** | Dynamic SQL execution via exec_sql | HIGH | Regex |
| **SP146** | Direct execution via document.write | HIGH | Regex |
| **SP147** | Unsanitized innerHTML assignment | HIGH | Regex |
| **SP148** | JavaScript scheme URI in navigation link | HIGH | Regex |
| **SP149** | XML entity resolution enabled in standard parser | HIGH | Regex |
| **SP150** | XSLT processing with extensions enabled | HIGH | Regex |
| **SP151** | Python subprocess execution with shell execution | HIGH | Regex |
| **SP152** | Node child_process.exec with template string | HIGH | Regex |
| **SP153** | Insecure Ruby deserialization | CRITICAL | Regex |
| **SP154** | Java insecure ObjectInputStream deserialization | CRITICAL | Regex |
| **SP155** | PHP dynamic evaluation via preg_replace /e | CRITICAL | Regex |
| **SP156** | LDAP query constructed with string concatenation | HIGH | Regex |
| **SP157** | XPath query constructed with string concatenation | HIGH | Regex |
| **SP158** | Hardcoded HTTP Basic Authorization header | HIGH | Regex |
| **SP159** | Cookie generated without Secure or HttpOnly flags | MEDIUM | Regex |
| **SP160** | Session token passed in URL query parameters | MEDIUM | Regex |
| **SP161** | Mass assignment via unfiltered model update | HIGH | Regex |
| **SP162** | Hardcoded localhost or private IP in webhook target | HIGH | Regex |
| **SP163** | Bypassed SSL context with unverified context | HIGH | Regex |
| **SP164** | Flask debug toolbar enabled in route setup | HIGH | Regex |
| **SP165** | Django raw query with string interpolation | HIGH | Regex |
| **SP166** | Server framework fingerprinting header enabled | LOW | Regex |
| **SP167** | GraphQL unauthenticated introspection enabled | MEDIUM | Regex |
| **SP168** | Sensitive credential passed in GET parameter | HIGH | Regex |
| **SP169** | Insecure file permissions set on created file | MEDIUM | Regex |
| **SP170** | Cleartext unencrypted protocol for external traffic | MEDIUM | Regex |
| **SP171** | GraphQL unbounded query depth or complexity | HIGH | Regex |
| **SP172** | MongoDB $where clause with string concatenation | CRITICAL | Regex |
| **SP173** | LDAP query built by string concatenation | HIGH | Regex |
| **SP174** | XPath query built by string concatenation | HIGH | Regex |
| **SP175** | HTTP header injection via unvalidated CRLF characters | HIGH | Regex |
| **SP176** | Prototype pollution via unsafe object merge | HIGH | Regex |
| **SP177** | Insecure window.postMessage with wildcard targetOrigin | HIGH | Regex |
| **SP178** | External script tag missing Subresource Integrity (SRI) | MEDIUM | Regex |
| **SP179** | Dynamic class instantiation from user input | CRITICAL | Regex |
| **SP180** | Frame inclusion allowed globally without frame-ancestors CSP | MEDIUM | Regex |
| **SP181** | Django raw SQL query with f-string interpolation | CRITICAL | Regex |
| **SP182** | Spring Expression Language (SpEL) expression injection | CRITICAL | Regex |
| **SP183** | Ruby ERB template rendering user string directly | CRITICAL | Regex |
| **SP184** | PHP extract on untrusted input enabling variable overwrite | CRITICAL | Regex |
| **SP185** | PHP dangerous assert with string expression | CRITICAL | Regex |
| **SP186** | Insecure .NET BinaryFormatter deserialization | CRITICAL | Regex |
| **SP187** | ASP.NET Request Validation explicitly disabled | HIGH | Regex |
| **SP188** | Go html/template unescaped HTML type conversion | HIGH | Regex |
| **SP189** | WebSocket server accepting arbitrary origin without check | HIGH | Regex |
| **SP190** | CORS policy reflecting null origin | HIGH | Regex |
| **SP191** | Insecure cookie SameSite None without Secure flag | HIGH | Regex |
| **SP192** | OAuth 2.0 PKCE code_challenge verification omitted | HIGH | Regex |
| **SP193** | OpenID Connect authentication nonce verification skipped | HIGH | Regex |
| **SP194** | SAML response assertion signature verification disabled | CRITICAL | Regex |
| **SP195** | Insecure gRPC channel created without transport security | HIGH | Regex |
| **SP196** | Redis connection without TLS encryption | MEDIUM | Regex |
| **SP197** | Elasticsearch query constructed with raw JSON string interpolation | HIGH | Regex |
| **SP198** | Mongoose mass assignment from raw request body | HIGH | Regex |
| **SP199** | Sequelize mass update with unconstrained request body | HIGH | Regex |
| **SP200** | TypeORM repository save with unsanitized request body | HIGH | Regex |
| **SP201** | Debug mode enabled | HIGH | Regex |
| **SP202** | Floating container base image | MEDIUM | Regex |
| **SP203** | Unpinned GitHub Action | HIGH | Regex |
| **SP204** | Sensitive data or credential logging | MEDIUM | Regex |
| **SP205** | Dockerfile running container as root | MEDIUM | Regex |
| **SP206** | Dockerfile package install via curl piped to shell | HIGH | Regex |
| **SP207** | Dockerfile copying sensitive environment files | HIGH | Regex |
| **SP208** | Dockerfile exposing privileged ports | LOW | Regex |
| **SP209** | GitHub Actions pull_request_target checkout of PR head | HIGH | Regex |
| **SP210** | GitHub Actions workflow script injection | HIGH | Regex |
| **SP211** | GitHub Actions workflow missing explicit permissions | MEDIUM | Regex |
| **SP212** | CI/CD step printing environment variables to console | HIGH | Regex |
| **SP213** | npm script with unsafe-perm or ignore-scripts | HIGH | Regex |
| **SP214** | Pip install without pinned versions | MEDIUM | Regex |
| **SP215** | Terraform AWS S3 bucket with public ACL | HIGH | Regex |
| **SP216** | Terraform security group with unrestricted ingress | HIGH | Regex |
| **SP217** | Kubernetes pod configured with privileged mode | HIGH | Regex |
| **SP218** | Kubernetes container missing resource limits | MEDIUM | Regex |
| **SP219** | Kubernetes service exposing unauthenticated NodePort | HIGH | Regex |
| **SP220** | Sensitive environment file tracked in git | HIGH | Regex |
| **SP221** | Unpinned git dependency in package manifest | MEDIUM | Regex |
| **SP222** | Docker Compose mounting Docker socket | CRITICAL | Regex |
| **SP223** | Nginx configuration with deprecated SSL/TLS protocols | HIGH | Regex |
| **SP224** | Nginx configuration missing security headers | MEDIUM | Regex |
| **SP225** | Logging HTTP request headers with credentials | MEDIUM | Regex |
| **SP226** | Dockerfile container missing non-root USER directive | MEDIUM | Regex |
| **SP227** | Dockerfile container missing HEALTHCHECK instruction | MEDIUM | Regex |
| **SP228** | Dockerfile using unpinned latest base image tag | HIGH | Regex |
| **SP229** | Dockerfile executing untrusted curl piped to shell | CRITICAL | Regex |
| **SP230** | Docker daemon socket exposed in container compose | CRITICAL | Regex |
| **SP231** | Dockerfile blanket host copy without .dockerignore | MEDIUM | Regex |
| **SP232** | Docker compose container running in privileged mode | CRITICAL | Regex |
| **SP233** | Docker compose container sharing host network namespace | HIGH | Regex |
| **SP234** | Docker compose container sharing host PID namespace | HIGH | Regex |
| **SP235** | Docker compose mounting host root filesystem | CRITICAL | Regex |
| **SP236** | Kubernetes privileged container execution enabled | CRITICAL | Regex |
| **SP237** | Kubernetes allowPrivilegeEscalation permitted | HIGH | Regex |
| **SP238** | Kubernetes container missing CPU or memory limit | HIGH | Regex |
| **SP239** | Kubernetes container missing resource requests | HIGH | Regex |
| **SP240** | Kubernetes container root filesystem writable | MEDIUM | Regex |
| **SP241** | Kubernetes container configured to run as root | HIGH | Regex |
| **SP242** | Kubernetes Pod running on hostNetwork | HIGH | Regex |
| **SP243** | Kubernetes Pod running with hostPID or hostIPC | HIGH | Regex |
| **SP244** | Kubernetes Pod mounting docker.sock hostPath volume | CRITICAL | Regex |
| **SP245** | Kubernetes ServiceAccount automatic token mounting enabled | MEDIUM | Regex |
| **SP246** | Kubernetes Ingress missing TLS configuration | HIGH | Regex |
| **SP247** | Kubernetes namespace missing default deny NetworkPolicy | MEDIUM | Regex |
| **SP248** | Terraform S3 bucket missing server-side encryption | HIGH | Regex |
| **SP249** | Terraform S3 bucket configured with public ACL | CRITICAL | Regex |
| **SP250** | Terraform S3 bucket missing public access block | HIGH | Regex |
| **SP251** | Terraform EBS volume created without encryption | HIGH | Regex |
| **SP252** | Terraform RDS instance missing storage encryption | HIGH | Regex |
| **SP253** | Terraform RDS database instance publicly accessible | CRITICAL | Regex |
| **SP254** | Terraform Security Group open SSH ingress from 0.0.0.0/0 | CRITICAL | Regex |
| **SP255** | Terraform Security Group open RDP ingress from 0.0.0.0/0 | CRITICAL | Regex |
| **SP256** | Terraform IAM policy granting full administrator wildcard | CRITICAL | Regex |
| **SP257** | Terraform CloudFront distribution viewer_protocol_policy allow-all | HIGH | Regex |
| **SP258** | Terraform DynamoDB table point-in-time recovery disabled | MEDIUM | Regex |
| **SP259** | Terraform EKS cluster public endpoint access unrestricted | HIGH | Regex |
| **SP260** | GitHub Actions inline script injection from untrusted event context | CRITICAL | Regex |
| **SP261** | GitHub Actions pull_request_target checking out untrusted pull request code | CRITICAL | Regex |
| **SP262** | GitHub Actions third-party action referenced without immutable commit SHA | MEDIUM | Regex |
| **SP263** | GitHub Actions echo statement printing secret token | CRITICAL | Regex |
| **SP264** | GitHub Actions workflow granting broad write-all permissions | HIGH | Regex |
| **SP265** | GitHub Actions public repository using self-hosted runner | HIGH | Regex |
| **SP266** | Helm values file containing hardcoded plaintext database password | CRITICAL | Regex |
| **SP267** | Nginx configuration enabling obsolete SSLv3 or TLSv1 protocols | HIGH | Regex |
| **SP268** | Nginx configuration missing X-Content-Type-Options nosniff header | MEDIUM | Regex |
| **SP269** | Systemd unit service running as root without User directive | MEDIUM | Regex |
| **SP270** | Systemd unit service configured with unrestricted Restart=always | MEDIUM | Regex |
| **SP301** | Redis KEYS in application path | HIGH | Regex |
| **SP302** | Unbounded SQL result | MEDIUM | Regex |
| **SP303** | Blocking sleep in async code | HIGH | Regex |
| **SP304** | Outbound request without timeout | HIGH | Regex |
| **SP305** | Unbounded pagination input | MEDIUM | Regex |
| **SP306** | Unbounded concurrency in collection | MEDIUM | Regex |
| **SP307** | N+1 database query in loop | HIGH | Regex |
| **SP308** | Unbounded in-memory global cache | MEDIUM | Regex |
| **SP309** | Goroutine spawned without context | MEDIUM | Regex |
| **SP310** | Busy-wait spin loop without backoff | HIGH | Regex |
| **SP311** | Event listener registered in request scope | MEDIUM | Regex |
| **SP312** | Retry loop without exponential backoff | MEDIUM | Regex |
| **SP313** | Non-singleton database client in serverless | HIGH | Regex |
| **SP314** | Committed SQLite database file | HIGH | Regex |
| **SP315** | Go HTTP request missing response body close | HIGH | Regex |
| **SP316** | Outbound HTTP call inside database transaction | HIGH | Regex |
| **SP317** | Blocking call in async def coroutine | HIGH | Regex |
| **SP318** | Retry policy without a stop condition | MEDIUM | Regex |
| **SP319** | Redis SMEMBERS or HGETALL on unbounded keys | HIGH | Regex |
| **SP320** | Redis cache key stored without TTL | MEDIUM | Regex |
| **SP321** | Blocking filesystem I/O in async loop | HIGH | Regex |
| **SP322** | SQL query with leading wildcard | MEDIUM | Regex |
| **SP323** | SQL query with random sorting | MEDIUM | Regex |
| **SP324** | SQL NOT IN subquery on nullable column | MEDIUM | Regex |
| **SP325** | Database transaction without statement timeout | HIGH | Regex |
| **SP326** | Transaction committed per row in bulk loop | MEDIUM | Regex |
| **SP327** | Monolithic single transaction on large table | HIGH | Regex |
| **SP328** | Missing connection pool max limit or acquire timeout | HIGH | Regex |
| **SP329** | Synchronous large JSON parsing in request thread | HIGH | Regex |
| **SP330** | Regex compiled repeatedly inside tight loop | LOW | Regex |
| **SP331** | Go HTTP client missing idle connection limits | MEDIUM | Regex |
| **SP332** | Go unbuffered channel send without consumer | HIGH | Regex |
| **SP333** | Go sync.WaitGroup counter incremented in goroutine | HIGH | Regex |
| **SP334** | Node process missing unhandledRejection listener | HIGH | Regex |
| **SP335** | Python asyncio task created without reference | HIGH | Regex |
| **SP336** | Node.js stream piped without error handler | HIGH | Regex |
| **SP337** | In-memory session store in web cluster | HIGH | Regex |
| **SP338** | External network call missing circuit breaker | MEDIUM | Regex |
| **SP339** | Synchronous heavy crypto in async request thread | HIGH | Regex |
| **SP340** | Deep offset pagination on large table | MEDIUM | Regex |
| **SP341** | Unbuffered file read into memory | HIGH | Regex |
| **SP342** | Synchronous heavy processing in webhook listener | MEDIUM | Regex |
| **SP343** | process.exit called inside request handler | HIGH | Regex |
| **SP344** | ThreadPoolExecutor instantiated per request | MEDIUM | Regex |
| **SP345** | Global lock held across async I/O call | HIGH | Regex |
| **SP346** | Python asyncio create_task reference dropped causing garbage collection | HIGH | Regex |
| **SP347** | Python asyncio gather without return_exceptions handling | MEDIUM | Regex |
| **SP348** | Python ThreadPoolExecutor instantiated without max_workers limit | HIGH | Regex |
| **SP349** | Python ProcessPoolExecutor created inside async request handler | HIGH | Regex |
| **SP350** | Python SQLAlchemy engine created without pool_size and max_overflow bounds | HIGH | Regex |
| **SP351** | Python SQLAlchemy session created without scoped session or context manager | HIGH | Regex |
| **SP352** | Python Redis client created without socket timeout | HIGH | Regex |
| **SP353** | Python Redis pub/sub listener without reconnect loop | MEDIUM | Regex |
| **SP354** | Python Celery task missing explicit time_limit or soft_time_limit | HIGH | Regex |
| **SP355** | Python Celery task with bind=True mutating global state | MEDIUM | Regex |
| **SP356** | Python Pydantic model string field without max_length constraint | MEDIUM | Regex |
| **SP357** | Python naive datetime comparison with datetime.now without timezone | MEDIUM | Regex |
| **SP358** | Python floating point direct equality comparison | MEDIUM | Regex |
| **SP359** | Node.js Express unhandled Promise rejection in async route | HIGH | Regex |
| **SP360** | Node.js EventEmitter listener added inside request handler without removal | HIGH | Regex |
| **SP361** | Node.js synchronous file read inside route handler blocking event loop | HIGH | Regex |
| **SP362** | Node.js synchronous crypto PBKDF2 inside route handler | HIGH | Regex |
| **SP363** | Node.js PostgreSQL or MySQL pool instantiated without max connections cap | HIGH | Regex |
| **SP364** | Node.js Axios or Got HTTP client request without timeout | HIGH | Regex |
| **SP365** | Node.js Prisma database query inside Array.forEach | HIGH | Regex |
| **SP366** | Node.js Mongoose read-only query missing lean optimization | MEDIUM | Regex |
| **SP367** | Node.js Stream pipe missing error handler | HIGH | Regex |
| **SP368** | Node.js process.exit called inside request handler | CRITICAL | Regex |
| **SP369** | Node.js setTimeout delay exceeding 32-bit integer maximum | MEDIUM | Regex |
| **SP370** | Node.js JSON.parse on raw payload without try/catch | MEDIUM | Regex |
| **SP371** | Go goroutine spawning inside loop capturing loop variable | HIGH | Regex |
| **SP372** | Go unbuffered channel receive without context cancellation select | HIGH | Regex |
| **SP373** | Go time.Tick called inside function scope causing memory leak | HIGH | Regex |
| **SP374** | Go sync.WaitGroup Wait called inside spawned goroutine causing deadlock | HIGH | Regex |
| **SP375** | Go sql.DB connection pool configured with unbounded connections | HIGH | Regex |
| **SP376** | Go HTTP client using zero-timeout DefaultClient | HIGH | Regex |
| **SP377** | Go http.Server missing ReadHeaderTimeout causing Slowloris vulnerability | HIGH | Regex |
| **SP378** | Go context.WithCancel or WithTimeout missing defer cancel call | HIGH | Regex |
| **SP379** | Go Mutex lock acquired without immediate defer Unlock | MEDIUM | Regex |
| **SP380** | Java Executors newCachedThreadPool unbounded thread creation | HIGH | Regex |
| **SP381** | Java CompletableFuture join called on main thread | HIGH | Regex |
| **SP382** | Java SimpleDateFormat shared across multiple threads | HIGH | Regex |
| **SP383** | Java unclosed JDBC Connection in try block without try-with-resources | HIGH | Regex |
| **SP384** | Java HikariCP connection pool missing maximumPoolSize setting | MEDIUM | Regex |
| **SP385** | C# async void method declaration masking unhandled exceptions | HIGH | Regex |
| **SP386** | C# synchronous Task.Result or Task.Wait causing deadlock | HIGH | Regex |
| **SP387** | C# HttpClient instantiated directly causing socket exhaustion | HIGH | Regex |
| **SP388** | C# Entity Framework DbContext shared across concurrent threads | HIGH | Regex |
| **SP389** | C# async database query ignoring CancellationToken | MEDIUM | Regex |
| **SP390** | Rust unwrap or expect on fallible network operation | HIGH | Regex |
| **SP391** | Rust tokio spawn without error handling or JoinHandle storage | MEDIUM | Regex |
| **SP392** | Rust std Mutex held across await point blocking tokio runtime | HIGH | Regex |
| **SP393** | Rust unbounded mpsc channel causing memory exhaustion | HIGH | Regex |
| **SP394** | Rust blocking std fs operations inside async context | HIGH | Regex |
| **SP395** | PHP PDO error mode silent masking database query failures | HIGH | Regex |
| **SP396** | PHP file_get_contents on remote URL without timeout context | HIGH | Regex |
| **SP397** | Ruby Net::HTTP request instantiated without read_timeout | HIGH | Regex |
| **SP398** | Ruby ActiveRecord queries in view templates causing N+1 query storm | HIGH | Regex |
| **SP399** | Redis unbounded KEYS pattern query in production code | CRITICAL | Regex |
| **SP400** | Redis sorted set or hash query without pagination limit | HIGH | Regex |
| **SP401** | Express app without helmet | MEDIUM | Regex |
| **SP402** | Express auth route without rate limiting | MEDIUM | Regex |
| **SP403** | Secret in NEXT_PUBLIC_ env var | HIGH | Regex |
| **SP404** | Django SECRET_KEY hardcoded | CRITICAL | Regex |
| **SP405** | Django ALLOWED_HOSTS accepts all | HIGH | Regex |
| **SP406** | Express error sent to client | MEDIUM | Regex |
| **SP407** | Cookie session routes without CSRF protection | MEDIUM | Regex |
| **SP408** | Meta-framework config without CSP header | MEDIUM | Regex |
| **SP409** | FastAPI route missing response_model schema | MEDIUM | Regex |
| **SP410** | Flask secret key set to hardcoded constant | CRITICAL | Regex |
| **SP411** | Django debug mode enabled in settings | HIGH | Regex |
| **SP412** | Express body-parser with excessive payload limit | MEDIUM | Regex |
| **SP413** | Next.js middleware missing static asset exclusion | MEDIUM | Regex |
| **SP414** | React list rendering using array index as key | LOW | Regex |
| **SP415** | Vue v-html directive with dynamic property | HIGH | Regex |
| **SP416** | Spring Boot actuator endpoints exposed publicly | HIGH | Regex |
| **SP417** | Ruby on Rails protect_from_forgery disabled | HIGH | Regex |
| **SP418** | ASP.NET Core UseDeveloperExceptionPage in production | HIGH | Regex |
| **SP419** | FastAPI CORS allows wildcard with credentials | HIGH | Regex |
| **SP420** | Next.js Server Action without authorization | HIGH | Regex |
| **SP421** | Next.js Server Action missing authorization check | HIGH | Regex |
| **SP422** | Next.js generateStaticParams fetching unbounded external API without limit | MEDIUM | Regex |
| **SP423** | React useEffect missing dependency array causing infinite render loop | HIGH | Regex |
| **SP424** | React state mutated directly bypassing setState | HIGH | Regex |
| **SP425** | Vue v-html directive rendering untrusted content | HIGH | Regex |
| **SP426** | Svelte @html tag rendering unescaped content | HIGH | Regex |
| **SP427** | Express helmet middleware explicitly disabling standard protections | MEDIUM | Regex |
| **SP428** | Express error handling middleware exposing stack traces to client | HIGH | Regex |
| **SP429** | Express express.json body parser without limit option | MEDIUM | Regex |
| **SP430** | Express session using default in-memory MemoryStore in production | HIGH | Regex |
| **SP431** | NestJS global ValidationPipe missing whitelist option | HIGH | Regex |
| **SP432** | NestJS controller administrative endpoint missing UseGuards decorator | HIGH | Regex |
| **SP433** | Fastify route missing input schema validation definition | MEDIUM | Regex |
| **SP434** | Fastify server missing connectionTimeout configuration | MEDIUM | Regex |
| **SP435** | Django DEBUG mode hardcoded in settings file | CRITICAL | Regex |
| **SP436** | Django ALLOWED_HOSTS configured with wildcard in settings | HIGH | Regex |
| **SP437** | Django SECRET_KEY hardcoded string literal in settings | CRITICAL | Regex |
| **SP438** | Django SESSION_COOKIE_SECURE explicitly disabled | HIGH | Regex |
| **SP439** | Django ORM extra() method used with format string | CRITICAL | Regex |
| **SP440** | FastAPI route missing response_model schema definition | MEDIUM | Regex |
| **SP441** | Flask app secret_key set to hardcoded string literal | CRITICAL | Regex |
| **SP442** | Flask SESSION_COOKIE_HTTPONLY disabled in configuration | HIGH | Regex |
| **SP443** | Spring Boot Actuator all endpoints exposed over web | CRITICAL | Regex |
| **SP444** | Spring Boot H2 in-memory web console enabled in configuration | CRITICAL | Regex |
| **SP445** | Spring Security CSRF protection explicitly disabled | HIGH | Regex |
| **SP446** | Spring Security permitAll on administrative path pattern | CRITICAL | Regex |
| **SP447** | Gin framework router missing Recovery panic middleware | HIGH | Regex |
| **SP448** | Fiber framework App initialized without Recover middleware | HIGH | Regex |
| **SP449** | Ruby on Rails params.permit! blanket mass assignment bypass | CRITICAL | Regex |
| **SP450** | Ruby on Rails config.force_ssl disabled in production | HIGH | Regex |
| **SP451** | Laravel Eloquent model guarded set to empty array | HIGH | Regex |
| **SP452** | Laravel DB::raw query constructed with string concatenation | CRITICAL | Regex |
| **SP453** | ASP.NET Core DeveloperExceptionPage enabled in non-development | HIGH | Regex |
| **SP454** | ASP.NET Core AllowAnonymous attribute on administrative controller | CRITICAL | Regex |
| **SP455** | Angular bypassSecurityTrustHtml called with dynamic input | HIGH | Regex |
| **SP456** | Apollo Server GraphQL introspection enabled in production | MEDIUM | Regex |
| **SP457** | tRPC mutation procedure declared without input validation schema | MEDIUM | Regex |
| **SP458** | Prisma schema Float type used for monetary currency fields | MEDIUM | Regex |
| **SP459** | Drizzle ORM sql.raw query constructed with f-string interpolation | CRITICAL | Regex |
| **SP460** | Knex query builder raw query built by string concatenation | CRITICAL | Regex |
| **SP461** | Remix loader function returning sensitive entity directly | MEDIUM | Regex |
| **SP462** | Astro API endpoint missing CSRF origin verification on POST handler | MEDIUM | Regex |
| **SP463** | Next.js Route Handler missing rate limit or authorization in sensitive action | MEDIUM | Regex |
| **SP464** | Express app trust proxy configured insecurely with true | MEDIUM | Regex |
| **SP465** | FastAPI background task created without error handling wrapper | MEDIUM | Regex |
| **SP466** | Django transaction.atomic missing in multi-table mutation endpoint | MEDIUM | Regex |
| **SP467** | Spring Boot multipart file upload without maxFileSize limit | MEDIUM | Regex |
| **SP468** | Ktor HTTP client engine missing timeout configuration | HIGH | Regex |
| **SP469** | Symfony controller missing IsGranted security attribute | HIGH | Regex |
| **SP470** | Phoenix LiveView mount callback missing session token verification | HIGH | Regex |
| **SP471** | FastAPI CORS middleware configured with allow_origins wildcard and allow_credentials | CRITICAL | Regex |
| **SP472** | Flask-CORS configured with origins wildcard and supports_credentials | CRITICAL | Regex |
| **SP473** | NestJS CORS configuration with origin true reflection | HIGH | Regex |
| **SP474** | Spring Boot WebMvcConfigurer addCorsMappings wildcard credentials | CRITICAL | Regex |
| **SP475** | Express rate-limit missing keyGenerator using default IP behind reverse proxy | MEDIUM | Regex |
| **SP476** | Next.js dangerouslySetInnerHTML used inside component | HIGH | Regex |
| **SP477** | Nuxt 3 useFetch missing server: false in client-only mutations | MEDIUM | Regex |
| **SP478** | FastAPI unhandled HTTPException re-thrown losing details | MEDIUM | Regex |
| **SP479** | Django CSRF_TRUSTED_ORIGINS missing https scheme | HIGH | Regex |
| **SP480** | Laravel route definition without rate limiting middleware | MEDIUM | Regex |
| **SP481** | Spring Boot Jackson deserialization default typing enabled | CRITICAL | Regex |
| **SP482** | Gin framework c.BindJSON ignoring binding validation error | HIGH | Regex |
| **SP483** | Fiber framework c.BodyParser ignoring returned error | HIGH | Regex |
| **SP484** | Echo framework c.Bind ignoring deserialization error | HIGH | Regex |
| **SP485** | NestJS microservice transport connection without retry strategy | MEDIUM | Regex |
| **SP486** | Prisma client instantiated repeatedly inside function scope | CRITICAL | Regex |
| **SP487** | FastAPI streaming response without generator exception handling | HIGH | Regex |
| **SP488** | Django database connection closed inside thread pool worker | HIGH | Regex |
| **SP489** | Fastify decorated request object mutating shared prototype state | MEDIUM | Regex |
| **SP490** | Next.js middleware matching all static assets causing performance degradation | MEDIUM | Regex |
| **SP501** | Unmetered AI/LLM API route | HIGH | Regex |
| **SP502** | Insecure payment webhook handler | CRITICAL | Regex |
| **SP503** | Leaked Supabase service role key | CRITICAL | Regex |
| **SP504** | Missing payment gateway idempotency key | HIGH | Regex |
| **SP505** | LLM prompt direct string interpolation | HIGH | Regex |
| **SP506** | LLM function call execution without schema validation | HIGH | Regex |
| **SP507** | Vector database query with unfiltered embedding | HIGH | Regex |
| **SP508** | AI agent autonomous tool execution without constraints | HIGH | Regex |
| **SP509** | Vector database API key committed | CRITICAL | Regex |
| **SP510** | Stripe payment webhook missing timestamp verification | HIGH | Regex |
| **SP511** | PayPal webhook signature verification omitted | HIGH | Regex |
| **SP512** | Supabase client without service role isolation | HIGH | Regex |
| **SP513** | Clerk or Auth0 webhook without raw signature verification | HIGH | Regex |
| **SP514** | LangChain unsafe code execution tool enabled | CRITICAL | Regex |
| **SP515** | AI streaming response without rate limiting or quota | HIGH | Regex |
| **SP516** | AI LLM prompt injection via direct f-string concatenation of user input | CRITICAL | Regex |
| **SP517** | AI LLM streaming API call without timeout or client disconnect cancellation | HIGH | Regex |
| **SP518** | AI agent tool executing shell commands without human-in-the-loop gate | CRITICAL | Regex |
| **SP519** | Vector database query requesting unbounded top_k results | HIGH | Regex |
| **SP520** | LangChain load_tools including dangerous shell or python execution | CRITICAL | Regex |
| **SP521** | LangChain SQLDatabaseChain instantiated without query checker verification | HIGH | Regex |
| **SP522** | OpenAI client initialized without request timeout | HIGH | Regex |
| **SP523** | LLM generated SQL query executed directly against production database without read-only mode | CRITICAL | Regex |
| **SP524** | LLM generated code evaluated directly using eval or exec | CRITICAL | Regex |
| **SP525** | RAG embedding generation called inside single-item loop instead of batch | HIGH | Regex |
| **SP526** | AI chat history stored in unbounded memory array causing context overflow | MEDIUM | Regex |
| **SP527** | AI agent tool calling recursion loop without max_iterations limit | HIGH | Regex |
| **SP528** | Stripe Checkout session created without client_reference_id or order metadata | HIGH | Regex |
| **SP529** | Stripe webhook handler parsing JSON without raw body buffer verification | CRITICAL | Regex |
| **SP530** | Stripe refund initiated without administrative permission verification | HIGH | Regex |
| **SP531** | Stripe customer created inside request loop without checking existing customer ID | MEDIUM | Regex |
| **SP532** | Payment charge created without idempotency_key parameter | HIGH | Regex |
| **SP533** | Webhook handler responding 200 before persisting event to queue or database | HIGH | Regex |
| **SP534** | Webhook timestamp tolerance verification omitted enabling replay attacks | HIGH | Regex |
| **SP535** | AWS S3 presigned URL generated with excessive expiration duration | MEDIUM | Regex |
| **SP536** | AWS SQS message receiver without visibility timeout extension in long task | MEDIUM | Regex |
| **SP537** | AWS Lambda handler missing connection caching outside handler function | HIGH | Regex |
| **SP538** | AWS DynamoDB scan operation used in user-facing query path | HIGH | Regex |
| **SP539** | GCP Cloud Storage signed URL generated without expiration cap | MEDIUM | Regex |
| **SP540** | Azure Blob Storage SAS token generated with full write and delete permissions | HIGH | Regex |
| **SP541** | Cloudflare Turnstile or reCAPTCHA verification skipped on backend | HIGH | Regex |
| **SP542** | Twilio SMS sending called inside loop without rate limiter | HIGH | Regex |
| **SP543** | ChromaDB persistent client instantiated per request without singleton | HIGH | Regex |
| **SP544** | Weaviate vector search query missing limit parameter | MEDIUM | Regex |
| **SP545** | AI system prompt containing hardcoded API keys or secret instructions | HIGH | Regex |
| **SP546** | Payment line item price taken directly from untrusted client payload | CRITICAL | Regex |
| **SP547** | Kafka producer publishing financial events without all ACKs guarantee | HIGH | Regex |
| **SP548** | Kafka consumer auto-committing offsets before message processing completes | HIGH | Regex |
| **SP549** | RabbitMQ channel created per message without connection pooling | HIGH | Regex |
| **SP550** | OpenTelemetry tracer span started without ending in finally block | MEDIUM | Regex |
| **SP551** | AWS SNS topic subscriber without subscription filter policy | MEDIUM | Regex |
| **SP552** | AWS EventBridge rule target missing Dead Letter Queue (DLQ) | HIGH | Regex |
| **SP553** | AWS Secrets Manager get_secret_value called inside Lambda handler | HIGH | Regex |
| **SP554** | AWS CloudWatch put_metric_data called synchronously in API path | HIGH | Regex |
| **SP555** | GCP Secret Manager client instantiated inside Cloud Function handler | HIGH | Regex |
| **SP556** | GCP Cloud Pub/Sub subscriber without automatic ack deadline extension | MEDIUM | Regex |
| **SP557** | Azure Key Vault secret retrieval inside HTTP request handler without cache | HIGH | Regex |
| **SP558** | Azure Cosmos DB query without partition key filter | HIGH | Regex |
| **SP559** | PayPal webhook verification skipped in production endpoint | CRITICAL | Regex |
| **SP560** | Razorpay webhook missing HMAC-SHA256 signature verification | CRITICAL | Regex |
| **SP561** | Adyen webhook missing HMAC signature calculation check | CRITICAL | Regex |
| **SP562** | Square payment create call missing idempotency_key | HIGH | Regex |
| **SP563** | Stripe subscription upgrade missing proration_behavior specification | MEDIUM | Regex |
| **SP564** | Stripe invoice payment failed webhook event unhandled | HIGH | Regex |
| **SP565** | Payment webhook processing without distributed idempotency lock | HIGH | Regex |
| **SP566** | Currency conversion calculation performed with float division instead of integer cents | HIGH | Regex |
| **SP567** | Billing balance decremented without non-negative check | CRITICAL | Regex |
| **SP568** | AI prompt template without delimiter boundary escaping | HIGH | Regex |
| **SP569** | AI assistant tool executing destructive file deletion | CRITICAL | Regex |
| **SP570** | AI model output rendered directly as unescaped markdown with HTML enabled | HIGH | Regex |
| **SP571** | Vector collection created without explicit distance metric | MEDIUM | Regex |
| **SP572** | Milvus vector search called without prior index loading | HIGH | Regex |
| **SP573** | SendGrid mail sending in single-item loop without batching | HIGH | Regex |
| **SP574** | RabbitMQ message consumed with auto_ack=True in durable queue | HIGH | Regex |
| **SP575** | AI prompt caching key constructed without hashing long content | MEDIUM | Regex |
| **SP576** | AI structured output JSON parsing missing validation error handler | HIGH | Regex |
| **SP577** | Prometheus metric counter registered inside request handler scope | HIGH | Regex |
| **SP578** | Feature flag evaluation without fallback default value on SDK timeout | HIGH | Regex |
| **SP579** | Feature flag client instantiated per request without background polling | HIGH | Regex |
| **SP580** | OpenTelemetry trace baggage headers forwarded without sanitization | MEDIUM | Regex |
| **SP581** | Redis distributed lock released without verifying lock token ownership | CRITICAL | Regex |
| **SP582** | Redis distributed lock acquired without TTL expiration timeout | CRITICAL | Regex |
| **SP583** | BullMQ job worker instantiated without stalledInterval configuration | MEDIUM | Regex |
| **SP584** | Temporal workflow activity called without start_to_close_timeout | HIGH | Regex |
| **SP585** | Temporal workflow mutating static or global variables | CRITICAL | Regex |
| **SP586** | Temporal workflow calling non-deterministic sleep or system clock | CRITICAL | Regex |
| **SP587** | Temporal activity retrying on non-retryable validation error | MEDIUM | Regex |
| **SP588** | Supabase client initialized on client side with service_role key | CRITICAL | Regex |
| **SP589** | Vector index created with Euclidean metric on un-normalized vectors | MEDIUM | Regex |
| **SP590** | Unbounded in-memory queue without maxsize parameter | HIGH | Regex |
| **SP591** | Server-only database or ORM client imported inside 'use client' bundle | CRITICAL | Regex |
| **SP592** | Next.js mutating route handler or action casting request body directly to any | HIGH | Regex |
| **SP593** | Next.js 15 route segment params accessed without await Promise resolution | HIGH | Regex |
| **SP594** | Authenticated user-specific API call configured with static force-cache | HIGH | Regex |
| **SP595** | Next.js Server Action database mutation without cache revalidation | MEDIUM | Regex |
| **SP596** | Client-only React hook used inside Server Component without use client | HIGH | Regex |
| **SP597** | Next.js Server Component sequential waterfall requests blocking initial SSR | HIGH | Regex |
| **SP598** | Next.js mutating route handler using cookie auth without CSRF origin verification | CRITICAL | Regex |
| **SP599** | TypeScript non-null assertion used on dynamic API response payload | HIGH | Regex |
| **SP600** | Next.js Server Action accepting unverified userId argument for database mutation | CRITICAL | Regex |
| **SP601** | LLM output dynamically evaluated in code or shell interpreter | CRITICAL | Regex |
| **SP602** | Direct rendering of raw LLM completion string into raw HTML | HIGH | Regex |
| **SP603** | Unbounded prompt input ingestion passed to LLM API without truncation | HIGH | Regex |
| **SP604** | Unsanitized user inputs concatenated directly into system prompt | CRITICAL | Regex |
| **SP605** | AI Agent tool definition with unbounded file write or shell execution capability | HIGH | Regex |
| **SP606** | Kubernetes container definition without CPU or memory resource limits | HIGH | Regex |
| **SP607** | Kubernetes container configured with privileged securityContext | CRITICAL | Regex |
| **SP608** | Kubernetes container root filesystem configured as writable | HIGH | Regex |
| **SP609** | Kubernetes container spec missing liveness or readiness probe | MEDIUM | Structural |
| **SP610** | Kubernetes pod volume configured with direct host filesystem mount | CRITICAL | Regex |
| **SP611** | GraphQL server initialized with introspection enabled in production | HIGH | Regex |
| **SP612** | GraphQL server configured without query depth or complexity limits | HIGH | Structural |
| **SP613** | Outbound gRPC client invoke called without deadline or timeout | HIGH | Regex |
| **SP614** | gRPC server initialized with insecure credentials or unencrypted channel | CRITICAL | Regex |
| **SP615** | OAuth2 authorization URL generated without random state parameter | HIGH | Regex |
| **SP616** | OAuth callback matching redirect_uri against wildcard or unanchored regex | HIGH | Regex |
| **SP617** | Public client OAuth2 authorization flow initiating without PKCE code_challenge | CRITICAL | Regex |
| **SP618** | Redis cache key set without expiration TTL parameter | MEDIUM | Regex |
| **SP619** | Kafka consumer configured with enable.auto.commit risking message loss | HIGH | Regex |
| **SP620** | PostgreSQL migration adding non-null column with volatile default acquiring table lock | HIGH | Regex |
| **SP621** | Rust unwrap or expect invoked in HTTP route handler risking thread panic | HIGH | Regex |
| **SP622** | Go deferred file or response Close in write operation without error check | HIGH | Regex |
| **SP623** | Java dynamic JNDI lookup via InitialContext allowing remote code execution | CRITICAL | Regex |
| **SP624** | Non-cryptographic PRNG used to generate security token or key | HIGH | Regex |
| **SP625** | Unawaited async task invoked in ASP.NET request handler swallowing exceptions | HIGH | Regex |
| **SP626** | AWS S3 bucket policy allowing public wildcard principal | CRITICAL | Regex |
| **SP627** | AWS storage resource created without encryption at rest | HIGH | Regex |
| **SP628** | Security group ingress rule allowing 0.0.0.0/0 on administrative ports | CRITICAL | Regex |
| **SP629** | IAM policy granting wildcard actions or resources | CRITICAL | Regex |
| **SP630** | CloudFront distribution or ALB listener allowing unencrypted HTTP | HIGH | Regex |
| **SP631** | Node.js native module imported in Edge or Serverless runtime | CRITICAL | Regex |
| **SP632** | Unbounded edge fetch loop against Cloudflare KV or database | HIGH | Regex |
| **SP633** | Edge Worker accumulating full response payload in memory instead of streaming | MEDIUM | Regex |
| **SP634** | Dynamic authenticated API response cached on edge CDN | HIGH | Regex |
| **SP635** | WebSocket connection initialized without heartbeat ping-pong interval timeout | HIGH | Regex |
| **SP636** | Server-Sent Events stream missing client disconnect event listener | HIGH | Regex |
| **SP637** | WebSocket upgrade handler accepting connection without authentication verification | CRITICAL | Regex |
| **SP638** | BroadcastChannel or event subscription without unmount cleanup listener | HIGH | Regex |
| **SP639** | Symmetric cipher initialized in insecure ECB mode | CRITICAL | Regex |
| **SP640** | RSA key pair generated with insufficient key length below 2048 bits | HIGH | Regex |
| **SP641** | Static hardcoded Initialization Vector or salt reused in cipher operation | CRITICAL | Regex |
| **SP642** | Broken hash algorithm MD5 or SHA1 used in security signature or password context | HIGH | Regex |
| **SP643** | Secret HMAC signature or token compared with non-constant-time equality operator | HIGH | Regex |
| **SP644** | Svelte raw HTML rendered with unescaped tag without sanitization | CRITICAL | Regex |
| **SP645** | Android WebView configured with JavaScript and file URL access enabled | HIGH | Regex |
| **SP646** | iOS URLSession configured to unconditionally trust all SSL certificates | HIGH | Regex |
| **SP647** | Frontend proxy API endpoint accepting arbitrary full target URL parameter | HIGH | Regex |
| **SP648** | React or Vue WebSocket connection opened inside effect without teardown return | MEDIUM | Regex |
| **SP649** | Multitenant database query missing tenant scope filter | CRITICAL | Regex |
| **SP650** | Unbounded recursive JSON parse or schema evaluation without nesting depth limits | HIGH | Regex |

## การทำงานร่วมกับเครื่องมือมาตรฐาน

ShipProof ถูกออกแบบมาเพื่อทำงานเสริมร่วมกับเครื่องมือระดับ Enterprise:

```text
  L1: ShipProof Heuristic Gate (ตรวจสอบรวดเร็วในเครื่อง < 1 วินาที)
  L2: Deep SAST / Secret Scanning (CodeQL, Semgrep, Trufflehog)
  L3: Software Supply Chain (Dependency Audit, OSV-Scanner)
  L4: Dynamic Testing & Load Proof (k6, Playwright, Staging Validation)
```

## เอกสารเพิ่มเติม

- [คำสั่งทั้งหมดและ Exit Codes](docs/commands.md)
- [คู่มือสถาปัตยกรรม Production Playbook](docs/production-playbook.md)
- [คู่มือการวิเคราะห์และที่มาของกฎ](docs/research.md)
- [แผนการพัฒนา (Roadmap)](docs/roadmap.md)
- [แนวทางการปล่อยเวอร์ชัน (Releasing)](docs/releasing.md)

## ใบอนุญาต (License)

โปรเจกต์นี้เผยแพร่ภายใต้ใบอนุญาต [MIT License](LICENSE)
