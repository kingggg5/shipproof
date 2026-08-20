# Rule expansion program: 1,000 evidence-backed candidates

Status: candidate program, not a promise to ship 1,000 blocking regexes.

ShipProof reserves `SP651` through `SP1650` for exactly 1,000 candidate investigations. A candidate receives a stable blocking detector only when its evidence, static detectability, precision corpus, and performance checks pass. Runtime-only risks become evidence adapters or documented checks instead of misleading regex rules.

The later [2021–2026 and expert expansion](rule-expansion-2021-2026.md) reserves `SP1651–SP4450`, and the [language expansion](rule-expansion-languages-5000.md) reserves `SP4451–SP9450`. Neither changes the promotion gates in this document.

## Allocation

| Candidate range | Count | Risk lane | Initial source families |
| --- | ---: | --- | --- |
| `SP651–SP750` | 100 | Cloud, containers, IaC, CI/CD, supply chain | Kubernetes Pod Security Standards, GitHub Actions security guidance, NIST SSDF, CISA KEV |
| `SP751–SP850` | 100 | Injection, unsafe evaluation, parsers, file and network boundaries | MITRE CWE Top 25, OWASP ASVS 5.0, language/runtime documentation |
| `SP851–SP950` | 100 | Authentication, session, authorization, API and business logic | OWASP ASVS 5.0, OWASP API Security 2023, MITRE CWE |
| `SP951–SP1050` | 100 | Secrets, cryptography, privacy and data exposure | OWASP ASVS 5.0, NIST publications, platform security documentation |
| `SP1051–SP1150` | 100 | Reliability, concurrency, backpressure and resource bounds | NIST SSDF, runtime/framework documentation, failure corpus |
| `SP1151–SP1250` | 100 | Web, frontend, mobile and framework secure defaults | Official framework and platform documentation, OWASP ASVS/MASVS |
| `SP1251–SP1350` | 100 | AI/LLM, agents, RAG, tool execution and model data boundaries | OWASP GenAI/LLM Top 10, NIST GenAI SSDF profile, provider documentation |
| `SP1351–SP1450` | 100 | Native code, memory safety, serialization and protocols | MITRE CWE, language specifications, CERT and vendor advisories |
| `SP1451–SP1550` | 100 | Databases, queues, events, transactions and distributed state | Official database/messaging documentation, CWE, real incident classes |
| `SP1551–SP1650` | 100 | Operational evidence, deployment invariants and production gates | NIST SSDF, SLSA, Kubernetes/GitHub/cloud operational guidance |
| **Total** | **1,000** |  |  |

An ID is a research slot, not proof that a detector is valid. Rejected candidates keep their research record and reason, but do not enter `RULES`.

## Primary research registry

These are starting points, not a license to translate every control into a pattern:

- [MITRE 2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html), its [methodology](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html), and [On the Cusp weaknesses](https://cwe.mitre.org/top25/archive/2025/2025_onthecusp_list.html)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) and [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) and the [NIST SSDF project](https://csrc.nist.gov/projects/ssdf)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [GitHub Actions script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections), [`pull_request_target` guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target), and [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [Next.js data-security guidance](https://nextjs.org/docs/app/guides/data-security) and [Server Actions configuration](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions)
- [OWASP GenAI/LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Framework rules must cite the official documentation for the supported version. A CWE or OWASP page can provide the risk mapping, but cannot by itself prove framework syntax.

## Candidate scoring and routing

Each candidate is scored before implementation:

| Dimension | Weight | Question |
| --- | ---: | --- |
| Real-world impact and exploit evidence | 25% | Does the weakness produce meaningful compromise or availability loss? |
| Static detectability | 25% | Can local source prove the unsafe state without guessing about runtime context? |
| False-positive safety | 25% | Can secure alternatives and common exceptions be excluded deterministically? |
| Prevalence and coverage gap | 15% | Is it common in current AI-generated production code and not already covered? |
| Remediation determinism | 10% | Can ShipProof give a specific, behavior-preserving remediation? |

Routing rules:

1. Explicit insecure syntax with local proof may become a scanner rule.
2. Missing configuration becomes a rule only when the file structure proves the relevant scope and no valid alternative exists.
3. Runtime reachability, deployed IAM, live CVEs, capacity, and performance become evidence checks, not regex findings.
4. Duplicate controls extend an existing rule's fixtures and engine rather than consuming a new ID.
5. A candidate with ambiguous framework semantics stays research-only until an AST or structural engine can represent it.

## Promotion gates

The repository enforces the first gate for all rules from `SP651` onward through `tests/test_rule_quality.py` and `tests/rule_cases_v2.json`.

| Stage | Minimum evidence | Release behavior |
| --- | --- | --- |
| Research | Two current primary/official sources from distinct authorities; CWE/control mapping; explicit detectability decision | No detector |
| Pilot | 3 positive, 5 negative, 2 adversarial cases; documented false-positive analysis; self-scan clean | Reported at medium severity; not blocking at the default high gate |
| Warning | 15 positive, 50 negative, 10 adversarial cases; zero observed false positives in the maintained corpus; benchmark within budget | Reported, not blocking by default |
| Blocking | 50 positive, 500 negative, 25 adversarial cases; at least 95% controlled-corpus recall; zero observed false positives; review across supported languages/versions | Eligible for default severity gate |

“Zero observed false positives” is a test result, not a claim that false positives are mathematically impossible. Every blocking rule retains inline suppression, confidence filtering, and baseline support.

## Pilot cohort

The first cohort is deliberately small and explicit:

- `SP651`: Kubernetes adds `ALL` or `SYS_ADMIN` capabilities.
- `SP652`: Kubernetes seccomp profile is explicitly `Unconfined`.
- `SP653`: Kubernetes `procMount` is explicitly `Unmasked`.
- `SP654`: Kubernetes Windows `HostProcess` is explicitly enabled.
- `SP655`: Kubernetes AppArmor is explicitly `Unconfined` through the current field or legacy annotation.
- `SP656`: Kubernetes RBAC Role or ClusterRole grants an exact wildcard API group, resource, or verb.
- `SP657`: Kubernetes RoleBinding or ClusterRoleBinding grants the built-in `cluster-admin` role.
- `SP658`: a GitHub Actions security scanner command forces its nonzero exit to success.
- `SP659`: a GitHub Actions security scanner step sets `continue-on-error: true`.
- `SP660`: a GitHub reusable-workflow call uses `secrets: inherit` instead of named secrets.
- `SP661`: a Kubernetes API server configuration enables the `AlwaysAllow` authorizer.

The cohort does not report absence of a security context. That broader policy belongs in admission control or a structural manifest validator unless ShipProof can prove the complete rendered workload.

## Execution waves

1. Engine correctness: file routing, multiline scope bounds, secret-safe rendering, Unicode Git paths, and verified autofix exits.
2. Foundation corpus: finish the quality manifest for the pilot and add performance regression thresholds.
3. First 100 investigations (`SP651–SP750`): prioritize explicit cloud-native and CI/CD unsafe states; reject duplicates already covered by `SP200–SP299`.
4. CWE/ASVS/API waves (`SP751–SP1050`): build AST or structural support before implementing absence-based rules.
5. Reliability/framework/AI/native/data waves (`SP1051–SP1550`): version every framework case and route runtime-only checks to evidence adapters.
6. Operational-evidence wave (`SP1551–SP1650`): add proof-producing adapters and schemas rather than pretending deployment state is visible in source.
7. For every cohort: run full tests, package smoke, self-scan at the high gate, regex stress cases, and before/after benchmarks.
