# Tool routing

Use tools already present in the repository or environment first. Ask before installing, downloading databases, uploading code, or running active tests.

| Need | Preferred evidence |
| --- | --- |
| Cross-file source/data flow | Existing CodeQL or Semgrep configuration |
| Dependency reachability/advisories | Native package audit, OSV-Scanner, or Trivy with lockfiles/SBOM |
| Secret history | Gitleaks or equivalent history-aware scanner; redact values |
| Skill/plugin trust | SkillSpector or equivalent static review before installation |
| C/C++ memory safety | Compiler warnings, clang-tidy, ASan, UBSan, MSan/LSan |
| Concurrency races | TSan for user space; KCSAN plus target-specific tests for kernels |
| Kernel interfaces | KASAN/KMSAN/KCSAN and syzkaller in an isolated authorized lab |
| Parsers, codecs, browser components | libFuzzer/AFL++/Centipede or OSS-Fuzz/ClusterFuzzLite with sanitizers |
| CPU | Sampling profiler/perf counters and production-shaped benchmark |
| Memory | Allocation/heap profile, RSS/working-set trend, leak detector, soak test |
| Database | Query plan, slow-query evidence, lock/pool metrics, production-shaped data |
| Service load | Existing k6/Locust/JMeter suite with latency/error/resource thresholds |

Use deterministic tools for reproducible gates and AI for architecture context, invariant discovery, path tracing, and candidate prioritization. Confirm high-severity findings with a complete path, reproducer, sanitizer failure, or focused regression test.
