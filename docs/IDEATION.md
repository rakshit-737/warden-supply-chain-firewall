# Ideation & Idea Selection

This document records the structured ideation process that preceded a single line of
implementation code. It is deliberately part of the repository: a senior engineer can
justify *why* a product exists and why competing directions were rejected, and that
reasoning is itself an interview asset.

## 1. Evaluation rubric

Each candidate was scored 1–5 on seven axes:

| Axis | Meaning |
|------|---------|
| **Orig** | Originality — how far from a tutorial/clone it is |
| **Cplx** | Technical complexity / number of interconnected subsystems |
| **Impact** | Real-world impact for organisations today |
| **Place** | Placement value (breadth of topics it lets you discuss) |
| **Resume** | Resume signal (does the title alone impress?) |
| **Intv** | Depth of interview discussion it enables |
| **Feas** | Feasibility for one engineering student |

`Total` is the unweighted sum (max 35). Feasibility acts as a gate — an idea scoring
< 3 on feasibility is effectively disqualified regardless of total.

## 2. The 20 candidates

| # | Idea | Orig | Cplx | Impact | Place | Resume | Intv | Feas | Total |
|---|------|:----:|:----:|:------:|:-----:|:------:|:----:|:----:|:-----:|
| 1 | **Software supply-chain firewall** (malicious dependency detection + policy gate) | 5 | 5 | 5 | 5 | 5 | 5 | 4 | **34** |
| 2 | LLM prompt-injection / guardrail proxy for AI apps | 5 | 4 | 5 | 5 | 5 | 5 | 4 | 33 |
| 3 | Reachability-aware SBOM vulnerability correlation (cut CVE noise via call-graph) | 5 | 5 | 5 | 4 | 4 | 5 | 3 | 31 |
| 4 | Honeytoken / deception platform with correlation engine | 4 | 4 | 4 | 4 | 4 | 5 | 4 | 29 |
| 5 | Cloud IAM least-privilege recommender from access logs (graph) | 4 | 5 | 5 | 4 | 4 | 4 | 3 | 29 |
| 6 | eBPF runtime workload behavioural baselining & anomaly detection | 5 | 5 | 4 | 3 | 5 | 4 | 2 | 28 |
| 7 | Automated BOLA/IDOR authorization fuzzer using learned object graphs | 5 | 4 | 4 | 4 | 3 | 4 | 3 | 27 |
| 8 | Kubernetes admission controller with risk-based policy + drift ML | 4 | 4 | 4 | 4 | 4 | 4 | 3 | 27 |
| 9 | Malicious OAuth / consent-grant detection for SaaS | 4 | 3 | 4 | 4 | 3 | 4 | 4 | 26 |
| 10 | IaC (Terraform) authorization drift & policy diff detector | 4 | 3 | 4 | 4 | 3 | 4 | 4 | 26 |
| 11 | DNS-tunneling / exfiltration detector using sequence models | 4 | 4 | 4 | 3 | 3 | 4 | 3 | 25 |
| 12 | Ransomware early-detection via FS entropy + honeyfiles (fanotify) | 4 | 4 | 4 | 3 | 4 | 3 | 3 | 25 |
| 13 | Purple-team attack simulation + detection validation harness | 3 | 4 | 4 | 4 | 3 | 4 | 3 | 25 |
| 14 | SPIFFE-based zero-trust identity broker for service mesh | 4 | 4 | 3 | 3 | 4 | 4 | 2 | 24 |
| 15 | API schema-aware WAF that learns per-endpoint behaviour | 4 | 4 | 4 | 3 | 3 | 4 | 2 | 24 |
| 16 | Secrets-leak detection + automatic cross-cloud rotation orchestration | 3 | 4 | 4 | 3 | 3 | 4 | 3 | 24 |
| 17 | Threat-intel enrichment & alert-triage copilot | 3 | 3 | 4 | 4 | 3 | 3 | 4 | 24 |
| 18 | Web-app attack-path graph builder from recon data | 3 | 3 | 3 | 3 | 3 | 4 | 4 | 23 |
| 19 | Encrypted-DNS/DoH anomaly detector | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 21 |
| 20 | Adversarial-ML evasion research toolkit | 4 | 4 | 2 | 2 | 3 | 4 | 2 | 21 |

## 3. Shortlist reasoning

**#3 (reachability SBOM)** is genuinely elite but the hard part — building precise
inter-procedural call graphs across ecosystems — is a research project on its own and
risks a demo that is impressive on paper but shallow in practice.

**#2 (LLM guardrail)** is superb and timely; it was the runner-up. It lost narrowly on
*breadth*: it is mostly one classifier behind a proxy, so it exercises fewer distinct
engineering subsystems than #1.

**#1 (supply-chain firewall)** wins because it maximises the product of *breadth* and
*depth* while remaining fully buildable and demonstrable by one person:

- **Real problem, right now.** `event-stream`, `ua-parser-js`, `xz/liblzma`,
  `PyTorch torchtriton` dependency-confusion, and a steady stream of malicious PyPI/npm
  uploads have made "should we even let this package in?" a board-level question.
- **Not a banned clone.** It is explicitly *not* a vulnerability scanner: a scanner asks
  "does this known-vulnerable version have a CVE?"; Warden asks "is this package
  *behaving* like malware, regardless of whether anyone has reported it yet?" That
  distinction is the core interview talking point.
- **ML earns its place.** Feature-based anomaly detection over package behaviour and
  metadata is a legitimate ML use case, not a bolted-on gimmick. We can also *ablate* it
  (rules-only vs rules+ML) and discuss precision/recall trade-offs.
- **Many interconnected components.** Fetcher → multi-analyzer pipeline → feature vector
  → hybrid (rules + ML) scorer → policy engine → verdict store → secure API → dashboard →
  CLI/CI gate. Every one of these is a separate interview thread.
- **Feasible and self-contained.** It analyses *real* packages from the public PyPI index
  with no paid infrastructure, and runs entirely from `docker compose up`.

## 4. Selected product

> **Warden — a Software Supply-Chain Firewall.**
> It sits between a developer/CI and the public package registries, statically analyses a
> package's real code and metadata *before* it is trusted, fuses rule-based and
> machine-learning signals into a 0–100 risk verdict, and enforces organisational policy
> (allow / warn / block) through an API, a `warden` CLI gate, and a security-team
> dashboard.

The remainder of the documentation set (`ARCHITECTURE.md`, `THREAT_MODEL.md`,
`API.md`, `ML_MODEL.md`) designs and defends this product in detail.
