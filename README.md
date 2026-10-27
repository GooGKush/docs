# SecOps Behavioral Analytics & Threat Hunting Documentation

Technical articles, threat hunting case studies, and reference guides for multi-stage statistical and UEBA hunting in **Google Security Operations (SecOps)**.

## Published Guides & Case Studies

* **[Beyond Static Rules: Hunting PHP2Shell and PHP UAF Exploitation with Multi-Stage Behavioral Analytics in Google SecOps](php2shell-ueba-hunting.md)**
  * A complete breakdown of 9 PHP2Shell ([CVE-2026-109618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618) / [CVE-2026-109619](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)) and PHP OPcache/session Use-After-Free (UAF) exploitation scenarios.
  * Compares traditional point-in-time YARA-L 2.0 rules against 14 live-compiler-verified multi-stage statistical and 30-day UEBA queries.
  * Includes a plain-English practitioner's appendix explaining **Zipfian Process Rarity**, **Two-Part Hurdle Models**, **Leave-One-Out Discrete Poisson**, **Fano Factor Dispersion**, **Median Absolute Deviation (MAD)**, **Markov 2-Gram Surprisal**, **Multi-Sector Threat Fusion**, and **Beta-Binomial Regularization**.
* **[Hunting Shadow AI and Autonomous Agents: A Signal-Processing & Bayesian UEBA Playbook for Google SecOps](shadow-ai-agentic-ueba-hunting.md)**
  * Formalizes a **Theory of the Case** separating Human ($H$), Deterministic Machine/Bot ($M_{\text{bot}}$), and Autonomous Agentic/Shadow AI ($M_{\text{AI}}$) resource consumption across cadence ($\text{CV}$, Fano dispersion, Circadian von Mises), entropy/surprisal (Markov 2-grams, novel resource scope), and directional byte asymmetry ($\rho$), conditioned on 30-day behavioral priors.
  * Provides 14 live-compiler-verified multi-stage YARA-L 2.0 queries (featuring Option 1 inline piecewise cold-start + mature 30-day `metrics.*` baselines, `secops-statistical-hunter` raw telemetry models, and Option 3 UDM Loopback cross-query entity bridging and Capstone convergence via `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) across Holistic Cross-Resource, Network/Proxy, Endpoint/EDR, Cloud Control Plane, and SaaS/Workspace contexts.
  * Fully compatible with the programmatic `PlaybookRunner` engine in `GooGKush/agentic-ueba`.

## Related Repositories

* [`GooGKush/secops-statistical-hunter`](https://github.com/GooGKush/secops-statistical-hunter) — Multi-stage statistical outlier hunting, Bayesian updating, and Entity Context Graph enrichment over raw UDM telemetry.
* [`GooGKush/secops-risk-metrics-multistage`](https://github.com/GooGKush/secops-risk-metrics-multistage) — 30-day behavioral baseline (`metrics.*`) UEBA threat hunting, peer cohort comparisons, 360° entity risk radar, and multi-sector threat fusion.
* [`GooGKush/agentic-ueba`](https://github.com/GooGKush/agentic-ueba) — Agentic UEBA orchestration and harness utilities.
