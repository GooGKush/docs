# SecOps Behavioral Analytics & Threat Hunting Documentation

Technical articles, threat hunting case studies, and reference guides for multi-stage statistical and UEBA hunting in **Google Security Operations (SecOps)**.

## Published Guides & Case Studies

* **[Beyond Static Rules: Hunting PHP2Shell and PHP UAF Exploitation with Multi-Stage Behavioral Analytics in Google SecOps](php2shell-ueba-hunting.md)**
  * A complete breakdown of 9 PHP2Shell ([CVE-2026-109618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618) / [CVE-2026-109619](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)) and PHP OPcache/session Use-After-Free (UAF) exploitation scenarios.
  * Compares traditional point-in-time YARA-L 2.0 rules against 14 live-compiler-verified multi-stage statistical and 30-day UEBA queries.
  * Includes a plain-English practitioner's appendix explaining **Zipfian Process Rarity**, **Two-Part Hurdle Models**, **Leave-One-Out Discrete Poisson**, **Fano Factor Dispersion**, **Median Absolute Deviation (MAD)**, **Markov 2-Gram Surprisal**, **Multi-Sector Threat Fusion**, and **Beta-Binomial Regularization**.

## Related Repositories

* [`GooGKush/secops-statistical-hunter`](https://github.com/GooGKush/secops-statistical-hunter) — Multi-stage statistical outlier hunting, Bayesian updating, and Entity Context Graph enrichment over raw UDM telemetry.
* [`GooGKush/secops-risk-metrics-multistage`](https://github.com/GooGKush/secops-risk-metrics-multistage) — 30-day behavioral baseline (`metrics.*`) UEBA threat hunting, peer cohort comparisons, 360° entity risk radar, and multi-sector threat fusion.
* [`GooGKush/agentic-ueba`](https://github.com/GooGKush/agentic-ueba) — Agentic UEBA orchestration and harness utilities.
