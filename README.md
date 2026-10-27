# SecOps Behavioral Analytics & Threat Hunting Documentation

Technical articles, threat hunting case studies, and reference guides for multi-stage statistical and UEBA hunting in **Google Security Operations (SecOps)**.

## Published Guides & Case Studies

* **[Beyond Static Rules: Hunting PHP2Shell and PHP UAF Exploitation with Multi-Stage Behavioral Analytics in Google SecOps](php2shell-ueba-hunting.md)**
  * A complete breakdown of 9 PHP2Shell ([CVE-2026-109618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618) / [CVE-2026-109619](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)) and PHP OPcache/session Use-After-Free (UAF) exploitation scenarios.
  * Compares traditional point-in-time YARA-L 2.0 rules against 14 live-compiler-verified multi-stage statistical and 30-day UEBA queries.
  * Includes a plain-English practitioner's appendix explaining **Zipfian Process Rarity**, **Two-Part Hurdle Models**, **Leave-One-Out Discrete Poisson**, **Fano Factor Dispersion**, **Median Absolute Deviation (MAD)**, **Markov 2-Gram Surprisal**, **Multi-Sector Threat Fusion**, and **Beta-Binomial Regularization**.
* **[Hunting Shadow AI and Autonomous Agents: A Signal-Processing & Bayesian UEBA Playbook for Google SecOps](shadow-ai-agentic-ueba-hunting.md)**
  * Formalizes a **Theory of the Case** separating Human ($H$), Deterministic Machine/Bot ($M_{\text{bot}}$), and Autonomous Agentic/Shadow AI ($M_{\text{AI}}$) resource consumption across cadence ($\text{CV}$, Fano dispersion, Circadian von Mises), entropy/surprisal (Markov 2-grams, novel resource scope), and directional byte asymmetry ($\rho$), conditioned on 30-day behavioral priors.
  * Provides 15 live-compiler-verified multi-stage YARA-L 2.0 queries across 10 scenarios (featuring unified multi-stage queries for Scenarios 1, 5, 6, and 7; Option 3 UDM Loopback Stage A $\rightarrow$ Stage B gating for Scenarios 2 and 4; parallel macro/micro pairs for Scenarios 3, 8, and 9; and a unified 3-stage Capstone rollup + raw telemetry forensic bridge in Scenario 10 via `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` regex token union).
  * Fully compatible with the programmatic `PlaybookRunner` engine in `GooGKush/agentic-ueba`.

## Curated Detections UEBA Hunting Playbooks

Cyclical 3-wave multi-stage UEBA and statistical hunting playbooks supplementing Google SecOps Curated Detections across all 12 rule categories (featuring Wave 1 Option 1 piecewise cold-start + 30-day baselines, Wave 2 Option 3 `A -> UDM -> B` candidate-gated sub-hour statistical models via `:q[0-9]+_query_Xa` tags, and Wave 3 3-stage Unified Capstone Euclidean L2 convergence + raw telemetry forensic bridges with `run_id` read-after-write validation):

* **[Chrome Enterprise Premium Threats UEBA Hunting](chrome-enterprise-premium-ueba-hunting.md)**
* **[Cloud Threats UEBA Hunting](cloud-threats-ueba-hunting.md)**
* **[Windows Threats UEBA Hunting](windows-threats-ueba-hunting.md)**
* **[Linux Threats UEBA Hunting](linux-threats-ueba-hunting.md)**
* **[macOS Threats UEBA Hunting](macos-threats-ueba-hunting.md)**
* **[Composite Rules UEBA Hunting](composite-rules-ueba-hunting.md)**
* **[Applied Threat Intelligence (ATI) Indicator Prioritization UEBA Hunting](indicator-prioritization-ueba-hunting.md)**
* **[Non-Prioritized IOC Matching UEBA Hunting](non-prioritized-ioc-matching-ueba-hunting.md)**
* **[Mandiant Hunting UEBA Playbook](mandiant-hunting-ueba-hunting.md)**
* **[Risk Analytics UEBA Hunting](risk-analytics-ueba-hunting.md)**
* **[Vendor Alerts UEBA Hunting](vendor-alerts-ueba-hunting.md)**
* **[Third-Party Vendor Alerts UEBA Hunting](third-party-vendor-alerts-ueba-hunting.md)**

## Related Repositories

* [`GooGKush/secops-statistical-hunter`](https://github.com/GooGKush/secops-statistical-hunter) — Multi-stage statistical outlier hunting, Bayesian updating, and Entity Context Graph enrichment over raw UDM telemetry.
* [`GooGKush/secops-risk-metrics-multistage`](https://github.com/GooGKush/secops-risk-metrics-multistage) — 30-day behavioral baseline (`metrics.*`) UEBA threat hunting, peer cohort comparisons, 360° entity risk radar, and multi-sector threat fusion.
* [`GooGKush/agentic-ueba`](https://github.com/GooGKush/agentic-ueba) — Agentic UEBA orchestration and harness utilities.
---

## 📜 License
This project is licensed under the [Apache License 2.0](LICENSE).
```
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---
*Created and maintained by Greg Kushmerek for Google Security Operations (Chronicle SIEM & SOAR).*
