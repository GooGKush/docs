# Contextualizing Non-Prioritized Domain, File & IP IOC Matching with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Non-Prioritized IOC Matching** curated detection pack provides broad indicator matching across domain, file hash, and IP address feeds where indicators may carry lower static confidence or broader infrastructure overlap (such as shared hosting, CDNs, or aged threat feeds).

To help analysts separate true compromises from benign shared-infrastructure noise—and to surface rare or newly introduced infrastructure absent from static lists—this runbook pairs indicator-adjacent telemetry with **30-Day Behavioral Baselines (`secops-risk-metrics-multistage`)**, **`DERIVED_CONTEXT` 10-Day Entity Context Graph Prevalence & Asset Age**, **Stateless Long-String & Rare-Token DNS Screening (`LONG_STRING_SCREEN`)**, **Leave-One-Out Discrete Poisson Arrival Rarity**, **Leave-One-Out Conjugate Gamma-Poisson Connection Shrinkage**, and **Non-Parametric Quantile / Bowley Skewness Tukey Fences**. All queries emit standardized Z or Z-equivalent statistical scores; the `[0–100]` Calibrated Risk Index (CRI) is computed post-query in Python via `ueba_constants.calculate_cri`.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the window and baseline constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba`:
  1. **Wave 1 — Upstream Macro/ECG & Bounded Raw Statistical Queries (`Queries 1A, 1B, 2A, 2B, 3A`, plus Section 3's 4-Stage Quantile/Bowley Fence)**: Executes all 30-day `metrics.*` + `DERIVED_CONTEXT` dual-plane baselines (enforcing the 7-active-day maturity gate and continuous count/byte dispersion floors) alongside bounded raw statistical queries concurrently. In Mode A (scoring the last complete UTC day `D`, e.g., `2026-10-29`), pure `metrics.*` queries scan `[D T00:00:00Z, D+1 T00:00:00Z)` while `DERIVED_CONTEXT` Entity Context Graph joins anchor `startTime = D-2` (`2026-10-27T00:00:00Z` to `2026-10-30T00:00:00Z`) and pin event stages to `D` with `timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"`. Every match is written back into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the run's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback — `Query 3B`)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, `Query 3B` reads `Query 3A`'s candidate endpoints in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`) to bound sub-day (`by 1h`) outbound connection burst and conjugate Gamma-Poisson shrinkage evaluation without scanning the entire fleet.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 4`)**: Unions upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)`), deduplicates per scenario in Stage 1, requires cross-scenario convergence across `>= 2` distinct scenario hits (`LOOPBACK_MIN_DISTINCT_HITS = 2`) with summed squared Z-scores `>= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD = 25.0`) in Stage 2, and joins winning entities to per-sector raw endpoint and network telemetry in Stage 3.

### 1.1 Optional Customization: Scoping Hunts with Custom Non-Prioritized IOC Data Tables

Teams operating custom low-confidence threat feeds or watchlists in Google SecOps Data Tables (for example, `%non_prioritized_ioc_domains`, `%non_prioritized_ioc_hashes`, or `%non_prioritized_ioc_watchlist` under `<PROJECT_ID>` / `<CUSTOMER_ID>`) can optionally scope Stage 1 of any query to those indicators.

> [!TIP]
> **Why Data Table References Are Commented Out by Default**: In Google SecOps YARA-L 2.0, referencing a Data Table (`%non_prioritized_ioc_domains.domain`) that has not yet been created in the target tenant causes an immediate compilation failure. To ensure every query in this runbook compiles out of the box—and to catch novel rare domains, hashes, and egress anomalies not yet listed on static feeds—all Data Table predicates are commented out with explanatory `//` notes. Uncomment them only after creating and populating the corresponding Data Table in your tenant.

### Table 1: Scenario Coverage Matrix — Applied Threat Intelligence — Non-Prioritized IOC Matching & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Domain Indicator Contextualization & Long/Rare DNS Screening** | Broad matching of DNS queries and HTTP requests against non-prioritized domain indicators. | Combines mature 30-day HTTP volume baselines (`>= 7` active days, count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$) and 10-day `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3`) with a stateless DNS long-string & within-host token rarity screen (`LONG_STRING_SCREEN` $\ge 5.5$, `fleet_prevalence <= 3`). | `Query 1A` (30d HTTP + 10d Domain Prevalence)<br>`Query 1B` (DNS Long-String & Rare-Token Screen) |
| **2. File Hash Contextualization & Rare Binary Arrival** | Matches endpoint process and file events against broad file-hash indicator feeds. | Pairs mature 30-day host file execution baselines (`metrics.file_executions_total`, `>= 7` active days) and 10-day `DERIVED_CONTEXT` `FILE` prevalence (`rolling_max <= 3`) with Leave-One-Out Discrete Poisson arrival rarity ($Z_{\text{Poisson}}^2 \ge 12.25$) on endpoints with established online history. | `Query 2A` (30d Execution + 10d File Prevalence)<br>`Query 2B` (Discrete Poisson Arrival Rarity) |
| **3. IP Indicator Contextualization & Anomalous Egress Flows** | Matches network connections against non-prioritized IP indicators. | Pairs mature 30-day outbound byte Z-scores (`metrics.network_bytes_outbound` with a $44,979\text{-byte}$ fleet dispersion floor) on recently onboarded assets (`DERIVED_CONTEXT` age $\le 14\text{d}$) with Wave 2 UDM-gated Leave-One-Out Conjugate Gamma-Poisson hourly connection shrinkage (`$bayesian_z >= 3.0`). | `Query 3A` (30d Outbound Bytes + Young Asset Age)<br>`Query 3B` (UDM-Gated Gamma-Poisson Shrinkage) |
| **4. Capstone Multi-Scenario IOC Entity Convergence** | Individual domain, file, or IP indicator matches evaluated independently. | Correlates entities matching $\ge 2$ distinct upstream behavioral scenarios in the active run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) with summed squared Z-scores $\sum Z_i^2 \ge 25.0$ and joins per-sector raw forensic telemetry. | `Query 4` (Capstone UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Domain-Based Indicator Matching — Behavioral Rarity & Long/Rare DNS Screening

* **Curated Detection Operational Focus**: Broad matching of DNS queries and HTTP requests against non-prioritized domain indicators.
* **How Multi-Stage UEBA Extends Coverage**: Pairs 30-day per-(host, domain) HTTP volume baselines and 10-day `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3`) with a stateless DNS long-string and within-host token rarity screen (`LONG_STRING_SCREEN`) gated by live fleet prevalence (`<= 3` hosts).

#### Query 1A: 2-Stage Hybrid 30-Day HTTP Volume (`metrics.http_queries_total`) + `DERIVED_CONTEXT` 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Scores per-(host, domain) HTTP request counts on Mode A day `D` (`2026-10-29`) against the 30-day `metrics.http_queries_total` baseline using the count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1.0)})$ and a 7-active-day maturity gate (`$active_baseline_days >= 7`), then inner-joins Chronicle's `DERIVED_CONTEXT` Entity Context Graph (`day_count = 10`, `rolling_max <= 3`). Ubiquitous CDN, SaaS, and reverse-DNS/mDNS names are excluded, while rare domains ($\le 3$ hosts) surging at `$z_score >= 3.0` receive a $2.5\times$ multiplier when `first_seen_time` is populated and $\le 7$ days old (or $1.5\times$ otherwise; when `first_seen_time = 0`, `$ecg_novelty_disabled = 1.0` disables the $<7\text{d}$ boost). Because the `DERIVED_CONTEXT` lookup is an inner join, brand-new unindexed domains or `< 7` active-day pairs should be covered alongside `first_seen_novelty_2stage.yl2` or a raw Day-0 companion query.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Suppress ubiquitous CDN/SaaS domain noise while detecting rare external domain HTTP surges (10-day rolling_max <= 3 hosts, >= 7 active baseline days).
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total, count dispersion floor) + DERIVED_CONTEXT 10-Day Domain Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Destination HTTP Query Baseline per (host, domain) pinned to Mode A UTC day
stage stage1_query_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional custom non-prioritized domain IOC Data Table filter (commented out; unpopulated tables break compilation):
    // $domain in %non_prioritized_ioc_domains.domain

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = count(metadata.id)
    $distinct_ports = count_distinct(target.port)

    $hist_mean = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $hist_stddev = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $hist_active_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Domain Prevalence & First Seen)
stage stage2_domain_derived_context {
    $dom.graph.metadata.source_type = "DERIVED_CONTEXT"
    $dom.graph.metadata.entity_type = "DOMAIN_NAME"
    $dom.graph.entity.domain.name = $domain
    $dom.graph.entity.domain.prevalence.day_count = 10
    $dom.graph.entity.domain.prevalence.rolling_max <= 3
    $dom.graph.entity.domain.prevalence.rolling_max > 0
    $domain != ""

  match:
    $domain

  outcome:
    $enterprise_day_count = min($dom.graph.entity.domain.prevalence.day_count)
    $enterprise_rolling_max = max($dom.graph.entity.domain.prevalence.rolling_max)
    $first_seen_ts = min($dom.graph.entity.domain.first_seen_time.seconds)
    $last_seen_ts = max($dom.graph.entity.domain.last_seen_time.seconds)
}

// Root Stage: Fuse Personal HTTP Query Z-Score with Enterprise Domain Prevalence Multiplier
$host = $stage1_query_baseline.host
$domain = $stage1_query_baseline.domain
$domain = $stage2_domain_derived_context.domain

match:
  $host, $domain by 1d

outcome:
  $observed_queries = max($stage1_query_baseline.observed_val)
  $mean_queries = max($stage1_query_baseline.hist_mean)
  $stddev_queries = max($stage1_query_baseline.hist_stddev)
  $safe_mean = if($mean_queries > 1.0, $mean_queries, 1.0)
  $dispersion_floor = math.sqrt($safe_mean)
  $safe_stddev = if($stddev_queries > $dispersion_floor, $stddev_queries, $dispersion_floor)
  $z_score = ($observed_queries - $mean_queries) / $safe_stddev
  $active_baseline_days = max($stage1_query_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_domain_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_domain_derived_context.enterprise_day_count)
  $first_seen = min($stage2_domain_derived_context.first_seen_ts)
  $obs_ts = max($stage1_query_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $domain_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Domain Multiplier: 2.5x boost when first_seen_time > 0 and <= 7 days old; 1.5x for <= 3 hosts
  $ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)
  $is_novel_domain = if($first_seen > 0 and $domain_age_days <= 7.0 and $domain_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_domain = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

condition:
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

#### Query 1B: 3-Stage Long-String & Rare-Token DNS Screen (`LONG_STRING_SCREEN` $\ge 5.5$) with Fleet Prevalence (`secops-statistical-hunter`)
Because YARA-L 2.0 has no per-character iteration primitive, this stateless query implements the canonical **`LONG_STRING_SCREEN`** candidate detector on `network.dns.questions.name`: it scores each `(host, domain)` pair by combining log query-name length with within-host token rarity, $\text{score} = \ln(\text{length}) + \ln(1 + \text{total\_events} / \text{token\_count}) \ge 5.5$, gated by minimum domain length (`$raw_length >= 25`), reverse-DNS/mDNS exclusion, and live enterprise fleet prevalence (`$fleet_prevalence <= 3` hosts). This surfaces long, host-rare, fleet-isolated DNS tunneling and DGA queries in a single stateless pass; exact per-character Shannon entropy ($H(s) = -\sum p(c)\log_2 p(c)$) can be evaluated post-query on candidate strings when needed via `SHANNON_ENTROPY_CHARACTER` (`micro_python_helpers.py shannon`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long, host-rare, and fleet-isolated DNS query names indicative of DGA lookups or DNS tunneling payloads across NETWORK_DNS traffic.
// Target Telemetry: UDM_EVENTS (NETWORK_DNS: network.dns.questions.name)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN: ln(length) + ln(1 + total_events / token_count) >= 5.5, fleet_prevalence <= 3)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Per-host daily DNS query volume
stage entity_baseline {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.hostname = $entity
    $entity != ""
    not re.regex(network.dns.questions.name, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)

  match:
    $entity by 1d

  outcome:
    $total_events = count(metadata.id)
}

// Stage 2: Per-(host, queried domain) observation count and string length
stage token_observation {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.hostname = $entity
    $entity != ""
    $token = network.dns.questions.name
    $token != ""
    not re.regex(network.dns.questions.name, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional custom non-prioritized domain IOC Data Table filter (commented out; unpopulated tables break compilation):
    // $token in %non_prioritized_ioc_domains.domain

  match:
    $entity, $token by 1d

  outcome:
    $token_count = count(metadata.id)
    $token_length = max(strings.length($token))
}

// Stage 3: Enterprise fleet prevalence per queried DNS name
stage dns_fleet_prevalence {
    $token = $token_observation.token
    $ws = $token_observation.window_start

  match:
    $token, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($token_observation.entity)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring + 6 Core Evidence Pillars
$entity = $entity_baseline.entity
$entity = $token_observation.entity
$token = $token_observation.token
$token = $dns_fleet_prevalence.token
$ws = $entity_baseline.window_start
$ws = $token_observation.window_start
$ws = $dns_fleet_prevalence.ws

match:
  $entity, $token, $ws by 1d

outcome:
  $total_activity = max($entity_baseline.total_events)
  $token_executions = max($token_observation.token_count)
  $raw_length = max($token_observation.token_length)
  $safe_length = if($raw_length > 0, $raw_length, 1)
  $safe_total = if($total_activity > 0, $total_activity, 1)
  $safe_tok = if($token_executions > 0, $token_executions, 1)

  $log_len = math.log($safe_length)
  $rarity_lift = math.log(1.0 + (1.0 * $safe_total / $safe_tok))
  $shannon_entropy_score = $log_len + $rarity_lift
  $z_score = $shannon_entropy_score

  // 6 Core Evidence Pillars
  $observation_count = $token_executions
  $baseline_active_samples = $total_activity
  $baseline_mean = $raw_length
  $baseline_dispersion = $log_len
  $fleet_prevalence = max($dns_fleet_prevalence.fleet_hosts)
  $distinct_binaries = 1

condition:
  $raw_length >= 25
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 5.5

order:
  $shannon_entropy_score desc
```

---

### Scenario 2: File-Based Indicator Matching — Rare Binary Prevalence & Discrete Poisson Arrival Rarity

* **Curated Detection Operational Focus**: Matches endpoint process and file events against broad file-hash indicator feeds.
* **How Multi-Stage UEBA Extends Coverage**: Pairs mature 30-day host file execution baselines (`metrics.file_executions_total`) and 10-day `DERIVED_CONTEXT` `FILE` prevalence (`rolling_max <= 3`) with Leave-One-Out Discrete Poisson arrival rarity across endpoints with verified multi-day online history.

#### Query 2A: 2-Stage Hybrid 30-Day Process Execution (`metrics.file_executions_total`) + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Suppresses sanctioned fleet-wide RMM and updater noise by scoring per-(host, SHA256) process execution counts on Mode A day `D` (`2026-10-29`) against the 30-day `metrics.file_executions_total` baseline using the count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1.0)})$ and a 7-active-day maturity gate (`$active_baseline_days >= 7`), joined with `DERIVED_CONTEXT` 10-day `FILE` prevalence (`rolling_max <= 3`). Binaries seen on $>3$ hosts drop out, while isolated binaries surging at `$z_score >= 3.0` receive a $2.5\times$ novelty multiplier when `first_seen_time` is populated and $\le 7$ days old (or $1.5\times$ otherwise). Day-0 or `< 7` active-day binaries route to `first_seen_novelty_2stage.yl2` or **Query 2B** below.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous execution surges of rare binaries (10-day org prevalence rolling_max <= 3 hosts, >= 7 active baseline days) while suppressing sanctioned fleet-wide tools.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.file_executions_total, count dispersion floor) + DERIVED_CONTEXT 10-Day File Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total) pinned to Mode A UTC day
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    $sha256 = strings.coalesce(target.process.file.sha256, principal.process.file.sha256)
    principal.process.file.sha256 != ""
    $host != ""
    $sha256 != ""
    // Optional custom non-prioritized file hash IOC Data Table filter (commented out; unpopulated tables break compilation):
    // $sha256 in %non_prioritized_ioc_hashes.sha256

  match:
    $host, $sha256 by 1d

  outcome:
    $observed_val = count(metadata.id)
    $sample_command = array_distinct(principal.process.command_line)
    $sample_path = array_distinct(principal.process.file.full_path)
    $distinct_users = count_distinct(principal.user.userid)

    $hist_mean = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        metadata.event_type: metadata.event_type,
        principal.asset.hostname: principal.asset.hostname,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $hist_stddev = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        metadata.event_type: metadata.event_type,
        principal.asset.hostname: principal.asset.hostname,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $hist_active_days = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        metadata.event_type: metadata.event_type,
        principal.asset.hostname: principal.asset.hostname,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Binary Prevalence & First Seen)
stage stage2_file_derived_context {
    $file.graph.metadata.source_type = "DERIVED_CONTEXT"
    $file.graph.metadata.entity_type = "FILE"
    $file.graph.entity.file.sha256 = $sha256
    $file.graph.entity.file.prevalence.day_count = 10
    $file.graph.entity.file.prevalence.rolling_max <= 3
    $file.graph.entity.file.prevalence.rolling_max > 0
    $sha256 != ""

  match:
    $sha256

  outcome:
    $enterprise_day_count = min($file.graph.entity.file.prevalence.day_count)
    $enterprise_rolling_max = max($file.graph.entity.file.prevalence.rolling_max)
    $first_seen_ts = min($file.graph.entity.file.first_seen_time.seconds)
    $last_seen_ts = max($file.graph.entity.file.last_seen_time.seconds)
}

// Root Stage: Fuse Personal Outlier Z-Score with Enterprise File Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $safe_mean = if($mean_execs > 1.0, $mean_execs, 1.0)
  $dispersion_floor = math.sqrt($safe_mean)
  $safe_stddev = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_stddev
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier: 2.5x boost when first_seen_time > 0 and <= 7 days old; 1.5x for <= 3 hosts
  $ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)
  $is_novel_binary = if($first_seen > 0 and $binary_age_days <= 7.0 and $binary_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_binary = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

  $sample_commands = array_distinct($stage1_process_baseline.sample_command)
  $sample_paths = array_distinct($stage1_process_baseline.sample_path)

condition:
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

#### Query 2B: Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 \ge 12.25$) on Rare Process Executions (`secops-statistical-hunter`)
Detects first-time or rare surges of RMM agents, tunneling utilities, cryptominers, and `/tmp` or `/dev/shm` binaries on `target.process.file.full_path` even when the binary hash changes or is absent from threat feeds. Over a 14-day Mode B window (`13.0` prior calendar days), it computes the **Leave-One-Out Jeffreys-Smoothed Poisson Rate** $\lambda = (\text{prior\_runs} + 0.5) / 13.0$ alongside independent host online calendar-day maturity in `host_online_baseline` (`$baseline_active_samples >= 7`), firing on the host's latest active day (`$is_latest_day = 1`) when $k \ge 3$, $\lambda \le 2.0\text{/day}$, and $Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 12.25$ ($3.5\sigma$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect statistically improbable surges in rare RMM, tunneling, or cryptomining binaries on endpoints with established online history via Leave-One-Out Discrete Poisson Rarity.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH: target.process.file.full_path)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (POISSON_RARE_SURGE: Z_Poisson^2 = (k - lambda)^2 / lambda >= 12.25)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily execution counts per host and target process binary (UTC-aligned by 1d)
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""
    (
      re.regex(target.process.file.full_path, `(?i)(anydesk|teamviewer|screenconnect|atera|splashtop|rustdesk|ngrok|chisel|cloudflared|xmrig|minerd|tmate|socat|/tmp/|/dev/shm/|/var/tmp/)`)
      or re.regex(target.process.command_line, `(?i)(stratum\+tcp|stratum\+ssl|xmrig|cryptonight|randomx|anydesk|screenconnect|rustdesk|ngrok|cloudflared|chmod\s+\+x\s+/tmp/)`)
    )
    // Optional custom endpoint watchlist Data Table filter (commented out; unpopulated tables break compilation):
    // $entity in %non_prioritized_ioc_watchlist.hostname

  match:
    $entity, $tool by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
    $bucket_max_ts = max(metadata.event_timestamp.seconds)
}

// Stage 2: Historical tool run accumulation per host and binary
stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool

  match:
    $entity, $tool

  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $tool_active_days = count($daily_tool_counts.window_start)
}

// Stage 3: Host online calendar-day maturity across all PROCESS_LAUNCH telemetry
stage host_online_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $utc_date = timestamp.get_date(metadata.event_timestamp.seconds, "UTC")

  match:
    $entity

  outcome:
    $online_days = count_distinct($utc_date)
    $host_max_ts = max(metadata.event_timestamp.seconds)
}

// Root Stage: Calculate Leave-One-Out Discrete Poisson Score on Latest Active Day & Emit 6 Evidence Pillars
$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool
$entity = $host_online_baseline.entity
$ws = $daily_tool_counts.window_start

match:
  $entity, $tool, $ws by 1d

outcome:
  // Leave-one-out prior runs & Jeffreys-smoothed daily arrival rate over 13 prior calendar days (14d Mode B window)
  $today_k = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 13.0

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($host_online_baseline.online_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $lambda
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

  // Aggregate Poisson Squared Score & Latest-Day Gate
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0.01, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda
  $lag_seconds = max($host_online_baseline.host_max_ts) - max($daily_tool_counts.bucket_max_ts)
  $is_latest_day = if($lag_seconds < 86400, 1, 0)

condition:
  $baseline_active_samples >= 7
  and $is_latest_day = 1
  and $observation_count >= 3
  and $baseline_mean <= 2.0
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 12.25

order:
  $poisson_z_sq desc
```

---

### Scenario 3: IP-Based Indicator Matching — Outbound Byte Anomalies & Bayesian Connection Shrinkage

* **Curated Detection Operational Focus**: Matches network connections against non-prioritized IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Scores per-host 30-day outbound byte volume (`metrics.network_bytes_outbound`, floored at the $44,979\text{-byte}$ fleet dispersion floor) on recently onboarded assets (`DERIVED_CONTEXT` age $\le 14\text{d}$) in Wave 1 (`Query 3A`), then feeds matched hosts via UDM Loopback into Wave 2 (`Query 3B`) for hourly Leave-One-Out Conjugate Gamma-Poisson connection burst evaluation with empirical excess overdispersion.

#### Query 3A: 2-Stage Hybrid 30-Day Outbound Network Bytes (`metrics.network_bytes_outbound`) + `DERIVED_CONTEXT` Young Asset Age (`secops-risk-metrics-multistage`)
Evaluates each endpoint's daily outbound byte volume on Mode A day `D` (`2026-10-29`) against its 30-day `metrics.network_bytes_outbound` baseline using the $44,979\text{-byte}$ fleet dispersion floor ($\max(\sigma, 44979.0)$) and a 7-active-day maturity gate (`$active_days >= 7`), joined with `DERIVED_CONTEXT` `ASSET` `first_seen_time`. Recently onboarded assets (`$asset_age_days <= 14.0`) breaking above `$z_score >= 3.0` receive a $1.5\times$ young-asset multiplier (or $2.5\times$ at $\le 7.0$ days). True Day-0/infant assets with `< 7` active baseline days should be paired with `first_seen_novelty_2stage.yl2` (`metrics.network_bytes_outbound(..., agg: first_seen)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous outbound network byte surges on recently provisioned young assets (first_seen_time <= 14 days, >= 7 active baseline days) regardless of static IP feed coverage.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.network_bytes_outbound, 44979B byte dispersion floor) + DERIVED_CONTEXT Young Asset Age Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT ASSET AGE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Host Outbound Network Byte Baseline (metrics.network_bytes_outbound) pinned to Mode A UTC day
stage stage1_asset_baseline {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    $host != ""
    // Optional custom endpoint/IP watchlist Data Table filter (commented out; unpopulated tables break compilation):
    // $host in %non_prioritized_ioc_watchlist.hostname

  match:
    $host by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)

    $hist_mean = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (Asset First Seen)
stage stage2_asset_derived_context {
    $asset.graph.metadata.source_type = "DERIVED_CONTEXT"
    $asset.graph.metadata.entity_type = "ASSET"
    $asset.graph.entity.asset.hostname = $host
    $host != ""

  match:
    $host

  outcome:
    $first_seen_ts = min($asset.graph.entity.asset.first_seen_time.seconds)
}

// Root Stage: Fuse Host Outbound Byte Z-Score with Young Asset Age Multiplier
$host = $stage1_asset_baseline.host
$host = $stage2_asset_derived_context.host

match:
  $host by 1d

outcome:
  $observed = max($stage1_asset_baseline.observed_val)
  $mean = max($stage1_asset_baseline.hist_mean)
  $stddev = max($stage1_asset_baseline.hist_stddev)
  $safe_stddev = if($stddev > 44979.0, $stddev, 44979.0)
  $z_score = ($observed - $mean) / $safe_stddev
  $active_days = max($stage1_asset_baseline.hist_active_days)
  $active_baseline_days = $active_days

  $first_seen = min($stage2_asset_derived_context.first_seen_ts)
  $obs_ts = max($stage1_asset_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $asset_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Young/Infant Asset Multiplier: 2.5x if <= 7d, 1.5x if <= 14d (disabled when first_seen_time = 0)
  $ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)
  $is_infant_asset = if($first_seen > 0 and $asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $is_young_asset = if($first_seen > 0 and $asset_age_days <= 14.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $young_mult = if($is_young_asset = 1.0, 1.5, 1.0)
  $threat_multiplier = if($is_infant_asset = 1.0, 2.5, $young_mult)
  $threat_score = $z_score * $threat_multiplier

condition:
  $active_days >= 7
  and $z_score >= 3.0
  and $asset_age_days <= 14.0

order:
  $threat_score desc
```

#### Query 3B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Outbound Network Connection Bursts (`secops-statistical-hunter`)
Executes in **Wave 2** strictly on candidate endpoints surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`). Over a 24-hour (`by 1h`) window (`23.0` prior hourly buckets), it updates a $\text{Gamma}(\alpha_0 = 2.0, \beta_0 = 2.0)$ prior using leave-one-out prior hourly counts and adds empirical excess overdispersion $\max(0, E[X^2]_{\text{prior}} - \mu_{\text{prior}}^2 - \mu_{\text{prior}})$, shrinking routine bursty workloads while surfacing acute hourly outbound connection spikes (`$bayesian_z >= 3.0`, `$observation_count >= 15`, `$baseline_active_samples >= 6`). Fleet breadth is not computed in this candidate-gated query and is emitted as the `-1` sentinel (`0 - 1`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect hourly outbound network connection bursts on candidate endpoints from Query 3A via Leave-One-Out Conjugate Gamma-Poisson Predictive Standardization.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Gamma-Poisson Predictive Z-Score with Excess Overdispersion (BAYESIAN_GAMMA_SHRINKAGE)
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_3a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_3a_z = max(security_result.confidence_score)
}

stage host_hourly_activity {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_exts = count_distinct(target.ip)
}

stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly_activity.hourly_count)
    $sum_x2 = sum($host_hourly_activity.hourly_count_sq)
    $active_hours = count($host_hourly_activity.window_start)
}

$host = $stage1_upstream_3a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_hourly_activity.distinct_exts)

  // Leave-One-Out Conjugate Gamma(2.0, 2.0) Prior & Excess Overdispersion across 23 prior hourly buckets
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 2.0 + $prior_sum
  $beta_prior = 25.0
  $baseline_mean = $alpha_prior / $beta_prior
  $prior_emp_mean = 1.0 * $prior_sum / 23.0
  $raw_excess_var = (1.0 * $prior_sum_sq / 23.0) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * ($beta_prior + 1.0) / $beta_prior) + $excess_var
  $safe_pred_var = if($raw_pred_var > 1.0, $raw_pred_var, 1.0)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $bayesian_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $z_score = $bayesian_z

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 15
  and $bayesian_z >= 3.0

order:
  $bayesian_z desc
```

---

### Scenario 4: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual domain, file, or IP indicator matches evaluated independently.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct upstream behavioral scenarios in the current run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$) and pivots winning entities directly into per-sector raw endpoint and network telemetry.

**Scenario 4 (`Query 4`)** executes in **Wave 3** after all **Wave 1** and **Wave 2** queries have written their findings into Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across Scenarios 1–3 (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, requiring `$distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) and summed squared Z-scores `$capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Fused Per-Sector Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates per-sector raw event counts (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `NETWORK_DNS`, `NETWORK_HTTP`, `USER_LOGIN`) using explicit conditional sums alongside process paths, target domains, and outbound bytes.

#### Query 4: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Non-Prioritized IOC Matching scenarios (1A through 3B) via UDM Loopback regex union while joining per-sector raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Fused Sector Raw Telemetry Bridge
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.ip[0])
    $entity != ""
    $run_id != ""
    // Optional custom watchlist Data Table filter (commented out; unpopulated tables break compilation):
    // $entity in %non_prioritized_ioc_watchlist.entity_id

  match:
    $entity, $scenario_tag

  outcome:
    $scenario_z = max(security_result.confidence_score)
    $scenario_z_sq = max(security_result.confidence_score) * max(security_result.confidence_score)
    $scenario_hits = count(metadata.id)
    $run_ids = array_distinct(metadata.product_log_id)
}

stage stage2_multi_scenario_rollup {
    $entity = $stage1_per_scenario_dedup.entity

  match:
    $entity

  outcome:
    $distinct_scenarios_matched = count_distinct($stage1_per_scenario_dedup.scenario_tag)
    $matched_scenario_tags = array_distinct($stage1_per_scenario_dedup.scenario_tag)
    $correlated_run_ids = array_distinct($stage1_per_scenario_dedup.run_ids)
    $total_loopback_matches = sum($stage1_per_scenario_dedup.scenario_hits)
    $peak_scenario_z = max($stage1_per_scenario_dedup.scenario_z)
    $capstone_threat_norm_sq = sum($stage1_per_scenario_dedup.scenario_z_sq)
}

stage stage3_raw_forensic_pivot {
    (
        metadata.event_type = "PROCESS_LAUNCH" or
        metadata.event_type = "NETWORK_CONNECTION" or
        metadata.event_type = "NETWORK_DNS" or
        metadata.event_type = "NETWORK_HTTP" or
        metadata.event_type = "USER_LOGIN"
    )
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.ip[0])
    $entity != ""

  match:
    $entity

  outcome:
    $raw_event_count = count(metadata.id)
    $process_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $network_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $dns_events = sum(if(metadata.event_type = "NETWORK_DNS", 1, 0))
    $http_events = sum(if(metadata.event_type = "NETWORK_HTTP", 1, 0))
    $login_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
    $distinct_event_types = count_distinct(metadata.event_type)
    $sample_processes = array_distinct(target.process.file.full_path)
    $sample_domains = array_distinct(target.hostname)
    $total_sent_bytes = sum(network.sent_bytes)
}

$entity = $stage2_multi_scenario_rollup.entity
$entity = $stage3_raw_forensic_pivot.entity

match:
  $entity

outcome:
  $distinct_scenarios_matched = max($stage2_multi_scenario_rollup.distinct_scenarios_matched)
  $matched_scenario_tags = array_distinct($stage2_multi_scenario_rollup.matched_scenario_tags)
  $correlated_run_ids = array_distinct($stage2_multi_scenario_rollup.correlated_run_ids)
  $total_loopback_matches = max($stage2_multi_scenario_rollup.total_loopback_matches)
  $peak_scenario_z = max($stage2_multi_scenario_rollup.peak_scenario_z)
  $capstone_threat_norm_sq = max($stage2_multi_scenario_rollup.capstone_threat_norm_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $dns_events = max($stage3_raw_forensic_pivot.dns_events)
  $http_events = max($stage3_raw_forensic_pivot.http_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_domains = array_distinct($stage3_raw_forensic_pivot.sample_domains)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

  $unified_threat_score = $capstone_threat_score + math.log($raw_event_count + 1)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $unified_threat_score desc
```

---

## 3. 4-Stage Non-Parametric Quantile/Bowley Skewness Egress Fence + Rare Domain Sieve

To surface outbound byte surges to rare external domains (`DERIVED_CONTEXT` `DOMAIN_NAME` `day_count = 10`, `rolling_max <= 3`) even when a host's 30-day `metrics.network_bytes_outbound` mean and standard deviation are inflated by historical bulk transfers, this 4-stage pipeline computes each host's empirical quartile envelope (`window.percentile` 25/50/75) in `quantile_envelope`, applies the Hubert-Vandervieren Skewness-Adjusted Tukey Upper Fence ($Q_{75} + 1.5 \cdot e^{1.35 \cdot \max(0, S_{\text{Bowley}})} \cdot \text{IQR}_{\text{safe}}$), and standardizes the breach above the fence into robust Gaussian scale units (`$tukey_excess_z = ($observed - $adj_upper_fence) / ($safe_iqr / 1.349) >= 1.0`) alongside a $44,979\text{-byte}$ floored 30-day `$personal_z` cross-check. Run over a multi-day baseline window (`>= 7` active days) with `$in_scoring_window = 1` pinning scored output buckets to Mode A day `D` (`2026-10-29`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Hunt for daily outbound byte surges to rare external domains (10-day rolling_max <= 3 hosts) that breach the Hubert-Vandervieren Skewness-Adjusted Tukey Fence.
// Statistical Model: 4-Stage Non-Parametric Quantile/Bowley Skewness Fence (tukey_excess_z >= 1.0, Bowley factor 1.35) + DERIVED_CONTEXT Rare Domain Sieve
// Skill: secops-risk-metrics-multistage
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional custom non-prioritized domain IOC Data Table filter (commented out; unpopulated tables break compilation):
    // $domain in %non_prioritized_ioc_domains.domain

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29", 1, 0))
    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
}

stage quantile_envelope {
    $host = $stage1_extract.host

  match:
    $host

  outcome:
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

stage stage3_rare_domain {
    $g.graph.metadata.entity_type = "DOMAIN_NAME"
    $g.graph.metadata.source_type = "DERIVED_CONTEXT"
    $g.graph.entity.domain.name = $domain
    $domain != ""
    $g.graph.entity.domain.prevalence.day_count = 10
    $g.graph.entity.domain.prevalence.rolling_max > 0
    $g.graph.entity.domain.prevalence.rolling_max <= 3

  match:
    $domain

  outcome:
    $domain_prevalence = min($g.graph.entity.domain.prevalence.rolling_max)
}

$host = $stage1_extract.host
$host = $quantile_envelope.host
$domain = $stage1_extract.domain
$domain = $stage3_rare_domain.domain
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $observed = sum($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)
  $min_domain_prevalence = min($stage3_rare_domain.domain_prevalence)
  $rare_domains = array_distinct($domain)

  $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  $iqr = $q75_val - $q25_val
  $q50_floor = $q50_val * 0.05 + 1.0
  $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $pos_skew = if($bowley_skew > 0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
  $robust_scale = $safe_iqr / 1.349
  $tukey_excess_z = ($observed - $adj_upper_fence) / $robust_scale

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0

order:
  $tukey_excess_z desc
```

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
