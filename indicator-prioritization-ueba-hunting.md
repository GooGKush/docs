# Extending Applied Threat Intelligence (ATI) Indicator Prioritization with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Applied Threat Intelligence (ATI) Curated Prioritization** suite enriches host, network, and authentication telemetry with Google Threat Intelligence (GTI) and Mandiant breach prioritization—surfacing matches against high-confidence active-breach and high-priority indicators of compromise (IoCs).

Because threat actors frequently deploy freshly compiled binaries, newly registered domains, or short-lived proxy infrastructure before static indicator feeds catalog them, this runbook supplements ATI indicator matching with **Behavioral Rarity, Prevalence, and Baseline Fusion** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). Rather than relying solely on known IoC reputation, these queries evaluate 30-day `metrics.*` behavioral baselines (with a 7-active-day maturity gate and continuous count/byte dispersion floors), 10-day `DERIVED_CONTEXT` organizational prevalence (`day_count = 10`, `rolling_max <= 3`), event-relative `GLOBAL_CONTEXT` WHOIS domain lifecycle age, stateless outbound flow-gap ratio regularity (`FLOW_GAP_RATIO_SCREEN`), Leave-One-Out Beta-Binomial authentication failure-rate standardization, and intraday network connection burst Z-scores (`BURST_Z_SCREEN`). Queries emit Z and Z-equivalent anomaly scores directly; Composite Risk Index (`CRI` in `[0, 100]`) is computed downstream in Python by `agentic_ueba` (`ueba_constants.calculate_cri`).

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba` (configured with `<PROJECT_ID>` and `<CUSTOMER_ID>`):
  1. **Wave 1 — Upstream Macro Baselines, Entity Graph Prevalence & Fleet Rarity (`6 Queries`)**: Executes all `by 1d` 30-day `metrics.*` baselines (`Queries 1A, 2A, 3A, 4A`), raw host-prevalence Zipfian binary rarity (`Query 1B`), and the Section 4 Skewness-Adjusted Tukey Fence rare-domain query concurrently. In Mode A (scoring the last complete UTC day `D`), Entity Graph (`DERIVED_CONTEXT` / `GLOBAL_CONTEXT`) queries run over `[D-2, D+1)` so daily lagged graph records join cleanly while event stages pin `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"` to `D`. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Micro Queries (`3 Queries`, `Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries (`Queries 2B, 3B, 4B`) read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw flow-gap dispersion, Leave-One-Out Beta-Binomial failure standardization, and Leave-One-Out connection burst Z-scores without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, enforces cross-scenario Euclidean $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`, matching `LOOPBACK_MIN_DISTINCT_HITS = 2` and `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD = 25.0`) in Stage 2, and pivots winning entities directly into per-sector raw endpoint, network, cloud, and authentication telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Applied Threat Intelligence (ATI) Curated Prioritization & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Host Binary Execution Prioritization & Novel Payloads** | Prioritizes process and file events matching high-confidence GTI file hashes and breach indicators. | Pairs 30-day per-(host, SHA256) execution Z-scores (`metrics.file_executions_total`, $\ge 7$ active days) filtered by 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`) with raw fleetwide host-prevalence Zipfian IDF rarity ($\ln(N_{\text{fleet}} / N_{\text{adopters}}) \ge 2.5$, $\le 2$ hosts) for unindexed Day-0 binaries. | `Query 1A` (30d Execution Z + 10d File Prevalence)<br>`Query 1B` (Host-Prevalence Zipfian Rarity) |
| **2. Network C2, Ephemeral Domains & Callback Regularity** | Matches outbound DNS and network connections against prioritized GTI domain and IP indicators. | Weights 30-day per-(host, domain) HTTP query Z-scores (`metrics.http_queries_total`) by event-relative WHOIS domain registration/expiration status (`2.5x` NRD $\le 30\text{d}$, `3.0x` expired) and screens `Query 2A` candidate hosts for uniform hourly outbound flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$). | `Query 2A` (30d HTTP Z + WHOIS Lifecycle)<br>`Query 2B` (UDM-Gated Flow-Gap Ratio Screen) |
| **3. Inbound Authentication Brute-Force & Breach Convergence** | Flags authentication events originating from known malicious or Tor/proxy IP indicators. | Fuses 30-day failed (`metrics.auth_attempts_fail`) and successful (`metrics.auth_attempts_success`) login Z-scores in a single-stage conditional union ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$) and evaluates `Query 3A` candidate users with Leave-One-Out Beta-Binomial predictive failure Z-scores ($Z_{\text{fail}} \ge 3.0\sigma$). | `Query 3A` (Dual-Sector Auth Fail + Success Fusion)<br>`Query 3B` (UDM-Gated Beta-Binomial Failure Z) |
| **4. Rare Domain C2 & Intraday Network Connection Surges** | Correlates prioritized indicator hits with subsequent host or network activity. | Pairs 30-day per-(host, domain) HTTP query Z-scores filtered by 10-day `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3` hosts) with UDM-gated Leave-One-Out hourly outbound connection burst Z-scores (`BURST_Z_SCREEN`, $Z_{\text{burst}} \ge 3.0\sigma$) on `Query 4A` candidate hosts. | `Query 4A` (30d HTTP Z + 10d Domain Prevalence)<br>`Query 4B` (UDM-Gated Hourly Burst Z Screen) |
| **5. Capstone Multi-Scenario ATI Entity Convergence** | Point-in-time indicator matches evaluated per event. | Correlates entities matching $\ge 2$ distinct behavioral prioritization queries within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean squared norm ($\sum Z_i^2 \ge 25.0$) and bridges directly to raw per-domain telemetry. | `Query 5` (UDM Loopback $L_2$ Convergence + Raw Bridge) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Host Binary Execution Prioritization Beyond Static GTI Hash Hits

* **Curated Detection Operational Focus**: Prioritizes process and file events matching high-confidence GTI file hashes and breach indicators.
* **How Multi-Stage UEBA Extends Coverage**: Pairs a 30-day per-(host, SHA256) execution Z-score (`metrics.file_executions_total`) joined with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`) in `Query 1A` with raw fleetwide host-prevalence Zipfian inverse document frequency ($\ln(N_{\text{fleet}} / N_{\text{adopters}}) \ge 2.5$) in `Query 1B`.

#### Query 1A: 2-Stage Hybrid 30-Day File Execution Baseline + Entity Context Graph Binary Prevalence (`secops-risk-metrics-multistage`)
Scores per-(host, SHA256) process execution counts on Mode A day `D` (`"2026-10-29"`) against the 30-day `metrics.file_executions_total` baseline using the continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ and a 7-active-day maturity gate (`$active_baseline_days >= 7`), then inner-joins `DERIVED_CONTEXT` 10-day organizational file prevalence (`day_count = 10`, `rolling_max <= 3`). Run over `[D-2, D+1)` (`startTime = D-2 T00:00:00Z`, `endTime = D+1 T00:00:00Z`) so lagged daily Entity Graph records overlap the search window. Because `stage2_file_derived_context` is an inner join and `$active_baseline_days >= 7` enforces baseline maturity, `Query 1A` isolates established rare binaries ($\le 3$ hosts enterprise-wide) experiencing acute execution surges ($Z \ge 3.0\sigma$), while brand-new Day-0 binaries absent from `DERIVED_CONTEXT` are covered by `Query 1B`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution surges (Z >= 3.0) of organizationally isolated binaries (10-day DERIVED_CONTEXT rolling_max <= 3 hosts) relative to mature 30-day per-(host, sha256) baselines.
// Statistical Model: 2-Stage Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day Binary Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline per (host, sha256) on Mode A day D
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    principal.process.file.sha256 = $sha256
    $host != ""
    $sha256 != ""

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

// Root Stage: Continuous Count Dispersion Floor & Enterprise Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $mean_floor_arg = if($mean_execs > 1.0, $mean_execs, 1.0)
  $dispersion_floor = math.sqrt($mean_floor_arg)
  $safe_stddev = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_stddev
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Guarded novelty boost: 2.5x when valid first_seen_time <= 7d before event; 1.5x for isolated rare binaries
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

#### Query 1B: 4-Stage Host-Prevalence Zipfian Inverse Document Frequency Binary Rarity (`secops-statistical-hunter`)
Catches newly dropped binaries, custom C2 implants, and isolated living-off-the-land utilities executing in the long tail of the active fleet ($\le 2$ adopter hosts across a fleet of $\ge 10$ active hosts) via pure **Host-Prevalence Inverse Document Frequency** ($\text{Zipf Score} = \ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}}) \ge 2.5$) directly over raw `PROCESS_LAUNCH` telemetry—requiring zero prior `GLOBAL_CONTEXT` or `DERIVED_CONTEXT` indexing and avoiding total-event-volume confounding from chatty daemons.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare binary executions in the enterprise Zipfian long tail (<= 2 adopter hosts across >= 10 active fleet hosts) via pure host-prevalence inverse document frequency before GTI indexing.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Host-Prevalence Inverse Document Frequency Rarity (ZIPFIAN_PROCESS_RARITY, zipf_rarity_score = ln(N_fleet_hosts / N_adopter_hosts) >= 2.5)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Endpoint Local Binary Execution Activity
stage endpoint_process_burst {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    principal.asset.hostname = $host
    $binary = target.process.file.full_path
    $host != ""
    $binary != ""

  match:
    $etype, $host, $binary by 1d

  outcome:
    $endpoint_executions = count(metadata.id)
    $sample_commands = array_distinct(target.process.command_line)
}

// Stage 2: Enterprise Fleetwide Binary Adopter Breadth across the Search Window
stage fleet_process_popularity {
    $etype = $endpoint_process_burst.etype
    $binary = $endpoint_process_burst.binary

  match:
    $etype, $binary

  outcome:
    $fleet_hosts = count_distinct($endpoint_process_burst.host)
    $fleet_total_executions = sum($endpoint_process_burst.endpoint_executions)
}

// Stage 3: Total Active Fleet Host Population across the Search Window
stage fleet_host_total {
    $etype = $endpoint_process_burst.etype

  match:
    $etype

  outcome:
    $total_fleet_hosts = count_distinct($endpoint_process_burst.host)
}

// Root Stage: Host-Prevalence Zipfian Rarity Scoring
$etype = $endpoint_process_burst.etype
$etype = $fleet_process_popularity.etype
$etype = $fleet_host_total.etype
$binary = $endpoint_process_burst.binary
$binary = $fleet_process_popularity.binary
$host = $endpoint_process_burst.host
$ws = $endpoint_process_burst.window_start

match:
  $host, $binary, $ws by 1d

outcome:
  $adopter_hosts = max($fleet_process_popularity.fleet_hosts)
  $fleet_total_hosts = max($fleet_host_total.total_fleet_hosts)
  $local_volume = max($endpoint_process_burst.endpoint_executions)
  $commands = array_distinct($endpoint_process_burst.sample_commands)

  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_fleet_hosts = if($fleet_total_hosts > $safe_hosts, $fleet_total_hosts, $safe_hosts)
  $host_ratio = 1.0 * $safe_fleet_hosts / $safe_hosts
  $zipf_rarity_score = math.log($host_ratio)

  // 6 Core Evidence Pillars
  $observation_count = $local_volume
  $baseline_active_samples = $safe_fleet_hosts
  $baseline_mean = 1.0 * $adopter_hosts / $safe_fleet_hosts
  $baseline_dispersion = $zipf_rarity_score
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = 1

condition:
  $safe_fleet_hosts >= 10
  and $adopter_hosts <= 2
  and $observation_count >= 1
  and $zipf_rarity_score >= 2.5

order:
  $zipf_rarity_score desc
```

---

### Scenario 2: Network C2 & Domain/IP Prioritization

* **Curated Detection Operational Focus**: Matches outbound DNS and network connections against prioritized GTI domain and IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Weights 30-day per-(host, domain) outbound HTTP query Z-scores by event-relative WHOIS domain registration and expiration timestamps in `Query 2A`, then screens `Query 2A` candidate hosts in Wave 2 for uniform hourly outbound flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$) in `Query 2B`.

#### Query 2A: 2-Stage Hybrid 30-Day HTTP Volume + Event-Relative WHOIS Domain Lifecycle Multiplier (`secops-risk-metrics-multistage`)
Pairs per-(host, target_hostname) HTTP request volume on Mode A day `D` (`"2026-10-29"`) with the matching two-dimensional 30-day `metrics.http_queries_total` baseline (enforcing `$active_baseline_days >= 7` and continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$) and `GLOBAL_CONTEXT` WHOIS creation/expiration timestamps anchored strictly to observed event time (`max(metadata.event_timestamp.seconds)`). Newly registered domains ($\le 30\text{d}$ old at event time, guarded against missing `$created = 0`) receive a $2.5\times$ multiplier and expired registrations ($0 < \text{expires} \le \text{obs\_ts}$) receive a $3.0\times$ multiplier. Run over `[D-2, D+1)` so `GLOBAL_CONTEXT` WHOIS records overlap the search window; domains without WHOIS graph records drop out of this inner join and are covered by `DERIVED_CONTEXT` prevalence in `Query 4A` and Section 4.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous per-(host, domain) HTTP query surges (Z >= 3.0) targeting newly registered (<= 30d at event time) or expired WHOIS domains before GTI IOC indexing.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + GLOBAL_CONTEXT WHOIS Domain Lifecycle Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE WHOIS DOMAIN LIFECYCLE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day HTTP Query Baseline per (host, domain) on Mode A day D
stage stage1_egress_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)

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

// Stage 2: Chronicle Global Context WHOIS Lookup (Creation & Expiration Timestamps)
stage stage2_whois_lifecycle {
    $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $whois.graph.metadata.vendor_name = "WHOIS"
    $whois.graph.metadata.entity_type = "DOMAIN_NAME"
    $whois.graph.entity.domain.name = $domain
    $domain != ""

  match:
    $domain

  outcome:
    $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)
    $expiration_ts = min($whois.graph.entity.domain.expiration_time.seconds)
}

// Root Stage: Continuous Count Dispersion Floor & Event-Relative WHOIS Lifecycle Scoring
$host = $stage1_egress_baseline.host
$domain = $stage1_egress_baseline.domain
$domain = $stage2_whois_lifecycle.domain

match:
  $host, $domain by 1d

outcome:
  $observed = max($stage1_egress_baseline.observed_val)
  $mean = max($stage1_egress_baseline.hist_mean)
  $stddev = max($stage1_egress_baseline.hist_stddev)
  $mean_floor_arg = if($mean > 1.0, $mean, 1.0)
  $dispersion_floor = math.sqrt($mean_floor_arg)
  $safe_stddev = if($stddev > $dispersion_floor, $stddev, $dispersion_floor)
  $z_score = ($observed - $mean) / $safe_stddev
  $active_baseline_days = max($stage1_egress_baseline.hist_active_days)

  $obs_ts = max($stage1_egress_baseline.event_timestamp)
  $created = max($stage2_whois_lifecycle.creation_ts)
  $expires = max($stage2_whois_lifecycle.expiration_ts)

  // Event-relative domain age in days (guarded against missing $created = 0)
  $raw_age_days = ($obs_ts - $created) / 86400.0
  $domain_age_days = if($created > 0, $raw_age_days, 9999.0)
  $is_nrd = if($created > 0 and $domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)
  $is_expired = if($expires <= $obs_ts and $expires > 0, 1.0, 0.0)
  $days_to_expiration = ($expires - $obs_ts) / 86400.0

  // Lifecycle Risk Multiplier: 3.0x for expired domains, 2.5x for NRD (<= 30d)
  $nrd_mult = if($is_nrd = 1.0, 2.5, 1.0)
  $whois_multiplier = if($is_expired = 1.0, 3.0, $nrd_mult)
  $fused_threat_score = $z_score * $whois_multiplier

condition:
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and ($is_nrd = 1.0 or $is_expired = 1.0)

order:
  $fused_threat_score desc
```

#### Query 2B: 4-Stage UDM-Gated Outbound Flow-Gap Ratio Regularity Screen (`secops-statistical-hunter`)
Screens candidate hosts surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`) for uniform hourly outbound span-to-count flow-gap ratios ($\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$) across $\ge 6$ active hours and $\ge 25$ external connections (`FLOW_GAP_RATIO_SCREEN`, excluding RFC 1918, loopback, multicast, broadcast, and link-local noise). Because stateless bucketed YARA-L measures cross-bucket dispersion of within-bucket `(max(ts) - min(ts)) / count` ratios rather than consecutive inter-packet $\Delta t$ intervals, exact sub-hour consecutive callback jitter on surfaced pairs can be confirmed post-query via `C2_BEACONING_JITTER` (`micro_python_helpers.py c2-jitter`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED OUTBOUND FLOW-GAP RATIO SCREEN PIPELINE
// Goal: Screen external outbound pairs on candidate hosts from Query 2A for uniform hourly bucket flow-gap ratios (CV <= 0.20 across >= 6 active hours and >= 25 connections).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN, CV = sigma_gap / mu_gap <= 0.20)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_2a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_2a_z = max(security_result.confidence_score)
}

stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 64
    target.ip = $dst_ip
    $dst_ip != ""
    $dst_ip != "::1"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "127.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "224.0.0.0/4")
    not net.ip_in_range_cidr($dst_ip, "169.254.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "255.255.255.255/32")
    not net.ip_in_range_cidr($dst_ip, "fe80::/10")
    not net.ip_in_range_cidr($dst_ip, "ff00::/8")
    $ts = metadata.event_timestamp.seconds

  match:
    $host, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = 1.0 * (max($ts) - min($ts)) / count(metadata.id)
    $hourly_sent = sum(network.sent_bytes)
}

stage timing_stats {
    $host = $host_intervals.host
    $dst_ip = $host_intervals.dst_ip

  match:
    $host, $dst_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $total_sent_bytes = sum($host_intervals.hourly_sent)
    $active_hours = count($host_intervals.window_start)
}

$host = $stage1_upstream_2a_candidates.host
$host = $timing_stats.host
$dst_ip = $timing_stats.dst_ip

match:
  $host, $dst_ip

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($timing_stats.total_conns)
  $total_outbound_bytes = max($timing_stats.total_sent_bytes)

  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $baseline_mean >= 1.0
  and $cv <= 0.20

order:
  $cv asc
```

---

### Scenario 3: Inbound Authentication from Suspicious / Proxy Infrastructure

* **Curated Detection Operational Focus**: Flags authentication events originating from known malicious or Tor/proxy IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Combines a single-stage conditional union of 30-day failed (`metrics.auth_attempts_fail`) and successful (`metrics.auth_attempts_success`) login Z-scores ($D^2 \ge 12.25$) in `Query 3A` with UDM-gated Leave-One-Out Beta-Binomial predictive failure-rate standardization ($Z_{\text{fail}} \ge 3.0\sigma$) in `Query 3B`.

#### Query 3A: 2-Stage Dual-Sector Authentication Failures + Authentication Successes Fusion (`secops-risk-metrics-multistage`)
Addresses the `$blocked = 0` self-suppression constraint in deterministic authentication rules by evaluating both **failed logins (`metrics.auth_attempts_fail`)** and **successful logins (`metrics.auth_attempts_success`)** for each `target.user.userid` inside a single conditional-sum union stage (`sector_union`). Using a single union stage preserves pure brute-force outliers when `ALLOW` events are zero on the scored day, applies continuous count dispersion floors $\max(\sigma, \sqrt{\max(\mu, 1)})$ and 7-active-day maturity gates (`>= 7` active days) independently to each metric, and scores half-rectified squared Euclidean distance `$composite_threat_norm_sq = Z_fail^2 + Z_success^2 >= 12.25`. Note that because `auth_attempts_fail` and `auth_attempts_success` belong to the same `AUTH` telemetry family, correlated login bursts exceed independent $\chi^2_2$ tail rates (`WS7-03`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect inbound brute-force and credential-stuffing attacks culminating in anomalous login failures and/or successes without dropping single-sector outliers.
// Statistical Model: 2-Stage Single-Union Dual-Sector Euclidean Risk Fusion (metrics.auth_attempts_fail + metrics.auth_attempts_success, D^2 >= 12.25)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (SINGLE-STAGE UNION)
// ADVISORY: Same-family pair (auth_attempts_fail + auth_attempts_success) carries positive inter-sector correlation; composite D^2 >= 12.25 exceeds independent chi^2_2 tail rates (WS7-03).
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Single-Stage Authentication Union (preserves single-sector outliers when companion count = 0)
stage sector_union {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if(not security_result.action = "ALLOW", 1, 0))
    $a_avg = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: target.user.userid
    ))
    $a_std = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: target.user.userid
    ))
    $a_days = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        target.user.userid: target.user.userid
    ))

    $b_obs = sum(if(security_result.action = "ALLOW", 1, 0))
    $b_avg = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: target.user.userid
    ))
    $b_std = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: target.user.userid
    ))
    $b_days = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        target.user.userid: target.user.userid
    ))
}

// Root Stage: Continuous Count Dispersion Floors, 7-Day Maturity Gates & Rectified Euclidean Norm
$entity = $sector_union.entity

match:
  $entity by 1d

outcome:
  $a_observed = max($sector_union.a_obs)
  $a_mean = max($sector_union.a_avg)
  $a_stddev = max($sector_union.a_std)
  $a_active_days = max($sector_union.a_days)
  $a_floor = math.sqrt(if($a_mean > 1.0, $a_mean, 1.0))
  $safe_a_std = if($a_stddev > $a_floor, $a_stddev, $a_floor)
  $z_a_raw = ($a_observed - $a_mean) / $safe_a_std
  $z_a_pos = if($z_a_raw > 0, $z_a_raw, 0.0)
  $z_a = if($a_observed > 0 and $a_active_days >= 7, $z_a_pos, 0.0)

  $b_observed = max($sector_union.b_obs)
  $b_mean = max($sector_union.b_avg)
  $b_stddev = max($sector_union.b_std)
  $b_active_days = max($sector_union.b_days)
  $b_floor = math.sqrt(if($b_mean > 1.0, $b_mean, 1.0))
  $safe_b_std = if($b_stddev > $b_floor, $b_stddev, $b_floor)
  $z_b_raw = ($b_observed - $b_mean) / $safe_b_std
  $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  $composite_threat_norm_sq = ($z_a * $z_a) + ($z_b * $z_b)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 3B: 4-Stage UDM-Gated Leave-One-Out Beta-Binomial Authentication Failure Rate (`secops-statistical-hunter`)
Evaluates hourly authentication failure surges on candidate identities surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`) using **Leave-One-Out Conjugate Beta-Binomial Updating**. Updates a $\text{Beta}(1.0, 19.0)$ hyperprior ($\approx 5\%$ baseline failure rate) with each user's leave-one-out prior failures and successes across the window, then standardizes each hour's failure count against exact Beta-Binomial predictive variance $n p_0 (1 - p_0) \frac{M + n}{M + 1}$ (`$fail_z >= 3.0`), suppressing service accounts with chronically noisy credentials while surfacing sudden credential-stuffing bursts on clean accounts.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT BETA-BINOMIAL FAILURE STANDARDIZATION PIPELINE
// Goal: Detect hourly credential-stuffing and brute-force failure-rate surges (fail_z >= 3.0) on candidate identities from Query 3A via Leave-One-Out Beta-Binomial predictive variance.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Beta-Binomial Predictive Failure Z-Score (BETA_BINOMIAL_FAILURE, fail_z >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_3a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)
    $user = strings.coalesce(principal.user.userid, target.user.userid, principal.asset.hostname)
    $user != ""
    $run_id != ""

  match:
    $user

  outcome:
    $upstream_3a_z = max(security_result.confidence_score)
}

stage entity_hourly_trials {
    metadata.event_type = "USER_LOGIN"
    $user = strings.coalesce(target.user.userid, principal.user.userid)
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count(metadata.id)
    $failed_trials = sum(if(security_result.action = "BLOCK" or security_result.action = "FAIL", 1, 0))
    $distinct_sources = count_distinct(principal.ip)
}

stage entity_historical_rates {
    $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

$user = $stage1_upstream_3a_candidates.user
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
  $observation_count = max($entity_hourly_trials.failed_trials)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Leave-One-Out Beta(1.0, 19.0) Prior & Exact Beta-Binomial Predictive Standardization
  $raw_prior_fails = max($entity_historical_rates.total_historical_fails) - $observation_count
  $prior_fails = if($raw_prior_fails > 0, $raw_prior_fails, 0)
  $raw_prior_events = max($entity_historical_rates.total_historical_events) - $hourly_trials_count
  $prior_events = if($raw_prior_events > $prior_fails, $raw_prior_events, $prior_fails)
  $alpha_prior = 1.0 + $prior_fails
  $beta_prior = 19.0 + ($prior_events - $prior_fails)
  $prior_total = $alpha_prior + $beta_prior
  $baseline_mean = $alpha_prior / $prior_total
  $posterior_fail_prob = ($alpha_prior + $observation_count) / ($prior_total + $safe_trials)
  $pred_var = $safe_trials * $baseline_mean * (1.0 - $baseline_mean) * (($prior_total + $safe_trials) / ($prior_total + 1.0))
  $safe_pred_var = if($pred_var > 0.25, $pred_var, 0.25)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $fail_z = ($observation_count - ($safe_trials * $baseline_mean)) / $baseline_dispersion

condition:
  $baseline_active_samples >= 6
  and $hourly_trials_count >= 15
  and $observation_count >= 8
  and $fail_z >= 3.0

order:
  $fail_z desc
```

---

### Scenario 4: ATI Composite Breach Escalation & Rare-Domain Network Surges

* **Curated Detection Operational Focus**: Correlates prioritized indicator hits with subsequent host or network activity.
* **How Multi-Stage UEBA Extends Coverage**: Pairs 30-day per-(host, domain) HTTP query Z-scores filtered by 10-day `DERIVED_CONTEXT` organizational domain prevalence (`rolling_max <= 3`) in `Query 4A` with UDM-gated Leave-One-Out hourly outbound network connection burst Z-scores (`BURST_Z_SCREEN`, $Z_{\text{burst}} \ge 3.0\sigma$) on `Query 4A` candidate hosts in `Query 4B`.

#### Query 4A: 2-Stage Hybrid 30-Day HTTP Volume + Entity Context Graph 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Replaces static `GTI_IOC` domain anchors with 10-day rolling `DERIVED_CONTEXT` organizational domain prevalence (`day_count = 10`, `rolling_max <= 3`) joined against each `(principal.asset.hostname, target.hostname)` pair's 30-day `metrics.http_queries_total` baseline (with continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ and `$active_baseline_days >= 7`). Run over `[D-2, D+1)` with Stage 1 pinned to Mode A day `"2026-10-29"`; note that `stage2_domain_derived_context` is an inner join, so domains absent from `DERIVED_CONTEXT` drop out rather than scoring as rare.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect per-(host, domain) HTTP communication surges (Z >= 3.0) targeting organizationally rare domains (10-day DERIVED_CONTEXT rolling_max <= 3 hosts) without requiring a prior GTI IOC match.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Destination HTTP Query Baseline per (host, domain) on Mode A day D
stage stage1_query_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)

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

// Root Stage: Continuous Count Dispersion Floor & Enterprise Domain Prevalence Multiplier
$host = $stage1_query_baseline.host
$domain = $stage1_query_baseline.domain
$domain = $stage2_domain_derived_context.domain

match:
  $host, $domain by 1d

outcome:
  $observed_queries = max($stage1_query_baseline.observed_val)
  $mean_queries = max($stage1_query_baseline.hist_mean)
  $stddev_queries = max($stage1_query_baseline.hist_stddev)
  $mean_floor_arg = if($mean_queries > 1.0, $mean_queries, 1.0)
  $dispersion_floor = math.sqrt($mean_floor_arg)
  $safe_stddev = if($stddev_queries > $dispersion_floor, $stddev_queries, $dispersion_floor)
  $z_score = ($observed_queries - $mean_queries) / $safe_stddev
  $active_baseline_days = max($stage1_query_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_domain_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_domain_derived_context.enterprise_day_count)
  $first_seen = min($stage2_domain_derived_context.first_seen_ts)
  $obs_ts = max($stage1_query_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $domain_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Guarded novelty boost: 2.5x when valid first_seen_time <= 7d before event; 1.5x for rare <= 3 hosts
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

#### Query 4B: 4-Stage UDM-Gated Leave-One-Out Hourly Network Connection Burst Z (`secops-statistical-hunter`)
Evaluates acute intraday outbound `NETWORK_CONNECTION` rate bursts on candidate hosts surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`). Scores each hourly bucket out-of-sample against the host's Leave-One-Out mean $\mu_{-t}$ and sample standard deviation $s_{-t}$ floored at $\sqrt{\max(\mu_{-t}, 1.0)}$ (`BURST_Z_SCREEN`, `$burst_z >= 3.0` across $\ge 6$ prior active hourly samples and $\ge 25$ connections). True recursive lag EWMA smoothing can be run post-query via `EWMA_BURST_VELOCITY` (`micro_python_helpers.py ewma`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT HOURLY NETWORK BURST Z PIPELINE
// Goal: Detect acute hourly outbound network connection bursts (burst_z >= 3.0) on candidate hosts from Query 4A using Leave-One-Out out-of-sample standardization.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Intraday Burst Z (BURST_Z_SCREEN, burst_z >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_4a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_4a_z = max(security_result.confidence_score)
}

stage entity_baseline {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $window_events = count(metadata.id)
    $window_events_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.ip)
}

stage entity_historical_stats {
    $host = $entity_baseline.host

  match:
    $host

  outcome:
    $sum_x = sum($entity_baseline.window_events)
    $sum_x2 = sum($entity_baseline.window_events_sq)
    $active_windows = count($entity_baseline.window_start)
}

$host = $stage1_upstream_4a_candidates.host
$host = $entity_baseline.host
$host = $entity_historical_stats.host
$ws = $entity_baseline.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_4a_candidates.upstream_4a_z)
  $observation_count = max($entity_baseline.window_events)
  $baseline_active_samples = max($entity_historical_stats.active_windows) - 1
  $safe_n_prior = if($baseline_active_samples > 1, $baseline_active_samples, 1)
  $loo_sum = max($entity_historical_stats.sum_x) - $observation_count
  $baseline_mean = 1.0 * $loo_sum / $safe_n_prior
  $df = $baseline_active_samples - 1
  $safe_df = if($df > 1, $df, 1)
  $raw_ss = (max($entity_historical_stats.sum_x2) - (1.0 * $observation_count * $observation_count)) - ((1.0 * $loo_sum * $loo_sum) / $safe_n_prior)
  $pos_ss = if($raw_ss > 0.0, $raw_ss, 0.0)
  $loo_sd = math.sqrt($pos_ss / $safe_df)
  $floor_arg = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $poisson_floor = math.sqrt($floor_arg)
  $baseline_dispersion = if($loo_sd > $poisson_floor, $loo_sd, $poisson_floor)
  $burst_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $velocity_score = $burst_z
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_baseline.distinct_targets)

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $burst_z >= 3.0

order:
  $burst_z desc
```

---

### Scenario 5: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Point-in-time indicator matches evaluated per event.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral prioritization queries within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean squared risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–4 can fire inside ambiguous regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific resource names.

**Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and fleet-rarity queries) and **Wave 2** (UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 4 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`, `LOOPBACK_MIN_DISTINCT_HITS`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 25.0`, `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Separated Per-Sector Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates per-sector conditional event counts (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ` / `USER_RESOURCE_ACCESS`, `USER_LOGIN`) and concrete forensic artifacts by `$entity`, joining them with Stage 2 in Root.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Scenarios 1 through 4B via UDM Loopback regex token union while joining per-sector raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.ip[0])
    $entity != ""
    $run_id != ""

  match:
    $entity, $scenario_tag

  outcome:
    $scenario_z = max(security_result.confidence_score)
    $scenario_cri = max(security_result.risk_score)
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
    $peak_scenario_cri = max($stage1_per_scenario_dedup.scenario_cri)
    $capstone_threat_norm_sq = sum($stage1_per_scenario_dedup.scenario_z_sq)
}

stage stage3_raw_forensic_pivot {
    (
        metadata.event_type = "PROCESS_LAUNCH" or
        metadata.event_type = "NETWORK_CONNECTION" or
        metadata.event_type = "RESOURCE_READ" or
        metadata.event_type = "USER_RESOURCE_ACCESS" or
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
    $cloud_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $auth_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
    $distinct_event_types = count_distinct(metadata.event_type)
    $sample_processes = array_distinct(target.process.file.full_path)
    $sample_resources = array_distinct(target.resource.name)
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
  $peak_scenario_cri = max($stage2_multi_scenario_rollup.peak_scenario_cri)
  $capstone_threat_norm_sq = max($stage2_multi_scenario_rollup.capstone_threat_norm_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $cloud_events = max($stage3_raw_forensic_pivot.cloud_events)
  $auth_events = max($stage3_raw_forensic_pivot.auth_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
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

## 4. Non-Parametric Quantile & Skewness-Adjusted Tukey Fence Prioritization for Rare Domains

When prioritizing outbound byte transfers from hosts whose parametric baseline is distorted by right-skewed backup or software-distribution spikes ($B_{\text{skew}} > 0$), `stage quantile_envelope` computes a 5-point per-destination daily byte quantile envelope (`$p10, $q25, $q50, $q75, $p90`) and pre-scoring sample statistics (with the `44979.0`-byte `network_bytes_outbound` fleet dispersion floor) in a single stage, leaving stage budget to inner-join 10-day `DERIVED_CONTEXT` rare domain prevalence (`day_count = 10`, `rolling_max <= 3`) in `stage3_rare_domain`. In production, run over a 14-day window `[D-14, D+1)` so at least 7 active days populate `quantile_envelope` while `$in_scoring_window` pins scored `(host, domain)` rows to Mode A day `D` (`"2026-10-29"`), firing when Hubert–Vandervieren (`Bowley 1.35`) robust scale-excess `$tukey_excess_z >= 1.0`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect skewed daily outbound byte surges to organizationally rare domains (10-day DERIVED_CONTEXT rolling_max <= 3 hosts) exceeding the Hubert-Vandervieren skewness-adjusted Tukey upper fence.
// Statistical Model: 4-Stage Non-Parametric Quantile Envelope + Hubert-Vandervieren Bowley-1.35 Tukey Scale-Excess (tukey_excess_z >= 1.0) + DERIVED_CONTEXT 10-Day Domain Prevalence
// ARCHITECTURE: 4-STAGE QUANTILE / BOWLEY SKEWNESS EGRESS FENCE + DERIVED_CONTEXT RARE DOMAIN SIEVE
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

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = 1.0 * sum(network.sent_bytes)
    $observed_val_sq = (1.0 * sum(network.sent_bytes)) * (1.0 * sum(network.sent_bytes))
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29", 1, 0))
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

stage quantile_envelope {
    $host = $stage1_extract.host

  match:
    $host

  outcome:
    $p10 = window.percentile($stage1_extract.observed_val, 10)
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $p90 = window.percentile($stage1_extract.observed_val, 90)
    $raw_active_days = count_distinct($stage1_extract.window_start)
    $pre_n = sum(if($stage1_extract.in_scoring_window = 0, 1, 0))
    $pre_sum = sum(if($stage1_extract.in_scoring_window = 0, $stage1_extract.observed_val, 0.0))
    $pre_sum_sq = sum(if($stage1_extract.in_scoring_window = 0, $stage1_extract.observed_val_sq, 0.0))
    $historical_active_days = max($stage1_extract.historical_active_days)
    $safe_pre_n = if($pre_n > 0, $pre_n, 1)
    $pre_avg = 1.0 * $pre_sum / $safe_pre_n
    $pre_df_raw = $pre_n - 1
    $safe_pre_df = if($pre_n > 1, $pre_df_raw, 1)
    $raw_var_num = $pre_sum_sq - (1.0 * $pre_n * $pre_avg * $pre_avg)
    $pos_var_num = if($raw_var_num > 0.0, $raw_var_num, 0.0)
    $pre_sd = math.sqrt($pos_var_num / $safe_pre_df)
    $safe_pre_sd = if($pre_sd > 44979.0, $pre_sd, 44979.0)
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
  $host, $domain, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($quantile_envelope.pre_avg)
  $pre_samples = max($quantile_envelope.pre_n)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)
  $domain_prevalence = min($stage3_rare_domain.domain_prevalence)

  // Pre-scoring sample Z cross-check with 44,979-byte network_bytes_outbound dispersion floor
  $safe_stddev = max($quantile_envelope.safe_pre_sd)
  $raw_pre_z = ($observed - $hist_avg) / $safe_stddev
  $pre_scoring_z = if($pre_samples >= 7, $raw_pre_z, 0.0)

  // Non-Parametric IQR, Bowley Quartile Skewness & Hubert-Vandervieren (1.35) Scale-Excess
  $iqr = $q75_val - $q25_val
  $q50_floor = $q50_val * 0.05 + 1.0
  $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $pos_skew = if($bowley_skew > 0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
  $tukey_excess_z = ($observed - $adj_upper_fence) / ($safe_iqr / 1.349)
  $z_score = $tukey_excess_z

condition:
  $in_scoring_window = 1
  and $raw_active_days >= 7
  and $tukey_excess_z >= 1.0

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
