# Cross-Vendor Alert Normalization & Behavioral Triage with Multi-Stage Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Third-Party Vendor Alerts** curated suite provides multi-vendor alert normalization across 40+ endpoint (EDR/XDR), identity protection (IDP), email threat prevention, SASE/web proxy, DLP, cloud security, and OT/mobile security integrations.

When organizations operate heterogeneous security stacks, individual vendor alerts often fire in isolation with static vendor-assigned severities. This runbook layers **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` on the 30-day `metrics.*` macro plane and `secops-statistical-hunter` on the bounded raw-event micro plane) over multi-vendor alert streams—applying 10-day `DERIVED_CONTEXT` binary and domain prevalence (`rolling_max <= 3`), Leave-One-Out Conjugate Gamma-Poisson alert shrinkage, 3-Metric Workspace/Identity Part-of-the-Whole triads, Leave-One-Out Beta-Binomial authentication failure standardization, Cross-Bucket Flow-Gap Ratio dispersion screening, 4-stage Non-Parametric Median Absolute Deviation (MAD), 3-stage Windowed Slack Sum multi-day byte drift, and Cross-Vendor UDM Loopback Capstone correlation. Calibrated Risk Index (`CRI`) values (`0–100`) are computed in Python by `agentic_ueba` (`ueba_constants.calculate_cri`); every query emits Z-scores or Z-equivalent model scores directly.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond single-stage window constraints through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba`:
  1. **Wave 1 — Upstream Macro Baselines, Entity Graph Prevalence & Bounded Raw MAD (`Queries 1A, 2A, 3A, 4A, 4B`)**: Executes `by 1d` 30-day `metrics.*` baselines (enforcing the 7-active-day maturity gate, continuous Poisson count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$, and empirical fleet byte dispersion floor `44,979.0` B on `metrics.network_bytes_outbound`), Mode A Entity Context Graph (`DERIVED_CONTEXT`) prevalence joins (`startTime = D-2`, event stages pinned to scored UTC day `D` via `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"`), and bounded ($\le 14\text{d}$) 4-stage raw MAD queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Micro Queries (`Queries 1B, 2B, 3B` — Option 3 Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound hourly (`by 1h`) raw Empirical Bayes alert shrinkage, Beta-Binomial failure standardization, and flow-gap ratio dispersion calculations without risking enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`) in Stage 2, and pivots winning entities directly into partitioned raw endpoint, network, cloud, and authentication telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Third-Party Vendor Alerts & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Multi-Vendor Endpoint & XDR Alert Triage** | Normalizes endpoint and XDR alert streams across diverse endpoint security agents. | Pairs 30-day per-host binary execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` file prevalence (`rolling_max <= 3` hosts) in Wave 1, then applies Leave-One-Out Conjugate Gamma-Poisson alert shrinkage on `Query 1A` candidate hosts in Wave 2. | `Query 1A` (30d File Execution Z + 10d `DERIVED_CONTEXT` Prevalence)<br>`Query 1B` (UDM-Gated Gamma-Poisson Alert Shrinkage) |
| **2. Identity Protection (IDP) & Email Threat Prevention Alerts** | Ingests identity risk and phishing/email delivery alerts from IDP and secure email gateways. | Scores every user across the 3-Metric Workspace Activity Triad (`workspace_auth_attempts_total`, `workspace_total_download_actions`, `workspace_total_change_actions`) using Leave-One-Out fleet Z-scores ($D_{\text{vs fleet}}^2 \ge 12.25$) in Wave 1, then applies Leave-One-Out Beta-Binomial authentication failure standardization on `Query 2A` candidate users in Wave 2. | `Query 2A` (3-Metric Workspace Activity Triad)<br>`Query 2B` (UDM-Gated Beta-Binomial Failure Rate) |
| **3. SASE, Web Proxy & Network Detection Alerts** | Surfaces web proxy, secure web gateway (SWG), and NDR alerts. | Pairs 30-day per-(host, domain) HTTP request baselines (`metrics.http_queries_total`) with 10-day `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3` hosts) in Wave 1, then screens `Query 3A` candidate hosts for uniform cross-bucket flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$) in Wave 2. | `Query 3A` (30d HTTP Query Z + 10d `DERIVED_CONTEXT` Domain Prevalence)<br>`Query 3B` (UDM-Gated Flow-Gap Ratio Screen) |
| **4. Data Loss Prevention (DLP), Cloud (CNAPP) & OT/Mobile Alerts** | Monitors DLP policy triggers, cloud runtime alerts, and specialized OT/mobile security notifications. | Scores bounded ($\le 14\text{d}$) daily vendor alert volume per asset via 4-stage Non-Parametric Median Absolute Deviation (`MAD`, $M_Z > 3.5$) alongside a 3-stage Windowed Slack Sum prefilter ($W = \sum \max(0, Z_t - 0.5) \ge 3.0$, `drift_days >= 2`) on 30-day `metrics.network_bytes_outbound`. | `Query 4A` (4-Stage Bounded Raw MAD / Modified Z)<br>`Query 4B` (3-Stage 30d Outbound Byte Windowed Slack Sum) |
| **5. Capstone Cross-Vendor Entity Convergence** | Vendor alerts evaluated per integration policy. | Correlates entities accumulating $\ge 2$ distinct cross-vendor behavioral matches within the current run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via a squared Euclidean $L_2$ threat norm ($\sum Z_i^2 \ge 25.0$) and bridges directly to partitioned raw forensic telemetry. | `Query 5` (Wave 3 UDM Loopback $L_2$ Capstone Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Multi-Vendor Endpoint & XDR Alert Normalization

* **Curated Detection Operational Focus**: Normalizes endpoint and XDR alert streams across diverse endpoint security agents.
* **How Multi-Stage UEBA Extends Coverage**: Pairs 30-day per-host binary execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` organizational file prevalence (`rolling_max <= 3` hosts) in Wave 1, then applies Leave-One-Out Conjugate Gamma-Poisson predictive standardization to hourly multi-vendor alert bursts on `Query 1A` candidate endpoints in Wave 2.

#### Query 1A: 2-Stage Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Corroborates vendor endpoint alerts (and closes the polymorphic hash gap in static SHA-256 indicator rules) by scoring endpoint `PROCESS_LAUNCH` events on the scored UTC day (`timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"`, queried over `startTime = D-2` to `endTime = D+1` so daily `DERIVED_CONTEXT` records overlap the search window) against the 30-day composite metric `metrics.file_executions_total` with the continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ and 7-active-day maturity gate, inner-joined with `DERIVED_CONTEXT` 10-day organizational file prevalence (`day_count = 10`, `rolling_max <= 3` and `> 0`). Because Stage 2 is an inner join, binaries absent from `DERIVED_CONTEXT` drop out; unindexed Day-0 binaries (< 7 active baseline days) are handled separately via `first_seen_novelty_2stage.yl2`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Corroborate endpoint vendor alerts by detecting execution surges of organizationally rare binaries (10-day rolling_max <= 3 hosts) against 30-day per-host execution baselines.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total)
// Mode A Entity Graph Window: startTime = D-2 00:00:00Z, endTime = D+1 00:00:00Z, with Stage 1 pinned to scored UTC day D ("2026-10-29").
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    $sha256 = strings.coalesce(target.process.file.sha256, principal.process.file.sha256)
    principal.process.file.sha256 != ""
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

// Stage 2: Chronicle Derived Context Graph Lookup (Binary Prevalence & First Seen)
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

// Stage 3 (Root Stage): Fuses Personal Outlier Z-Score with Enterprise Prevalence Multiplier
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
  $safe_std = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_std
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier: 2.5x boost when DERIVED_CONTEXT first_seen > 0 and binary age <= 7 days, else 1.5x
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

#### Query 1B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Multi-Vendor EDR Alerts (`secops-statistical-hunter`)
Evaluates hourly multi-vendor alert velocity (`security_result.rule_name != ""`, excluding synthetic loopback events) via **Leave-One-Out Conjugate Gamma-Poisson Predictive Standardization** (`BAYESIAN_GAMMA_SHRINKAGE`) strictly on candidate endpoints surfaced by `Query 1A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_1a`)`). For each scored hour, the query subtracts the current hour's count and squared count from the host's prior window totals across `23.0` prior hourly buckets, updates a $\text{Gamma}(0.5, 0.1)$ prior, adds empirical excess overdispersion $\max(0, E[X^2]_{\text{prior}} - \mu_{\text{prior}}^2 - \mu_{\text{prior}})$, and computes `$bayesian_z` so chronically noisy hosts are shrunk while sudden alert bursts on quiet hosts produce high predictive Z-scores.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect multi-vendor EDR alert bursts on candidate endpoints from Query 1A using Leave-One-Out Gamma-Poisson predictive standardization.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Gamma-Poisson Predictive Z-Score (BAYESIAN_GAMMA_SHRINKAGE)
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_1a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_1a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_1a_z = max(security_result.confidence_score)
}

stage host_hourly_activity {
    security_result.rule_name != ""
    metadata.product_event_type != "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_rules = count_distinct(security_result.rule_name)
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

stage fleet_context {
    $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = sum(if($host_hourly_activity.hourly_count >= 15, 1, 0))
}

$host = $stage1_upstream_1a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_1a_candidates.upstream_1a_z)
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_rules)

  // Leave-One-Out Conjugate Gamma(0.5, 0.1) Prior over 23.0 prior hourly buckets (beta_prior = 0.1 + 23.0 = 23.1)
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 0.5 + $prior_sum
  $baseline_mean = $alpha_prior / 23.1
  $posterior_arrival_rate = ($alpha_prior + $observation_count) / 24.1
  $prior_emp_mean = 1.0 * $prior_sum / 23.0
  $raw_excess_var = (1.0 * $prior_sum_sq / 23.0) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * 24.1 / 23.1) + $excess_var
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

### Scenario 2: Identity Protection (IDP) & Email Threat Prevention Alerts

* **Curated Detection Operational Focus**: Ingests identity risk and phishing/email delivery alerts from IDP and secure email gateways.
* **How Multi-Stage UEBA Extends Coverage**: Scores every human Google Workspace user across the **3-Metric Workspace Activity Triad** (`metrics.workspace_auth_attempts_total`, `metrics.workspace_total_download_actions`, `metrics.workspace_total_change_actions`) using Leave-One-Out fleet cross-sectional Z-scores ($D_{\text{vs fleet}}^2 \ge 12.25$) alongside personal 30-day Z-scores in Wave 1, then evaluates hourly `USER_LOGIN` failure bursts on `Query 2A` candidate users via **Leave-One-Out Beta-Binomial Predictive Standardization** in Wave 2.

#### Query 2A: 3-Metric Multilevel Part-of-the-Whole Workspace/Identity Triad (`secops-risk-metrics-multistage`)
Corroborates upstream phishing and identity protection alerts by scoring human users (`principal.user.userid`) across the canonical **Workspace Activity Triad**—`metrics.workspace_auth_attempts_total`, `metrics.workspace_total_download_actions`, and `metrics.workspace_total_change_actions` (which counts every Google Workspace event and provides the 7-active-day maturity gate). Stage 2 and Stage 3 compute exact Leave-One-Out enterprise cross-sectional Z-scores excluding the scored user from the fleet mean and sum of squares, and the Root stage upper-tail rectifies each Z-score ($\max(0, Z_m)$) before squaring into $D_{\text{vs fleet}}^2 = \sum \max(0, Z_{\text{vs enterprise}, m})^2 \ge 12.25$ so quiet users never inflate composite distance.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Corroborate IDP and email phishing alerts by detecting post-compromise authentication, file download hoarding, and activity surges across the Workspace Activity Triad.
// Statistical Model: 3-Metric Multilevel Part-of-the-Whole Triad (Personal 30d Z + Leave-One-Out Fleet Z-Scores, Rectified D_vs_fleet^2 >= 12.25)
// ARCHITECTURE: 3-METRIC MULTILEVEL PART-OF-THE-WHOLE TRIAD DAG
// ADVISORY: Sibling Workspace triad metrics share underlying Google Workspace telemetry (positive inter-metric correlation); negative Z-scores are rectified at 0.0 before squaring.
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Enterprise Population Telemetry + 30-Day Baselines for the Workspace Activity Triad
stage all_entities {
    metadata.vendor_name = "Google Workspace"
    principal.user.userid = $user
    $user != ""
    not re.regex(principal.user.userid, `(?i)^(system|local service|network service)$|\$$`)

  match:
    $user by 1d

  outcome:
    $m1_obs = sum(if((metadata.product_name = "login" or metadata.product_name = "saml" or metadata.product_name = "token"), 1, 0))
    $m1_p_avg = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m1_p_std = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    $m2_obs = sum(if(metadata.product_event_type = "download", 1, 0))
    $m2_p_avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m2_p_std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    $m3_obs = count(metadata.id)
    $m3_p_avg = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m3_p_std = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
    $m3_active_days = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid
    ))
}

// Stage 2: Enterprise Whole (Macro fleet moments across all active human users on the scored day)
stage enterprise_stats {
    $ws = $all_entities.window_start

  match:
    $ws by 1d

  outcome:
    $m1_fleet_sum = sum($all_entities.m1_obs)
    $m1_fleet_avg = avg($all_entities.m1_obs)
    $m1_fleet_std = stddev($all_entities.m1_obs)

    $m2_fleet_sum = sum($all_entities.m2_obs)
    $m2_fleet_avg = avg($all_entities.m2_obs)
    $m2_fleet_std = stddev($all_entities.m2_obs)

    $m3_fleet_sum = sum($all_entities.m3_obs)
    $m3_fleet_avg = avg($all_entities.m3_obs)
    $m3_fleet_std = stddev($all_entities.m3_obs)

    $fleet_size = count_distinct($all_entities.user)
    $fleet_valid = if($fleet_size > 1, 1.0, 0.0)
    $safe_n2 = if($fleet_size > 1, $fleet_size, 2)
    $fleet_peer_n = $safe_n2 - 1.0
    $fleet_n_over_nm1 = $fleet_size / $fleet_peer_n
    $safe_n3 = if($fleet_size > 2, $fleet_size, 3)
    $fleet_df = $safe_n3 - 2.0
    $fleet_inv_df = 1.0 / $fleet_df
    $m1_fleet_ss = $fleet_peer_n * $m1_fleet_std * $m1_fleet_std
    $m2_fleet_ss = $fleet_peer_n * $m2_fleet_std * $m2_fleet_std
    $m3_fleet_ss = $fleet_peer_n * $m3_fleet_std * $m3_fleet_std
}

// Stage 3: Per-Entity Leave-One-Out Cross-Sectional Z-Scores & Metric 1 Personal Z-Score
stage loo_scores {
    $user = $all_entities.user
    $ws = $all_entities.window_start
    $ws = $enterprise_stats.ws

  match:
    $user, $ws by 1d

  outcome:
    $e1_loo_avg = (max($enterprise_stats.m1_fleet_sum) - max($all_entities.m1_obs)) / max($enterprise_stats.fleet_peer_n)
    $e1_var = (max($enterprise_stats.m1_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m1_obs) - max($enterprise_stats.m1_fleet_avg)) * (max($all_entities.m1_obs) - max($enterprise_stats.m1_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e1_dom = if($e1_var > $e1_loo_avg, $e1_var, $e1_loo_avg)
    $e1_safe_var = if($e1_dom > 1.0, $e1_dom, 1.0)
    $z1_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m1_obs) - $e1_loo_avg) / math.sqrt($e1_safe_var)

    $e2_loo_avg = (max($enterprise_stats.m2_fleet_sum) - max($all_entities.m2_obs)) / max($enterprise_stats.fleet_peer_n)
    $e2_var = (max($enterprise_stats.m2_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m2_obs) - max($enterprise_stats.m2_fleet_avg)) * (max($all_entities.m2_obs) - max($enterprise_stats.m2_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e2_dom = if($e2_var > $e2_loo_avg, $e2_var, $e2_loo_avg)
    $e2_safe_var = if($e2_dom > 1.0, $e2_dom, 1.0)
    $z2_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m2_obs) - $e2_loo_avg) / math.sqrt($e2_safe_var)

    $e3_loo_avg = (max($enterprise_stats.m3_fleet_sum) - max($all_entities.m3_obs)) / max($enterprise_stats.fleet_peer_n)
    $e3_var = (max($enterprise_stats.m3_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m3_obs) - max($enterprise_stats.m3_fleet_avg)) * (max($all_entities.m3_obs) - max($enterprise_stats.m3_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e3_dom = if($e3_var > $e3_loo_avg, $e3_var, $e3_loo_avg)
    $e3_safe_var = if($e3_dom > 1.0, $e3_dom, 1.0)
    $z3_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m3_obs) - $e3_loo_avg) / math.sqrt($e3_safe_var)

    $p1_f_arg = if(max($all_entities.m1_p_avg) > 1.0, max($all_entities.m1_p_avg), 1.0)
    $p1_floor = math.sqrt($p1_f_arg)
    $p1_div = if(max($all_entities.m1_p_std) > $p1_floor, max($all_entities.m1_p_std), $p1_floor)
    $z1_personal = (max($all_entities.m1_obs) - max($all_entities.m1_p_avg)) / $p1_div
}

// Root Stage: Positive-Rectified Multilevel Triad Scoring & Composite Distance vs Fleet
$user = $all_entities.user
$ws = $all_entities.window_start
$user = $loo_scores.user
$ws = $loo_scores.ws

match:
  $user, $ws by 1d

outcome:
  $m1_observed = max($all_entities.m1_obs)
  $m2_observed = max($all_entities.m2_obs)
  $m3_observed = max($all_entities.m3_obs)
  $active_days = max($all_entities.m3_active_days)

  // 1. Personal 30-Day Historical Z-Scores with continuous count dispersion floors
  $z1_personal = max($loo_scores.z1_personal)
  $p2_f_arg = if(max($all_entities.m2_p_avg) > 1.0, max($all_entities.m2_p_avg), 1.0)
  $p2_floor = math.sqrt($p2_f_arg)
  $p2_div = if(max($all_entities.m2_p_std) > $p2_floor, max($all_entities.m2_p_std), $p2_floor)
  $z2_personal = ($m2_observed - max($all_entities.m2_p_avg)) / $p2_div

  $p3_f_arg = if(max($all_entities.m3_p_avg) > 1.0, max($all_entities.m3_p_avg), 1.0)
  $p3_floor = math.sqrt($p3_f_arg)
  $p3_div = if(max($all_entities.m3_p_std) > $p3_floor, max($all_entities.m3_p_std), $p3_floor)
  $z3_personal = ($m3_observed - max($all_entities.m3_p_avg)) / $p3_div

  // 2. Leave-One-Out Enterprise Cross-Sectional Z-Scores ("Part of the Fleet")
  $z1_vs_enterprise = max($loo_scores.z1_vs_enterprise)
  $z2_vs_enterprise = max($loo_scores.z2_vs_enterprise)
  $z3_vs_enterprise = max($loo_scores.z3_vs_enterprise)

  // 3. Upper-Tail Rectified Composite Threat Norm Across the Triad vs the Fleet
  $z1_pos = if($z1_vs_enterprise > 0.0, $z1_vs_enterprise, 0.0)
  $z2_pos = if($z2_vs_enterprise > 0.0, $z2_vs_enterprise, 0.0)
  $z3_pos = if($z3_vs_enterprise > 0.0, $z3_vs_enterprise, 0.0)
  $d_vs_fleet_sq = ($z1_pos * $z1_pos) + ($z2_pos * $z2_pos) + ($z3_pos * $z3_pos)

condition:
  $active_days >= 7
  and $d_vs_fleet_sq >= 12.25

order:
  $d_vs_fleet_sq desc
```

#### Query 2B: 4-Stage UDM-Gated Beta-Binomial Empirical Bayes Authentication Failure Rate (`secops-statistical-hunter`)
Evaluates hourly `USER_LOGIN` authentication failure bursts (`BLOCK` or `FAIL`) via **Leave-One-Out Conjugate Beta-Binomial Predictive Standardization** (`BETA_BINOMIAL_FAILURE`) strictly on candidate users surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`). It updates a $\text{Beta}(1.0, 19.0)$ hyperprior (~5% baseline failure rate) with each user's leave-one-out prior failures and successes and standardizes the scored hour's failures against exact Beta-Binomial predictive variance $n p_0 (1 - p_0) \frac{M + n}{M + 1}$ (floored at `0.25`), suppressing accounts with chronically elevated failure rates while flagging acute brute-force or credential-stuffing spikes (`$fail_z >= 3.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect credential stuffing and SSO brute-force failure-rate surges on candidate users from Query 2A via Leave-One-Out Beta-Binomial predictive standardization.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Beta-Binomial Predictive Failure Z-Score (BETA_BINOMIAL_FAILURE)
// ARCHITECTURE: 4-STAGE UDM-GATED BETA-BINOMIAL PREDICTIVE FAILURE STANDARDIZATION PIPELINE
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_2a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)
    $user = strings.coalesce(principal.user.userid, target.user.userid, principal.asset.hostname)
    $user != ""
    $run_id != ""

  match:
    $user

  outcome:
    $upstream_2a_z = max(security_result.confidence_score)
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

stage fleet_stats {
    $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = sum(if($entity_hourly_trials.failed_trials >= 8, 1, 0))
}

$user = $stage1_upstream_2a_candidates.user
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($entity_hourly_trials.failed_trials)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $fleet_prevalence = max($fleet_stats.fleet_users)
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

### Scenario 3: SASE, Web Proxy & Network Detection Alerts

* **Curated Detection Operational Focus**: Surfaces web proxy, secure web gateway (SWG), and NDR alerts.
* **How Multi-Stage UEBA Extends Coverage**: Pairs 30-day per-(host, domain) HTTP query baselines (`metrics.http_queries_total`) with 10-day `DERIVED_CONTEXT` organizational domain prevalence (`rolling_max <= 3` hosts) in Wave 1, then screens `Query 3A` candidate hosts for persistent low-prevalence external connections exhibiting uniform cross-bucket flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$) in Wave 2.

#### Query 3A: 2-Stage Hybrid 30-Day HTTP Volume Baseline + `DERIVED_CONTEXT` 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Closes unlisted-domain coverage gaps across threat intelligence, SWG, and NGFW integrations by scoring each `(host, target_domain)` pair's daily HTTP request count (`timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"`, queried over `startTime = D-2` to `endTime = D+1`) against its 30-day behavioral baseline (`metrics.http_queries_total` keyed on both `principal.asset.hostname` and `target.hostname`) with the continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ and 7-active-day maturity gate, inner-joined with `DERIVED_CONTEXT` **10-day rolling organizational domain prevalence** (`day_count = 10`, `rolling_max <= 3` and `> 0`). Domains without a `DERIVED_CONTEXT` record drop out of the inner join; brand-new Day-0 `(host, domain)` pairs (< 7 active baseline days) are covered via `first_seen_novelty_2stage.yl2`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect endpoints generating HTTP request surges to organizationally rare external domains (10-day rolling_max <= 3 hosts) against 30-day per-(host, domain) HTTP baselines.
// Statistical Model: Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Destination HTTP Query Baseline per (host, domain)
// Mode A Entity Graph Window: startTime = D-2 00:00:00Z, endTime = D+1 00:00:00Z, with Stage 1 pinned to scored UTC day D ("2026-10-29").
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

// Stage 2: Chronicle Derived Context Graph Lookup (Domain Prevalence & First Seen)
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

// Stage 3 (Root Stage): Fuses Personal Query Z-Score with Enterprise Domain Prevalence Multiplier
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
  $safe_std = if($stddev_queries > $dispersion_floor, $stddev_queries, $dispersion_floor)
  $z_score = ($observed_queries - $mean_queries) / $safe_std
  $active_baseline_days = max($stage1_query_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_domain_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_domain_derived_context.enterprise_day_count)
  $first_seen = min($stage2_domain_derived_context.first_seen_ts)
  $obs_ts = max($stage1_query_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $domain_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Domain Multiplier: 2.5x boost when DERIVED_CONTEXT first_seen > 0 and domain age <= 7 days, else 1.5x
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

#### Query 3B: 4-Stage UDM-Gated Cross-Bucket Flow-Gap Ratio Dispersion Screen (`FLOW_GAP_RATIO_SCREEN`) on Proxy & Firewall Callbacks (`secops-statistical-hunter`)
Screens persistent external `(host, dst_ip)` pairs on candidate hosts surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`) using **Cross-Bucket Flow-Gap Ratio Dispersion** (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$, destination IP prevalence $\le 2$ internal hosts). Because stateless bucketed YARA-L cannot sort consecutive timestamps within a bucket, Stage 2 computes each active hourly bucket's span-to-count flow-gap ratio `1.0 * (max($ts) - min($ts)) / count(metadata.id)` and Stage 3 measures the Coefficient of Variation of that ratio across active hours (`>= 6` active buckets, `>= 25` connections, excluding RFC 1918, loopback, multicast, broadcast, and link-local ranges). True consecutive inter-arrival C2 jitter is evaluated separately via `C2_BEACONING_JITTER` (`c2_beaconing_jitter_2stage.yl2` + `micro_python_helpers.py c2-jitter`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen persistent low-prevalence external pairs with uniform hourly flow-gap ratios (CV <= 0.20) on candidate hosts from Query 3A.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN, CV <= 0.20)
// ARCHITECTURE: 4-STAGE UDM-GATED CROSS-BUCKET FLOW-GAP RATIO DISPERSION SCREEN PIPELINE
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_3a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_3a_z = max(security_result.confidence_score)
}

stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 64
    target.ip = $dst_ip
    $dst_ip != ""
    $dst_ip != "::1"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    // Exclude internal RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local destinations
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

stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip

  outcome:
    $src_breadth = count_distinct($host_intervals.host)
}

$host = $stage1_upstream_3a_candidates.host
$host = $timing_stats.host
$dst_ip = $timing_stats.dst_ip
$dst_ip = $dst_prevalence.dst_ip

match:
  $host, $dst_ip

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.total_conns)
  $total_outbound_bytes = max($timing_stats.total_sent_bytes)

  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $baseline_mean >= 1.0
  and $fleet_prevalence <= 2
  and $cv <= 0.20

order:
  $cv asc
```

---

### Scenario 4: Data Loss Prevention (DLP), Cloud (Wiz) & OT/Mobile Vendor Alerts

* **Curated Detection Operational Focus**: Monitors DLP policy triggers, cloud runtime alerts, and specialized OT/mobile security notifications.
* **How Multi-Stage UEBA Extends Coverage**: Scores bounded ($\le 14\text{d}$) daily vendor alert volume per asset via 4-stage Non-Parametric Median Absolute Deviation (`MAD`, $M_Z > 3.5$, `active_days >= 7`) alongside a 3-stage **Windowed Slack Sum** prefilter ($W = \sum \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ drift days) over 30-day `metrics.network_bytes_outbound` baselines.

#### Query 4A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Bounded Daily DLP, Cloud & OT Vendor Alerts (`secops-statistical-hunter`)
Scores daily alert volume across DLP (`DIGITALGUARDIAN_EDR`), Cloud (`WIZ_IO`), and OT (`CLAROTY_CTD`, `CLAROTY_XDOME`, `FORESCOUT_EYEINSPECT`, `NOZOMI_GUARDIAN`) log streams per host over a bounded ($\le 14\text{d}$) raw telemetry window against a 4-stage **Median Absolute Deviation (MAD)** baseline (`$m_z_score > 3.5`, `$baseline_active_samples >= 7`, `$observation_count >= 10`) with the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) when $\text{MAD} = 0$. Entities with fewer than 7 active days are excluded by the maturity gate and can be evaluated separately with `TWO_PART_HURDLE` (`two_part_hurdle_2stage.yl2`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous daily surges in DLP, Cloud (Wiz), and OT vendor alert telemetry per asset over a bounded (<= 14d) window using 4-stage Median Absolute Deviation (MAD).
// Target Telemetry: UDM_EVENTS (DIGITALGUARDIAN_EDR, WIZ_IO, CLAROTY_CTD, CLAROTY_XDOME, FORESCOUT_EYEINSPECT, NOZOMI_GUARDIAN)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (MAD_EXFILTRATION, M_Z > 3.5)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily observed DLP, Cloud, and OT vendor alert volume per entity
stage daily_stats {
    (
      metadata.log_type = "DIGITALGUARDIAN_EDR"
      or metadata.log_type = "WIZ_IO"
      or metadata.log_type = "CLAROTY_CTD"
      or metadata.log_type = "CLAROTY_XDOME"
      or metadata.log_type = "FORESCOUT_EYEINSPECT"
      or metadata.log_type = "NOZOMI_GUARDIAN"
    )
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $daily_value = count(metadata.id)
    $distinct_sample_values = count_distinct(security_result.rule_name)
    $sample_data = array_distinct(security_result.rule_name)
}

// Stage 2: Baseline median of the daily value per entity (active days only)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, mean absolute deviation (MAD=0 fallback), and active day count per entity
stage mad_stats {
    $entity = $daily_stats.entity
    $entity = $median_stats.entity

  match:
    $entity

  outcome:
    $mad = window.median(math.abs($daily_stats.daily_value - $median_stats.baseline_median), false)
    $mean_abs_dev = avg(math.abs($daily_stats.daily_value - $median_stats.baseline_median))
    $median_val = max($median_stats.baseline_median)
    $active_days = count_distinct($daily_stats.window_start)
}

// Root Stage: Modified Z-Score per entity-day and the 6 Core Evidence Pillars
$entity = $daily_stats.entity
$entity = $mad_stats.entity
$window_start = $daily_stats.window_start

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_stats.daily_value)
  $baseline_active_samples = max($mad_stats.active_days)
  $baseline_median = max($mad_stats.median_val)
  $baseline_mean = max($mad_stats.median_val)
  $baseline_dispersion = max($mad_stats.mad)
  $baseline_mean_abs_dev = max($mad_stats.mean_abs_dev)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_stats.distinct_sample_values)
  $sample_commands = array_distinct($daily_stats.sample_data)

  // Robust scale with Iglewicz-Hoaglin MAD=0 fallback
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 10
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

#### Query 4B: 3-Stage Windowed Slack Sum (Longitudinal CUSUM Prefilter) on 30-Day Outbound Network Bytes (`secops-risk-metrics-multistage`)
Corroborates DLP, Cloud, and OT alerts—and catches multi-day outbound data exfiltration that stays beneath single-day $3\sigma$ thresholds—by computing the lossless **Windowed Slack Sum** prefilter $W = \sum_t \max(0, Z_t - 0.5)$ across a multi-day Mode B evaluation window (`2–3` days; single-day Mode A cannot satisfy `drift_days >= 2`) against each host's 30-day `metrics.network_bytes_outbound` baseline using the empirical fleet byte dispersion floor (`44,979.0` bytes) and 7-active-day maturity gate (`$active_days >= 7`, `$windowed_slack_sum >= 3.0`, `$drift_days >= 2`). Because YARA-L 2.0 cannot carry recursive $S_{t-1}$ state across day buckets, exact sequential Page's CUSUM $S_t = \max(0, S_{t-1} + Z_t - 0.5)$ with quiet-day reset is evaluated downstream via `longitudinal_cusum_series_3stage.yl2` + `cusum_helper.py` on candidates passing $W \ge 3.0$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen multi-day low-and-slow outbound data exfiltration across endpoints, cloud workloads, and OT assets via the Windowed Slack Sum prefilter on 30-day outbound network bytes.
// Statistical Model: 3-Stage Windowed Slack Sum / Longitudinal CUSUM Prefilter (WINDOWED_SLACK_SUM, k = 0.5 sigma slack, windowed_slack_sum >= 3.0, drift_days >= 2)
// ARCHITECTURE: 3-STAGE WINDOWED SLACK SUM (LONGITUDINAL CUSUM PREFILTER) PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Bytes & 30-Day Metric Baseline Extraction
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $observed_events = count(metadata.id)

    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_max = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: max,
        principal.asset.hostname: principal.asset.hostname
    ))
}

// Stage 2: Daily Standardized Slack-Excess Drift per Entity-Day (44,979.0 B fleet byte dispersion floor)
stage stage2_daily_drift {
    $entity = $stage1_extract.entity
    $day_ws = $stage1_extract.window_start

  match:
    $entity, $day_ws by 1d

  outcome:
    $observed = max($stage1_extract.observed_val)
    $hist_avg = max($stage1_extract.historical_avg)
    $hist_stddev = max($stage1_extract.historical_stddev)
    $active_days = max($stage1_extract.historical_active_days)
    $hist_max = max($stage1_extract.historical_max)

    $raw_drift = $observed - $hist_avg
    $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
    $daily_z = $raw_drift / $safe_stddev
    $z_minus_slack = $daily_z - 0.5
    $daily_excess = if($active_days >= 7 and $z_minus_slack > 0.0, $z_minus_slack, 0.0)
}

// Stage 3 (Root Stage): Multi-Day Windowed Slack Sum Aggregation Across Evaluation Window
$entity = $stage2_daily_drift.entity

match:
  $entity

outcome:
  $observed = sum($stage2_daily_drift.observed)
  $peak_daily_observed = max($stage2_daily_drift.observed)
  $baseline_mean = max($stage2_daily_drift.hist_avg)
  $baseline_stddev = max($stage2_daily_drift.hist_stddev)
  $active_days = max($stage2_daily_drift.active_days)
  $hist_max = max($stage2_daily_drift.hist_max)

  // Lossless non-resetting Windowed Slack Sum W = sum(max(0, Z_t - 0.5)) across scored days
  $windowed_slack_sum = sum($stage2_daily_drift.daily_excess)
  $cusum_drift_score = $windowed_slack_sum
  $drift_days = sum(if($stage2_daily_drift.daily_excess > 0.0, 1, 0))
  $max_daily_z = max($stage2_daily_drift.daily_z)

condition:
  $active_days >= 7
  and $windowed_slack_sum >= 3.0
  and $drift_days >= 2

order:
  $windowed_slack_sum desc
```

---

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge

* **Curated Detection Operational Focus**: Vendor alerts evaluated per integration policy.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities accumulating $\ge 2$ distinct cross-vendor behavioral matches (`LOOPBACK_MIN_DISTINCT_HITS = 2`) within the active run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via a squared Euclidean $L_2$ risk norm ($\sum Z_i^2 \ge 25.0$, `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD = 25.0`) while bridging directly to partitioned raw forensic telemetry.

Individual behavioral queries in Scenarios 1–4 frequently fire inside ambiguous overlap regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud resource names. **Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** (`Queries 1A, 2A, 3A, 4A, 4B`) and **Wave 2** (`Queries 1B, 2B, 3B`) stages have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 4 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using `re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)` and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-equivalent scores (`$capstone_threat_norm_sq >= 25.0`).
3. **Partitioned Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) with per-domain conditional event sums by `$entity` and joins it with Stage 2 in Root to return both the cross-scenario Euclidean $L_2$ convergence norm and concrete raw forensic artifacts in one query.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 Third-Party Vendor Alerts scenarios (1A through 4B) via UDM Loopback Capstone regex union while joining partitioned raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Partitioned Raw Telemetry Bridge
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
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
    // Optional Data Table watchlist filter (commented out by default because unpopulated Data Tables fail compilation):
    // $entity in %ueba_entity_watchlist.entity

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
  $capstone_threat_norm_sq = max($stage2_multi_scenario_rollup.capstone_threat_norm_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)
  $z_score = $capstone_threat_score

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $cloud_events = max($stage3_raw_forensic_pivot.cloud_events)
  $auth_events = max($stage3_raw_forensic_pivot.auth_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_norm_sq desc
```

---

## 3. Cross-Vendor Telemetry Ingestion-Lag & Forwarder Backpressure Quantile Audit (`window.percentile`)

Before correlating third-party XDR, SASE, and IdP alerts across hourly windows (`by 1h`), execute this single-stage non-parametric quantile audit over `metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds` (`$p10, $p25, $p50, $p75, $p90`). Negative `$p10 < 0` surfaces forwarder clock skew or event timestomping, `$p90 >= 300` flags 5+ minute tail ingestion delay, and elevated Bowley quartile skewness (`$bowley_skew >= 0.75`, alongside the Moors interdecile-to-interquartile ratio `$tail_heaviness = $idr / $safe_iqr`) warns the SOC that a cloud-to-cloud webhook or syslog forwarder is experiencing batch backpressure:

```yara
// Goal: Profile telemetry ingestion lag quantiles, Bowley quartile skewness, Moors tail heaviness, and negative clock-skew anomalies per log_type
// Statistical Model: Single-Stage Empirical Quantile Lag & Bowley Skewness Audit (window.percentile)
metadata.event_timestamp.seconds > 0
$log_type = metadata.log_type
$log_type != ""

match:
  $log_type by 1h

outcome:
  $event_count = count(metadata.id)
  $p10 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 10)
  $p25 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 25)
  $p50 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 50)
  $p75 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 75)
  $p90 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 90)

  $iqr = $p75 - $p25
  $bowley_num = $p75 + $p25 - (2 * $p50)
  $safe_iqr = if($iqr > 0, $iqr, 1.0)
  $bowley_skew = $bowley_num / $safe_iqr
  $idr = $p90 - $p10
  $tail_heaviness = $idr / $safe_iqr

condition:
  $event_count >= 10 and ($p10 < 0 or $p90 >= 300 or $bowley_skew >= 0.75)

order:
  $p90 desc
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
