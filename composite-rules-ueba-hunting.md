# Hunting Multi-Stage Kill-Chain & Cloud/Endpoint Composite Threats with Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Composite Rules** curated detection suite correlates multiple upstream rule detections or MITRE ATT&CK tactics across endpoint and cloud telemetry to surface multi-step intrusions.

While deterministic composite rules correlate discrete rule firings within fixed short-term correlation windows, adversaries often pace intrusion stages across hours or days, or blend low-severity activity with subtle behavioral shifts in authentication, API usage, and network transfers. This runbook supplements composite detections with **30-day Multi-Sector Behavioral Risk Fusion (`secops-risk-metrics-multistage`)**, **Windowed Slack Sum (`LONGITUDINAL_CUSUM` prefilter)**, **Skewness-Adjusted Tukey Fences with `DERIVED_CONTEXT` Rare Domain Prevalence**, **Leave-One-Out Gamma-Poisson & Parametric Hourly Scoring (`secops-statistical-hunter`)**, and **UDM Loopback Capstone Convergence**.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond fixed short-window correlation cliffs through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba` (where queries emit pure Z / Z-equivalent statistical scores and `PlaybookRunner` computes Composite Risk Index scores in Python via `ueba_constants.calculate_cri`):
  1. **Wave 1 — Macro 30-Day Sector Fusions, Windowed Slack Sum & Bounded Micro Baselines (`7 Queries`)**: Executes `by 1d` 30-day `metrics.*` baselines (enforcing the 7-active-day maturity gate `$active_days >= 7`, continuous Poisson dispersion floors `max(sigma, math.sqrt(max(mu, 1.0)))` on count metrics, and empirical fleet byte floors `44979.0` on `network_bytes_outbound` and `28276845.0` on `network_bytes_inbound`), 4-stage `window.percentile` + `DERIVED_CONTEXT` rare domain prevalence hunts, and bounded 7d–14d raw-event statistical hunts (`Two-Part Hurdle` and `4-Stage Non-Parametric MAD`). Mode A evaluates the last complete UTC day `[D T00:00:00Z, D+1 T00:00:00Z)` against `[D-30, D)` (with Entity Graph joins anchored at `startTime = D-2` and scored rows pinned to `D`). Every match is written to Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Micro Queries (`2 Queries: 1B, 2B`)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` hunts read `Query XA`'s candidate hosts in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to scope hourly (`by 1h`) raw process and alert velocity models without risking enterprise raw-event scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, requires cross-scenario convergence across `$distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) with squared Euclidean Z-norm `$capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`) in Stage 2, and pivots matched entities directly into raw endpoint, network, authentication, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Composite Rules & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Multi-Tactic Endpoint Kill-Chain Clustering** | Correlates multiple endpoint detections or distinct MITRE ATT&CK tactics on a single host within a short time window. | Fuses 30-day per-rule host alert volume (`metrics.alert_event_name_count`, rolled up with a Gaussian max-order multiplicity offset) with 30-day outbound network bytes (`metrics.network_bytes_outbound`, $D^2 \ge 12.25$), then scores candidate hosts hourly with Leave-One-Out Gamma-Poisson shrinkage. | `Query 1A` (4-Stage Roll-Up 30d Alert + Outbound Bytes Fusion)<br>`Query 1B` (UDM-Gated Leave-One-Out Gamma-Poisson Shrinkage) |
| **2. Cross-Host Propagation & Lateral Movement** | Detects shared malware indicators or sequential lateral movement alerts across multiple endpoints. | Fuses 30-day host authentication failures (`metrics.auth_attempts_fail`) with 30-day inbound network bytes (`metrics.network_bytes_inbound`, $D^2 \ge 12.25$) on a shared union spine, then evaluates hourly process launch surges on candidate hosts via Leave-One-Out Z-scores. | `Query 2A` (Dual-Sector 30d Host Auth Fail + Inbound Bytes Fusion)<br>`Query 2B` (UDM-Gated Leave-One-Out Process Surge Z-Score) |
| **3. Cloud Account Compromise & Multi-Step IAM/Resource Chaining** | Correlates sequences of suspicious cloud control-plane alerts across AWS, GCP, and Azure. | Fuses 30-day per-service cloud resource read failures (`metrics.resource_read_fail`) with 30-day user login successes (`metrics.auth_attempts_success`, $D^2 \ge 12.25$), paired with a Two-Part Hurdle model catching both dormant cloud account awakenings and active intensity surges. | `Query 3A` (4-Stage Roll-Up 30d Cloud Read Fail + Auth Success Fusion)<br>`Query 3B` (Two-Part Hurdle on Daily Cloud API Activity) |
| **4. Low-and-Slow Multi-Day Exfiltration & Post-Exploitation Drift** | Identifies high-volume data transfer following upstream compromise alerts. | Accumulates sub-threshold daily outbound byte drift via a 3-stage Windowed Slack Sum (`LONGITUDINAL_CUSUM` prefilter, $k = 0.5\sigma$, $W \ge 3.0$ across $\ge 2$ drift days) and scores daily cloud resource access volume with 4-stage non-parametric MAD ($M_Z > 3.5$). | `Query 4A` (3-Stage Windowed Slack Sum on 30d Outbound Bytes)<br>`Query 4B` (4-Stage Non-Parametric MAD on Daily Cloud Resource Access) |
| **5. Capstone Multi-Scenario Entity Convergence** | Short-window correlation of discrete upstream rule firings. | Correlates entities matching $\ge 2$ distinct behavioral composite queries over a 7-day horizon (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean squared Z-norm ($\sum Z_i^2 \ge 25.0$) joined with raw forensic artifacts. | `Query 5` (3-Stage UDM Loopback $L_2$ Capstone Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Multi-Tactic Endpoint Kill-Chain Clustering

* **Curated Detection Operational Focus**: Correlates multiple endpoint detections or distinct MITRE ATT&CK tactics on a single host within a short time window.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day per-rule host alert volume (`metrics.alert_event_name_count`) with 30-day outbound network bytes (`metrics.network_bytes_outbound`) ($D^2 \ge 12.25$) on a shared entity-union spine, then applies Leave-One-Out Gamma-Poisson shrinkage to hourly endpoint process and alert velocity on candidate hosts.

#### Query 1A: 4-Stage Roll-Up Endpoint Alert (`metrics.alert_event_name_count`) + Outbound Network Bytes (`metrics.network_bytes_outbound`) Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Replaces fixed short-window correlation cliffs and static rule-count thresholds with a **4-Stage Roll-Up Multi-Sector Fusion** ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$). Both UDM stages use a shared entity-union spine so single-sector outliers survive even when the companion sector has zero events today. Stage 1 scores each `(principal.asset.hostname, security_result.rule_name)` pair against its 30-day `metrics.alert_event_name_count` baseline (gated at $\ge 7$ active days with count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$); Stage 2 rolls per-rule Z-scores up to the host level and subtracts the Gaussian max-order multiplicity offset $\sqrt{2 \ln K_{\text{eff}}}$ across active rules; Stage 3 scores daily outbound bytes against `metrics.network_bytes_outbound` using the empirical fleet byte floor (`44979.0` bytes); and the Root Stage computes the squared Euclidean norm $D^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ADVISORY: Sector A rolls alert_event_name_count up from per-(security_result.rule_name) baselines: its Z is the largest per-security_result.rule_name Z for the entity after multiplicity adjustment, not a Z of the entity's total volume (the metric has no entity-only baseline).
// Goal: Fuse endpoint security alert anomalies with outbound network byte surges on the same host to detect multi-stage endpoint kill chains across a full 24-hour window.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2, union spine): one row per host and alert rule_name ---
stage sector_a_detail {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""
    security_result.rule_name = $security_result_rule_name

  match:
    $entity, $security_result_rule_name by 1d

  outcome:
    $d_obs = sum(if((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "", 1, 0))
    $d_avg = max(metrics.alert_event_name_count(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        security_result.rule_name: security_result.rule_name
    ))
    $d_std = max(metrics.alert_event_name_count(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        security_result.rule_name: security_result.rule_name
    ))
    $d_days = max(metrics.alert_event_name_count(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        security_result.rule_name: security_result.rule_name
    ))
    $d_floor = math.sqrt(if($d_avg > 1.0, $d_avg, 1.0))
    $d_safe_std = if($d_std > $d_floor, $d_std, $d_floor)
    $d_z_raw = ($d_obs - $d_avg) / $d_safe_std
    $d_z_pos = if($d_z_raw > 0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per host with K-key multiplicity offset ---
stage sector_a {
    $entity = $sector_a_detail.entity

  match:
    $entity by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.security_result_rule_name)
    $a_active_keys = sum($sector_a_detail.d_active)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a_max = max($sector_a_detail.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

// --- STAGE 3: Sector B — Outbound Network Bytes (UDM Source 2 of 2, union spine) ---
stage sector_b {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)
    $b_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_safe_std = if($b_std > 44979.0, $b_std, 44979.0)
    $z_b_raw = ($b_obs - $b_avg) / $b_safe_std
    $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
    $z_b = if($b_obs > 0 and $b_days >= 7, $z_b_pos, 0.0)
}

// --- ROOT STAGE: Roll-Up Sector Fusion & Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity
$ws = $sector_a.window_start
$ws = $sector_b.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $a_keys = max($sector_a.a_keys)
  $a_hot_keys = max($sector_a.a_hot_keys)
  $a_novel_keys = max($sector_a.a_novel_keys)
  $b_observed = max($sector_b.b_obs)
  $b_active_days = max($sector_b.b_days)

  // Rectified, baseline-gated, multiplicity-adjusted sector scores (missing sector contributes 0.0)
  $z_a = max($sector_a.z_a)
  $z_b = max($sector_b.z_b)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 1B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Endpoint Process & Alert Velocity (`secops-statistical-hunter`)
Evaluates hourly endpoint process and security alert velocity via **Leave-One-Out Conjugate Gamma-Poisson Predictive Standardization with Empirical Excess Overdispersion** strictly on candidate endpoints surfaced by `Query 1A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_1a`)`). Excluding the scored hour from $\Sigma x$ and $\Sigma x^2$ across the 23 prior hourly buckets prevents a single burst from inflating its own prior, while adding empirical excess variance shrinks routinely bursty servers and highlights genuine spikes on quiet endpoints (`$bayesian_z >= 3.0`). Since Stage 1 is consumed by the UDM candidate gate rather than a fleet stage, `$fleet_prevalence` emits the `0 - 1` (`-1`) not-computed sentinel.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect multi-stage endpoint execution and alert bursts on candidate hosts from Query 1A via Leave-One-Out Conjugate Gamma-Poisson predictive Z-scoring.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Gamma-Poisson Predictive Standardization (BAYESIAN_GAMMA_SHRINKAGE)
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
    (
      metadata.event_type = "PROCESS_LAUNCH"
      or security_result.rule_name != ""
    )
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmds = array_distinct(target.process.command_line)
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

$host = $stage1_upstream_1a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_1a_candidates.upstream_1a_z)
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_hourly_activity.distinct_procs)
  $sample_commands = array_distinct($host_hourly_activity.sample_cmds)

  // Leave-One-Out Conjugate Gamma(0.5, 0.1) Prior over 23 Prior Hourly Buckets (24h Window)
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 0.5 + $prior_sum
  $baseline_mean = $alpha_prior / 23.1
  $prior_emp_mean = 1.0 * $prior_sum / 23.0
  $raw_excess_var = (1.0 * $prior_sum_sq / 23.0) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * 24.1 / 23.1) + $excess_var
  $safe_pred_var = if($raw_pred_var > 1.0, $raw_pred_var, 1.0)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $bayesian_z = ($observation_count - $baseline_mean) / $baseline_dispersion

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 15
  and $bayesian_z >= 3.0

order:
  $bayesian_z desc
```

---

### Scenario 2: Cross-Host Malware Propagation & Lateral Movement

* **Curated Detection Operational Focus**: Detects shared malware indicators or sequential lateral movement alerts across multiple endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day host authentication failures (`metrics.auth_attempts_fail`) with 30-day inbound network bytes (`metrics.network_bytes_inbound`, $D^2 \ge 12.25$) on a single-stage union spine, then evaluates hourly process launch surges on candidate hosts via Leave-One-Out standardized Z-scores (`$z_score > 2.0`).

#### Query 2A: Dual-Sector Host Authentication Failures (`metrics.auth_attempts_fail`) + Inbound Network Bytes (`metrics.network_bytes_inbound`) Fusion (`secops-risk-metrics-multistage`)
Detects lateral movement authentication probing paired with ingress tool/payload transfer on a host without requiring upstream discovery rule firings. A single-stage union (`stage sector_union`) preserves single-sector outliers when the companion sector has zero events today, applying the count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ to `metrics.auth_attempts_fail`, the empirical fleet byte floor (`28276845.0` bytes) to `metrics.network_bytes_inbound`, and the 7-active-day maturity gate (`$a_active_days >= 7`, `$b_active_days >= 7`) before scoring $D^2 = Z_{\text{auth fail}}^2 + Z_{\text{inbound bytes}}^2 \ge 12.25$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect lateral movement authentication probing paired with ingress tool/payload transfer on the same endpoint via 30-day Dual-Sector Risk Fusion.
// Statistical Model: Dual-Sector Threat Fusion (metrics.auth_attempts_fail + metrics.network_bytes_inbound, D^2 >= 12.25)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (GENERIC SINGLE-STAGE UNION: ANY TWO ENTITY-KEYED METRICS)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Single-Stage Sector Union (UDM Source 1 of 2; preserves single-sector outliers) ---
stage sector_union {
    ((metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW") or (network.received_bytes > 0 and network.received_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if(metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW", 1, 0))
    $a_avg = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_std = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_days = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_floor = math.sqrt(if($a_avg > 1.0, $a_avg, 1.0))
    $a_safe_std = if($a_std > $a_floor, $a_std, $a_floor)
    $z_a_raw = ($a_obs - $a_avg) / $a_safe_std
    $z_a_pos = if($z_a_raw > 0, $z_a_raw, 0.0)
    $z_a = if($a_obs > 0, $z_a_pos, 0.0)

    $b_obs = sum(if(network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0) * network.received_bytes)
    $b_avg = max(metrics.network_bytes_inbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.network_bytes_inbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.network_bytes_inbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_safe_std = if($b_std > 28276845.0, $b_std, 28276845.0)
    $z_b_raw = ($b_obs - $b_avg) / $b_safe_std
    $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
    $z_b = if($b_obs > 0, $z_b_pos, 0.0)
}

// --- ROOT STAGE: Dual-Sector Threat Fusion & Distance Scoring ---
$entity = $sector_union.entity

match:
  $entity by 1d

outcome:
  $a_observed = max($sector_union.a_obs)
  $b_observed = max($sector_union.b_obs)
  $a_active_days = max($sector_union.a_days)
  $b_active_days = max($sector_union.b_days)
  $z_a = max($sector_union.z_a)
  $z_b = max($sector_union.z_b)

  // Sparse-baseline gate: a missing or < 7 active-day sector contributes 0.0
  $z_a_gated = if($a_active_days >= 7, $z_a, 0.0)
  $z_b_gated = if($b_active_days >= 7, $z_b, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a_gated * $z_a_gated
  $z_b_sq = $z_b_gated * $z_b_gated
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 2B: 4-Stage UDM-Gated Leave-One-Out Process Surge Z-Score on Endpoint Execution Activity (`secops-statistical-hunter`)
Evaluates hourly `PROCESS_LAUNCH` surges strictly on candidate endpoints surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`). Computes an exact **Leave-One-Out ($n - 1$) Parametric Z-Score** with a continuous Poisson dispersion floor $\max(s_{-t}, \sqrt{\max(\mu_{-t}, 1)})$ so an extreme execution spike cannot inflate its own baseline standard deviation. `$upstream_z` records the upstream `Query 2A` confidence score for triage context while `$z_score` emits the pure standardized hourly process Z-score (cross-query fusion occurs in Wave 3 Capstone).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT PROCESS SURGE Z-SCORE PIPELINE
// Goal: Detect post-authentication payload execution spikes on candidate hosts from Query 2A via Leave-One-Out hourly process Z-scores.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Parametric Z-Score with Continuous Poisson Floor (ZSCORE_PROCESS_SURGE)
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

stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

stage host_stats {
    $host = $host_hourly.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly.hourly_count)
    $sum_x2 = sum($host_hourly.hourly_count_sq)
    $active_samples = count($host_hourly.window_start)
}

$host = $stage1_upstream_2a_candidates.host
$host = $host_hourly.host
$host = $host_stats.host
$ws = $host_hourly.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($host_stats.active_samples) - 1
  $safe_n_prior = if($baseline_active_samples > 1, $baseline_active_samples, 1)
  $loo_sum = max($host_stats.sum_x) - $observation_count
  $baseline_mean = 1.0 * $loo_sum / $safe_n_prior
  $df = $baseline_active_samples - 1
  $safe_df = if($df > 1, $df, 1)
  $raw_ss = (max($host_stats.sum_x2) - (1.0 * $observation_count * $observation_count)) - ((1.0 * $loo_sum * $loo_sum) / $safe_n_prior)
  $pos_ss = if($raw_ss > 0.0, $raw_ss, 0.0)
  $loo_sd = math.sqrt($pos_ss / $safe_df)
  $floor_arg = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $poisson_floor = math.sqrt($floor_arg)
  $baseline_dispersion = if($loo_sd > $poisson_floor, $loo_sd, $poisson_floor)
  $z_score = ($observation_count - $baseline_mean) / $baseline_dispersion
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $z_score > 2.0

order:
  $z_score desc
```

---

### Scenario 3: Cloud Account Compromise & Multi-Step IAM/Secret Chaining

* **Curated Detection Operational Focus**: Correlates sequences of suspicious cloud control-plane alerts across AWS, GCP, and Azure.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day per-service cloud resource read failures (`metrics.resource_read_fail`) with 30-day authentication successes (`metrics.auth_attempts_success`, $D^2 \ge 12.25$) for the same user, complemented by a Two-Part Hurdle model on daily cloud API volume that separates dormant account awakenings from continuous intensity spikes on established cloud identities.

#### Query 3A: 4-Stage Roll-Up Cloud Resource Read Failures (`metrics.resource_read_fail`) + Auth Successes (`metrics.auth_attempts_success`) Fusion (`secops-risk-metrics-multistage`)
Eliminates short-window and same-IP correlation constraints by fusing **30-day Cloud Resource Read Failures (`metrics.resource_read_fail` rolled up across `principal.user.userid`, `metadata.product_name`, `metadata.vendor_name` with the $\sqrt{2 \ln K_{\text{eff}}}$ multiplicity offset)** with **30-day Authentication Successes (`metrics.auth_attempts_success` keyed on `target.user.userid`)** on a shared `userid` union spine ($D^2 = Z_{\text{read fail}}^2 + Z_{\text{auth success}}^2 \ge 12.25$). Both sectors enforce the 7-active-day maturity gate and continuous count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ADVISORY: Sector A rolls resource_read_fail up from per-(metadata.product_name, metadata.vendor_name) baselines: its Z is the largest per-metadata.product_name Z for the entity after multiplicity adjustment, not a Z of the entity's total volume (the metric has no entity-only baseline).
// Goal: Detect cloud account compromise followed by IAM/resource permission probing across any IP or cloud provider via 4-Stage Roll-Up Sector Fusion.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.resource_read_fail + metrics.auth_attempts_success, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2, union spine): one row per user, product_name, and vendor_name ---
stage sector_a_detail {
    (((metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS") and not security_result.action = "ALLOW" and principal.user.userid != "" and metadata.product_name != "" and metadata.vendor_name != "") or (metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW" and target.user.userid != ""))
    $entity = strings.coalesce(target.user.userid, principal.user.userid)
    $entity != ""
    metadata.product_name = $product_name
    metadata.vendor_name = $vendor_name

  match:
    $entity, $product_name, $vendor_name by 1d

  outcome:
    $d_obs = sum(if((metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS") and not security_result.action = "ALLOW" and metadata.product_name != "" and metadata.vendor_name != "" and principal.user.userid = $entity, 1, 0))
    $d_avg = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_std = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_days = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_floor = math.sqrt(if($d_avg > 1.0, $d_avg, 1.0))
    $d_safe_std = if($d_std > $d_floor, $d_std, $d_floor)
    $d_z_raw = ($d_obs - $d_avg) / $d_safe_std
    $d_z_pos = if($d_z_raw > 0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per cloud user with K-key multiplicity offset ---
stage sector_a {
    $entity = $sector_a_detail.entity

  match:
    $entity by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.product_name)
    $a_active_keys = sum($sector_a_detail.d_active)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a_max = max($sector_a_detail.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

// --- STAGE 3: Sector B — Cloud User Authentication Successes (UDM Source 2 of 2, union spine) ---
stage sector_b {
    (((metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS") and not security_result.action = "ALLOW" and principal.user.userid != "" and metadata.product_name != "" and metadata.vendor_name != "") or (metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW" and target.user.userid != ""))
    $entity = strings.coalesce(target.user.userid, principal.user.userid)
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(if(metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW" and target.user.userid = $entity, 1, 0))
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
    $b_floor = math.sqrt(if($b_avg > 1.0, $b_avg, 1.0))
    $b_safe_std = if($b_std > $b_floor, $b_std, $b_floor)
    $z_b_raw = ($b_obs - $b_avg) / $b_safe_std
    $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
    $z_b = if($b_obs > 0 and $b_days >= 7, $z_b_pos, 0.0)
}

// --- ROOT STAGE: Roll-Up Sector Fusion & Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity
$ws = $sector_a.window_start
$ws = $sector_b.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $a_keys = max($sector_a.a_keys)
  $a_hot_keys = max($sector_a.a_hot_keys)
  $a_novel_keys = max($sector_a.a_novel_keys)
  $b_observed = max($sector_b.b_obs)
  $b_active_days = max($sector_b.b_days)

  // Rectified, baseline-gated, multiplicity-adjusted sector scores (missing sector contributes 0.0)
  $z_a = max($sector_a.z_a)
  $z_b = max($sector_b.z_b)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 3B: Two-Part Hurdle Model on Cross-Service Cloud API Activity (`secops-statistical-hunter`)
Detects both dormant cloud identities/service accounts awakening to harvest secrets or assume roles *and* established cloud identities surging across `RESOURCE_READ`, `RESOURCE_WRITTEN`, and `USER_RESOURCE_ACCESS` events over `1d` buckets. Part 1 (Discrete Bernoulli Hurdle) requires identities with $\le 7$ active baseline days to clear an explicit awakening volume gate (`$observation_count >= 10`) before scoring `3.0 * (obs / 10.0)`, suppressing low-volume trickle noise; Part 2 (Continuous Intensity) scores mature accounts (`> 7` active days) using a positive-rectified Leave-One-Out Z-score with a continuous $\sqrt{\max(\mu_{-t}, 1)}$ dispersion floor (`$hurdle_threat_score >= 3.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant or compromised cloud accounts and service accounts awakening with anomalous cross-service API activity (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS).
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS)
// Statistical Model: Two-Part Hurdle Outlier Model (TWO_PART_HURDLE, hurdle_threat_score >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily cross-service cloud API activity extraction per cloud user
stage entity_historical {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "RESOURCE_WRITTEN"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
    )
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $read_events = sum(if(metadata.event_type = "RESOURCE_READ", 1, 0))
    $write_events = sum(if(metadata.event_type = "RESOURCE_WRITTEN", 1, 0))
    $access_events = sum(if(metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $distinct_targets = count_distinct(target.resource.name)
    $sample_target = array_distinct(target.resource.name)
}

// Stage 2: Historical moment accumulation across active daily windows
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

// Stage 3: Enterprise fleet prevalence of surging cloud users per daily window
stage fleet_context {
    $ws = $entity_historical.window_start

  match:
    $ws by 1d

  outcome:
    $fleet_users = sum(if($entity_historical.bucket_count >= 5, 1, 0))
}

// Root Stage: Two-Part Hurdle Evaluation (Dormant Awakening Gate + LOO Positive Intensity Z)
$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start
$window_start = $fleet_context.ws

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = max($fleet_context.fleet_users)
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

  // Part 2: Leave-One-Out Continuous Intensity Standardization (Positive-Rectified, > 7 active days)
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $raw_loo_sum = max($entity_stats.sum_x) - $observation_count
  $loo_sum = if($raw_loo_sum > 0, $raw_loo_sum, 0)
  $baseline_mean = 1.0 * $loo_sum / $n_prior
  $raw_loo_var = ((max($entity_stats.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $raw_intensity_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $intensity_z = if($raw_intensity_z > 0.0, $raw_intensity_z, 0.0)

  // Part 1: Dormant Awakening Branch (<= 7 active days, gated by observation_count >= 10)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 10.0)
  $dormant_score = if($observation_count >= 10, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 7, $dormant_score, $intensity_z)

condition:
  $observation_count >= 5
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

### Scenario 4: Low-and-Slow Multi-Day Exfiltration & Post-Exploitation Drift

* **Curated Detection Operational Focus**: Identifies high-volume data transfer following upstream compromise alerts.
* **How Multi-Stage UEBA Extends Coverage**: Accumulates sub-$3\sigma$ daily egress pacing via a 3-stage **Windowed Slack Sum (`LONGITUDINAL_CUSUM` prefilter)** over `metrics.network_bytes_outbound` ($W = \sum \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ drift days) and evaluates daily cloud resource access hoarding via 4-stage non-parametric **Median Absolute Deviation (MAD)** ($M_Z > 3.5$).

#### Query 4A: 3-Stage Windowed Slack Sum (`LONGITUDINAL_CUSUM` Prefilter, `cusum_drift_score >= 3.0`, `drift_days >= 2`) on 30-Day `metrics.network_bytes_outbound` (`secops-risk-metrics-multistage`)
Defeats both short-window correlation cliffs and sub-$3\sigma$ daily pacing by computing the **Windowed Slack Sum** (`$windowed_slack_sum` / `$cusum_drift_score >= 3.0`, `$drift_days >= 2`) over a multi-day Mode B window against each endpoint's 30-day `metrics.network_bytes_outbound` baseline. Stage 1 extracts daily outbound bytes and 30-day `metrics.network_bytes_outbound` moments; Stage 2 applies the empirical fleet byte floor (`44979.0` bytes), enforces the 7-active-day maturity gate (`$active_days >= 7`), and computes positive daily slack excess $\max(0, Z_t - 0.5)$; and the Root Stage sums positive drift increments across days ($W \ge S_t$, acting as a lossless multi-day prefilter; true recursive Page's $S_t$ with zero-day reset reconstruction is evaluated via `cusum_helper.py` over $\le 14\text{d}$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-and-slow multi-day data exfiltration drips that stay below single-day thresholds via Windowed Slack Sum (Longitudinal CUSUM prefilter) on 30-day outbound network bytes.
// Statistical Model: LONGITUDINAL_CUSUM — 3-Stage Multi-Day Cumulative Drift / Windowed Slack Sum (cusum_drift_score >= 3.0, drift_days >= 2, k = 0.5 sigma slack)
// ARCHITECTURE: 3-STAGE WINDOWED SLACK SUM (LONGITUDINAL CUSUM PREFILTER)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Outbound Network Bytes & 30d Historical Baseline
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    $sent = network.sent_bytes

  match:
    $entity by 1d

  outcome:
    $observed_val = sum($sent)
    $observed_connections = count(metadata.id)
    $distinct_dest_ips = count_distinct(target.ip)
    $distinct_dest_ports = count_distinct(target.port)

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

// Stage 2: Daily Standardized Slack-Excess Drift Extraction — Windowed Slack Sum Prefilter (by 1d)
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

    // Standardized daily drift with 44979.0 byte floor and k = 0.5 sigma slack; < 7 active days contributes 0.0
    $raw_drift = $observed - $hist_avg
    $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
    $daily_z = $raw_drift / $safe_stddev
    $z_minus_slack = $daily_z - 0.5
    $daily_excess = if($active_days >= 7 and $z_minus_slack > 0, $z_minus_slack, 0.0)
}

// Stage 3 (Root Stage): Multi-Day Windowed Slack Sum Aggregation Across Window
$entity = $stage2_daily_drift.entity

match:
  $entity

outcome:
  $observed = sum($stage2_daily_drift.observed)
  $peak_daily_observed = max($stage2_daily_drift.observed)
  $hist_avg = max($stage2_daily_drift.hist_avg)
  $hist_stddev = max($stage2_daily_drift.hist_stddev)
  $active_days = max($stage2_daily_drift.active_days)
  $hist_max = max($stage2_daily_drift.hist_max)

  // Windowed Slack Sum W = sum(max(0, Z_t - 0.5)) across daily buckets in the evaluation window
  $cusum_drift = sum($stage2_daily_drift.daily_excess)
  $windowed_slack_sum = $cusum_drift
  $cusum_drift_score = $cusum_drift
  $drift_days = sum(if($stage2_daily_drift.daily_excess > 0, 1, 0))
  $max_daily_z = max($stage2_daily_drift.daily_z)

condition:
  $active_days >= 7
  and $cusum_drift_score >= 3.0
  and $drift_days >= 2

order:
  $cusum_drift_score desc
```

#### Query 4B: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Cloud Resource Access Volume (`secops-statistical-hunter`)
Eliminates fixed correlation windows between initial cloud login (`T1078.004`) and storage/secret collection (`T1530`) by scoring each user's daily resource access volume (`RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `RESOURCE_WRITTEN`) against their own non-parametric **Median Absolute Deviation (MAD)** baseline ($M_Z > 3.5$, gated at `$baseline_active_samples >= 7` active days). Because the median and MAD have a 50% breakdown point—backed by the Iglewicz-Hoaglin MeanAD fallback (`1.253314 * $baseline_mean_abs_dev`) when `MAD = 0`—a compromised account hoarding storage objects days after initial access is scored without outlier self-masking.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous post-compromise cloud storage and resource access hoarding per user via 4-stage Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, USER_RESOURCE_ACCESS, RESOURCE_WRITTEN)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (M_Z > 3.5)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily observed cloud resource access volume per user
stage daily_stats {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
      or metadata.event_type = "RESOURCE_WRITTEN"
    )
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $daily_value = count(metadata.id)
    $read_events = sum(if(metadata.event_type = "RESOURCE_READ", 1, 0))
    $access_events = sum(if(metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $write_events = sum(if(metadata.event_type = "RESOURCE_WRITTEN", 1, 0))
    $distinct_sample_values = count_distinct(target.resource.name)
    $sample_data = array_distinct(target.resource.name)
}

// Stage 2: Baseline median of daily resource access events per user (active days only)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, mean absolute deviation (MAD=0 fallback), and active day count per user
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

// Root Stage: Modified Z-Score per user-day and the 6 Core Evidence Pillars
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

  // Robust scale with Iglewicz-Hoaglin MAD=0 fallback (precomputed branches for Malachite if())
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 25
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

---

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` UDM Loopback)

* **Curated Detection Operational Focus**: Short-window correlation of discrete upstream rule firings.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral composite queries over a 7-day horizon (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean squared Z-norm ($\sum Z_i^2 \ge 25.0$) and pivots directly into raw endpoint, network, authentication, and cloud telemetry.

Individual behavioral queries in Scenarios 1–4 can fire inside ambiguous operational overlap regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud resource names.

**Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** (`1A, 2A, 3A, 3B, 4A, 4B`) and **Wave 2** (`1B, 2B`) hunts have written their matches to Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Per-Scenario Deduplication (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events using the hierarchical scenario regex (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario hits (`$distinct_scenarios_matched >= 2`, `LOOPBACK_MIN_DISTINCT_HITS`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 25.0`, `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Separates per-domain raw event counts (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ` / `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins them in Root alongside the Euclidean $L_2$ Z-score `$capstone_threat_score = math.sqrt($capstone_threat_norm_sq)`.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Scenarios 1 through 4B via UDM Loopback regex union while joining raw telemetry for forensic attribution.
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
    // Optional high-priority watchlist Data Table filter (uncomment after populating %composite_hunt_watchlist; unpopulated tables break compilation):
    // $entity in %composite_hunt_watchlist.entity

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
    $login_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
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
  $login_events = max($stage3_raw_forensic_pivot.login_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_score desc
```

---

## 4. Stage-Budget Optimization: 4-Stage Quantile/Bowley Skewness Fence + Rare Domain Entity Context Graph (`secops-risk-metrics-multistage`)

True Median Absolute Deviation (`MAD`) requires 2 intermediate stages (`median_stats` $\to$ `mad_stats`), consuming 3 named stages and leaving no room to combine a multi-day baseline, a secondary Stage 2 envelope, and an Entity Context Graph (`DERIVED_CONTEXT`) stage when stage budgets are tight. Using `window.percentile(expr, P)`, `stage quantile_envelope` computes `$q25, $q50, $q75`, Bowley quartile skewness (`$bowley_skew`), and the Hubert-Vandervieren skewness-adjusted Tukey upper fence (`$adj_upper_fence = $q75 + 1.5 * exp(1.35 * max(0, $bowley_skew)) * $safe_iqr`) in **1 intermediate stage**, freeing Stage 3 to join `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3`, `day_count = 10`). When executed over a multi-day quantile baseline window (or anchored back to `D-2` for `DERIVED_CONTEXT` snapshot coverage), `$in_scoring_window` pins scored alerts to the target UTC day (`"2026-10-29"`):

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Hunt for outbound byte surges that breach the Skewness-Adjusted Tukey Fence and contact rare external domains (<= 3 hosts) via 1-stage window.percentile + DERIVED_CONTEXT.
// Statistical Model: 4-Stage Non-Parametric Quantiles, Bowley Skewness (1.35) & Skew-Adjusted Tukey Excess Z (tukey_excess_z >= 1.0) + DERIVED_CONTEXT Rare Domain Sieve (rolling_max <= 3, day_count = 10)
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
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $raw_active_days = count_distinct($stage1_extract.window_start)
    $iqr = $q75 - $q25
    $q50_floor = $q50 * 0.05 + 1.0
    $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
    $bowley_skew = ($q75 + $q25 - (2.0 * $q50)) / $safe_iqr
    $pos_skew = if($bowley_skew > 0, $bowley_skew, 0.0)
    $adj_upper_fence = $q75 + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
    $robust_scale = $safe_iqr / 1.349
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
  $peak_rare_domain_bytes = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $hist_active_days = max($stage1_extract.historical_active_days)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)
  $min_domain_prevalence = min($stage3_rare_domain.domain_prevalence)
  $rare_domains = array_distinct($domain)

  $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
  $raw_personal_z = ($observed - $hist_avg) / $safe_stddev
  $personal_z = if($hist_active_days >= 7, $raw_personal_z, 0.0)

  $adj_upper_fence = max($quantile_envelope.adj_upper_fence)
  $robust_scale = max($quantile_envelope.robust_scale)
  $tukey_excess_z = ($peak_rare_domain_bytes - $adj_upper_fence) / $robust_scale

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
