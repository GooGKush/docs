# Extending Google SecOps Risk Analytics for UEBA with Multi-Stage Behavioral Models

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Risk Analytics for UEBA** curated rule pack leverages pre-computed 30-day behavioral metrics (`metrics.*`) and entity context to detect anomalous network byte transfers, authentication spikes, newly active accounts or hosts, multi-alert escalation, and process-driven data exfiltration.

This runbook extends single-stage `metrics.*` detections into **Multi-Stage Behavioral Pipelines** (`secops-risk-metrics-multistage` on the 30-day `metrics.*` macro plane and `secops-statistical-hunter` on the raw-telemetry micro plane). Every query enforces the remediated harness contracts:
* **Dispersion Floors & 7-Day Maturity Gates**: Replaces legacy `sigma -> 1.0` fallbacks with domain-calibrated dispersion floors—`max(sigma, math.sqrt(max(mu, 1.0)))` for count metrics and empirical fleet byte floors (`44979.0` bytes for `metrics.network_bytes_outbound`)—paired with a 7-active-day baseline maturity gate (`DEFAULT_MIN_BASELINE_DAYS = 7`) so sparse baselines never inflate Z-scores.
* **Heavy-Tailed & Sequential Drift Estimators**: Combines **4-Stage Non-Parametric Median Absolute Deviation (MAD)** (`window.median(..., false)`), **3-Stage Empirical Quantiles with Hubert–Vandervieren Skew-Adjusted Tukey Fences**, and **Multi-Day Windowed Slack Sum** (`W = sum(max(0, Z_t - 0.5))`) to catch both single-day exfiltration spikes masked by historical backup variance and multi-day low-and-slow drip exfiltration.
* **Union-Spine Multi-Sector Fusion & Multiplicity Adjustment**: Uses single-stage union spines and K-key Gaussian expected-maximum offsets (`math.sqrt(2.0 * math.log($k_eff))`) so single-sector outliers survive when a companion sector is quiet today.
* **Leave-One-Out Empirical Bayes & Two-Part Hurdle Regularization**: Applies leave-one-out **Beta-Binomial** failure-rate standardization, **Gamma-Poisson** conjugate shrinkage with empirical excess overdispersion, and **Two-Part Hurdle** dormant-awakening gates over raw UDM events.
* **Python-Calibrated Risk Index (`CRI`)**: Queries emit Z or Z-equivalent statistical scores directly; `agentic_ueba` computes the `[0, 100]` Calibrated Risk Index in Python (`ueba_constants.calculate_cri`) rather than embedding piecewise CRI ladders inside YARA-L.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond single-stage window and estimator constraints through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba`:
  1. **Wave 1 — Macro `metrics.*` Baselines, Entity Graph Joins & Pre-Filtered Hurdle Hunts (`Queries 1A, 1B, 1C, 2A, 3A, 3B, 4A, 5A`)**: Executes `by 1d` `metrics.*` pipelines, `DERIVED_CONTEXT` Entity Graph joins, and daily Two-Part Hurdle evaluations concurrently. Standard Mode A evaluations score the last complete UTC day `D` (`startTime = D T00:00:00Z`, `endTime = D+1 T00:00:00Z` against `[D-30, D)` `metrics.*` baselines); Mode A Entity Graph joins widen the search window to `startTime = D-2 T00:00:00Z` to cover daily graph snapshot lag while pinning each event stage to `"YYYY-MM-DD"` (`timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"`). Every match is written back to Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Micro Queries (`Option 3` Stage B Loopback: `Queries 2B, 4B, 5B`)**: After `PlaybookRunner` flushes Wave 1 findings and verifies UDM indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` pipelines join `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to scope hourly (`by 1h`) Leave-One-Out Beta-Binomial, Personal Z, and Gamma-Poisson shrinkage models without hitting enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`), deduplicates per `(entity, scenario_tag)` in Stage 1, enforces cross-scenario $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, authentication, and cloud telemetry in Stage 3.

### 1.2 Optional Customization: Scoping Hunts with a SecOps Data Table (`%ueba_hunt_bridge`)

Security operations teams frequently maintain watchlists or candidate bridge tables (such as high-value crown-jewel hosts, privileged identities, or offboarding cohorts) in a SecOps **Data Table** (`%ueba_hunt_bridge`).

> [!TIP]
> **Why Data Table References Are Commented Out by Default**: In Google SecOps YARA-L 2.0, referencing a Data Table (`%ueba_hunt_bridge.hostname`) that has not yet been created and populated in `<PROJECT_ID>` / `<CUSTOMER_ID>` causes an immediate query compilation failure. To ensure all 12 queries compile and run out-of-the-box across any tenant, every Data Table filter in this runbook is commented out with an explanatory note (`// $entity in %ueba_hunt_bridge.hostname` or `// $entity in %ueba_hunt_bridge.userid`). Uncomment those lines only after creating `%ueba_hunt_bridge` in your tenant.

### Table 1: Scenario Coverage Matrix — Risk Analytics for UEBA & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Network Byte Volume Anomalies (Outbound Exfiltration & Multi-Day Drift)** | Single-stage 30-day metric baseline checks on entity network byte volume (`metrics.network_bytes_*`). | Replaces parametric $\mu + k\sigma$ gates that suffer from backup/weekend variance masking with 4-stage Median Absolute Deviation (`MAD`), multi-day **Windowed Slack Sum** drift accumulation, and 3-stage **Bowley Skew-Adjusted Tukey Fences** using a `44979.0` B dispersion floor and 7-day maturity gate. | `Query 1A` (4-Stage 30d MAD Modified Z)<br>`Query 1B` (Windowed Slack Sum Drift)<br>`Query 1C` (3-Stage Skew-Adjusted Tukey Fence) |
| **2. Authentication Spikes & Brute-Force-to-Success Chains** | Single-stage baseline checks on authentication attempts and failed-login counts (`metrics.auth_attempts_*`). | Fuses 30-day Auth Failure + Auth Success baselines in a single-stage union ($D^2 \ge 12.25$, preserving single-sector bursts) and gates an hourly Leave-One-Out **Beta-Binomial** predictive failure-rate Z-score (`Query 2B`) via UDM Loopback. | `Query 2A` (Single-Stage Union Auth Fail + Success Fusion)<br>`Query 2B` (UDM-Gated LOO Beta-Binomial Failure Z) |
| **3. Recently Onboarded Hosts & Dormant Identity Activation** | Detects newly active accounts or authentication surges on recently introduced endpoints. | Scores 30-day host login surges enriched with `DERIVED_CONTEXT` asset `first_seen_time` (`Query 3A`) and pairs it with a raw-event **Two-Part Hurdle** model (`Query 3B`) separating dormant account awakening ($\ge 10$ logins on $\le 7$ active days) from LOO intensity Z-scores (replacing retired city-centroid geo-velocity and circular von Mises models). | `Query 3A` (2-Stage 30d Host Auth + `DERIVED_CONTEXT` Asset Age)<br>`Query 3B` (2-Stage Two-Part Identity Hurdle) |
| **4. Multi-Alert Entity Risk & Cross-Sector Escalation** | Aggregates security alerts per entity over a 30-day metric window (`metrics.alert_event_name_count`). | Rolls up per-rule 30-day alert Z-scores with a $\sqrt{2\ln K_{\text{eff}}}$ multiplicity offset, fuses them with 30-day outbound network bytes ($D^2 \ge 12.25$), and gates an hourly Leave-One-Out personal alert Z-score (`Query 4B`) via UDM Loopback. | `Query 4A` (4-Stage Roll-Up Alert + Egress Fusion)<br>`Query 4B` (UDM-Gated LOO Hourly Personal Alert Z) |
| **5. Process-Driven Data Exfiltration & Rare Binary Execution** | Correlates process execution with external reputation context and outbound network data transfers. | Combines 30-day per-(host, SHA256) execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` organizational prevalence (`rolling_max <= 3`), gating an hourly Leave-One-Out **Gamma-Poisson** network egress shrinkage model (`Query 5B`). | `Query 5A` (2-Stage 30d File Execution + 10d Prevalence)<br>`Query 5B` (UDM-Gated LOO Gamma-Poisson Egress Z) |
| **6. Capstone Multi-Scenario Risk Analytics Convergence** | Individual risk metric rules contributing independent risk scores. | Correlates entities matching $\ge 2$ distinct UEBA scenarios within the active `run_id` (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) with squared $L_2$ norm $\sum Z_i^2 \ge 25.0$ and bridges directly into raw endpoint, network, auth, and cloud telemetry. | `Query 6` (3-Stage UDM Loopback $L_2$ Convergence + Raw Forensic Bridge) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Upgrading Network Byte Anomaly Rules

* **Curated Detection Operational Focus**: Single-stage 30-day metric baseline checks on entity network byte volume (`metrics.network_bytes_*`).
* **How Multi-Stage UEBA Extends Coverage**: Replaces single-stage Gaussian thresholds with three complementary estimators over `network.sent_bytes` (`principal.asset.hostname`) backed by the `44979.0`-byte `network_bytes_outbound` dispersion floor and a 7-active-day maturity requirement:
  1. `Query 1A` computes a **4-stage Median Absolute Deviation (MAD) Modified Z-Score** (`$modified_z >= 3.5`) alongside a pre-scoring active-day classical Z-score (`$classical_z`) so historical burst masking (`$z_gap = $modified_z - $classical_z`) is directly observable.
  2. `Query 1B` computes a multi-day **Windowed Slack Sum** (`$windowed_slack_sum = sum(max(0, Z_t - 0.5)) >= 4.0` across `>= 2` drift days) over Mode B multi-day windows as a stateless lossless upper-bound prefilter (`S_t <= W`) for longitudinal CUSUM exfiltration drift.
  3. `Query 1C` computes a **3-stage 5-point empirical quantile envelope** (`window.percentile` at $P_{10}, Q_{25}, Q_{50}, Q_{75}, P_{90}$), Bowley quartile skewness, Moors tail-heaviness ratio, and the Hubert–Vandervieren skewness-adjusted Tukey upper fence (`1.35` Bowley exponent, `$tukey_excess_z >= 1.0`), saving one stage relative to 4-stage MAD.

#### Query 1A: 4-Stage Robust Modified Z-Score (30-Day MAD) on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Scores daily outbound network bytes from `first_scored_date` (`"2026-10-29"` in Mode A) against the entity's active-day median and MAD across the raw lookback window (`~30d` in production; compiles cleanly on single-day Mode A windows as well), falling back to `1.253314 * MeanAD` when `MAD = 0` and comparing against pre-scoring classical Z with the `44979.0` B byte floor.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous outbound network byte exfiltration per host using a 4-stage non-parametric Median Absolute Deviation (MAD) Modified Z-Score that resists historical burst masking.
// Statistical Model: 4-Stage Robust Modified Z-Score (True Median Absolute Deviation vs. Pre-Scoring Classical Z)
// ARCHITECTURE: 4-STAGE ROBUST MODIFIED Z-SCORE (TRUE MEDIAN ABSOLUTE DEVIATION)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Byte Extraction & 30-Day Metrics Provenance Lookup
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.hostname

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-29", 1, 0))
    $obs_float = 1.0 * $observed_val
    $pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)
    $pre_obs_sq = $pre_obs * $pre_obs
    $pre_day = if($in_scoring_window = 0, 1, 0)
    $observed_events = count(metadata.id)

    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

// Stage 2: Non-Parametric Median Center & Pre-Scoring Active-Day Sums
stage mad_center {
    $entity = $stage1_extract.entity

  match:
    $entity

  outcome:
    $median_val = window.median($stage1_extract.observed_val, false)
    $raw_active_days = count_distinct($stage1_extract.window_start)
    $pre_n = sum($stage1_extract.pre_day)
    $pre_sum = sum($stage1_extract.pre_obs)
    $pre_sum_sq = sum($stage1_extract.pre_obs_sq)
    $historical_active_days = max($stage1_extract.historical_active_days)
}

// Stage 3: Median Absolute Deviation (MAD), MeanAD & Pre-Scoring Sample SD with Byte Floor
stage mad_spread {
    $entity = $stage1_extract.entity
    $entity = $mad_center.entity

  match:
    $entity

  outcome:
    $mad = window.median(math.abs($stage1_extract.observed_val - $mad_center.median_val), false)
    $mean_abs_dev = avg(math.abs($stage1_extract.observed_val - $mad_center.median_val))
    $median_val = max($mad_center.median_val)
    $raw_active_days = max($mad_center.raw_active_days)
    $pre_n = max($mad_center.pre_n)
    $pre_sum = max($mad_center.pre_sum)
    $pre_sum_sq = max($mad_center.pre_sum_sq)
    $safe_pre_n = if($pre_n > 0, $pre_n, 1.0)
    $pre_avg = $pre_sum / $safe_pre_n
    $pre_df_raw = $pre_n - 1.0
    $safe_pre_df = if($pre_n > 1, $pre_df_raw, 1.0)
    $raw_var_num = $pre_sum_sq - ($pre_n * $pre_avg * $pre_avg)
    $pos_var_num = if($raw_var_num > 0.0, $raw_var_num, 0.0)
    $pre_sd = math.sqrt($pos_var_num / $safe_pre_df)
    $safe_pre_sd = if($pre_sd > 44979.0, $pre_sd, 44979.0)
}

// Root Stage: Robust Modified Z (MAD) vs. Pre-Scoring Classical Z
$entity = $stage1_extract.entity
$entity = $mad_spread.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($mad_spread.pre_avg)
  $hist_stddev = max($mad_spread.pre_sd)
  $active_days = max($mad_spread.pre_n)
  $median_val = max($mad_spread.median_val)
  $mad = max($mad_spread.mad)
  $mean_abs_dev = max($mad_spread.mean_abs_dev)
  $raw_active_days = max($mad_spread.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)

  // 1. Pre-scoring raw active-day Z (cross-check for historical burst masking)
  $safe_stddev = max($mad_spread.safe_pre_sd)
  $raw_classical_z = ($observed - $hist_avg) / $safe_stddev
  $classical_z = if($active_days >= 7, $raw_classical_z, 0.0)

  // 2. Robust scale with Iglewicz-Hoaglin MAD=0 fallback and flat-history floor
  $scale_from_mad = $mad / 0.6745
  $scale_from_meanad = $mean_abs_dev * 1.253314
  $robust_scale = if($mad > 0, $scale_from_mad, $scale_from_meanad)
  $median_floor = $median_val * 0.05 + 1.0
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, $median_floor)

  // 3. Modified Z-score and outlier-masking gap
  $modified_z = ($observed - $median_val) / $safe_robust_scale
  $z_gap = $modified_z - $classical_z

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $modified_z >= 3.5

order:
  $modified_z desc
```

#### Query 1B: Windowed Slack Sum (Longitudinal CUSUM Prefilter) on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Accumulates positive daily standardized excesses above a $k = 0.5\sigma$ slack reference ($W = \sum \max(0, Z_t - 0.5) \ge 4.0$ across $\ge 2$ drift days) on mature hosts (`$active_days >= 7`) using the `44979.0` B byte dispersion floor. Because stateless YARA-L sums positive daily slack increments without day-to-day reset (`S_t = max(0, S_{t-1} + Z_t - k)`), this query operates over multi-day Mode B windows (2–14 days) as a lossless upper-bound prefilter (`S_t <= W`) for sequential CUSUM drift.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-and-slow multi-day outbound network exfiltration drift per host using a Windowed Slack Sum prefilter over 30-day metrics.network_bytes_outbound baselines.
// Statistical Model: Windowed Slack Sum (Longitudinal CUSUM Prefilter, windowed_slack_sum >= 4.0, drift_days >= 2, active_days >= 7)
// ARCHITECTURE: WINDOWED SLACK SUM (LONGITUDINAL CUSUM PREFILTER) PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Byte Extraction & 30-Day Metrics Baseline Lookup
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.hostname

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
}

// Stage 2: Per-Day Standardized Slack Excess (k = 0.5 sigma, 44979.0 B byte floor, 7-day maturity gate)
stage daily_slack {
    $entity = $stage1_extract.entity
    $ws = $stage1_extract.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $observed_val = max($stage1_extract.observed_val)
    $historical_avg = max($stage1_extract.historical_avg)
    $historical_stddev = max($stage1_extract.historical_stddev)
    $historical_active_days = max($stage1_extract.historical_active_days)
    $safe_stddev = if($historical_stddev > 44979.0, $historical_stddev, 44979.0)
    $daily_z = ($observed_val - $historical_avg) / $safe_stddev
    $deviation = $daily_z - 0.5
    $daily_excess = if($historical_active_days >= 7 and $deviation > 0.0, $deviation, 0.0)
}

// Root Stage: Multi-Day Windowed Slack Sum Across Active Days
$entity = $daily_slack.entity

match:
  $entity

outcome:
  $observed_val = max($daily_slack.observed_val)
  $baseline_mean = max($daily_slack.historical_avg)
  $baseline_stddev = max($daily_slack.historical_stddev)
  $active_days = max($daily_slack.historical_active_days)

  // 1. Peak daily standardized shift across the multi-day evaluation window
  $daily_z = max($daily_slack.daily_z)

  // 2. Windowed Slack Sum of positive daily drift increments above k = 0.5 sigma
  $slack_excess = sum($daily_slack.daily_excess)
  $windowed_slack_sum = $slack_excess
  $cusum_drift_score = $windowed_slack_sum
  $drift_days = sum(if($daily_slack.daily_excess > 0.0, 1, 0))

condition:
  $active_days >= 7 and $cusum_drift_score >= 4.0 and $drift_days >= 2

order:
  $cusum_drift_score desc
```

#### Query 1C: 3-Stage Empirical Quantiles (`window.percentile`), Bowley Skewness & Skew-Adjusted Tukey Fence (`secops-risk-metrics-multistage`)

Whereas `Query 1A` (`mad_robust_z_4stage.yl2`) uses two intermediate stages (`mad_center` $\to$ `mad_spread`) to compute nested `window.median(math.abs(x - median), false)`, `quantile_iqr_skew_3stage.yl2` computes all five empirical quantiles (`$p10, $q25, $q50, $q75, $p90`) in a single intermediate stage (`stage quantile_envelope`). It evaluates **Bowley Quartile Skewness**, **Moors Tail-Heaviness Ratio**, and the **Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence** (`1.35` Bowley exponent), scoring exceedance in robust scale units (`$tukey_excess_z = ($observed - $adj_upper_fence) / ($safe_iqr / 1.349) >= 1.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect right-skewed outbound network byte spikes per host using 1-stage empirical quantiles, Bowley skewness, and the Hubert-Vandervieren skew-adjusted Tukey upper fence.
// Statistical Model: 3-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Fence (tukey_excess_z >= 1.0)
// ARCHITECTURE: 3-STAGE NON-PARAMETRIC QUANTILES, BOWLEY SKEWNESS & SKEW-ADJUSTED TUKEY FENCE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Byte Extraction & 30-Day Metrics Provenance Lookup
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.hostname

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-29", 1, 0))
    $obs_float = 1.0 * $observed_val
    $pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)
    $pre_obs_sq = $pre_obs * $pre_obs
    $pre_day = if($in_scoring_window = 0, 1, 0)
    $observed_events = count(metadata.id)

    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

// Stage 2: 5-Point Empirical Quantile Envelope & Pre-Scoring Sample Statistics
stage quantile_envelope {
    $entity = $stage1_extract.entity

  match:
    $entity

  outcome:
    $p10 = window.percentile($stage1_extract.observed_val, 10)
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $p90 = window.percentile($stage1_extract.observed_val, 90)
    $raw_active_days = count_distinct($stage1_extract.window_start)
    $pre_n = sum($stage1_extract.pre_day)
    $pre_sum = sum($stage1_extract.pre_obs)
    $pre_sum_sq = sum($stage1_extract.pre_obs_sq)
    $historical_active_days = max($stage1_extract.historical_active_days)
    $safe_pre_n = if($pre_n > 0, $pre_n, 1.0)
    $pre_avg = $pre_sum / $safe_pre_n
    $pre_df_raw = $pre_n - 1.0
    $safe_pre_df = if($pre_n > 1, $pre_df_raw, 1.0)
    $raw_var_num = $pre_sum_sq - ($pre_n * $pre_avg * $pre_avg)
    $pos_var_num = if($raw_var_num > 0.0, $raw_var_num, 0.0)
    $pre_sd = math.sqrt($pos_var_num / $safe_pre_df)
    $safe_pre_sd = if($pre_sd > 44979.0, $pre_sd, 44979.0)
}

// Root Stage: Skewness-Adjusted Tukey Fence & Robust Scale-Excess vs. Pre-Scoring Classical Z
$entity = $stage1_extract.entity
$entity = $quantile_envelope.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $active_days = max($quantile_envelope.pre_n)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)

  // 1. Pre-scoring raw active-day Z cross-check
  $safe_stddev = max($quantile_envelope.safe_pre_sd)
  $raw_classical_z = ($observed - max($quantile_envelope.pre_avg)) / $safe_stddev
  $classical_z = if($active_days >= 7, $raw_classical_z, 0.0)

  // 2. Non-parametric IQR, Bowley quartile skewness & Moors tail-heaviness ratio
  $iqr = $q75_val - $q25_val
  $q50_floor = $q50_val * 0.05 + 1.0
  $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $tail_heaviness = (max($quantile_envelope.p90) - max($quantile_envelope.p10)) / $safe_iqr

  // 3. Hubert-Vandervieren Skewness-Adjusted Tukey Upper Fence (Bowley 1.35) & Z-equivalent excess
  $pos_skew = if($bowley_skew > 0.0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
  $robust_scale = $safe_iqr / 1.349
  $tukey_excess_z = ($observed - $adj_upper_fence) / $robust_scale
  $z_score = $tukey_excess_z

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0

order:
  $tukey_excess_z desc
```

---

### Scenario 2: Upgrading Authentication & Brute-Force Rules

* **Curated Detection Operational Focus**: Single-stage baseline checks on authentication attempts and failed-login counts (`metrics.auth_attempts_*`).
* **How Multi-Stage UEBA Extends Coverage**: Combines a macro single-stage union fusion of 30-day failed and successful login baselines (`Query 2A`, $D^2 \ge 12.25$ with Poisson count floors and 7-day maturity gates) with an inline Wave 2 UDM-gated Leave-One-Out **Beta-Binomial** hourly failure-rate standardization (`Query 2B`). Note that because `auth_attempts_fail` and `auth_attempts_success` both measure authentication activity, concurrent login volume surges correlate across both dimensions; `Query 2B` resolves that ambiguity by testing whether the candidate's hourly failure proportion significantly exceeds its leave-one-out `Beta(1.0, 19.0)` predictive distribution.

#### Query 2A: Single-Stage Union Dual-Sector Authentication Failures + Successes Fusion (`secops-risk-metrics-multistage`)
Evaluates `metrics.auth_attempts_fail` and `metrics.auth_attempts_success` (`target.user.userid`) inside a single union stage (`sector_union`) so accounts with pure failure bursts (`$b_observed = 0`) or pure session-compromise login surges (`$a_observed = 0`) are never dropped by an inner join. Each sector enforces a `math.sqrt(max(mu, 1.0))` Poisson count floor, positive rectification, and a `>= 7` active-day baseline gate before computing $D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ADVISORY: 'auth_attempts_fail' and 'auth_attempts_success' are both auth metrics. They are likely correlated, so the fused distance will overweight that one behavior.
// Goal: Detect brute-force-to-success progression and single-sector authentication surges per user by fusing 30-day failed and successful login baselines without inner-join drop.
// Statistical Model: Dual-Sector Threat Fusion (Single-Stage Union, D_sq = Z_fail_sq + Z_success_sq >= 12.25, active_days >= 7)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (GENERIC SINGLE-STAGE UNION: ANY TWO ENTITY-KEYED METRICS)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Single-Stage Sector Union (UDM Source 1 of 2; preserves single-sector outliers) ---
stage sector_union {
    ((metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW") or (metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW"))
    target.user.userid = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.userid

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if(metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW", 1, 0))
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

    $b_obs = sum(if(metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW", 1, 0))
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

// --- ROOT STAGE: Dual-Sector Threat Fusion & Distance Scoring ---
$entity = $sector_union.entity
$ws = $sector_union.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_union.a_obs)
  $a_mean = max($sector_union.a_avg)
  $a_stddev = max($sector_union.a_std)
  $a_active_days = max($sector_union.a_days)
  $a_floor = math.sqrt(if($a_mean > 1.0, $a_mean, 1.0))
  $safe_a_std = if($a_stddev > $a_floor, $a_stddev, $a_floor)
  $z_a_raw = ($a_observed - $a_mean) / $safe_a_std
  $z_a_pos = if($z_a_raw > 0.0, $z_a_raw, 0.0)
  $z_a_gated = if($a_observed > 0 and $a_active_days >= 7, $z_a_pos, 0.0)

  $b_observed = max($sector_union.b_obs)
  $b_mean = max($sector_union.b_avg)
  $b_stddev = max($sector_union.b_std)
  $b_active_days = max($sector_union.b_days)
  $b_floor = math.sqrt(if($b_mean > 1.0, $b_mean, 1.0))
  $safe_b_std = if($b_stddev > $b_floor, $b_stddev, $b_floor)
  $z_b_raw = ($b_observed - $b_mean) / $safe_b_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b_gated = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $composite_threat_norm_sq = ($z_a_gated * $z_a_gated) + ($z_b_gated * $z_b_gated)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 2B: 4-Stage UDM-Gated Leave-One-Out Beta-Binomial Authentication Failure Rate (`secops-statistical-hunter`)
Evaluates hourly authentication failure-rate surges strictly on candidate identities surfaced by `Query 2A` via Wave 2 UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`). Updates a `Beta(1.0, 19.0)` hyperprior (~5% baseline failure rate) with each user's leave-one-out prior failures and successes, then standardizes the current hour's failed logins (`BLOCK` or `FAIL`) against the exact Beta-Binomial predictive variance $n p_0 (1 - p_0) \frac{M + n}{M + 1}$ (`$fail_z >= 3.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT BETA-BINOMIAL AUTH FAILURE RATE PIPELINE
// Goal: Detect sub-day credential stuffing and brute-force failure-rate surges on candidate identities from Query 2A using leave-one-out Beta-Binomial predictive standardization.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Beta-Binomial Predictive Failure Z-Score ($fail_z >= 3.0)
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
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $user in %ueba_hunt_bridge.userid

  match:
    $user

  outcome:
    $upstream_2a_z = max(security_result.confidence_score)
}

stage hourly_auth_stats {
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

stage user_prior_stats {
    $user = $hourly_auth_stats.user

  match:
    $user

  outcome:
    $total_historical_events = sum($hourly_auth_stats.total_trials)
    $total_historical_fails = sum($hourly_auth_stats.failed_trials)
    $active_hours = count($hourly_auth_stats.window_start)
}

$user = $stage1_upstream_2a_candidates.user
$user = $hourly_auth_stats.user
$user = $user_prior_stats.user
$ws = $hourly_auth_stats.window_start

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($hourly_auth_stats.failed_trials)
  $hourly_trials_count = max($hourly_auth_stats.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1)
  $baseline_active_samples = max($user_prior_stats.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($hourly_auth_stats.distinct_sources)

  // Leave-One-Out Beta(1.0, 19.0) Prior & Beta-Binomial Predictive Standardization
  $raw_prior_fails = max($user_prior_stats.total_historical_fails) - $observation_count
  $prior_fails = if($raw_prior_fails > 0, $raw_prior_fails, 0)
  $raw_prior_events = max($user_prior_stats.total_historical_events) - $hourly_trials_count
  $prior_events = if($raw_prior_events > $prior_fails, $raw_prior_events, $prior_fails)
  $alpha_prior = 1.0 + $prior_fails
  $prior_total = 20.0 + $prior_events
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

### Scenario 3: Upgrading Recently Onboarded Host & Dormant Identity Rules

* **Curated Detection Operational Focus**: Detects newly active accounts or authentication activity on newly introduced devices.
* **How Multi-Stage UEBA Extends Coverage**: Pairs a **2-stage hybrid 30-day host authentication + `DERIVED_CONTEXT` asset age pipeline** (`Query 3A`) with a **Two-Part Hurdle model on raw `USER_LOGIN` events** (`Query 3B`). City-centroid geo-velocity (`IMPOSSIBLE_TRAVEL`) and circular von Mises off-hours models (`CIRCADIAN_VON_MISES`) are retired due to VPN egress and bimodal schedule false positives; for temporal schedule anomalies, use empirical `HOUR_OF_DAY_PROFILE`, and for newly active assets or dormant accounts, combine `DERIVED_CONTEXT` first-seen age with Two-Part Hurdle volume gates.

#### Query 3A: 2-Stage Hybrid 30-Day Host Authentication + `DERIVED_CONTEXT` Asset Age (`secops-risk-metrics-multistage`)
Scores 30-day host login volume (`metrics.auth_attempts_total` with `math.sqrt(max(mean, 1.0))` Poisson count floor and `$active_days >= 7`) and inner-joins Chronicle `DERIVED_CONTEXT` (`ASSET`) `first_seen_time` to isolate recently onboarded endpoints (`$asset_age_days <= 30.0`, applying a $1.5\times$ boost when $\le 14$ days old and $2.5\times$ if $\le 7$ days old). In Mode A, run with `startTime = 2026-10-27T00:00:00Z` (`D-2`) and `endTime = 2026-10-30T00:00:00Z` (`D+1`) while `stage1_asset_baseline` pins raw login events to `"2026-10-29"`; hosts with no `DERIVED_CONTEXT` graph record drop out of the inner join, and true Day-0 assets (`< 7` active days) route to boolean `first_seen` novelty (`first_seen_novelty_2stage.yl2`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Isolate recently onboarded endpoints (<= 30 days old in DERIVED_CONTEXT, >= 7 active baseline days) exhibiting anomalous authentication surges against 30-day host baselines.
// Statistical Model: 2-Stage Hybrid 30d Host Auth Z-Score + DERIVED_CONTEXT Asset Age Multiplier (active_days >= 7, z_score >= 3.0)
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT ASSET AGE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Host Authentication Baseline (pinned to Mode A scored UTC date)
stage stage1_asset_baseline {
    metadata.event_type = "USER_LOGIN"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    $host != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $host in %ueba_hunt_bridge.hostname

  match:
    $host by 1d

  outcome:
    $observed_val = count(metadata.id)

    $hist_mean = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_stddev = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_active_days = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (Asset First Seen; no time predicate)
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

// Root Stage: Fuses Host Anomaly Z-Score with Young/Infant Asset Age Multiplier
$host = $stage1_asset_baseline.host
$host = $stage2_asset_derived_context.host

match:
  $host by 1d

outcome:
  $observed = max($stage1_asset_baseline.observed_val)
  $mean = max($stage1_asset_baseline.hist_mean)
  $stddev = max($stage1_asset_baseline.hist_stddev)
  $dispersion_floor = math.sqrt(if($mean > 1.0, $mean, 1.0))
  $safe_stddev = if($stddev > $dispersion_floor, $stddev, $dispersion_floor)
  $z_score = ($observed - $mean) / $safe_stddev
  $active_days = max($stage1_asset_baseline.hist_active_days)
  $active_baseline_days = $active_days

  $first_seen = min($stage2_asset_derived_context.first_seen_ts)
  $obs_ts = max($stage1_asset_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $asset_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Young/Infant Asset Multiplier (disabled when first_seen_time = 0)
  $ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)
  $is_infant_asset = if($first_seen > 0 and $asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $is_young_asset = if($first_seen > 0 and $asset_age_days <= 14.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $young_mult = if($is_young_asset = 1.0, 1.5, 1.0)
  $threat_multiplier = if($is_infant_asset = 1.0, 2.5, $young_mult)
  $threat_score = $z_score * $threat_multiplier

condition:
  $active_days >= 7
  and $z_score >= 3.0
  and $asset_age_days <= 30.0

order:
  $threat_score desc
```

#### Query 3B: Two-Part Hurdle Outlier Model on User Logins (`secops-statistical-hunter`)
Evaluates `USER_LOGIN` activity per `principal.user.userid` (`by 1d` across a bounded 7–14 day raw window, or `by 1h` on intraday windows) using a **Two-Part Hurdle Model**:
* **Part 1 (Dormant Awakening Gate)**: Accounts with `$baseline_active_samples <= 7` must clear an explicit awakening volume gate (`$observation_count >= 10`) before scoring `3.0 * ($observation_count / 10.0)`, suppressing low-volume trickle noise.
* **Part 2 (Leave-One-Out Positive Intensity Z)**: Accounts with `> 7` active windows are standardized against their leave-one-out mean and variance with a `math.sqrt(max(mean, 1.0))` floor and positive rectification (`max(0, Z)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant or newly active accounts suddenly awakening with high-volume login bursts or mature accounts surging above leave-one-out intensity baselines.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Two-Part Hurdle Outlier Model (Dormant Awakening Volume Gate >= 10 & Positive-Rectified LOO Intensity Z >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily login activity extraction per user (single raw stage)
stage entity_historical {
    metadata.event_type = "USER_LOGIN"
    principal.user.userid = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.userid

  match:
    $entity by 1d

  outcome:
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.user.userid)
    $sample_target = array_distinct(target.user.userid)
}

// Stage 2: Historical moment accumulation across active windows
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

// Root Stage: Two-Part Hurdle Evaluation (Dormant Awakening Gate + LOO Positive Intensity Z)
$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

  // Part 2: Leave-One-Out Continuous Intensity Standardization (Positive-Rectified)
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

  // Part 1: Dormant Awakening Branch (Gated by observation_count >= 10)
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

### Scenario 4: Upgrading Alerts-by-Entity & Multi-Signal Escalation

* **Curated Detection Operational Focus**: Aggregates security alerts per entity over a 30-day metric window (`metrics.alert_event_name_count`).
* **How Multi-Stage UEBA Extends Coverage**: Because `metrics.alert_event_name_count` is a composite-keyed metric (no host-only baseline exists in the compiler), `Query 4A` evaluates per-`(host, security_result.rule_name)` 30-day baselines (`>= 7` active days, Poisson count floor), rolls them up to the host with a Gaussian expected-maximum multiplicity offset (`math.sqrt(2.0 * math.log($k_eff))`), and fuses the adjusted alert score with 30-day outbound network bytes (`44979.0` B byte floor, union spine, $D^2 \ge 12.25$). `Query 4B` then inspects `Query 4A` candidates via Wave 2 UDM Loopback to isolate acute hourly (`by 1h`) Leave-One-Out personal alert spikes.

#### Query 4A: 4-Stage Roll-Up Security Alert + Outbound Network Bytes Fusion (`secops-risk-metrics-multistage`)
Uses a shared union spine across EDR/Graph alert logs (`CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, `SENTINELONE_ALERTS`) and outbound network bytes so single-sector outliers survive when the companion sector has zero events today. Notice that Sector A's score `$z_a` measures whether *any individual alert rule* is unusually elevated on the host after subtracting the K-key expected-maximum offset `math.sqrt(2.0 * math.log($k_eff))`, rather than a host-total alert baseline.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ADVISORY: Sector A rolls alert_event_name_count up from per-(security_result.rule_name) baselines: its Z is the largest per-rule Z for the host after K-key multiplicity adjustment, not a Z of total host alert volume.
// Goal: Fuse multiplicity-adjusted per-rule security alert surges with 30-day outbound network byte anomalies on the same host without dropping single-sector outliers.
// Statistical Model: Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D_sq >= 12.25, active_days >= 7)
// ARCHITECTURE: ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2, union spine): one row per host and alert rule_name ---
stage sector_a_detail {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""
    security_result.rule_name = $security_result_rule_name
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.hostname

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
}

// --- STAGE 2: Sector A per-rule Z-scoring (Poisson floor & 7-active-day gate) ---
stage sector_a_scored {
    $entity = $sector_a_detail.entity
    $security_result_rule_name = $sector_a_detail.security_result_rule_name
    $ws = $sector_a_detail.window_start

  match:
    $entity, $security_result_rule_name, $ws by 1d

  outcome:
    $d_obs = max($sector_a_detail.d_obs)
    $d_avg = max($sector_a_detail.d_avg)
    $d_std = max($sector_a_detail.d_std)
    $d_days = max($sector_a_detail.d_days)
    $d_floor = math.sqrt(if($d_avg > 1.0, $d_avg, 1.0))
    $safe_d_std = if($d_std > $d_floor, $d_std, $d_floor)
    $d_z_raw = ($d_obs - $d_avg) / $safe_d_std
    $d_z_pos = if($d_z_raw > 0.0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

// --- STAGE 3: Sector A host roll-up with K-key expected-maximum multiplicity offset ---
stage sector_a {
    $entity = $sector_a_scored.entity
    $ws = $sector_a_scored.ws

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_scored.d_obs)
    $a_keys = count_distinct($sector_a_scored.security_result_rule_name)
    $a_active_keys = sum($sector_a_scored.d_active)
    $a_hot_keys = sum($sector_a_scored.d_hot)
    $a_novel_keys = sum($sector_a_scored.d_novel)
    $a_days = max($sector_a_scored.d_days)
    $z_a_max = max($sector_a_scored.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

// --- STAGE 4: Sector B — Outbound Network Bytes (UDM Source 2 of 2, union spine) ---
stage sector_b {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "" and network.sent_bytes < 1000000000000000) or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.hostname

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(network.sent_bytes)
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
}

// --- ROOT STAGE: Roll-Up Sector Fusion & Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity
$ws = $sector_a.ws
$ws = $sector_b.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $a_keys = max($sector_a.a_keys)
  $a_hot_keys = max($sector_a.a_hot_keys)
  $a_novel_keys = max($sector_a.a_novel_keys)
  $z_a = max($sector_a.z_a)

  $b_observed = max($sector_b.b_obs)
  $b_mean = max($sector_b.b_avg)
  $b_stddev = max($sector_b.b_std)
  $b_active_days = max($sector_b.b_days)
  $safe_b_std = if($b_stddev > 44979.0, $b_stddev, 44979.0)
  $z_b_raw = ($b_observed - $b_mean) / $safe_b_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 4B: 4-Stage UDM-Gated Leave-One-Out Hourly Personal Alert Z-Score (`secops-statistical-hunter`)
Evaluates hourly security alert surges strictly on candidate hosts surfaced by `Query 4A` via Wave 2 UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`). Computes each candidate host's leave-one-out hourly alert mean and sample variance across prior active hours with a continuous `math.sqrt(max(loo_mean, 1.0))` Poisson floor (`$personal_z >= 3.0`), projecting `$upstream_z` alongside as macro context.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT HOURLY PERSONAL ALERT Z-SCORE PIPELINE
// Goal: Detect acute hourly security alert bursts on candidate hosts from Query 4A using leave-one-out personal standardization with a continuous Poisson dispersion floor.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Hourly Personal Z-Score ($personal_z >= 3.0)
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
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $host in %ueba_hunt_bridge.hostname

  match:
    $host

  outcome:
    $upstream_4a_z = max(security_result.confidence_score)
}

stage hourly_counts {
    (metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
    security_result.rule_name != ""
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_val = count(metadata.id)
    $hourly_val_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_rules = count_distinct(security_result.rule_name)
}

stage personal_baseline {
    $host = $hourly_counts.host

  match:
    $host

  outcome:
    $sum_x = sum($hourly_counts.hourly_val)
    $sum_x2 = sum($hourly_counts.hourly_val_sq)
    $active_hours = count($hourly_counts.window_start)
}

$host = $stage1_upstream_4a_candidates.host
$host = $hourly_counts.host
$host = $personal_baseline.host
$ws = $hourly_counts.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_4a_candidates.upstream_4a_z)
  $observation_count = max($hourly_counts.hourly_val)
  $baseline_active_samples = max($personal_baseline.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($hourly_counts.distinct_rules)

  // Leave-One-Out Personal Standardization with Continuous Poisson Floor
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $raw_loo_sum = max($personal_baseline.sum_x) - $observation_count
  $loo_sum = if($raw_loo_sum > 0, $raw_loo_sum, 0)
  $baseline_mean = 1.0 * $loo_sum / $n_prior
  $raw_loo_var = ((max($personal_baseline.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $personal_z = ($observation_count - $baseline_mean) / $baseline_dispersion

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 5
  and $personal_z >= 3.0

order:
  $personal_z desc
```

---

### Scenario 5: Upgrading Process-Driven Data Exfiltration

* **Curated Detection Operational Focus**: Correlates process execution with external reputation tags and outbound network data transfers.
* **How Multi-Stage UEBA Extends Coverage**: Scores 30-day per-`(host, SHA256)` execution volume (`metrics.file_executions_total` with `math.sqrt(max(mean, 1.0))` Poisson floor and `>= 7` active days) inner-joined with Chronicle `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3`, `Query 5A`), then gates an hourly Leave-One-Out **Gamma-Poisson** network egress shrinkage query (`Query 5B`) on `Query 5A` candidate endpoints via Wave 2 UDM Loopback.

#### Query 5A: 2-Stage Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Evaluates `PROCESS_LAUNCH` events pinned to the Mode A scored UTC day (`"2026-10-29"`, executed over `startTime = 2026-10-27T00:00:00Z` to `endTime = 2026-10-30T00:00:00Z` so daily `DERIVED_CONTEXT` prevalence snapshots are in-window) and keeps only rare binaries (`day_count = 10`, `0 < rolling_max <= 3`). Note that `stage2_file_derived_context` is an inner join (binaries absent from `DERIVED_CONTEXT` drop out rather than scoring as rare), and Day-0 unseen binaries (`< 7` active days) route to boolean `first_seen` novelty (`first_seen_novelty_2stage.yl2`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-prevalence binaries (DERIVED_CONTEXT day_count = 10, rolling_max <= 3) exhibiting anomalous execution surges against mature 30-day per-(host, SHA256) baselines.
// Statistical Model: 2-Stage Hybrid 30d File Execution Z-Score + DERIVED_CONTEXT 10-Day File Prevalence (active_baseline_days >= 7, z_score >= 3.0)
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (pinned to Mode A scored UTC date)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    $sha256 = strings.coalesce(target.process.file.sha256, principal.process.file.sha256)
    principal.process.file.sha256 != ""
    $host != ""
    $sha256 != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $host in %ueba_hunt_bridge.hostname

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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day File Prevalence & First Seen)
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

// Root Stage: Fuses Personal Execution Z-Score with Organizational Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $dispersion_floor = math.sqrt(if($mean_execs > 1.0, $mean_execs, 1.0))
  $safe_stddev = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_stddev
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier (novelty boost disabled when first_seen_time = 0)
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

#### Query 5B: 4-Stage UDM-Gated Leave-One-Out Gamma-Poisson Shrinkage on Outbound Network Connections (`secops-statistical-hunter`)
Evaluates hourly outbound `NETWORK_CONNECTION` surges (`network.sent_bytes > 0`) strictly on candidate hosts surfaced by `Query 5A` via Wave 2 UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)`). Updates a `Gamma(0.5, 0.1)` prior with leave-one-out prior volume across `23` prior hourly buckets (for a 24-hour `by 1h` lookback) and adds empirical excess overdispersion $\max(0, E[X^2]_{\text{prior}} - \mu_{\text{prior}}^2 - \mu_{\text{prior}})$ so routinely bursty hosts are shrunk while sudden exfiltration bursts produce high `$bayesian_z >= 3.0`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED LEAVE-ONE-OUT GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect hourly outbound network connection surges on candidate hosts from Query 5A using leave-one-out conjugate Gamma-Poisson predictive standardization with excess overdispersion.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Leave-One-Out Conjugate Gamma-Poisson Predictive Z-Score ($bayesian_z >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_upstream_5a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""
    $run_id != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $host in %ueba_hunt_bridge.hostname

  match:
    $host

  outcome:
    $upstream_5a_z = max(security_result.confidence_score)
}

stage host_hourly_activity {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(principal.process.file.full_path)
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

$host = $stage1_upstream_5a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_5a_candidates.upstream_5a_z)
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_hourly_activity.distinct_procs)

  // Leave-One-Out Conjugate Gamma(0.5, 0.1) Prior Across 23 Prior Hourly Buckets & Excess Overdispersion
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 0.5 + $prior_sum
  $baseline_mean = $alpha_prior / 23.1
  $prior_emp_mean = 1.0 * $prior_sum / 23.0
  $raw_excess_var = (1.0 * $prior_sum_sq / 23.0) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * (24.1 / 23.1)) + $excess_var
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

### Scenario 6: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual risk metric rules contributing independent risk scores.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct multi-stage UEBA queries within the active `run_id` (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via a squared $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$) and pivots directly into raw endpoint, network, authentication, and cloud telemetry.

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–5 can fire inside ambiguous overlap regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or accessed resource names.

**Scenario 6 (`Query 6`)** executes in **Wave 3** after all **Wave 1** (upstream macro and hurdle queries) and **Wave 2** (UDM-gated `Query 2B`, `4B`, `5B` Stage B queries) have exported their matches into Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Per-Scenario Deduplication (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` via `re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)` and deduplicates by `$entity, $scenario_tag`, taking the peak Z-equivalent `security_result.confidence_score` per scenario.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, requiring `$distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) and `$capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Per-Domain Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) with explicit per-event-type conditional sums and joins with Stage 2 in Root to emit `$capstone_threat_score = math.sqrt($capstone_threat_norm_sq)` alongside concrete process paths, resource names, and outbound byte totals (`PlaybookRunner` then computes the final `[0, 100]` CRI in Python via `ueba_constants.calculate_cri`).

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Scenarios 1 through 5B via UDM Loopback regex union while joining per-domain raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.ip[0])
    $entity != ""
    $run_id != ""
    // Optional Data Table cohort filter (uncomment after populating %ueba_hunt_bridge):
    // $entity in %ueba_hunt_bridge.entity_id

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
    $cloud_read_events = sum(if(metadata.event_type = "RESOURCE_READ", 1, 0))
    $resource_access_events = sum(if(metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $login_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
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

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $cloud_read_events = max($stage3_raw_forensic_pivot.cloud_read_events)
  $resource_access_events = max($stage3_raw_forensic_pivot.resource_access_events)
  $login_events = max($stage3_raw_forensic_pivot.login_events)
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
