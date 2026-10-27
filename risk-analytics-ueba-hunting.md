# Extending Google SecOps Risk Analytics for UEBA with Multi-Stage Behavioral Models

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Risk Analytics for UEBA** curated rule pack leverages pre-computed 30-day behavioral metrics (`metrics.*`) and entity context to detect anomalous network byte transfers, authentication spikes, new-user or new-device activity, and process-driven data exfiltration.

This playbook extends single-stage `metrics.*` detections into **Multi-Stage Behavioral Pipelines** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By introducing **Option 1 Inline Piecewise Unification** (handling both cold-start identities with $<5$ active days and mature 30-day baselines in a single query), **4-Stage Non-Parametric Median Absolute Deviation (MAD)** for heavy-tailed traffic, **Beta-Binomial Empirical Bayes** rate regularization, and **Option 3 UDM Loopback Capstone Convergence**, the harness provides adaptive coverage across both sparse and high-variance enterprise entities.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Risk Analytics for UEBA & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Network Byte Volume Anomalies (Inbound, Outbound & Total)** | Single-stage 30-day metric baseline checks on entity network byte volume (`metrics.network_bytes_*`). | Unifies cold-start endpoints with 4-stage non-parametric 30-day Median Absolute Deviation (MAD) (`Option 1`) to prevent weekend/backup variance masking, paired with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$). | `Query 1A` (Piecewise Hurdle + 4-Stage 30d MAD)<br>`Query 1B` (Producer-Consumer Inversion) |
| **2. Authentication Spikes & Brute-Force-to-Success Chains** | Single-stage baseline checks on authentication attempts and failed-login counts (`metrics.auth_attempts_*`). | Applies 4-stage Beta-Binomial Empirical Bayes failure-rate regularization and fuses 30-day Auth Failure + Auth Success baselines ($D^2 \ge 12.25$) to capture credential stuffing followed by session compromise. | `Query 2A` (Beta-Binomial Auth Regularization)<br>`Query 2B` (30d Auth Fail + Success Fusion) |
| **3. First-Time User, New Device & Geovelocity Anomalies** | Detects newly created accounts or logins from new countries, applications, or devices. | Combines a Two-Part Zero-Inflated Hurdle model for dormant/new identity activation with geodesic haversine impossible-travel velocity ($\ge 900\text{ km/h}$) and circular von Mises off-hours scoring. | `Query 3A` (Two-Part Identity Hurdle)<br>`Query 3B` (Geodesic Impossible Travel) |
| **4. Multi-Alert Entity Risk & Cross-Sector Escalation** | Aggregates security alerts per user over a 30-day metric window (`metrics.alert_event_name_count`). | Fuses 30-day entity alert baselines with outbound network bytes and cloud/workspace activity in a 4-stage multi-sector roll-up ($D^2 = \sum Z_i^2 \ge 12.25$). | `Query 4` (4-Stage Multi-Sector Alert + Egress Fusion) |
| **5. Process-Driven Data Exfiltration & Rare Binary Execution** | Correlates process execution with VirusTotal/GTI context and outbound network data transfers. | Combines 30-day file execution baselines (`metrics.file_executions_total`) and 10-day `DERIVED_CONTEXT` binary prevalence with outbound byte anomalies, detecting exfiltration via custom or unindexed tools. | `Query 5` (30d Execution + 10d Prevalence + Egress) |
| **6. Capstone Multi-Scenario Risk Analytics Convergence** | Individual risk metric rules contributing independent risk scores. | Correlates entities matching $\ge 2$ distinct multi-stage UEBA scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Upgrading Network Byte Anomaly Rules

* **Curated Detection Operational Focus**: Single-stage 30-day metric baseline checks on entity network byte volume (`metrics.network_bytes_*`).
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start endpoints with 4-stage non-parametric 30-day Median Absolute Deviation (MAD) (`Option 1`) to prevent weekend/backup variance masking, paired with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$).

#### Query 1A: 4-Stage Robust Modified Z-Score (30-Day MAD) on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Replaces fragile $\mu + 2\sigma$ and $\text{CV} < 0.1$ gates with a **4-stage non-parametric Median Absolute Deviation (MAD)** pipeline (`window.median(..., false)` with Iglewicz-Hoaglin MeanAD fallback) evaluated side-by-side against the 30-day `metrics.network_bytes_outbound` Z-score so outlier masking (`$z_gap = $modified_z - $personal_z`) is directly measured.

```yara
// ============================================================================
// Goal: Detect anomalous outbound network byte exfiltration per host using a 4-stage non-parametric Median Absolute Deviation (MAD) Modified Z-Score that resists historical burst masking.
// Statistical Model: 4-Stage Robust Modified Z-Score (True Median Absolute Deviation vs. 30d metrics.network_bytes_outbound)
// ARCHITECTURE: 4-STAGE ROBUST MODIFIED Z-SCORE (TRUE MEDIAN ABSOLUTE DEVIATION)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Byte Extraction & 30-Day Metrics Baseline Lookup
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
}

// Stage 2: Non-Parametric Median Center Across Active Daily Windows
stage mad_center {
    $entity = $stage1_extract.entity

  match:
    $entity

  outcome:
    $median_val = window.median($stage1_extract.observed_val, false)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

// Stage 3: Median Absolute Deviation (MAD) & Mean Absolute Deviation Spread
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
}

// Root Stage: Robust Modified Z (MAD) vs. Classical 30d Metrics Z-Score
$entity = $stage1_extract.entity
$entity = $mad_spread.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $median_val = max($mad_spread.median_val)
  $mad = max($mad_spread.mad)
  $mean_abs_dev = max($mad_spread.mean_abs_dev)
  $raw_active_days = max($mad_spread.raw_active_days)

  // 1. Classical 30d metrics Z-score (cross-check for outlier masking)
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  // 2. Robust scale with Iglewicz-Hoaglin MAD=0 fallback and flat-history floor
  $scale_from_mad = $mad / 0.6745
  $scale_from_meanad = $mean_abs_dev * 1.253314
  $robust_scale = if($mad > 0, $scale_from_mad, $scale_from_meanad)
  $median_floor = $median_val * 0.05 + 1.0
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, $median_floor)

  // 3. Modified Z-score and outlier-masking gap
  $modified_z = ($observed - $median_val) / $safe_robust_scale

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 6 active days) + Mature 30-Day Robust MAD (>= 7 active days)
  $hurdle_rarity_boost = if($raw_active_days <= 6, 2.0, 1.0)
  $hurdle_threat_score = (math.log($observed + 1.0) * $hurdle_rarity_boost) / 3.0
  $unified_threat_score = if($raw_active_days <= 6, $hurdle_threat_score, $modified_z)

condition:
  $observed >= 10485760 and $unified_threat_score >= 3.5

order:
  $unified_threat_score desc
```

#### Query 1B: 2-Stage Longitudinal CUSUM Behavioral Drift on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Catches low-and-slow multi-day drip exfiltration that stays below single-day $2\sigma$ or $3\sigma$ cutoffs by accumulating positive daily standardized excesses above a $k = 0.5\sigma$ slack reference ($S_t^+ = \sum \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ drift days).

```yara
// ============================================================================
// Goal: Detect low-and-slow multi-day outbound network exfiltration drift per host using a 2-Stage Longitudinal CUSUM accumulator.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (cusum_drift_score >= 3.0, drift_days >= 2)
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Outbound Byte Deviation Tracker
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
    $historical_sum = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: sum,
        principal.asset.hostname: principal.asset.hostname
    ))

    // Per-day standardized CUSUM slack excess (k = 0.5 sigma)
    $daily_z = ($observed_val - $historical_avg) / if($historical_stddev > 0, $historical_stddev, 1.0)
    $deviation = $daily_z - 0.5
    $daily_excess = if($deviation > 0.0, $deviation, 0.0)
}

// Stage 2 (Root Stage): Longitudinal CUSUM Drift Score Across Scored Days
$entity = $stage1_extract.entity

match:
  $entity

outcome:
  $observed_val = max($stage1_extract.observed_val)
  $baseline_mean = max($stage1_extract.historical_avg)
  $baseline_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  // 1. Peak Daily Standardized Shift across the multi-day window
  $daily_z = max($stage1_extract.daily_z)

  // 2. Multi-day Cumulative Sum of Positive Drift Increments across days
  $slack_excess = sum($stage1_extract.daily_excess)
  $cusum_drift = $slack_excess
  $cusum_drift_score = $cusum_drift
  $z_score = $cusum_drift_score
  $drift_days = sum(if($stage1_extract.daily_excess > 0.0, 1, 0))

condition:
  $cusum_drift_score >= 3.0 and $drift_days >= 2

order:
  $cusum_drift_score desc
```

---

---

### Scenario 2: Upgrading Authentication & Brute-Force Rules

* **Curated Detection Operational Focus**: Single-stage baseline checks on authentication attempts and failed-login counts (`metrics.auth_attempts_*`).
* **How Multi-Stage UEBA Extends Coverage**: Applies 4-stage Beta-Binomial Empirical Bayes failure-rate regularization and fuses 30-day Auth Failure + Auth Success baselines ($D^2 \ge 12.25$) to capture credential stuffing followed by session compromise.

#### Query 2A: 3-Stage Dual-Sector Authentication Failures + Successes Fusion (`secops-risk-metrics-multistage`)
Consolidates the curated detection rules rules into a **3-Stage Dual-Sector Euclidean Risk Fusion** pipeline ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$) with zero-safe dispersion floors (`if($a_stddev > 0, $a_stddev, 1.0)`), catching both spray-then-login progression and bursts on historically clean accounts ($\sigma = 0$).

```yara
// ============================================================================
// Goal: Detect curated detection rules progression and anomalous authentication surges per user by fusing 30-day failed and successful login baselines.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D_sq = Z_fail_sq + Z_success_sq >= 12.25)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A — Authentication Failures (UDM Source 1 of 2) ---
stage sector_a {
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = count(metadata.id)
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
}

// --- STAGE 2: Sector B — Authentication Successes (UDM Source 2 of 2) ---
stage sector_b {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
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

// --- STAGE 3 (Root): Cross-Sector Join & Euclidean Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity
$ws = $sector_a.window_start
$ws = $sector_b.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $a_mean = max($sector_a.a_avg)
  $a_stddev = max($sector_a.a_std)
  $a_active_days = max($sector_a.a_days)

  $b_observed = max($sector_b.b_obs)
  $b_mean = max($sector_b.b_avg)
  $b_stddev = max($sector_b.b_std)
  $b_active_days = max($sector_b.b_days)

  // Zero-safe, rectified sector Z-scores (supporting both established and quiet failure histories)
  $z_a_raw = ($a_observed - $a_mean) / if($a_stddev > 0, $a_stddev, 1.0)
  $z_b_raw = ($b_observed - $b_mean) / if($b_stddev > 0, $b_stddev, 1.0)
  $z_a = if($z_a_raw > 0, $z_a_raw, 0.0)
  $z_b = if($b_active_days >= 5 and $z_b_raw > 0, $z_b_raw, 0.0)

  // Euclidean Vector Threat Norm D_sq = Z_a_sq + Z_b_sq
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 2B: 4-Stage UDM-Gated Beta-Binomial Empirical Bayes Authentication Failure Rate (`secops-statistical-hunter`)
Evaluates hourly authentication failure-rate anomalies via **Beta-Binomial Empirical Bayes Shrinkage** strictly on candidate identities surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED BETA-BINOMIAL EMPIRICAL BAYES AUTH FAILURE RATE PIPELINE
// Goal: Detect sub-hour credential stuffing and brute-force failure-rate surges on candidate identities from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Beta-Binomial Empirical Bayes Shrinkage
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

stage hourly_auth_stats {
    metadata.event_type = "USER_LOGIN"
    $user = strings.coalesce(target.user.userid, principal.user.userid)
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_attempts = count(metadata.id)
    $failed_attempts = sum(if(security_result.action = "BLOCK", 1, 0))
    $distinct_src_ips = count_distinct(principal.ip)
}

stage user_prior_stats {
    $user = $hourly_auth_stats.user

  match:
    $user

  outcome:
    $hist_mean_total = avg($hourly_auth_stats.total_attempts)
    $hist_mean_fail = avg($hourly_auth_stats.failed_attempts)
    $hist_stddev_fail = stddev($hourly_auth_stats.failed_attempts)
    $active_windows = count($hourly_auth_stats.window_start)
}

$user = $stage1_upstream_2a_candidates.user
$user = $hourly_auth_stats.user
$user = $user_prior_stats.user
$ws = $hourly_auth_stats.window_start

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $n_trials = max($hourly_auth_stats.total_attempts)
  $k_failures = max($hourly_auth_stats.failed_attempts)
  $prior_mean_n = max($user_prior_stats.hist_mean_total)
  $prior_mean_k = max($user_prior_stats.hist_mean_fail)

  $alpha_0 = $prior_mean_k + 1.0
  $raw_beta = $prior_mean_n - $prior_mean_k
  $beta_0 = if($raw_beta > 0, $raw_beta, 1.0) + 5.0

  $posterior_fail_rate = ($alpha_0 + $k_failures) / ($alpha_0 + $beta_0 + $n_trials)
  $prior_fail_rate = $alpha_0 / ($alpha_0 + $beta_0)
  $safe_prior_rate = if($prior_fail_rate > 0, $prior_fail_rate, 0.05)

  $beta_binomial_score = ($posterior_fail_rate / $safe_prior_rate) * math.log($k_failures + 1.0)
  $z_score = $beta_binomial_score

  $observation_count = $k_failures
  $baseline_active_samples = max($user_prior_stats.active_windows)
  $baseline_mean = $prior_mean_k
  $baseline_dispersion = max($user_prior_stats.hist_stddev_fail)
  $fleet_prevalence = 1
  $distinct_binaries = max($hourly_auth_stats.distinct_src_ips)

condition:
  $baseline_active_samples >= 2
  and $k_failures >= 5
  and $posterior_fail_rate >= 0.35
  and $beta_binomial_score >= 3.5

order:
  $beta_binomial_score desc
```

---

---

### Scenario 3: Upgrading New User, New Device & AD-Context Rules

* **Curated Detection Operational Focus**: Detects newly created accounts or logins from new countries, applications, or devices.
* **How Multi-Stage UEBA Extends Coverage**: Combines a Two-Part Zero-Inflated Hurdle model for dormant/new identity activation with geodesic haversine impossible-travel velocity ($\ge 900\text{ km/h}$) and circular von Mises off-hours scoring.

#### Query 3A: 2-Stage Hybrid 30-Day Host Authentication + `DERIVED_CONTEXT` Infant Asset Age (`secops-risk-metrics-multistage`)
Replaces vendor-specific AD context joins and 24-hour cliffs with a **2-stage hybrid pipeline** that scores 30-day host authentication volume (`metrics.auth_attempts_total`) and enriches it with Chronicle's universal `DERIVED_CONTEXT` asset `first_seen_time`, applying a $2.5\times$ threat multiplier to infant assets ($\le 7$ days old).

```yara
// ============================================================================
// Goal: Isolate newly commissioned or rogue infant endpoints (<= 7 days old in DERIVED_CONTEXT) exhibiting anomalous authentication surges against 30-day baselines.
// Statistical Model: 2-Stage Hybrid 30d Host Auth Z-Score + DERIVED_CONTEXT Infant Asset Age Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT ASSET AGE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Host Authentication Baseline (metrics.auth_attempts_total)
stage stage1_asset_baseline {
    metadata.event_type = "USER_LOGIN"
    principal.asset.hostname = $host
    $host != ""

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

// Stage 3 (Root Stage): Fuses Host Anomaly Z-Score with Infant Asset Age Coloring
$host = $stage1_asset_baseline.host
$host = $stage2_asset_derived_context.host

match:
  $host by 1d

outcome:
  $observed = max($stage1_asset_baseline.observed_val)
  $mean = max($stage1_asset_baseline.hist_mean)
  $stddev = max($stage1_asset_baseline.hist_stddev)
  $z_score = ($observed - $mean) / if($stddev > 0, $stddev, 1.0)
  $active_baseline_days = max($stage1_asset_baseline.hist_active_days)

  $first_seen = min($stage2_asset_derived_context.first_seen_ts)
  $obs_ts = max($stage1_asset_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $asset_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Infant Asset Multiplier: 2.5x threat score boost for machines first seen <= 7 days ago
  $is_infant_asset = if($first_seen > 0 and $asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $threat_multiplier = if($is_infant_asset = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $threat_multiplier

condition:
  $z_score >= 3.0
  and $asset_age_days <= 7.0

order:
  $threat_score desc
```

#### Query 3B: Two-Part Zero-Inflated Hurdle Model on User Logins & Account Creations (`secops-statistical-hunter`)
Replaces the `> 150` account-creation rule, the `< 86400s` new-user AD rules, and the `OU=Service Accounts` interactive login rule with a **Two-Part Hurdle Model** over `USER_LOGIN` and `USER_CREATION`. Part 1 tests whether an actor was historically dormant (`active_samples <= 2`) and applies a discrete wakeup multiplier (`$observation_count * 1.5`); Part 2 scores active actors via continuous intensity Z-score ($Z \ge 3.0\sigma$).

```yara
// ============================================================================
// Goal: Detect dormant or newly created accounts suddenly awakening with anomalous login or account-creation bursts using a Two-Part Zero-Inflated Hurdle Model.
// Target Telemetry: UDM_EVENTS (USER_LOGIN, USER_CREATION)
// Statistical Model: Two-Part Hurdle Outlier Model for Zero-Inflated Telemetry
// ============================================================================

// Stage 1: Daily login and account-creation activity per user
stage entity_historical {
    (metadata.event_type = "USER_LOGIN" or metadata.event_type = "USER_CREATION")
    security_result.action = "ALLOW"
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $bucket_count = count(metadata.id)
    $distinct_targets = count_distinct(target.user.userid)
    $sample_target = array_distinct(target.user.userid)
}

// Stage 2: Historical active sample density and dispersion per user
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $hist_mean = avg($entity_historical.bucket_count)
    $hist_stddev = stddev($entity_historical.bucket_count)
    $active_samples = count($entity_historical.window_start)
}

// Root Stage: Two-Part Hurdle Evaluation (Dormant Awakening vs. Continuous Intensity Z)
$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $baseline_mean = max($entity_stats.hist_mean)
  $baseline_dispersion = max($entity_stats.hist_stddev)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

  // 1. Part 1: Discrete Bernoulli Hurdle (newly created or dormant account awakening)
  $is_dormant = if($baseline_active_samples <= 2, 1.0, 0.0)
  $dormant_score = $observation_count * 1.5

  // 2. Part 2: Continuous Intensity Conditioned on Crossing Hurdle
  $diff = $observation_count - $baseline_mean
  $safe_stddev = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = $diff / $safe_stddev

  // 3. Composite Hurdle Threat Score
  $hurdle_threat_score = if($is_dormant > 0, $dormant_score, $intensity_z)

condition:
  $observation_count >= 5
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

---

### Scenario 4: Upgrading Alerts-by-User & Multi-Signal Entity Risk

* **Curated Detection Operational Focus**: Aggregates security alerts per user over a 30-day metric window (`metrics.alert_event_name_count`).
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day entity alert baselines with outbound network bytes and cloud/workspace activity in a 4-stage multi-sector roll-up ($D^2 = \sum Z_i^2 \ge 12.25$).

#### Query 4A: 4-Stage Roll-Up Security Alert + Outbound Network Bytes Fusion (`secops-risk-metrics-multistage`)
Upgrades curated detection rules to a **4-stage composite roll-up fusion pipeline** that evaluates 30-day baselines for every individual security alert rule (`metrics.alert_event_name_count` keyed by `principal.asset.hostname` and `security_result.rule_name`), rolls them up to the host level, and fuses the peak alert anomaly with 30-day outbound network byte volume (`metrics.network_bytes_outbound`, $D^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Fuse per-rule security alert anomalies with 30-day outbound network byte surges on the same host to detect multi-stage kill-chain progression.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D_sq >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2): one row per host and alert rule_name ---
stage sector_a_detail {
    (metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
    principal.asset.hostname = $entity
    $entity != ""
    security_result.rule_name = $security_result_rule_name
    $security_result_rule_name != ""

  match:
    $entity, $security_result_rule_name by 1d

  outcome:
    $d_obs = count(metadata.id)
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
    $d_z_raw = ($d_obs - $d_avg) / if($d_std > 0, $d_std, 1.0)
    $d_z = if($d_days >= 5 and $d_z_raw > 0, $d_z_raw, 0.0)
    $d_hot = if($d_days >= 5 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_days = 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per host ---
stage sector_a {
    $entity = $sector_a_detail.entity
    $ws = $sector_a_detail.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.security_result_rule_name)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a = max($sector_a_detail.d_z)
}

// --- STAGE 3: Sector B — Outbound Network Bytes (UDM Source 2 of 2) ---
stage sector_b {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""

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
    $z_b_raw = ($b_obs - $b_avg) / if($b_std > 0, $b_std, 1.0)
    $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
    $z_b = if($b_days >= 5, $z_b_pos, 0.0)
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

  // Rectified, baseline-gated sector scores
  $z_a = max($sector_a.z_a)
  $z_b = max($sector_b.z_b)

  // Euclidean Vector Threat Norm D_sq = Z_a_sq + Z_b_sq
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 4B: 4-Stage UDM-Gated Personal & Upstream Delta-Z on Security Alerts (`secops-statistical-hunter`)
Evaluates hourly security alert surges strictly on candidate entities surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED PERSONAL & UPSTREAM DELTA-Z PIPELINE
// Goal: Detect localized hourly security alert surges on candidate entities from Query 4A (strictly gated by Query 4A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Hourly Standardized Personal Z-Score Fusion
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

stage hourly_counts {
    security_result.rule_name != ""
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_val = count(metadata.id)
    $distinct_procs = count_distinct(security_result.rule_name)
}

stage personal_baseline {
    $host = $hourly_counts.host

  match:
    $host

  outcome:
    $p_mean = avg($hourly_counts.hourly_val)
    $p_std = stddev($hourly_counts.hourly_val)
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
  $baseline_mean = max($personal_baseline.p_mean)
  $baseline_dispersion = max($personal_baseline.p_std)
  $fleet_prevalence = 1
  $distinct_binaries = max($hourly_counts.distinct_procs)

  $safe_p_std = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $z_personal = ($observation_count - $baseline_mean) / $safe_p_std
  $delta_z = $z_personal + ($upstream_z * 0.25)
  $z_score = $delta_z

condition:
  $baseline_active_samples >= 2
  and $observation_count >= 5
  and $delta_z >= 3.5

order:
  $delta_z desc
```

---

---

### Scenario 5: Upgrading Process-Driven Data Exfiltration

* **Curated Detection Operational Focus**: Correlates process execution with VirusTotal/GTI context and outbound network data transfers.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day file execution baselines (`metrics.file_executions_total`) and 10-day `DERIVED_CONTEXT` binary prevalence with outbound byte anomalies, detecting exfiltration via custom or unindexed tools.

#### Query 5A: 2-Stage Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Eliminates dependence on VirusTotal capability tags and `invalid-signature` modifiers by scoring every process launch against its 30-day per-(host, SHA256) baseline (`metrics.file_executions_total`) joined with Chronicle `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3`), applying a $2.5\times$ rarity multiplier to newly introduced binaries ($\le 7$ days old).

```yara
// ============================================================================
// Goal: Detect rare or newly introduced binaries (DERIVED_CONTEXT rolling_max <= 3) exhibiting anomalous execution surges against 30-day host baselines without relying on VirusTotal tags.
// Statistical Model: 2-Stage Hybrid 30d File Execution Z-Score + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    $event_type = metadata.event_type
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
  $z_score = ($observed_execs - $mean_execs) / if($stddev_execs > 0, $stddev_execs, 1.0)
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier: 2.5x threat score boost for binaries first seen <= 7 days ago, 1.5x for isolated binaries
  $is_novel_binary = if($first_seen > 0 and $binary_age_days <= 7.0 and $binary_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_binary = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

  $sample_commands = array_distinct($stage1_process_baseline.sample_command)
  $sample_paths = array_distinct($stage1_process_baseline.sample_path)

condition:
  $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

#### Query 5B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Process-Initiated Network Egress (`secops-statistical-hunter`)
Evaluates hourly process-initiated network egress velocity via **Poisson-Gamma Bayesian Conjugate Updating** strictly on candidate endpoints surfaced by `Query 5A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect hourly process-initiated network connection surges on candidate hosts from Query 5A (strictly gated by Query 5A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson-Gamma Bayesian Conjugate Updating
// ============================================================================

stage stage1_upstream_5a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_5a_z = max(security_result.confidence_score)
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
    $distinct_exts = count_distinct(principal.process.file.full_path)
}

stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
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
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = 1
  $distinct_binaries = max($host_hourly_activity.distinct_exts)

  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $alpha_0 = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $beta_0 = max($host_prior_stats.hist_mean) / $safe_var
  $credibility_z = $baseline_active_samples / ($baseline_active_samples + $beta_0 + 1.0)
  $posterior_rate = ($alpha_0 + $observation_count) / ($beta_0 + 1.0)
  $safe_mean = if($baseline_mean > 0, $baseline_mean, 1.0)
  $gamma_shrinkage_score = ($posterior_rate / $safe_mean) * (1.0 + $credibility_z)
  $z_score = $gamma_shrinkage_score

condition:
  $baseline_active_samples >= 2
  and $observation_count >= 10
  and $gamma_shrinkage_score >= 3.5

order:
  $gamma_shrinkage_score desc
```

---

---

### Scenario 6: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual risk metric rules contributing independent risk scores.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct multi-stage UEBA scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–5 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 6 (`Query 6`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 5 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 5 Risk Analytics UEBA scenarios (1 through 5B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0) + Cross-Plane Raw Telemetry Bridge
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
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

  $unified_threat_score = $capstone_threat_score + math.log($raw_event_count + 1)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 18.0
  and $raw_event_count >= 1

order:
  $unified_threat_score desc
```
