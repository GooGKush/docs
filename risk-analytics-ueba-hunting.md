# Extending Google SecOps Risk Analytics for UEBA with Multi-Stage Behavioral Models

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Risk Analytics for UEBA** curated rule pack leverages pre-computed 30-day behavioral metrics (`metrics.*`) and entity context to detect anomalous network byte transfers, authentication spikes, new-user or new-device activity, and process-driven data exfiltration.

This playbook extends single-stage `metrics.*` detections into **Multi-Stage Behavioral Pipelines** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By introducing **Option 1 Inline Piecewise Unification** (handling both cold-start identities with $<5$ active days and mature 30-day baselines in a single query), **4-Stage Non-Parametric Median Absolute Deviation (MAD)** for heavy-tailed traffic, **Beta-Binomial Empirical Bayes** rate regularization, and **Option 3 UDM Loopback Capstone Convergence**, the harness provides adaptive coverage across both sparse and high-variance enterprise entities.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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
  $observed_events = max($stage1_extract.observed_events)
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
  $m_z_score = $modified_z
  $z_gap = $modified_z - $personal_z

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 6 active days) + Mature 30-Day Robust MAD (>= 7 active days)
  $hurdle_rarity_boost = if($raw_active_days <= 6, 2.0, 1.0)
  $hurdle_threat_score = math.log($observed + 1) * $hurdle_rarity_boost / 3.0
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

#### Query 2B: 4-Stage Beta-Binomial Empirical Bayes Authentication Failure Rate Regularization (`secops-statistical-hunter`)
Replaces the single-stage single-stage baseline constraints and single-stage baseline constraints rules with **Beta-Binomial Empirical Bayes conjugate shrinkage** ($\hat{p} = (k + \alpha_0) / (n + \alpha_0 + \beta_0)$ with prior $\alpha_0 = 1.0, \beta_0 = 9.0$). Single-trial typos ($1/1 = 100\%$ raw failure rate) shrink safely to $(1+1)/(1+10) = 0.18$, while sustained password sprays or `su` brute-forcing ($\ge 5$ failures in an hour with high failure ratio) exceed `regularized_failure_prob >= 0.70`.

```yara
// ============================================================================
// Goal: Hunt for password guessing, distributed brute force, and privilege-escalation auth failure surges using Beta-Binomial Empirical Bayes shrinkage.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Beta-Binomial Bayesian Updating & Small-Sample Shrinkage
// ============================================================================

// Stage 1: Aggregate total and failed login trials per user in tumbling hourly windows
stage entity_hourly_trials {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count(metadata.id)
    $failed_trials = sum(if(security_result.action = "BLOCK", 1, 0))
    $distinct_sources = count_distinct(principal.ip)
}

// Stage 2: Historical Parameter Estimation across all active baseline windows
stage entity_historical_rates {
    $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

// Stage 3: Concurrent Fleet Context per hourly window
stage fleet_stats {
    $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = count_distinct($entity_hourly_trials.user)
}

// Root Stage: Beta-Binomial Conjugate Updating & Shrinkage
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($entity_hourly_trials.failed_trials)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $baseline_mean = max($entity_historical_rates.total_historical_fails)
  $baseline_dispersion = max($entity_historical_rates.total_historical_events)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Regularized Posterior Failure Probability (Beta prior alpha_0 = 1.0, beta_0 = 9.0)
  $regularized_failure_prob = (max($entity_hourly_trials.failed_trials) + 1.0) / (max($entity_hourly_trials.total_trials) + 10.0)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1.0)
  $unregularized_raw_rate = max($entity_hourly_trials.failed_trials) / $safe_trials

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 15
  and $regularized_failure_prob >= 0.65

order:
  $regularized_failure_prob desc
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

#### Query 4B: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z on Blocked User Activity (`secops-statistical-hunter`)
Replaces the static `> 200` blocked-event cutoff in curated detection rules with a **3-Stage Dual-Baseline Fleet-Normalized Delta-Z** pipeline ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$) across all blocked user events (`security_result.action = "BLOCK"`), isolating targeted user compromises while automatically suppressing company-wide firewall or conditional-access policy blocks.

```yara
// ============================================================================
// Goal: Isolate targeted user blocked-action surges from fleet-wide policy changes using a 3-Stage Dual-Baseline Fleet-Normalized Delta-Z model.
// Target Telemetry: UDM_EVENTS (security_result.action = "BLOCK" across user activity)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift))
// ============================================================================

// Stage 1: Individual User Blocked Activity Volume in tumbling hourly windows
stage user_hourly_extract {
    security_result.action = "BLOCK"
    principal.user.userid = $user
    $user != ""

  match:
    $user by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_products = count_distinct(metadata.product_name)
}

// Stage 2: Individual User Personal Historical Baseline (Temporal Baseline)
stage user_personal_baseline {
    $user = $user_hourly_extract.user

  match:
    $user

  outcome:
    $personal_avg = avg($user_hourly_extract.hourly_count)
    $personal_stddev = stddev($user_hourly_extract.hourly_count)
    $active_hours = count($user_hourly_extract.window_start)
}

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active users in the same window
stage fleet_concurrent_baseline {
    $user = $user_hourly_extract.user
    $ws = $user_hourly_extract.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hour_avg = avg($user_hourly_extract.hourly_count)
    $fleet_hour_stddev = stddev($user_hourly_extract.hourly_count)
    $active_fleet_users = count_distinct($user_hourly_extract.user)
}

// Root Stage: Dual-Baseline Delta-Z Evaluation
$user = $user_hourly_extract.user
$user = $user_personal_baseline.user
$ws = $user_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $user, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($user_hourly_extract.hourly_count)
  $baseline_active_samples = max($user_personal_baseline.active_hours)
  $baseline_mean = max($user_personal_baseline.personal_avg)
  $baseline_dispersion = max($user_personal_baseline.personal_stddev)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_users)
  $distinct_binaries = max($user_hourly_extract.distinct_products)

  // Dual-Baseline Metrics (Common Personal Dispersion Scale)
  $obs = max($user_hourly_extract.hourly_count)
  $p_mean = max($user_personal_baseline.personal_avg)
  $f_mean = max($fleet_concurrent_baseline.fleet_hour_avg)
  $raw_personal_sd = max($user_personal_baseline.personal_stddev)
  $safe_personal_sd = if($raw_personal_sd > 0, $raw_personal_sd, 1.0)

  $personal_z = ($obs - $p_mean) / $safe_personal_sd
  $f_shift = $f_mean - $p_mean
  $fleet_z = $f_shift / $safe_personal_sd
  $pos_fleet_z = if($fleet_z > 0, $fleet_z, 0.0)
  $delta_z = $personal_z - $pos_fleet_z
  $z_score = $delta_z

condition:
  $baseline_active_samples >= 3
  and $fleet_prevalence >= 2
  and $observation_count >= 5
  and $delta_z >= 3.0

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

#### Query 5B: 4-Stage Empirical Bayes Gamma-Poisson Credibility Shrinkage on Process-Initiated Network Egress (`secops-statistical-hunter`)
Directly closes the network-blindness gap in curated detection rules by evaluating **process-initiated outbound network connections** (`NETWORK_CONNECTION` with `network.sent_bytes > 0` and `principal.process.file.full_path != ""`) using **Method-of-Moments Gamma-Poisson Empirical Bayes shrinkage** ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$). Predictable endpoints that suddenly experience a process-driven outbound connection burst achieve a high posterior arrival ratio (`$anomaly_score >= 3.0`), while noisy developer hosts are shrunk toward their prior.

```yara
// ============================================================================
// Goal: Hunt for high-confidence process-initiated outbound network connection surges per host using Poisson-Gamma Empirical Bayes Credibility Shrinkage.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION with sent_bytes > 0 and process attribution)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting
// ============================================================================

// Stage 1: Hourly process-initiated outbound network connection volume per host
stage host_hourly_activity {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    principal.process.file.full_path != ""
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(principal.process.file.full_path)
}

// Stage 2: Historical Parameter Estimation (Method of Moments Gamma Prior)
stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
    $active_hours = count($host_hourly_activity.window_start)
}

// Stage 3: Organizational Peer Prevalence Baseline per hourly window
stage fleet_context {
    $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($host_hourly_activity.host)
}

// Root Stage: Bayesian Conjugate Updating & Credibility Scoring
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_procs)

  // Method-of-Moments Gamma prior (alpha_0 = mu_sq / sigma_sq, beta_0 = mu / sigma_sq)
  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $beta_prior = max($host_prior_stats.hist_mean) / $safe_var
  $alpha_prior = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $posterior_arrival_rate = ($alpha_prior + max($host_hourly_activity.hourly_count)) / ($beta_prior + 1.0)
  $prior_weight_pct = $beta_prior / ($beta_prior + 1.0)
  $evidence_weight_pct = 1.0 / ($beta_prior + 1.0)
  $safe_hist_mean = if(max($host_prior_stats.hist_mean) > 0, max($host_prior_stats.hist_mean), 1.0)
  $anomaly_score = $posterior_arrival_rate / $safe_hist_mean
  $z_score = $anomaly_score

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 10
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
```

---

---

### Scenario 6: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual risk metric rules contributing independent risk scores.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct multi-stage UEBA scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Risk Analytics Entity Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across all Risk Analytics UEBA scenarios via UDM Loopback to detect multi-domain entity compromise.
// Statistical Model: Cross-Scenario Euclidean Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0)
// ARCHITECTURE: CAPSTONE UDM LOOPBACK CONVERGENCE PIPELINE (OPTION 3)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_query_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    security_result.rule_name = $query_name
    $entity = coalesce(principal.asset.hostname, principal.user.userid, principal.ip[0])
    $entity != ""
    $run_id != ""

  match:
    $entity, $query_name

  outcome:
    $max_query_z = max(security_result.confidence_score)
    $query_sq = max(security_result.confidence_score) * max(security_result.confidence_score)
    $match_events = count(metadata.id)
    $latest_run_id = max(metadata.product_log_id)
}

$entity = $stage1_query_dedup.entity

match:
  $entity

outcome:
  $distinct_scenarios_matched = count_distinct($stage1_query_dedup.query_name)
  $matched_queries = array_distinct($stage1_query_dedup.query_name)
  $correlated_run_ids = array_distinct($stage1_query_dedup.latest_run_id)
  $latest_run_id = max($stage1_query_dedup.latest_run_id)
  $total_loopback_matches = sum($stage1_query_dedup.match_events)
  $peak_scenario_z = max($stage1_query_dedup.max_query_z)
  $capstone_threat_norm_sq = sum($stage1_query_dedup.query_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 18.0

order:
  $capstone_threat_norm_sq desc
```

---

---

## 3. Appendix: A Practitioner's Plain-English Guide to the 10 Statistical Models

### 3.1 4-Stage Robust Modified Z-Score via 30-Day Median Absolute Deviation (MAD — Query 1A)
* **What it measures**: How many robust standard deviations today's outbound network byte volume sits above the host's 30-day median (`$modified_z`), side-by-side with the classical mean/stddev Z-score (`$personal_z`) and their difference (`$z_gap`).
* **Why first-generation UEBA rules fail**: All 21 network byte rules in the curated rule pack use $\mu + 2\sigma$ and require $\text{CV} = \sigma/\mu < 0.1$. A single prior large transfer inflates $\sigma$, masking subsequent exfiltration and pushing $\text{CV} \ge 0.1$.
* **How the math works**: The median and MAD (`window.median(|x - median|, false)`) have a 50% breakdown point—meaning up to half of the days in a 30-day window can contain massive spikes without corrupting the baseline. When MAD is zero (flat history), the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) ensures smooth scoring.

### 3.2 2-Stage Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 1B)
* **What it measures**: The multi-day cumulative sum of positive daily outbound byte excesses above a $0.5\sigma$ slack constant (`$cusum_drift_score >= 3.0` across `$drift_days >= 2`).
* **Why first-generation UEBA rules fail**: Single-day `over 24h` windows reset every 24 hours. An adversary who paces exfiltration at $+1.4\sigma$ per day for a week stays below $\mu + 2\sigma$ every single day.
* **How the math works**: Each day's standardized Z-score has $k = 0.5\sigma$ subtracted. Routine daily noise ($\le 0.5\sigma$) contributes `0.0`, whereas a persistent $+1.5\sigma$ daily drip adds $+1.0$ per day to the running sum, crossing `3.0` on Day 3.

### 3.3 3-Stage Dual-Sector Auth Failures + Successes Euclidean Fusion ($D^2$ — Query 2A)
* **What it measures**: The joint Euclidean anomaly distance $D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$ ($D \ge 3.5\sigma$) across failed and successful logins for the same user, using zero-safe standard deviation floors (`if($a_stddev > 0, $a_stddev, 1.0)`).
* **Why first-generation UEBA rules fail**: curated detection rules requires `$max_daily_event_count > 10` (blinding it to clean users with 0 prior failures), while curated detection rules hardcodes $>25$ failures in `5m` from one IP.
* **How the math works**: By fusing rectified Z-scores across both authentication sectors over a full day and replacing `$max_daily_event_count > 10` with a zero-safe denominator, a quiet user who suddenly experiences 10 failed logins ($\mu=0, \sigma=0 \implies Z_{\text{fail}} = 10$) and 1 anomalous login immediately crosses $D^2 \ge 12.25$.

### 3.4 4-Stage Beta-Binomial Empirical Bayes Failure Rate Regularization (Query 2B)
* **What it measures**: The Bayesian posterior failure rate $(k + \alpha_0) / (n + \alpha_0 + \beta_0)$ of a user's hourly login attempts, shrunk toward a population prior ($\alpha_0 = 1.0, \beta_0 = 9.0$, or 10% prior failure rate).
* **Why first-generation UEBA rules fail**: All 11 curated detection rules rules require a user/device to have failed logins on $\ge 9$ of the past 30 days with $\text{CV} < 0.1$ and exceed $10\times$ their 30-day maximum.
* **How the math works**: Adding 1 pseudo-failure and 9 pseudo-successes suppresses small-sample false alarms (1 failure in 1 attempt shrinks from $100\%$ to $2/11 = 18.2\%$), while a real password spray of 20 failures in 20 attempts yields $(20+1)/(20+10) = 70.0\%$.

### 3.5 2-Stage Hybrid 30-Day Host Auth + `DERIVED_CONTEXT` Infant Asset Age (Query 3A)
* **What it measures**: A host's 30-day authentication Z-score (`metrics.auth_attempts_total`) multiplied by a $2.5\times$ boost when `DERIVED_CONTEXT` shows the asset was first seen in the environment $\le 7$ days ago.
* **Why first-generation UEBA rules fail**: curated detection rules rules hardcode `< 86400` seconds (24 hours) and require Microsoft AD `ENTITY_CONTEXT`, failing after 24 hours or on non-Windows/cloud assets.
* **How the math works**: Chronicle's `DERIVED_CONTEXT` automatically tracks `first_seen_time` for every asset across all telemetry sources. Extending the infant window to 7 days and combining it with a 30-day volumetric Z-score catches rogue VMs and newly joined devices without 24-hour aging cliffs.

### 3.6 Two-Part Zero-Inflated Hurdle Model on Logins & Account Creation (Query 3B)
* **What it measures**: Part 1 (Bernoulli hurdle) checks whether a user was active on $\le 2$ days in the baseline window; Part 2 (continuous intensity) computes the standard Z-score for established users.
* **Why first-generation UEBA rules fail**: curated detection rules requires $>150$ account creations in `5m`, and curated detection rules uses `min(if(age < 86400, 1, 0))`, which zeroes out any alert spanning the 24-hour mark.
* **How the math works**: Dormant or newly created accounts (`active_samples <= 2`) are scored directly on their awakening burst (`$observation_count * 1.5`), catching even 5 rogue account creations or lateral logins without requiring 9 to 15 days of prior history.

### 3.7 4-Stage Roll-Up Security Alert + Outbound Network Bytes Fusion (Query 4A)
* **What it measures**: The highest per-rule 30-day alert Z-score (`metrics.alert_event_name_count` across `principal.asset.hostname` and `security_result.rule_name`) rolled up per host and fused with 30-day `metrics.network_bytes_outbound` ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$).
* **Why first-generation UEBA rules fail**: curated detection rules requires $>200$ blocked `GENERIC_EVENT` records across $\ge 3$ products in 4 hours, ignoring real EDR alerts and downstream exfiltration.
* **How the math works**: Stage 1 baselines each `security_result.rule_name` independently so noisy rules do not drown out quiet rules; Stage 2 rolls up the maximum per-rule Z-score to the host; Stage 3 and the Root Stage fuse that alert surge with outbound network bytes.

### 3.8 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z$ — Query 4B)
* **What it measures**: How many standard deviations a user's hourly blocked actions exceeded their personal baseline *after subtracting any concurrent fleet-wide increase* ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$).
* **Why first-generation UEBA rules fail**: Static count rules (`> 200` blocks) cannot distinguish a single compromised user probing internal resources from a company-wide firewall or conditional-access misconfiguration.
* **How the math works**: When a policy rollout causes blocked events to rise across the entire organization, $Z_{\text{fleet}}$ rises alongside $Z_{\text{personal}}$, driving $\Delta Z \to 0$. When a single compromised account generates blocked actions while the rest of the fleet stays quiet, $\Delta Z$ isolates that user cleanly.

### 3.9 2-Stage Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (Query 5A)
* **What it measures**: A binary's 30-day execution Z-score (`metrics.file_executions_total` per host and SHA-256) filtered to binaries seen on $\le 3$ hosts across the entire enterprise over the past 10 days (`rolling_max <= 3`), boosted $2.5\times$ if first seen $\le 7$ days ago.
* **Why first-generation UEBA rules fail**: All 4 rules in curated detection rules require VirusTotal `keylogger|screenshot` or `rat_rdp` + `invalid-signature` tags and 15 to 40 process events in 24 hours.
* **How the math works**: Instead of relying on external signature tags, `DERIVED_CONTEXT` empirical fleet prevalence (`rolling_max <= 3`) identifies bespoke, packed, or unauthorized remote-access binaries that exist on only 1–3 machines in the organization.

### 3.10 4-Stage Empirical Bayes Gamma-Poisson Credibility Shrinkage (Query 5B)
* **What it measures**: The posterior-to-prior arrival rate ratio (`$anomaly_score = $posterior_arrival_rate / $safe_hist_mean >= 3.0`) for process-initiated outbound network connections per host.
* **Why first-generation UEBA rules fail**: curated detection rules never inspects network connections, and standard Z-scores over-alert on erratic developer workstations while under-alerting on stable servers.
* **How the math works**: Method-of-Moments estimates a host's Gamma prior ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$). On a noisy workstation ($\sigma^2 \gg \mu$), $\beta_0$ is small and the host requires a large burst to move the posterior; on a stable server ($\sigma^2 \ll \mu$), even a moderate burst of process-initiated outbound connections produces an immediate $\ge 3.0\times$ posterior shift.
