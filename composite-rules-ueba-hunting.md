# Hunting Multi-Stage Kill-Chain & Cloud/Endpoint Composite Threats with Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Composite Rules** curated detection suite correlates multiple upstream rule detections or MITRE ATT&CK tactics across endpoint and cloud telemetry to surface multi-step intrusions.

While deterministic composite rules correlate discrete rule firings within fixed short-term correlation windows, adversaries often pace intrusion stages across hours or days, or blend low-severity activity with subtle behavioral shifts in authentication, API usage, and network egress. This playbook supplements composite detections with **30-day Multi-Sector Behavioral Risk Fusion (`secops-risk-metrics-multistage`)**, **Empirical Bayes Alert Shrinkage**, **Dual-Baseline Fleet Delta-Z**, and **UDM Loopback Capstone Convergence**.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

### Table 1: Scenario Coverage Matrix — Composite Rules & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Multi-Tactic Endpoint Kill-Chain Clustering** | Correlates multiple endpoint detections or distinct MITRE ATT&CK tactics on a single host within a short time window. | Fuses 30-day host alert volume (`metrics.alert_event_name_count`) with 30-day outbound network bytes (`metrics.network_bytes_outbound`) ($D^2 \ge 12.25$) and applies Empirical Bayes Gamma-Poisson shrinkage to multi-tactic alert velocity. | `Query 1A` (30d Alert + Egress Fusion)<br>`Query 1B` (Empirical Bayes Alert Shrinkage) |
| **2. Cross-Host Propagation & Lateral Movement** | Detects shared malware indicators or sequential lateral movement alerts across multiple endpoints. | Separates targeted lateral propagation from enterprise-wide administrative rollouts via 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) and fuses 30-day Host Auth Failures with Inbound Network Bytes. | `Query 2A` (Dual-Baseline Fleet Delta-Z)<br>`Query 2B` (30d Auth Fail + Inbound Bytes) |
| **3. Cloud Account Compromise & Multi-Step IAM/Resource Chaining** | Correlates sequences of suspicious cloud control-plane alerts across AWS, GCP, and Azure. | Unifies cold-start cloud identities (Two-Part Hurdle) with 30-day multi-metric Cloud CRUD baselines (`Option 1`) and measures Markov 2-gram cloud API transition surprisal across sequential control-plane actions. | `Query 3A` (Piecewise Hurdle + 30d Cloud CRUD)<br>`Query 3B` (Markov 2-Gram Cloud Surprisal) |
| **4. Low-and-Slow Multi-Day Exfiltration & Post-Exploitation Drift** | Identifies high-volume data transfer following upstream compromise alerts. | Applies 4-stage non-parametric 30-day Median Absolute Deviation (MAD) and 7d-vs-30d MACD momentum velocity divergence to detect gradual multi-day exfiltration drift. | `Query 4A` (4-Stage 30d MAD Egress)<br>`Query 4B` (MACD Momentum Velocity) |
| **5. Capstone Multi-Scenario Entity Convergence** | Short-window correlation of discrete upstream rule firings. | Correlates entities matching $\ge 2$ distinct behavioral composite queries over a 7-day horizon (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Multi-Tactic Endpoint Kill-Chain Clustering

* **Curated Detection Operational Focus**: Correlates multiple endpoint detections or distinct MITRE ATT&CK tactics on a single host within a short time window.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day host alert volume (`metrics.alert_event_name_count`) with 30-day outbound network bytes (`metrics.network_bytes_outbound`) ($D^2 \ge 12.25$) and applies Empirical Bayes Gamma-Poisson shrinkage to multi-tactic alert velocity.

#### Query 1A: 4-Stage Roll-Up Endpoint Alert (`metrics.alert_event_name_count`) + Outbound Network Bytes (`metrics.network_bytes_outbound`) Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Replaces the rigid `15m` window, `$rule_name_count > 2` cliff, and static `+40` network-connection bonus with a **4-Stage Roll-Up Multi-Sector Fusion** ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$). Stage 1 scores each `(principal.asset.hostname, security_result.rule_name)` pair against its own 30-day behavioral baseline (`metrics.alert_event_name_count`); Stage 2 rolls those per-rule Z-scores up to the host level (`$z_a = max($sector_a_detail.d_z)`); Stage 3 scores the host's daily outbound network byte volume against its 30-day baseline (`metrics.network_bytes_outbound`); and the Root Stage fuses both sectors over a full 24-hour day (`by 1d`). Even a single anomalous alert rule paired with an outbound byte surge on the same day breaches $D^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$).

```yara
// ============================================================================
// Goal: Fuse endpoint security alert anomalies with outbound network byte surges on the same host to detect multi-stage endpoint kill chains across a full 24-hour window.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A (alert_event_name_count) is a composite-only roll-up sector; Z_a is the largest per-rule Z for the host.
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

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 1B: Empirical Bayes Gamma-Poisson Credibility Shrinkage on Suspicious Endpoint Process & Alert Velocity (`secops-statistical-hunter`)
Compensates for both the upstream-rule dependency and noisy developer host alert fatigue by applying **Poisson-Gamma Bayesian Conjugate Updating** (curated detection rules) directly over hourly endpoint process execution and security alert telemetry (`by 1h`). Using Method-of-Moments Gamma prior estimation ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$), volatile developer machines with high historical variance ($\sigma^2 \gg \mu$) have their posterior arrival rate shrunk toward their historical mean, while a sudden burst of LOLBin/script executions or security alerts on a historically stable endpoint triggers a high posterior shift ratio ($\text{anomaly\_score} \ge 3.0$).

```yara
// ============================================================================
// Goal: Detect high-confidence endpoint LOLBin process and alert bursts while suppressing noisy developer workstation false alarms via Empirical Bayes Gamma-Poisson shrinkage.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH of interpreters/LOLBins or endpoint security alerts)
// Statistical Model: 4-Stage Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting (anomaly_score >= 3.0)
// ============================================================================

// Stage 1: Hourly suspicious endpoint process and alert velocity per host
stage host_hourly_activity {
    metadata.event_type = "PROCESS_LAUNCH"
    (
      re.regex(target.process.file.full_path, `(?i)(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|curl|bash|sh|python)`)
      or security_result.rule_name != ""
    )
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
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

  // Method-of-Moments Gamma prior (alpha_0 = mu^2 / sigma^2, beta_0 = mu / sigma^2)
  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $beta_prior = max($host_prior_stats.hist_mean) / $safe_var
  $alpha_prior = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $posterior_arrival_rate = ($alpha_prior + max($host_hourly_activity.hourly_count)) / ($beta_prior + 1.0)
  $prior_weight_pct = $beta_prior / ($beta_prior + 1.0)
  $evidence_weight_pct = 1.0 / ($beta_prior + 1.0)
  $safe_hist_mean = if(max($host_prior_stats.hist_mean) > 0, max($host_prior_stats.hist_mean), 1.0)
  $anomaly_score = $posterior_arrival_rate / $safe_hist_mean

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 10
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
```

---

---

### Scenario 2: Cross-Host Malware Propagation & Lateral Movement

* **Curated Detection Operational Focus**: Detects shared malware indicators or sequential lateral movement alerts across multiple endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Separates targeted lateral propagation from enterprise-wide administrative rollouts via 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) and fuses 30-day Host Auth Failures with Inbound Network Bytes.

#### Query 2A: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) on Endpoint Process & Payload Activity (`secops-statistical-hunter`)
Solves both the hash-polymorphism coverage considerations and the enterprise rollout false-positive problem by computing **3-Stage Dual-Baseline Fleet-Normalized Delta-Z** ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$) on endpoint process and payload execution activity per host (`by 1h`). Stage 1 measures each host's hourly process/payload volume and distinct binary count (independent of whether hashes match across hosts); Stage 2 computes the host's personal historical mean and standard deviation; Stage 3 computes the concurrent fleet-wide mean across all active endpoints in the same hour; and the Root Stage subtracts any positive fleet-wide shift from the host's personal Z-score. Fleet-wide software deployments cancel out ($\Delta Z \approx 0$), while targeted lateral movement on 1–3 hosts stands out at $\Delta Z \ge 3.0\sigma$.

```yara
// ============================================================================
// Goal: Isolate targeted lateral movement and polymorphic payload execution surges per host while suppressing fleet-wide software deployments via Dual-Baseline Delta-Z.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH across enterprise endpoints)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift) >= 3.0)
// ============================================================================

// Stage 1: Individual Host Process & Payload Activity Volume in tumbling hourly windows
stage host_hourly_extract {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
}

// Stage 2: Individual Host Personal Historical Baseline (Temporal Baseline)
stage host_personal_baseline {
    $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active endpoints in the same window
stage fleet_concurrent_baseline {
    $host = $host_hourly_extract.host
    $ws = $host_hourly_extract.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hour_avg = avg($host_hourly_extract.hourly_count)
    $fleet_hour_stddev = stddev($host_hourly_extract.hourly_count)
    $active_fleet_hosts = count_distinct($host_hourly_extract.host)
}

// Root Stage: Dual-Baseline Delta-Z Evaluation & 6 Standardized Evidence Pillars
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly_extract.hourly_count)
  $baseline_active_samples = max($host_personal_baseline.active_hours)
  $baseline_mean = max($host_personal_baseline.personal_avg)
  $baseline_dispersion = max($host_personal_baseline.personal_stddev)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_hosts)
  $distinct_binaries = max($host_hourly_extract.distinct_procs)

  // Dual-Baseline Metrics (Common Personal Dispersion Scale)
  $obs = max($host_hourly_extract.hourly_count)
  $p_mean = max($host_personal_baseline.personal_avg)
  $f_mean = max($fleet_concurrent_baseline.fleet_hour_avg)
  $raw_personal_sd = max($host_personal_baseline.personal_stddev)
  $safe_personal_sd = if($raw_personal_sd > 0, $raw_personal_sd, 1.0)

  $personal_z = ($obs - $p_mean) / $safe_personal_sd
  $f_shift = $f_mean - $p_mean
  $fleet_z = $f_shift / $safe_personal_sd
  $pos_fleet_z = if($fleet_z > 0, $fleet_z, 0.0)
  $delta_z = $personal_z - $pos_fleet_z

  $personal_z_score = $personal_z
  $fleet_concurrent_z = $fleet_z
  $targeted_delta_z = $delta_z

condition:
  $baseline_active_samples >= 4
  and $fleet_prevalence >= 3
  and $observation_count >= 15
  and $delta_z >= 3.0

order:
  $delta_z desc
```

#### Query 2B: 3-Stage Dual-Sector Host Authentication Failures (`metrics.auth_attempts_fail`) + Inbound Network Bytes (`metrics.network_bytes_inbound`) Fusion (`secops-risk-metrics-multistage`)
Detects lateral movement and ingress tool transfer on a host without requiring upstream `TA0007` discovery rules by fusing 30-day baselines for **Host Authentication Failures (`metrics.auth_attempts_fail`)** and **Inbound Network Bytes (`metrics.network_bytes_inbound` with `network.received_bytes > 0` and `network.received_bytes < 1000000000000000`, `metric: value_sum`)** keyed on `principal.asset.hostname` ($D^2 = Z_{\text{auth\_fail}}^2 + Z_{\text{inbound\_bytes}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Detect lateral movement authentication probing paired with ingress tool/payload transfer on the same endpoint via 30-day Dual-Sector Risk Fusion.
// Statistical Model: 3-Stage Dual-Sector Threat Fusion (metrics.auth_attempts_fail + metrics.network_bytes_inbound, D^2 >= 12.25)
// ARCHITECTURE: 3-STAGE DUAL-SECTOR THREAT FUSION (GENERIC: ANY TWO ENTITY-KEYED METRICS)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A — Host Authentication Failures (UDM Source 1 of 2) ---
stage sector_a {
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = count(metadata.id)
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
    $z_a_raw = ($a_obs - $a_avg) / if($a_std > 0, $a_std, 1.0)
    $z_a = if($z_a_raw > 0, $z_a_raw, 0.0)
}

// --- STAGE 2: Sector B — Host Inbound Network Bytes (UDM Source 2 of 2) ---
stage sector_b {
    network.received_bytes > 0
    network.received_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(network.received_bytes)
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
    $z_b_raw = ($b_obs - $b_avg) / if($b_std > 0, $b_std, 1.0)
    $z_b = if($z_b_raw > 0, $z_b_raw, 0.0)
}

// --- ROOT STAGE: Dual-Sector Threat Fusion & Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity

match:
  $entity by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $b_observed = max($sector_b.b_obs)
  $a_active_days = max($sector_a.a_days)
  $b_active_days = max($sector_b.b_days)
  $z_a = max($sector_a.z_a)
  $z_b = max($sector_b.z_b)

  // Sparse-baseline gate: a sector with fewer active baseline days contributes 0
  $z_a_gated = if($a_active_days >= 5, $z_a, 0.0)
  $z_b_gated = if($b_active_days >= 5, $z_b, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a_gated * $z_a_gated
  $z_b_sq = $z_b_gated * $z_b_gated
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

---

### Scenario 3: Cloud Account Compromise & Multi-Step IAM/Secret Chaining

* **Curated Detection Operational Focus**: Correlates sequences of suspicious cloud control-plane alerts across AWS, GCP, and Azure.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start cloud identities (Two-Part Hurdle) with 30-day multi-metric Cloud CRUD baselines (`Option 1`) and measures Markov 2-gram cloud API transition surprisal across sequential control-plane actions.

#### Query 3A: 4-Stage Roll-Up Cloud Resource Read Failures (`metrics.resource_read_fail`) + Auth Successes (`metrics.auth_attempts_success`) Fusion (`secops-risk-metrics-multistage`)
Eliminates the `10m` window cliff, `$method_count >= 3` magic number, and same-IP constraint by fusing **30-day Cloud Resource Read Failures (`metrics.resource_read_fail` rolled up across `principal.user.userid`, `metadata.product_name`, `metadata.vendor_name`)** with **30-day Authentication Successes (`metrics.auth_attempts_success` keyed on `target.user.userid`)** for the same cloud user ($D^2 = Z_{\text{read\_fail}}^2 + Z_{\text{auth\_success}}^2 \ge 12.25$). Whenever a compromised cloud identity logs in or assumes roles across *any* IP address and subsequently triggers an anomalous surge of access-denied `RESOURCE_READ` / `USER_RESOURCE_ACCESS` probes against AWS, GCP, or Azure services over a 24-hour window, the joint Euclidean distance surfaces the compromise.

```yara
// ============================================================================
// Goal: Detect cloud account compromise followed by IAM/resource permission probing across any IP or cloud provider via 4-Stage Roll-Up Sector Fusion.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.resource_read_fail + metrics.auth_attempts_success, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A (resource_read_fail) is a composite-only roll-up sector; Z_a is the largest per-(product, vendor) Z for the user.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2): one row per user, product_name, and vendor_name ---
stage sector_a_detail {
    (metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS")
    not security_result.action = "ALLOW"
    principal.user.userid = $entity
    $entity != ""
    metadata.product_name = $product_name
    $product_name != ""
    metadata.vendor_name = $vendor_name
    $vendor_name != ""

  match:
    $entity, $product_name, $vendor_name by 1d

  outcome:
    $d_obs = count(metadata.id)
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
    $d_z_raw = ($d_obs - $d_avg) / if($d_std > 0, $d_std, 1.0)
    $d_z = if($d_days >= 5 and $d_z_raw > 0, $d_z_raw, 0.0)
    $d_hot = if($d_days >= 5 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_days = 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per cloud user ---
stage sector_a {
    $entity = $sector_a_detail.entity
    $ws = $sector_a_detail.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.product_name)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a = max($sector_a_detail.d_z)
}

// --- STAGE 3: Sector B — Cloud User Authentication Successes (UDM Source 2 of 2) ---
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

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 3B: Two-Part Zero-Inflated Hurdle Model on Cross-Service Cloud API Activity (`secops-statistical-hunter`)
Detects both dormant cloud accounts/service accounts suddenly waking up to harvest secrets or assume roles *and* active cloud identities spiking across `RESOURCE_READ`, `RESOURCE_WRITTEN`, and `USER_RESOURCE_ACCESS` events over `1d` buckets (curated detection rules). Part 1 (Discrete Bernoulli Hurdle) flags identities active on $\le 2$ days in the lookback window with a discrete activation multiplier, while Part 2 (Continuous Intensity) scores established identities via their positive-activity Z-score ($\text{hurdle\_threat\_score} \ge 3.0$).

```yara
// ============================================================================
// Goal: Detect dormant or compromised cloud accounts and service accounts awakening with anomalous cross-service API activity (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS).
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS)
// Statistical Model: Two-Part Zero-Inflated Hurdle Outlier Model (hurdle_threat_score >= 3.0)
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
    $distinct_targets = count_distinct(target.resource.name)
    $sample_target = array_distinct(target.resource.name)
}

// Stage 2: Historical active day density (Part 1 Hurdle) and positive-activity dispersion (Part 2 Intensity)
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $hist_mean = avg($entity_historical.bucket_count)
    $hist_stddev = stddev($entity_historical.bucket_count)
    $active_samples = count($entity_historical.window_start)
}

// Stage 3: Enterprise fleet prevalence of active cloud users per daily window
stage fleet_context {
    $ws = $entity_historical.window_start

  match:
    $ws by 1d

  outcome:
    $fleet_users = count_distinct($entity_historical.entity)
}

// Root Stage: Two-Part Hurdle Evaluation & 6 Core Evidence Pillars
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
  $baseline_mean = max($entity_stats.hist_mean)
  $baseline_dispersion = max($entity_stats.hist_stddev)
  $fleet_prevalence = max($fleet_context.fleet_users)
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

  // 1. Part 1: Discrete Bernoulli Hurdle (dormant cloud account awakening, <= 2 active days)
  $is_dormant = if($baseline_active_samples <= 2, 1.0, 0.0)
  $dormant_score = $observation_count * 0.5

  // 2. Part 2: Continuous Intensity Conditioned on Crossing Hurdle
  $diff = $observation_count - $baseline_mean
  $safe_stddev = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = $diff / $safe_stddev

  // 3. Composite Hurdle Threat Score
  $hurdle_threat_score = if($is_dormant > 0, $dormant_score, $intensity_z)

condition:
  $observation_count >= 10
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

---

### Scenario 4: Low-and-Slow Multi-Day Exfiltration & Post-Exploitation Drift

* **Curated Detection Operational Focus**: Identifies high-volume data transfer following upstream compromise alerts.
* **How Multi-Stage UEBA Extends Coverage**: Applies 4-stage non-parametric 30-day Median Absolute Deviation (MAD) and 7d-vs-30d MACD momentum velocity divergence to detect gradual multi-day exfiltration drift.

#### Query 4A: 2-Stage Longitudinal CUSUM Behavioral Drift (`cusum_drift_score >= 3.0`, `drift_days >= 2`) on 30-Day `metrics.network_bytes_outbound` (`secops-risk-metrics-multistage`)
Defeats both the `2h` composite window cliff and sub-$3\sigma$ daily pacing by computing **2-Stage Longitudinal Cumulative Sum (CUSUM) Behavioral Drift** (`cusum_drift_score >= 3.0`, `drift_days >= 2`) against each endpoint's 30-day `metrics.network_bytes_outbound` baseline. Stage 1 computes each day's standardized Z-score (`$daily_z`) and subtracts a $k = 0.5\sigma$ slack allowance (`$deviation = $daily_z - 0.5`, rectified to `$daily_excess`). The Root Stage sums `$daily_excess` across the multi-day evaluation window: normal daily fluctuations ($\le 0.5\sigma$) contribute `0.0`, whereas a sustained $1.8\sigma$ daily exfiltration drip over 3 days accumulates $3 \times (1.8 - 0.5) = 3.9 \ge 3.0$ across `drift_days >= 2`.

```yara
// ============================================================================
// Goal: Detect low-and-slow multi-day data exfiltration drips that stay below single-day thresholds via Longitudinal CUSUM drift on 30-day outbound network bytes.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (cusum_drift_score >= 3.0, drift_days >= 2, k = 0.5 sigma slack)
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Deviation Tracker for Outbound Network Bytes
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

    // Per-day standardized CUSUM slack excess (k = 0.5 sigma)
    $daily_z = ($observed_val - $historical_avg) / if($historical_stddev > 0, $historical_stddev, 1.0)
    $deviation = $daily_z - 0.5
    $daily_excess = if($deviation > 0.0, $deviation, 0.0)
}

// Stage 2 (Root Stage): Longitudinal Drift Score & Multi-Day Accumulation
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
  $drift_days = sum(if($stage1_extract.daily_excess > 0.0, 1, 0))
  $z_score = $cusum_drift_score

condition:
  $active_days >= 5
  and $cusum_drift_score >= 3.0
  and $drift_days >= 2

order:
  $cusum_drift_score desc
```

#### Query 4B: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Cloud & Endpoint Resource Access Volume (`secops-statistical-hunter`)
Eliminates the `2h` correlation cliff between login (`T1078.004`) and storage access (`T1530`) in curated detection rules by scoring each user's daily cloud and endpoint resource access volume (`RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `RESOURCE_WRITTEN`) against their own non-parametric **Median Absolute Deviation (MAD)** baseline (curated detection rules, $M_Z > 3.5$). Because the median and MAD have a 50% breakdown point—backed by the Iglewicz-Hoaglin MeanAD fallback (`1.253314 * $baseline_mean_abs_dev`) when `MAD = 0`—a compromised account hoarding storage objects or secrets days after initial access is flagged accurately even on skewed telemetry.

```yara
// ============================================================================
// Goal: Detect anomalous post-compromise cloud storage and resource access hoarding per user regardless of how many hours or days elapsed since initial login.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, USER_RESOURCE_ACCESS, RESOURCE_WRITTEN)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (M_Z > 3.5)
// ============================================================================

// Stage 1: Daily observed cloud/endpoint resource access volume per user
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

  // Robust scale with Iglewicz-Hoaglin MAD=0 fallback
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 4 active days) + Mature Robust MAD (>= 5 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 4, 2.5, 1.0)
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost
  $unified_threat_score = if($baseline_active_samples <= 4, $hurdle_threat_score, $m_z_score)

condition:
  $observation_count >= 15
  and $unified_threat_score >= 3.5

order:
  $unified_threat_score desc
```

---

---

### Scenario 5: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Short-window correlation of discrete upstream rule firings.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral composite queries over a 7-day horizon (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Composite Entity Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across all Composite Rules scenarios via UDM Loopback to detect multi-stage kill-chain convergence.
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

## 3. Appendix: A Practitioner's Plain-English Guide to the 8 Statistical Models

### 3.1 4-Stage Roll-Up Endpoint Alert + Outbound Network Bytes Fusion ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$ — Query 1A)
* **What it measures**: The combined 30-day behavioral anomaly across two orthogonal host telemetry vectors: the most anomalous individual EDR/alert rule triggered on the endpoint (`metrics.alert_event_name_count`) and the endpoint's total daily outbound network byte transfer (`metrics.network_bytes_outbound`).
* **Why static composite rules fail**: curated detection rules requires $>2$ distinct rules within a `15m` window and adds a flat `+40` risk bonus if *any* `NETWORK_CONNECTION` event is present. An attacker who triggers only 1 alert rule or waits 20 minutes before exfiltrating data evades the composite rule.
* **How the math works**: Because `metrics.alert_event_name_count` is a composite-keyed metric, Stage 1 computes a 30-day Z-score per `(host, rule_name)` and Stage 2 rolls up the maximum per-rule Z-score ($Z_A$) for the host. Stage 3 computes the 30-day Z-score for outbound bytes ($Z_B$). Combining rectified scores via $D^2 = Z_A^2 + Z_B^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius) catches multi-stage host compromises across a full 24-hour window even when each individual signal sits at a moderate $2.5\sigma$.

### 3.2 Empirical Bayes Gamma-Poisson Credibility Shrinkage ($\text{anomaly\_score} \ge 3.0$ — Query 1B)
* **What it measures**: The ratio of a host's posterior hourly LOLBin/alert arrival rate to its historical mean, weighted by how stable or erratic that host's baseline is.
* **Why static composite rules fail**: Static rules (`c_mitre_ttps_4p_multi_tactic`, curated detection rules) treat noisy developer laptops and quiet production servers identically, causing constant alert fatigue on developer machines while missing 2-tactic bursts on servers.
* **How the math works**: Method-of-Moments estimates a Gamma prior ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$) from each host's hourly history. Erratic developer workstations have high variance ($\sigma^2 \gg \mu$), shrinking their credibility weight, whereas a sudden burst of suspicious process executions on a predictable workstation or server produces an immediate posterior shift ($\ge 3.0\times$).

### 3.3 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$ — Query 2A)
* **What it measures**: How much a single endpoint's process and payload execution volume surged above its own historical baseline *after subtracting any concurrent fleet-wide surge*.
* **Why static composite rules fail**: `c_chrome_suspicious_downloads_with_matching_hashes_on_multiple_hosts` groups by `$sha256file_hash over 1h` (`$host_count > 1`). It is completely blinded when attackers use per-victim polymorphic hashes, and it floods the SOC with false positives whenever IT deploys a new tool across the fleet.
* **How the math works**: During a company-wide software rollout or Patch Tuesday, both $Z_{\text{personal}}$ and $Z_{\text{fleet}}$ spike together, so $\Delta Z \approx 0$. During targeted lateral movement or polymorphic malware staging on 1–3 hosts, the fleet mean stays flat ($Z_{\text{fleet}} \approx 0$) while the targeted host's $\Delta Z$ exceeds $3.0\sigma$.

### 3.4 3-Stage Dual-Sector Host Auth Failures + Inbound Network Bytes Fusion ($D^2 \ge 12.25$ — Query 2B)
* **What it measures**: The joint 30-day behavioral deviation of failed login attempts (`metrics.auth_attempts_fail`) and inbound network bytes (`metrics.network_bytes_inbound`) on the same endpoint (`principal.asset.hostname`).
* **Why static composite rules fail**: `c_mitre_ttps_lateral_movement_multi_discovery` requires at least two upstream `TA0007` discovery rule alerts alongside a `TA0008` lateral movement alert within `3h`. Attackers who brute-force or spray credentials and stage payloads over SMB/WinRM/RDP without running noisy discovery binaries evade it.
* **How the math works**: By fusing rectified 30-day Z-scores for authentication failures and inbound byte volume on `principal.asset.hostname`, any host experiencing abnormal login probing paired with abnormal ingress payload transfer in the same day crosses $D^2 \ge 12.25$ without needing upstream `TA0007` rules to fire.

### 3.5 4-Stage Roll-Up Cloud Resource Read Failures + Auth Success Fusion ($D^2 \ge 12.25$ — Query 3A)
* **What it measures**: The combined 30-day behavioral anomaly between a cloud user's denied resource/API read attempts (`metrics.resource_read_fail` rolled up across cloud `product_name` and `vendor_name`) and their successful authentications (`metrics.auth_attempts_success`).
* **Why static composite rules fail**: curated detection rules requires both role assumptions to share the exact same `$principal_ip` within `2h`, and curated detection rules requires $\ge 3$ blocked IAM discovery methods within `10m`. Rotating proxy IPs, pivoting into CloudShell/EC2, or pacing IAM probes $>10\text{m}$ apart defeats both rules.
* **How the math works**: Keying on the cloud user identity (`userid`) rather than `$principal_ip` tracks the actor across IP changes and role assumptions over a full 24-hour window, fusing login/session anomalies with rolled-up access-denied `RESOURCE_READ` / `USER_RESOURCE_ACCESS` spikes across AWS, GCP, and Azure.

### 3.6 Two-Part Zero-Inflated Hurdle Model ($\text{hurdle\_threat\_score} \ge 3.0$ — Query 3B)
* **What it measures**: Part 1 (Bernoulli Hurdle) tests whether a cloud user or service account was historically dormant ($\le 2$ active days); Part 2 (Continuous Intensity) measures the positive-activity Z-score of cross-service cloud API calls (`RESOURCE_READ`, `RESOURCE_WRITTEN`, `USER_RESOURCE_ACCESS`) for established accounts.
* **Why static composite rules fail**: Rules like curated detection rules hardcode static allowlists (`!= /gsa5-caf-mgmt@/`) and fixed counts (`$target_resource_count >= 3 over 60m`), missing dormant CI/CD service accounts waking up or slow secrets collection.
* **How the math works**: Separating *presence* from *magnitude* prevents zero-inflation distortion: dormant cloud identities that suddenly wake up receive a direct hurdle activation score (`$observation_count * 0.5`), while active accounts are scored against their active-day mean and standard deviation.

### 3.7 2-Stage Longitudinal CUSUM Behavioral Drift ($S_t^+ \ge 3.0, \text{drift\_days} \ge 2$ — Query 4A)
* **What it measures**: The multi-day accumulation of positive standardized outbound byte excesses ($Z_t - 0.5\sigma$) above a host's 30-day `metrics.network_bytes_outbound` baseline.
* **Why static composite rules fail**: Endpoint and cloud exfiltration composites (`c_exfiltration_over_c2_channel_and_ingress_tool_transfer`, curated detection rules) enforce `1h`–`2h` correlation windows and require an upstream C2/exfiltration alert. Adversaries who trickle stolen data out at $1.5\sigma\text{–}2.0\sigma$ per day across multiple days evade both single-day Z-scores and short composite windows.
* **How the math works**: Subtracting the $k = 0.5\sigma$ slack constant zeros out routine daily noise, while a steady $1.8\sigma$ daily exfiltration drip adds $+1.3$ to $S_t^+$ each day, crossing `cusum_drift_score >= 3.0` with `drift_days >= 2` within 3 days.

### 3.8 4-Stage Non-Parametric Median Absolute Deviation (MAD / Modified Z-Score $M_Z > 3.5$ — Query 4B)
* **What it measures**: How many robust standard deviations a user's daily cloud and endpoint resource access volume (`RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `RESOURCE_WRITTEN`) sits above their historical median.
* **Why static composite rules fail**: curated detection rules requires an upstream `T1078.004` credential alert and a `T1530` storage alert within a `2h` window. Waiting 3 hours—or 3 days—after compromising an account before bulk-reading cloud storage completely bypasses the rule.
* **How the math works**: Unlike parametric mean and standard deviation—which are easily corrupted by a single noisy backup day—the median and MAD have a 50% breakdown point. When `MAD = 0` (a user whose daily resource reads are nearly constant), the Iglewicz-Hoaglin MeanAD fallback (`1.253314 * MeanAD`) ensures a sudden storage-hoarding spike is still scored with high precision ($M_Z > 3.5$).
