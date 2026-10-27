# Hunting Multi-Stage Kill-Chain & Cloud/Endpoint Composite Threats with Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Composite Rules** curated detection suite correlates multiple upstream rule detections or MITRE ATT&CK tactics across endpoint and cloud telemetry to surface multi-step intrusions.

While deterministic composite rules correlate discrete rule firings within fixed short-term correlation windows, adversaries often pace intrusion stages across hours or days, or blend low-severity activity with subtle behavioral shifts in authentication, API usage, and network egress. This playbook supplements composite detections with **30-day Multi-Sector Behavioral Risk Fusion (`secops-risk-metrics-multistage`)**, **Empirical Bayes Alert Shrinkage**, **Dual-Baseline Fleet Delta-Z**, and **UDM Loopback Capstone Convergence**.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

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

#### Query 1B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Endpoint Process & Alert Velocity (`secops-statistical-hunter`)
Evaluates hourly endpoint process and security alert velocity via **Poisson-Gamma Bayesian Conjugate Updating** strictly on candidate endpoints surfaced by `Query 1A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_1a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect multi-stage endpoint execution and alert bursts on candidate hosts from Query 1A (strictly gated by Query 1A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson-Gamma Bayesian Conjugate Updating
// ============================================================================

stage stage1_upstream_1a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_1a`)
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
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
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_exts = count_distinct(target.process.file.full_path)
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

### Scenario 2: Cross-Host Malware Propagation & Lateral Movement

* **Curated Detection Operational Focus**: Detects shared malware indicators or sequential lateral movement alerts across multiple endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Separates targeted lateral propagation from enterprise-wide administrative rollouts via 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) and fuses 30-day Host Auth Failures with Inbound Network Bytes.

#### Query 2A: 3-Stage Dual-Sector Host Authentication Failures (`metrics.auth_attempts_fail`) + Inbound Network Bytes (`metrics.network_bytes_inbound`) Fusion (`secops-risk-metrics-multistage`)
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

#### Query 2B: 4-Stage UDM-Gated Personal & Upstream Delta-Z on Endpoint Process & Payload Activity (`secops-statistical-hunter`)
Evaluates hourly endpoint process execution surges against personal hourly baselines strictly on candidate endpoints surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED PERSONAL & UPSTREAM DELTA-Z PIPELINE
// Goal: Detect post-authentication payload execution spikes on candidate hosts from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Hourly Standardized Personal Z-Score Fusion
// ============================================================================

stage stage1_upstream_2a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_2a_z = max(security_result.confidence_score)
}

stage hourly_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_val = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
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

$host = $stage1_upstream_2a_candidates.host
$host = $hourly_counts.host
$host = $personal_baseline.host
$ws = $hourly_counts.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
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

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–4 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 4 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 Composite Rules scenarios (1 through 4B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0) + Cross-Plane Raw Telemetry Bridge
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
