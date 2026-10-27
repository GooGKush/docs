# Cross-Vendor Alert Normalization & Behavioral Triage with Multi-Stage Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Third-Party Vendor Alerts** curated suite provides broad multi-vendor alert normalization across 40+ endpoint (EDR/XDR), identity protection (IDP), email threat prevention, SASE/web proxy, DLP, cloud security, and OT/mobile security integrations.

When organizations operate heterogeneous security stacks, individual vendor alerts often fire in isolation with static vendor-assigned severities. This playbook layers **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`) over multi-vendor alert streams—applying Empirical Bayes Gamma-Poisson credibility shrinkage, 10-day `DERIVED_CONTEXT` binary prevalence, Beta-Binomial identity failure-rate regularization, 3-Metric Workspace/Identity triads, and Cross-Vendor UDM Loopback Capstone correlation.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

### Table 1: Scenario Coverage Matrix — Third-Party Vendor Alerts & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Multi-Vendor Endpoint & XDR Alert Triage** | Normalizes endpoint and XDR alert streams across diverse endpoint security agents. | Applies Empirical Bayes Gamma-Poisson credibility shrinkage to normalize host alert bursts against fleet priors and pairs 30-day file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` prevalence. | `Query 1A` (Empirical Bayes Alert Shrinkage)<br>`Query 1B` (30d Execution + 10d Prevalence) |
| **2. Identity Protection (IDP) & Email Threat Prevention Alerts** | Ingests identity risk and phishing/email delivery alerts from IDP and secure email gateways. | Combines 4-stage Beta-Binomial Empirical Bayes authentication failure-rate regularization with a 3-Metric Multilevel Part-of-the-Whole Workspace/Identity behavioral triad. | `Query 2A` (Beta-Binomial Auth Regularization)<br>`Query 2B` (3-Metric Workspace/Identity Triad) |
| **3. SASE, Web Proxy & Network Detection Alerts** | Surfaces web proxy, secure web gateway (SWG), and NDR alerts. | Fuses 30-day Outbound Network Bytes and HTTP/DNS baselines ($D^2 \ge 12.25$) and measures inter-arrival C2 callback jitter ($\text{CV} \le 0.20$) across flagged network destinations. | `Query 3A` (30d Egress + Web Fusion)<br>`Query 3B` (C2 Inter-Arrival CV) |
| **4. Data Loss Prevention (DLP), Cloud (CNAPP) & OT/Mobile Alerts** | Monitors DLP policy triggers, cloud runtime alerts, and specialized OT/mobile security notifications. | Unifies cold-start entities (Two-Part Hurdle) with 4-stage non-parametric 30-day Median Absolute Deviation (MAD) (`Option 1`) on outbound data volume and cloud resource operations. | `Query 4A` (Piecewise Hurdle + 4-Stage 30d MAD)<br>`Query 4B` (Two-Part Cross-Domain Hurdle) |
| **5. Capstone Cross-Vendor Entity Convergence** | Vendor alerts evaluated per integration policy. | Correlates entities accumulating $\ge 2$ distinct cross-vendor behavioral matches within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Multi-Vendor Endpoint & XDR Alert Normalization

* **Curated Detection Operational Focus**: Normalizes endpoint and XDR alert streams across diverse endpoint security agents.
* **How Multi-Stage UEBA Extends Coverage**: Applies Empirical Bayes Gamma-Poisson credibility shrinkage to normalize host alert bursts against fleet priors and pairs 30-day file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` prevalence.

#### Query 1A: Empirical Bayes Gamma-Poisson Credibility Shrinkage on Multi-Vendor EDR Alerts (`secops-statistical-hunter`)
Normalizes alert volume across all endpoint and XDR vendors (`CB_EDR`, `CS_DETECTS`, `CS_ALERTS`, `CYBEREASON_EDR`, `DEEP_INSTINCT_EDR`, `ESET_EDR`, `LIMACHARLIE_EDR`, `Malwarebytes_EDR`, `MICROSOFT_GRAPH_ALERT`, `CORTEX_XDR`, `EDR`, `SOPHOS_EDR`, `SYMANTEC_EDR`, `TRELLIX_HX_ALERTS`, `TRENDMICRO_VISION_ONE`, `UPTYCS_EDR`) per host (`principal.asset.hostname`, `by 1h`). Using Method-of-Moments Gamma prior estimation ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$), chronically noisy hosts with high historical variance ($\sigma^2 \gg \mu$) have their credibility weight shrunk toward their prior mean, whereas a sudden multi-alert burst on a historically stable endpoint produces an immediate posterior belief shift ($\text{anomaly\_score} \ge 3.0$).

```yara
// ============================================================================
// Goal: Normalize multi-vendor EDR/XDR alert streams per host using Empirical Bayes Gamma-Poisson shrinkage to suppress noisy agents and amplify true alert bursts on stable endpoints.
// Target Telemetry: UDM_EVENTS (Multi-vendor EDR/XDR alert log types)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting (anomaly_score >= 3.0)
// ============================================================================

// Stage 1: Hourly multi-vendor EDR/XDR alert volume and rule diversity per host
stage host_hourly_activity {
    (
      metadata.log_type = "CB_EDR"
      or metadata.log_type = "CS_DETECTS"
      or metadata.log_type = "CS_ALERTS"
      or metadata.log_type = "CYBEREASON_EDR"
      or metadata.log_type = "DEEP_INSTINCT_EDR"
      or metadata.log_type = "ESET_EDR"
      or metadata.log_type = "FORTINET_FORTIEDR"
      or metadata.log_type = "LIMACHARLIE_EDR"
      or metadata.log_type = "Malwarebytes_EDR"
      or metadata.log_type = "MICROSOFT_GRAPH_ALERT"
      or metadata.log_type = "PAN_EDR"
      or metadata.log_type = "CORTEX_XDR"
      or metadata.log_type = "EDR"
      or metadata.log_type = "SOPHOS_EDR"
      or metadata.log_type = "SYMANTEC_EDR"
      or metadata.log_type = "TRELLIX_HX_ALERTS"
      or metadata.log_type = "TRENDMICRO_VISION_ONE"
      or metadata.log_type = "TRENDMICRO_VISION_ONE_WORKBENCH"
      or metadata.log_type = "TRENDMICRO_VISION_ONE_DETECTIONS"
      or metadata.log_type = "UPTYCS_EDR"
    )
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(security_result.rule_name)
}

// Stage 2: Historical Parameter Estimation (Method of Moments Gamma Prior per host)
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

// Root Stage: Bayesian Conjugate Updating, Credibility Shrinkage & 6 Core Evidence Pillars
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
  $z_score = $anomaly_score

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 5
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
```

#### Query 1B: 2-Stage Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Corroborates vendor endpoint alerts (and closes the polymorphic hash gap in `google-threat-intelligence`'s `gcp_threatintel_ioc_about_file_sha256` and `gcp_threatintel_ioc_target_process_file_sha256` rules) by scoring endpoint `PROCESS_LAUNCH` events against the 30-day composite metric `metrics.file_executions_total` joined with `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3` hosts).

```yara
// ============================================================================
// Goal: Corroborate endpoint vendor alerts by detecting execution of organizationally rare binaries (10-day rolling_max <= 3 hosts) with anomalous 30-day per-host execution volume.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence Multiplier
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint Process Execution + 30-Day Composite Baseline per (host, event_type, sha256)
stage process_metric_anomalies {
    metadata.event_type = "PROCESS_LAUNCH"
    metadata.event_type = $event_type
    principal.asset.hostname = $host
    principal.process.file.sha256 = $sha256
    $host != ""
    $sha256 != ""

  match:
    $host, $event_type, $sha256 by 1d

  outcome:
    $exec_count = count(metadata.id)
    $b_avg = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $b_std = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $b_days = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $z_score = ($exec_count - $b_avg) / if($b_std > 0, $b_std, 1.0)
}

// Root Stage: Join with DERIVED_CONTEXT 10-Day File Prevalence (rolling_max <= 3)
$host = $process_metric_anomalies.host
$sha256 = $process_metric_anomalies.sha256

$g.graph.metadata.entity_type = "FILE"
$g.graph.metadata.source_type = "DERIVED_CONTEXT"
$g.graph.entity.file.sha256 = $sha256
$g.graph.entity.file.prevalence.day_count = 10
$g.graph.entity.file.prevalence.rolling_max <= 3
$g.graph.entity.file.prevalence.rolling_max > 0

match:
  $host, $sha256

outcome:
  $observed_execs = max($process_metric_anomalies.exec_count)
  $baseline_mean = max($process_metric_anomalies.b_avg)
  $baseline_stddev = max($process_metric_anomalies.b_std)
  $active_days = max($process_metric_anomalies.b_days)
  $z_score = max($process_metric_anomalies.z_score)
  $org_file_prevalence_10d = max($g.graph.entity.file.prevalence.rolling_max)

  // Novel binary (0 prior active days on host) or singleton in org gets 2.5x multiplier
  $novelty_boost = if($active_days = 0 or $org_file_prevalence_10d <= 1, 2.5, 1.5)
  $base_signal = if($z_score > 1.0, $z_score, 1.5)
  $fused_threat_score = $base_signal * $novelty_boost

condition:
  $observed_execs >= 1
  and $fused_threat_score >= 3.0

order:
  $fused_threat_score desc
```

---

---

### Scenario 2: Identity Protection (IDP) & Email Threat Prevention Alerts

* **Curated Detection Operational Focus**: Ingests identity risk and phishing/email delivery alerts from IDP and secure email gateways.
* **How Multi-Stage UEBA Extends Coverage**: Combines 4-stage Beta-Binomial Empirical Bayes authentication failure-rate regularization with a 3-Metric Multilevel Part-of-the-Whole Workspace/Identity behavioral triad.

#### Query 2A: 4-Stage Beta-Binomial Empirical Bayes Authentication Failure Rate Regularization (`secops-statistical-hunter`)
Eliminates single-trial password typo false alarms while isolating sustained credential stuffing, password spraying, and post-phishing brute-force attacks on `USER_LOGIN` events. By applying a Beta($\alpha_0 = 1.0, \beta_0 = 9.0$) conjugate prior to hourly login trials per user (`target.user.userid`), a single failed login out of 1 attempt is shrunk from $100\%$ to $(1+1)/(1+10) = 18.2\%$, whereas a user experiencing 15 failures out of 16 attempts achieves a regularized posterior failure probability of $(15+1)/(16+10) = 61.5\%$ (and $\ge 70\%$ at higher spray intensities).

```yara
// ============================================================================
// Goal: Detect sustained credential stuffing, password spraying, and post-phishing login failure surges using Beta-Binomial Empirical Bayes regularization.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: 4-Stage Beta-Binomial Bayesian Conjugate Updating & Small-Sample Shrinkage (regularized_failure_prob >= 0.70)
// ============================================================================

// Stage 1: Aggregate login trials and failures per user in tumbling hourly windows
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

// Stage 2: Historical Parameter Estimation across all active baseline windows per user
stage entity_historical_rates {
    $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

// Stage 3: Enterprise Fleet Context per hourly window
stage fleet_stats {
    $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = count_distinct($entity_hourly_trials.user)
}

// Root Stage: Beta-Binomial Conjugate Updating, Shrinkage & 6 Core Evidence Pillars
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
  $z_score = $regularized_failure_prob * 10.0

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 5
  and $regularized_failure_prob >= 0.70

order:
  $regularized_failure_prob desc
```

#### Query 2B: 3-Metric Multilevel Part-of-the-Whole Workspace/Identity Triad (`secops-risk-metrics-multistage`)
Corroborates upstream phishing (`proofpoint-tap`, `trellix-etp`, `trellix-ex`) and identity (`crowdstrike-idp`, `microsoft-defender-identity`) alerts by scoring every user across the **Workspace/Identity Activity Triad**—`metrics.workspace_auth_attempts_total`, `metrics.workspace_total_download_actions`, and `metrics.workspace_total_change_actions`—against both their personal 30-day behavioral baseline (with zero-safe denominators so dormant 0-baseline users are never dropped) and the enterprise fleet ($D_{\text{vs\_fleet}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Corroborate IDP and email phishing alerts by detecting post-compromise authentication, file download hoarding, and change surges across the Workspace/Identity Triad.
// Statistical Model: 3-Metric Multilevel Part-of-the-Whole Triad (Personal + Fleet Z-Scores, D_vs_fleet^2 >= 12.25)
// ARCHITECTURE: 3-METRIC MULTILEVEL PART-OF-THE-WHOLE TRIAD DAG
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Enterprise Population Telemetry + 30-Day Baselines for the Workspace/Identity Triad
stage all_entities {
    metadata.vendor_name = "Google Workspace"
    principal.user.userid = $user
    $user != ""

  match:
    $user by 1d

  outcome:
    // Metric 1: Workspace Auth Attempts Total (login, saml, token)
    $m1_obs = sum(if((metadata.product_name = "login" or metadata.product_name = "saml" or metadata.product_name = "token"), 1, 0))
    $m1_p_avg = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m1_p_std = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // Metric 2: Workspace Total Download Actions (zero-safe for dormant users)
    $m2_obs = sum(if(metadata.product_event_type = "download", 1, 0))
    $m2_p_avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m2_p_std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // Metric 3: Workspace Total Change Actions
    $m3_obs = count(metadata.id)
    $m3_p_avg = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m3_p_std = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // In-Stage Personal Historical Z-Scores with zero-safe denominators
    $z1_personal = ($m1_obs - $m1_p_avg) / if($m1_p_std > 0, $m1_p_std, 1.0)
    $z2_personal = ($m2_obs - $m2_p_avg) / if($m2_p_std > 0, $m2_p_std, 1.0)
    $z3_personal = ($m3_obs - $m3_p_avg) / if($m3_p_std > 0, $m3_p_std, 1.0)
}

// Stage 2: Enterprise Whole (Macro baseline across all active users in the window)
stage enterprise_stats {
    $ws = $all_entities.window_start

  match:
    $ws by 1d

  outcome:
    $m1_fleet_avg = avg($all_entities.m1_obs)
    $m1_fleet_std = stddev($all_entities.m1_obs)

    $m2_fleet_avg = avg($all_entities.m2_obs)
    $m2_fleet_std = stddev($all_entities.m2_obs)

    $m3_fleet_avg = avg($all_entities.m3_obs)
    $m3_fleet_std = stddev($all_entities.m3_obs)

    $m1_fleet_div = if($m1_fleet_std > 0, $m1_fleet_std, 1.0)
    $m2_fleet_div = if($m2_fleet_std > 0, $m2_fleet_std, 1.0)
    $m3_fleet_div = if($m3_fleet_std > 0, $m3_fleet_std, 1.0)

    $fleet_size = count_distinct($all_entities.user)
}

// Root Stage: Multilevel Triad Scoring & Composite Euclidean Distance vs Fleet
$user = $all_entities.user
$ws = $all_entities.window_start
$ws = $enterprise_stats.ws

match:
  $user, $ws by 1d

outcome:
  $m1_observed = max($all_entities.m1_obs)
  $m2_observed = max($all_entities.m2_obs)
  $m3_observed = max($all_entities.m3_obs)

  // 1. Personal Historical Z-Scores
  $z1_personal = max($all_entities.z1_personal)
  $z2_personal = max($all_entities.z2_personal)
  $z3_personal = max($all_entities.z3_personal)

  // 2. Enterprise Cross-Sectional Z-Scores ("Part of the Fleet")
  $z1_vs_enterprise = ($m1_observed - max($enterprise_stats.m1_fleet_avg)) / max($enterprise_stats.m1_fleet_div)
  $z2_vs_enterprise = ($m2_observed - max($enterprise_stats.m2_fleet_avg)) / max($enterprise_stats.m2_fleet_div)
  $z3_vs_enterprise = ($m3_observed - max($enterprise_stats.m3_fleet_avg)) / max($enterprise_stats.m3_fleet_div)

  // 3. Composite Threat Norm Across the Triad vs the Fleet
  $d_vs_fleet_sq = ($z1_vs_enterprise * $z1_vs_enterprise) + ($z2_vs_enterprise * $z2_vs_enterprise) + ($z3_vs_enterprise * $z3_vs_enterprise)
  $composite_threat_norm_sq = $d_vs_fleet_sq

condition:
  $d_vs_fleet_sq >= 12.25

order:
  $d_vs_fleet_sq desc
```

---

---

### Scenario 3: SASE, Web Proxy & Network Detection Alerts

* **Curated Detection Operational Focus**: Surfaces web proxy, secure web gateway (SWG), and NDR alerts.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day Outbound Network Bytes and HTTP/DNS baselines ($D^2 \ge 12.25$) and measures inter-arrival C2 callback jitter ($\text{CV} \le 0.20$) across flagged network destinations.

#### Query 3A: 2-Stage Hybrid 30-Day HTTP Volume Baseline + `DERIVED_CONTEXT` 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Closes the unlisted-domain coverage considerations in `google-threat-intelligence`, `zscaler`, `pan`, and `fortinet` by scoring each host's daily HTTP volume against its 30-day behavioral baseline (`metrics.http_queries_total`) and joining with `DERIVED_CONTEXT` **10-day rolling organizational domain prevalence** (`rolling_max <= 3` hosts). Even when a C2 domain has zero Threat Intelligence hits, if $\le 3$ hosts in the enterprise have ever contacted it and it drives an HTTP anomaly on the host, this query surfaces it immediately.

```yara
// ============================================================================
// Goal: Detect endpoints communicating with rare external domains (10-day rolling_max <= 3 hosts) alongside a 30-day HTTP query anomaly, catching unlisted C2 domains missed by static IOC feeds and web proxy signatures.
// Statistical Model: Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence Multiplier
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint HTTP Activity + 30-Day Behavioral Baseline per (host, target_domain)
stage http_metric_anomalies {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $http_count = count(metadata.id)
    $b_avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z_score = ($http_count - $b_avg) / if($b_std > 0, $b_std, 1.0)

  condition:
    $http_count >= 10 and $b_days >= 5
}

// Root Stage: Enrich with DERIVED_CONTEXT 10-Day Domain Prevalence (rolling_max <= 3)
$host = $http_metric_anomalies.host
$domain = $http_metric_anomalies.domain

$g.graph.metadata.entity_type = "DOMAIN_NAME"
$g.graph.metadata.source_type = "DERIVED_CONTEXT"
$g.graph.entity.domain.name = $domain
$g.graph.entity.domain.prevalence.day_count = 10
$g.graph.entity.domain.prevalence.rolling_max <= 3
$g.graph.entity.domain.prevalence.rolling_max > 0

match:
  $host, $domain

outcome:
  $observed_http = max($http_metric_anomalies.http_count)
  $baseline_mean = max($http_metric_anomalies.b_avg)
  $baseline_stddev = max($http_metric_anomalies.b_std)
  $z_score = max($http_metric_anomalies.z_score)
  $org_prevalence_10d = max($g.graph.entity.domain.prevalence.rolling_max)
  $domain_first_seen = max($g.graph.entity.domain.first_seen_time.seconds)

  // Rarity multiplier: singleton domain in the org gets 2.0x boost; <= 3 hosts gets 1.5x
  $rarity_multiplier = if($org_prevalence_10d <= 1, 2.0, 1.5)
  $pos_z = if($z_score > 0, $z_score, 0.5)
  $fused_threat_score = $pos_z * $rarity_multiplier

condition:
  $fused_threat_score >= 3.0

order:
  $fused_threat_score desc
```

#### Query 3B: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on Proxy & Firewall Network Callbacks (`secops-statistical-hunter`)
Detects automated C2 beaconing across firewall, proxy, and NDR telemetry (`NETWORK_CONNECTION`) even when the implant uses 15%–20% randomized sleep jitter and communicates over allowed HTTPS ports without triggering a `CORELIGHT`, `FIREEYE_NX`, `VECTRA_DETECT`, or `PAN_FIREWALL` signature. Human web browsing exhibits high inter-arrival variance ($\text{CV} = \sigma/\mu > 0.50$), whereas programmed C2 heartbeats maintain $\text{CV} \le 0.20$ to low-prevalence external IPs ($\le 3$ internal hosts).

```yara
// ============================================================================
// Goal: Detect persistent Command & Control (C2) beaconing with randomized sleep jitter across proxy, firewall, and NDR network telemetry to low-prevalence external IPs.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ <= 0.20) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Measure hourly inter-arrival timing intervals per (src_ip, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    principal.asset.ip = $src_ip
    $src_ip != ""
    $dst_ip != ""
    // Exclude internal RFC 1918 subnets for destination
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    $ts = metadata.event_timestamp.seconds

  match:
    $src_ip, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
}

// Stage 2: Aggregate historical inter-arrival timing stats across active hours
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip

  match:
    $src_ip, $dst_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $active_hours = count($host_intervals.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of the destination IP across internal hosts
stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip

  outcome:
    $src_breadth = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute CV = σ / μ, and emit 6 Core Evidence Pillars
$src_ip = $timing_stats.src_ip
$dst_ip = $timing_stats.dst_ip
$dst_ip = $dst_prevalence.dst_ip

match:
  $src_ip, $dst_ip

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.total_conns)

  // Aggregate Coefficient of Variation (CV = σ / μ)
  $raw_mean = max($timing_stats.mean_gap)
  $safe_mean = if($raw_mean > 0, $raw_mean, 1.0)
  $raw_stddev = max($timing_stats.stddev_gap)
  $cv = $raw_stddev / $safe_mean

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 20
  and $baseline_mean >= 1.0
  and $fleet_prevalence <= 3
  and $cv <= 0.20

order:
  $cv asc
```

---

---

### Scenario 4: Data Loss Prevention (DLP), Cloud (Wiz) & OT/Mobile Vendor Alerts

* **Curated Detection Operational Focus**: Monitors DLP policy triggers, cloud runtime alerts, and specialized OT/mobile security notifications.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start entities (Two-Part Hurdle) with 4-stage non-parametric 30-day Median Absolute Deviation (MAD) (`Option 1`) on outbound data volume and cloud resource operations.

#### Query 4A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily DLP, Cloud & OT Vendor Alerts (`secops-statistical-hunter`)
Deduplicates unwindowed `WIZ_IO` events and scores daily alert/transfer volume across DLP (`DIGITALGUARDIAN_EDR`), Cloud (`WIZ_IO`), Mobile (`CS_ALERTS`), and OT (`CLAROTY_CTD`, `CLAROTY_XDOME`, `FORESCOUT_EYEINSPECT`, `NOZOMI_GUARDIAN`) telemetry per entity against a non-parametric **Median Absolute Deviation (MAD)** baseline ($M_Z > 3.5$) with the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) when $\text{MAD} = 0$.

```yara
// ============================================================================
// Goal: Detect anomalous daily surges in DLP, Cloud (Wiz), Mobile, and OT vendor telemetry per entity using robust Median Absolute Deviation (MAD) scaling.
// Target Telemetry: UDM_EVENTS (DIGITALGUARDIAN_EDR, WIZ_IO, CLAROTY_CTD, CLAROTY_XDOME, FORESCOUT_EYEINSPECT, NOZOMI_GUARDIAN)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (M_Z > 3.5)
// ============================================================================

// Stage 1: Daily observed DLP, Cloud, and OT alert/transfer volume per entity
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

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 4 active days) + Mature Robust MAD (>= 5 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 4, 2.5, 1.0)
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost
  $unified_threat_score = if($baseline_active_samples <= 4, $hurdle_threat_score, $m_z_score)

condition:
  $observation_count >= 10
  and $unified_threat_score > 3.5

order:
  $unified_threat_score desc
```

#### Query 4B: 2-Stage Longitudinal CUSUM Behavioral Drift on 30-Day Outbound Network Bytes (`secops-risk-metrics-multistage`)
Corroborates DLP (`digital-guardian`), Cloud (`wiz`), and OT (`claroty-*`, `forescout-eyeinspect`, `nozomi-*`) alerts—and catches stealthy multi-day data exfiltration that stays beneath single-day $3\sigma$ thresholds—by tracking the **Cumulative Sum (CUSUM)** of positive daily standardized excesses ($S_t^+ = \sum \max(0, Z_t - 0.5)$) against each host's 30-day `metrics.network_bytes_outbound` baseline across multiple days (`cusum_drift_score >= 3.0` and `drift_days >= 2`).

```yara
// ============================================================================
// Goal: Detect multi-day low-and-slow outbound data exfiltration across endpoints, cloud workloads, and OT assets via Longitudinal CUSUM drift on 30-day outbound network bytes.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (k = 0.5 sigma slack, cusum_drift_score >= 3.0, drift_days >= 2)
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

---

---

### Scenario 5: Capstone Multi-Scenario Third-Party Vendor Alert Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Vendor alerts evaluated per integration policy.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities accumulating $\ge 2$ distinct cross-vendor behavioral matches within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Third-Party Vendor Alert Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across all Third-Party Vendor Alert (curated_rules_v1) scenarios via UDM Loopback.
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

### 3.1 Empirical Bayes Gamma-Poisson Credibility Shrinkage (Query 1A)
* **What it measures**: The ratio of a host's posterior multi-vendor EDR alert rate to its historical mean, weighted by how stable or erratic that host's alert history is.
* **How multi-stage UEBA extends coverage**: Curated vendor passthrough rules (curated detection rules) fire every day on chronically noisy developer workstations (`condition: $e`), while `trellix-hx` buckets every alert into `Medium` regardless of severity.
* **How the math works**: Method-of-Moments estimates a Gamma prior ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$) from each host's hourly alert history. Erratic, noisy hosts have high variance ($\sigma^2 \gg \mu$), shrinking their credibility weight toward their baseline mean, whereas a sudden burst of EDR alerts on a rock-solid, predictable server produces an immediate posterior shift ($\text{anomaly\_score} \ge 3.0\times$).

### 3.2 Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` Binary Prevalence (Query 1B)
* **What it measures**: Combines a 30-day per-(host, SHA256) process execution Z-score (`metrics.file_executions_total`) with `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3` hosts).
* **How multi-stage UEBA extends coverage**: Pre-execution EDR prevention rules alert on quarantined files that never ran, while `google-threat-intelligence` SHA-256 rules (`gcp_threatintel_ioc_*_sha256`) only match known hashes in `ENTITY_CONTEXT` and miss novel or polymorphic binaries.
* **How the math works**: Even if a binary has zero GTI hits, if $\le 3$ hosts in the entire organization have executed that SHA-256 over the past 10 days (`rolling_max <= 3`) and its execution count deviates from the host's 30-day history, a $2.5\times$ novelty multiplier elevates the fused threat score above `3.0`.

### 3.3 4-Stage Beta-Binomial Empirical Bayes Failure Regularization (Query 2A)
* **What it measures**: The regularized probability that a user's login attempts in a given hour are failing ($P_{\text{reg}} = (\text{fails} + \alpha_0) / (\text{trials} + \alpha_0 + \beta_0)$),shrinking small sample sizes toward a $10\%$ baseline error prior ($\alpha_0 = 1.0, \beta_0 = 9.0$).
* **How multi-stage UEBA extends coverage**: `proofpoint-tap`, `trellix-etp`, and `trellix-ex` alert on every permitted phishing click or delivered email without checking if the user's credentials are being brute-forced, while naive failure ratios ($\text{fails}/\text{trials}$) false-alert whenever a user mistypes their password once ($1/1 = 100\%$).
* **How the math works**: Adding 1 pseudo-failure and 9 pseudo-successes shrinks a $1/1$ single typo down to $2/11 = 18.2\%$ (well below threshold), while a sustained credential stuffing or post-phishing brute-force wave of 20 failures out of 20 attempts scores $21/30 = 70.0\%$ (`regularized_failure_prob >= 0.70`).

### 3.4 3-Metric Multilevel Part-of-the-Whole Workspace/Identity Triad (Query 2B)
* **What it measures**: The combined 3-dimensional Euclidean anomaly distance ($D_{\text{vs\_fleet}}^2 = Z_{\text{auth}}^2 + Z_{\text{download}}^2 + Z_{\text{change}}^2$) across authentication attempts, file downloads, and configuration/file changes relative to both the user's 30-day baseline and the active enterprise fleet.
* **How multi-stage UEBA extends coverage**: Isolated IDP (`crowdstrike-idp`, `microsoft-defender-identity`) and email (`proofpoint-tap`) passthrough alerts cannot see whether a compromised identity subsequently hoarded documents or altered settings in Google Workspace.
* **How the math works**: Zero-safe variance floors (`if($std > 0, $std, 1.0)`) ensure dormant accounts with zero prior downloads are never dropped by division-by-zero, while the squared Euclidean norm $D_{\text{vs\_fleet}}^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius) catches coordinated post-phishing account takeover across all three behavioral axes.

### 3.5 Hybrid 30-Day HTTP Volume Baseline + `DERIVED_CONTEXT` Domain Prevalence (Query 3A)
* **What it measures**: Fuses a host's 30-day HTTP request volume Z-score (`metrics.http_queries_total`) with `DERIVED_CONTEXT` 10-day organizational domain prevalence (`rolling_max <= 3` hosts).
* **How multi-stage UEBA extends coverage**: `gcp_threatintel_ioc_target_hostname` only matches known malicious domains in `ENTITY_CONTEXT`, and `zscaler` / `pan` / `fortinet` passthroughs rely on static proxy categories and known signatures.
* **How the math works**: By filtering for domains contacted by at most 3 hosts across the entire enterprise over a 10-day rolling window (`day_count = 10, rolling_max <= 3`) and multiplying the host's 30-day HTTP Z-score by a $1.5\times\text{–}2.0\times$ rarity boost, unlisted C2 redirectors and custom phishing domains are surfaced without requiring a prior Threat Intelligence hit.

### 3.6 Inter-Arrival Jitter Coefficient of Variation ($\text{CV} = \sigma / \mu$ — Query 3B)
* **What it measures**: The timing regularity of outbound network connections (`NETWORK_CONNECTION`) between an internal host and an external IP address across active hours.
* **How multi-stage UEBA extends coverage**: NDR and firewall passthrough rules (`corelight-suricata`, `trellix-nx`, `vectra-detect`, `vectra-xdr`, `pan`, `fortinet`) rely on payload signatures or static vendor severities, missing encrypted HTTPS C2 channels with 15%–20% randomized sleep jitter.
* **How the math works**: Human web browsing produces chaotic, wide time gaps ($\sigma \gg \mu \implies \text{CV} > 0.50$). Programmed C2 beacons (`sleep(60)` with $15\%$ jitter) maintain a tight ratio of standard deviation to mean inter-arrival gap ($\text{CV} = \sigma / \mu \le 0.20$) to low-prevalence external destinations (`fleet_prevalence <= 3`).

### 3.7 4-Stage Non-Parametric Median Absolute Deviation (MAD / Modified Z-Score $M_Z$ — Query 4A)
* **What it measures**: How many robust standard deviations an entity's daily DLP, Cloud (`WIZ_IO`), or OT (`CLAROTY_*`, `FORESCOUT_EYEINSPECT`, `NOZOMI_GUARDIAN`) alert/transfer volume sits above its historical median.
* **How multi-stage UEBA extends coverage**: All 5 `wiz` rules omit `match: ... by 1d`, triggering an unwindowed alert storm on every event, while parametric mean/stddev baselines are easily skewed by a single noisy backup or OT scan day.
* **How the math works**: Grouping `by 1d` in Stage 1 immediately fixes the `wiz` single-event storm. Computing the median and $\text{MAD} = \text{median}(|x_i - \text{median}|)$ provides a $50\%$ breakdown point against historical spikes, while the Iglewicz-Hoaglin fallback ($1.253314 \times \text{MeanAD}$) ensures entities with a steady baseline ($\text{MAD} = 0$) are still scored accurately when a sudden spike ($M_Z > 3.5$) occurs.

### 3.8 Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 4B)
* **What it measures**: The multi-day cumulative sum of positive daily outbound network byte excesses ($Z_t - 0.5\sigma$) above a host's 30-day `metrics.network_bytes_outbound` baseline.
* **How multi-stage UEBA extends coverage**: Static 24-hour DLP and NDR passthrough rules reset their counters every day, missing an adversary who throttles outbound exfiltration to $1.5\sigma\text{–}2.0\sigma$ per day across several days.
* **How the math works**: Subtracting the $k = 0.5\sigma$ slack constant filters out normal daily noise ($Z_t \le 0.5\sigma \implies \text{excess} = 0$), while a persistent $1.5\sigma$ daily exfiltration drip adds $+1.0$ to $S_t^+$ each day, breaching `cusum_drift_score >= 3.0` and `drift_days >= 2` within 3 days.
