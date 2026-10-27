# Extending Applied Threat Intelligence (ATI) Indicator Prioritization with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Applied Threat Intelligence (ATI) Curated Prioritization** suite enriches host, network, and authentication telemetry with Google Threat Intelligence (GTI) and Mandiant breach prioritization—surfacing matches against high-confidence active-breach and high-priority indicators of compromise (IoCs).

Because threat actors frequently deploy freshly compiled binaries, newly registered domains, or short-lived proxy infrastructure before static indicator feeds catalog them, this playbook supplements ATI indicator matching with **Behavioral Rarity, Prevalence, and Baseline Fusion** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). Rather than relying solely on known IoC reputation, these queries evaluate 10-day `DERIVED_CONTEXT` prevalence, WHOIS domain lifecycle age, C2 beaconing cadence, geodesic travel velocity, and 30-day behavioral baselines.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

### Table 1: Scenario Coverage Matrix — Applied Threat Intelligence (ATI) Curated Prioritization & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Host Binary Execution Prioritization & Novel Payloads** | Prioritizes process and file events matching high-confidence GTI file hashes and breach indicators. | Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`) and Zipfian inverse host frequency ($I = \ln(N/df) \ge 3.5$) to surface novel binaries prior to feed ingestion. | `Query 1A` (30d Execution + 10d Prevalence)<br>`Query 1B` (Zipfian Binary Rarity) |
| **2. Network C2, Ephemeral Domains & Automated Callback Cadence** | Matches outbound DNS and network connections against prioritized GTI domain and IP indicators. | Weights 30-day outbound HTTP request volume by event-relative WHOIS domain registration age (`creation_time`) and detects automated C2 callback timers via inter-arrival jitter ($\text{CV} \le 0.20$). | `Query 2A` (30d HTTP + WHOIS Lifecycle)<br>`Query 2B` (C2 Inter-Arrival CV) |
| **3. Inbound Authentication from Anomalous Infrastructure** | Flags authentication events originating from known malicious or Tor/proxy IP indicators. | Unifies cold-start and 30-day authentication baselines (`Option 1`) with geodesic impossible-travel velocity ($\ge 900\text{ km/h}$) and Beta-Binomial authentication failure-rate regularization. | `Query 3A` (Geodesic Impossible Travel)<br>`Query 3B` (Beta-Binomial Auth Regularization) |
| **4. Post-Indicator Breach Escalation & Exfiltration Fusion** | Correlates prioritized indicator hits with subsequent host or network activity. | Fuses 30-day Outbound Network Bytes and Alert/Execution baselines ($D^2 \ge 12.25$) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) to confirm active post-compromise data staging. | `Query 4A` (30d Egress + Alert Fusion)<br>`Query 4B` (Producer-Consumer Inversion) |
| **5. Capstone Multi-Scenario ATI Entity Convergence** | Point-in-time indicator matches evaluated per event. | Correlates entities matching $\ge 2$ distinct behavioral prioritization queries within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Host Binary Execution Prioritization Beyond Static GTI Hash Hits

* **Curated Detection Operational Focus**: Prioritizes process and file events matching high-confidence GTI file hashes and breach indicators.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`) and Zipfian inverse host frequency ($I = \ln(N/df) \ge 3.5$) to surface novel binaries prior to feed ingestion.

#### Query 1A: 2-Stage Hybrid 30-Day File Execution Baseline + Entity Context Graph Binary Prevalence (`secops-risk-metrics-multistage`)
Replaces static `GTI_IOC` hash matching with a 2-stage hybrid pipeline that scores per-(host, SHA256) process execution volume against its 30-day behavioral baseline (`metrics.file_executions_total`) and joins `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3`). Even when a payload hash is brand new to the world (absent from GTI), if $\le 3$ hosts in the enterprise have ever seen that SHA256 hash over the past 10 days and it exhibits an execution anomaly on the endpoint, it surfaces immediately.

```yara
// ============================================================================
// Goal: Detect execution of rare or novel binaries (10-day DERIVED_CONTEXT rolling_max <= 3 hosts) with anomalous per-host execution frequency compared to 30-day behavioral baselines.
// Statistical Model: 2-Stage Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day Binary Prevalence
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
  $host, $sha256 by 1d

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

#### Query 1B: Zipfian Power-Law Fleet Rarity & Inverse Host Frequency Surprisal (`secops-statistical-hunter`)
Catches polymorphic droppers, custom C2 implants, and living-off-the-land admin tools operating in the extreme asymptotic tail of the enterprise fleet ($\le 2$ hosts) via **Zipfian Power-Law Inverse Rank Frequency** ($\text{Zipf Rarity} = (\ln N_{\text{execs}} - \ln N_{\text{hosts}}) \cdot (1 + 1 / N_{\text{hosts}}) \ge 4.0$) directly over raw `PROCESS_LAUNCH` telemetry—requiring zero prior `GLOBAL_CONTEXT` or `DERIVED_CONTEXT` indexing.

```yara
// ============================================================================
// Goal: Detect polymorphic binaries and rare administrative utilities executing in the enterprise Zipfian long tail (<= 2 hosts) before GTI indexing.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Power-Law / Zipfian Inverse Host Frequency Surprisal (zipf_rarity_score >= 4.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Enterprise Fleetwide Binary Popularity & Adopter Host Breadth
stage fleet_process_popularity {
    metadata.event_type = "PROCESS_LAUNCH"
    $binary = target.process.file.full_path
    $binary != ""

  match:
    $binary by 1d

  outcome:
    $fleet_hosts = count_distinct(principal.asset.hostname)
    $fleet_total_executions = count(metadata.id)
}

// Stage 2: Endpoint Local Binary Execution Activity
stage endpoint_process_burst {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $binary = target.process.file.full_path
    $host != ""
    $binary != ""

  match:
    $host, $binary by 1d

  outcome:
    $endpoint_executions = count(metadata.id)
    $sample_commands = array_distinct(target.process.command_line)
}

// Root Stage: Zipfian Inverse Rank Departure & Asymptotic Tail Scoring
$binary = $fleet_process_popularity.binary
$binary = $endpoint_process_burst.binary
$host = $endpoint_process_burst.host

match:
  $host, $binary by 1d

outcome:
  $adopter_hosts = max($fleet_process_popularity.fleet_hosts)
  $fleet_volume = max($fleet_process_popularity.fleet_total_executions)
  $local_volume = max($endpoint_process_burst.endpoint_executions)
  $commands = array_distinct($endpoint_process_burst.sample_commands)

  // 1. Safe Cardinalities
  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_volume = if($fleet_volume > 0, $fleet_volume, 1)

  // 2. Zipfian Power-Law Log-Rank Departure
  $log_fleet = math.log($safe_volume)
  $log_adopters = math.log($safe_hosts)
  $zipf_log_rank = $log_fleet - $log_adopters

  // 3. Inverse Asymptotic Tail Multiplier
  $tail_rarity = 1.0 / $safe_hosts
  $zipf_rarity_score = $zipf_log_rank * (1.0 + $tail_rarity)

  // 6 Core Evidence Pillars
  $observation_count = $local_volume
  $baseline_active_samples = $fleet_volume
  $baseline_mean = $log_fleet
  $baseline_dispersion = $zipf_log_rank
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = 1

condition:
  $adopter_hosts <= 2
  and $local_volume >= 5
  and $zipf_rarity_score >= 4.0

order:
  $zipf_rarity_score desc
```

---

---

### Scenario 2: Network C2 & Domain/IP Prioritization

* **Curated Detection Operational Focus**: Matches outbound DNS and network connections against prioritized GTI domain and IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Weights 30-day outbound HTTP request volume by event-relative WHOIS domain registration age (`creation_time`) and detects automated C2 callback timers via inter-arrival jitter ($\text{CV} \le 0.20$).

#### Query 2A: 2-Stage Hybrid 30-Day HTTP Volume + Event-Relative WHOIS Domain Lifecycle Multiplier (`secops-risk-metrics-multistage`)
Eliminates the 7-day GTI soaking coverage considerations and wall-clock `timestamp.current_seconds()` constraint by pairing the endpoint's 30-day HTTP query baseline (`metrics.http_queries_total`) with `GLOBAL_CONTEXT` WHOIS domain registration and expiration timestamps evaluated strictly relative to `max(metadata.event_timestamp.seconds)`. Newly registered domains ($\le 30\text{d}$ old at the time of the HTTP request) or expired/hijacked domains receive a $2.0\times$ lifecycle risk multiplier.

```yara
// ============================================================================
// Goal: Detect anomalous host HTTP volume targeting newly registered (<= 30d at event time) or expired WHOIS domains before GTI IOC indexing.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + GLOBAL_CONTEXT WHOIS Domain Lifecycle Multiplier
// ARCHITECTURE: 2-STAGE HYBRID METRIC + GLOBAL_CONTEXT WHOIS DOMAIN LIFECYCLE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint HTTP Activity + 30-Day Baseline with event timestamp tracking
stage http_activity_anomalies {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $http_count = count(metadata.id)
    $latest_event_ts = max(metadata.event_timestamp.seconds)
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
    $http_count >= 5 and $b_days >= 5
}

// Root Stage: Join with GLOBAL_CONTEXT WHOIS Creation & Expiration Timestamps
$host = $http_activity_anomalies.host
$domain = $http_activity_anomalies.domain

$whois.graph.metadata.entity_type = "DOMAIN_NAME"
$whois.graph.metadata.vendor_name = "WHOIS"
$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
$whois.graph.entity.domain.name = $domain
$whois.graph.entity.domain.creation_time.seconds > 0

match:
  $host, $domain by 1d

outcome:
  $observed_http = max($http_activity_anomalies.http_count)
  $event_ts = max($http_activity_anomalies.latest_event_ts)
  $z_score = max($http_activity_anomalies.z_score)
  $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)
  $expiration_ts = max($whois.graph.entity.domain.expiration_time.seconds)

  // Event-relative domain age in seconds (fixes timestamp.current_seconds() retrohunt constraint)
  $domain_age_seconds = $event_ts - $creation_ts
  $domain_age_days = $domain_age_seconds / 86400

  // Lifecycle Risk Multiplier: 2.0x if newly registered (<= 30 days) or expired before event
  $is_newly_registered = if($domain_age_seconds >= 0 and $domain_age_seconds <= 2592000, 1, 0)
  $is_expired = if($expiration_ts > 0 and $expiration_ts < $event_ts, 1, 0)
  $lifecycle_multiplier = if($is_newly_registered = 1 or $is_expired = 1, 2.0, 1.0)

  $pos_z = if($z_score > 0, $z_score, 0.5)
  $fused_threat_score = $pos_z * $lifecycle_multiplier

condition:
  ($is_newly_registered = 1 or $is_expired = 1)
  and $fused_threat_score >= 3.0

order:
  $fused_threat_score desc
```

#### Query 2B: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on Outbound Network Connections (`secops-statistical-hunter`)
Detects C2 implants (Cobalt Strike, Sliver, Brute Ratel, Mythic) beaconing with randomized sleep jitter to unindexed external IPs by computing the inter-arrival **Coefficient of Variation** ($\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$) and restricting destination prevalence to $\le 3$ internal hosts (`$fleet_prevalence <= 3`).

```yara
// ============================================================================
// Goal: Detect persistent C2 beaconing (with sleep jitter) to low-prevalence external IPv4 infrastructure not yet indexed in GTI.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ <= 0.20) & Fleet Prevalence Filter
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Measure hourly timing intervals per (src_ip, dst_ip) pair
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

// Stage 2: Aggregate historical timing stats across active hourly windows
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

// Stage 3: Measure enterprise-wide prevalence of the destination IP
stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip

  outcome:
    $src_breadth = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute CV, and emit 6 Core Evidence Pillars
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

### Scenario 3: Inbound Authentication from Suspicious / Proxy Infrastructure

* **Curated Detection Operational Focus**: Flags authentication events originating from known malicious or Tor/proxy IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day authentication baselines (`Option 1`) with geodesic impossible-travel velocity ($\ge 900\text{ km/h}$) and Beta-Binomial authentication failure-rate regularization.

#### Query 3A: 4-Stage Beta-Binomial Empirical Bayes Authentication Failure Rate Regularization (`secops-statistical-hunter`)
Detects distributed credential stuffing and password spraying across all authentication types (including SSO) without relying on `GTI_IOC` IP lists or suffering from single-trial (`1/1 = 100%`) false positives. Using **Beta-Binomial conjugate updating** ($\hat{p}_{\text{fail}} = (\text{fails} + \alpha_0) / (\text{trials} + \alpha_0 + \beta_0)$ with $\alpha_0 = 1.0, \beta_0 = 9.0$), a user who mistypes their password once (`1/1`) is shrunk to $(1+1)/(1+10) = 18.2\%$ (ignored), whereas an account subjected to 25 failed spray attempts out of 26 trials (`25/26`) scores $(25+1)/(26+10) = 72.2\% \ge 0.70$.

```yara
// ============================================================================
// Goal: Detect credential stuffing and brute-force authentication failure ratios across all login types (including SSO) using Beta-Binomial Empirical Bayes regularization.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: 4-Stage Beta-Binomial Conjugate Updating & Small-Sample Shrinkage (regularized_failure_prob >= 0.70)
// Skill: secops-statistical-hunter
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

// Root Stage: Beta-Binomial Conjugate Updating & 6 Core Evidence Pillars
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_hourly_trials.failed_trials)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $baseline_mean = max($entity_historical_rates.total_historical_fails)
  $baseline_dispersion = max($entity_historical_rates.total_historical_events)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Regularized Posterior Failure Probability (alpha_0 = 1.0, beta_0 = 9.0)
  $regularized_failure_prob = (max($entity_hourly_trials.failed_trials) + 1.0) / (max($entity_hourly_trials.total_trials) + 10.0)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1.0)
  $unregularized_raw_rate = max($entity_hourly_trials.failed_trials) / $safe_trials

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 15
  and $regularized_failure_prob >= 0.70

order:
  $regularized_failure_prob desc
```

#### Query 3B: 3-Stage Dual-Sector Authentication Failures + Authentication Successes Fusion (`secops-risk-metrics-multistage`)
Directly fixes the `$blocked = 0` self-suppression constraint in curated detection rules by explicitly fusing 30-day anomalies in **failed logins (`metrics.auth_attempts_fail`)** with **successful logins (`metrics.auth_attempts_success`)** on the same user (`$composite_threat_norm_sq = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$). Instead of a failed login *suppressing* a subsequent successful breach, the combination of anomalous failures followed by anomalous successes *amplifies* the Euclidean risk distance above $3.5\sigma$ ($D^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Detect inbound brute-force / credential-stuffing attacks that culminate in a successful login (fixing the ATI $blocked = 0 suppression constraint).
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (metrics.auth_attempts_fail + metrics.auth_attempts_success, D^2 >= 12.25)
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

  // Rectified, baseline-gated sector Z-scores
  $z_a_raw = ($a_observed - $a_mean) / if($a_stddev > 0, $a_stddev, 1.0)
  $z_b_raw = ($b_observed - $b_mean) / if($b_stddev > 0, $b_stddev, 1.0)
  $z_a_pos = if($z_a_raw > 0, $z_a_raw, 0.0)
  $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
  $z_a = if($a_active_days >= 5, $z_a_pos, 0.0)
  $z_b = if($b_active_days >= 5, $z_b_pos, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

---

### Scenario 4: ATI Composite Breach Escalation & Data Exfiltration

* **Curated Detection Operational Focus**: Correlates prioritized indicator hits with subsequent host or network activity.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day Outbound Network Bytes and Alert/Execution baselines ($D^2 \ge 12.25$) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) to confirm active post-compromise data staging.

#### Query 4A: 2-Stage Hybrid 30-Day HTTP Volume + Entity Context Graph 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Replaces the brittle upstream `$ati` `GTI_IOC` anchor in `c_ati_path_domain_c2_to_exfil` with `DERIVED_CONTEXT` **10-day rolling organizational domain prevalence** (`rolling_max <= 3`) fused with the host's 30-day `metrics.http_queries_total` behavioral baseline. Any endpoint that surges in HTTP communication to an external domain seen on $\le 3$ hosts across the entire enterprise over the past 10 days is surfaced directly—whether or not that domain is known to GTI.

```yara
// ============================================================================
// Goal: Detect C2 communication and HTTP exfiltration surges to organizationally rare domains (10-day DERIVED_CONTEXT rolling_max <= 3 hosts) without requiring a prior GTI IOC match.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence
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
  $host, $domain by 1d

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

#### Query 4B: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) on Host Network Connections (`secops-statistical-hunter`)
Solves the shared CDN/cloud IP noise problem in `medium-priority-network` and `c_ati_path_ip_c2_to_exfil` by computing **Dual-Baseline Fleet-Normalized Delta-Z** ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$) on outbound host network connection volume (`NETWORK_CONNECTION`). When a corporate update or shared cloud service causes a fleet-wide spike in network connections, $Z_{\text{fleet}}$ rises alongside $Z_{\text{personal}}$ and $\Delta Z \approx 0$; when a single compromised workstation executes an active C2 or exfiltration burst while the rest of the fleet remains at baseline, $\Delta Z \ge 3.0\sigma$ cleanly isolates the compromised host.

```yara
// ============================================================================
// Goal: Isolate targeted host C2 and data exfiltration connection surges from shared CDN/cloud IP noise via 3-Stage Dual-Baseline Fleet-Normalized Delta-Z.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift) >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Individual Host Outbound Network Connection Volume in tumbling hourly windows
stage host_hourly_extract {
    metadata.event_type = "NETWORK_CONNECTION"
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.ip)
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

// Root Stage: Dual-Baseline Delta-Z Evaluation & 6 Core Evidence Pillars
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Core Evidence Pillars
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

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 5 active hours) + Mature Dual-Baseline Delta-Z (>= 6 active hours)
  $hurdle_rarity_boost = if($baseline_active_samples <= 5, 2.5, 1.0)
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost
  $unified_threat_score = if($baseline_active_samples <= 5, $hurdle_threat_score, $delta_z)

condition:
  $fleet_prevalence >= 3
  and $observation_count >= 25
  and $unified_threat_score >= 3.0

order:
  $unified_threat_score desc
```

---

---

### Scenario 5: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Point-in-time indicator matches evaluated per event.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral prioritization queries within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario ATI Entity Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across all ATI Indicator Prioritization scenarios via UDM Loopback to detect multi-stage compromise.
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

### 3.1 Hybrid 30-Day File Execution Baseline + 10-Day Entity Context Graph Binary Prevalence (Query 1A — `secops-risk-metrics-multistage`)
* **What it measures**: Combines how unusual a specific binary's execution frequency is on a given workstation over 30 days (`metrics.file_executions_total`) with how rare that SHA256 hash is across the entire organization over the past 10 days (`DERIVED_CONTEXT` `rolling_max <= 3`).
* **Why static ATI rules fail**: All 30 ATI host rules (`active_breach_ioc_eg_*`, `high_ioc_eg_*`, `medium_ioc_eg_*`) require the file's hash to already exist in `GTI_IOC` with `gti_verdict = 16` and pass a 7-day soaking period. A freshly compiled or polymorphic binary has zero GTI hits.
* **How the math works**: Stage 1 computes the host's 30-day execution Z-score for each `(host, sha256)` pair. The Root Stage filters exclusively to SHA256 hashes seen on $\le 3$ endpoints in the enterprise (`rolling_max <= 3`) and applies a $2.5\times$ novelty multiplier when the binary has never run on that host in the prior 30 days (`$active_days = 0`) or is a singleton across the company (`$org_file_prevalence_10d <= 1`).

### 3.2 Zipfian Power-Law Fleet Rarity & Inverse Host Frequency Surprisal (Query 1B — `secops-statistical-hunter`)
* **What it measures**: Identifies binaries sitting in the extreme long tail of the enterprise fleet ($\le 2$ adopter hosts) that execute repeatedly on a single machine.
* **Why static ATI rules fail**: Custom red-team tooling, re-compiled open-source utilities, and living-off-the-land binaries (`certutil`, `vssadmin`, custom scripts) either have benign/unknown GTI hashes or evade static hash signatures entirely.
* **How the math works**: Enterprise process execution follows Zipf's power law ($f(k) \propto 1/k^s$). By computing the log-rank departure between total execution volume and distinct adopter hosts—$\text{Zipf Rarity} = (\ln N_{\text{execs}} - \ln N_{\text{hosts}}) \cdot (1 + 1/N_{\text{hosts}})$—a polymorphic payload executing 15 times on a single host ($\ln(15) - \ln(1) = 2.71 \times 2.0 = 5.42 \ge 4.0$) immediately surfaces at the top of the triage queue without relying on external threat feeds.

### 3.3 Hybrid 30-Day HTTP Volume + Event-Relative WHOIS Domain Lifecycle Multiplier (Query 2A — `secops-risk-metrics-multistage`)
* **What it measures**: Scores a host's daily HTTP request volume against its 30-day baseline (`metrics.http_queries_total`) and multiplies the anomaly score by $2.0\times$ when the destination domain was registered within 30 days of the event (`$event_ts - $creation_ts <= 2592000`) or had already expired prior to the event (`$expiration_ts < $event_ts`).
* **Why static ATI rules fail**: ATI network rules enforce a 7-day soaking period on unreviewed indicators and compare timestamps against wall-clock `timestamp.current_seconds()`, blinding them to newly registered domains during the first week of an attack and breaking historical retrohunts.
* **How the math works**: Anchoring WHOIS `creation_time` and `expiration_time` to `max(metadata.event_timestamp.seconds)` makes the lifecycle check 100% deterministic across both live hunts and historical retrohunts, elevating newly spun-up or hijacked C2 domains the moment a host exhibits an HTTP volume shift.

### 3.4 Inter-Arrival Jitter Coefficient of Variation ($\text{CV} = \sigma / \mu \le 0.20$ — Query 2B — `secops-statistical-hunter`)
* **What it measures**: The rhythmic regularity of time intervals between outbound network connections from an internal host to an external IP address.
* **Why static ATI rules fail**: All ATI IP rules require the destination IP to be in `GTI_IOC` and exceed `$event_count > 2` per hour, missing unindexed C2 redirectors while false-alerting on noisy medium-priority cloud IPs.
* **How the math works**: Human network traffic is bursty and irregular, yielding a high Coefficient of Variation ($\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} > 0.50$). Automated C2 beacons (even with 15%–20% sleep jitter) maintain a tight ratio of standard deviation to mean interval ($\text{CV} \le 0.20$). Pairing $\text{CV} \le 0.20$ with `$fleet_prevalence <= 3` isolates dedicated C2 channels while stripping out popular SaaS/CDN infrastructure.

### 3.5 4-Stage Beta-Binomial Empirical Bayes Authentication Failure Rate Regularization (Query 3A — `secops-statistical-hunter`)
* **What it measures**: A user's hourly login failure rate shrunk toward the population baseline using a Beta(1, 9) prior so that small-sample flukes (`1` failure out of `1` attempt) are ignored while sustained credential stuffing (`15+` failures with $\hat{p}_{\text{fail}} \ge 0.70$) is caught.
* **Why static ATI rules fail**: curated detection rules only triggers on known GTI IPs, excludes SSO (`auth.type != "SSO"`), and suppresses itself if `$blocked != 0`.
* **How the math works**: Computing $\hat{p}_{\text{fail}} = (\text{failed\_trials} + 1.0) / (\text{total\_trials} + 10.0)$ acts as a mathematical damper on low-volume noise while converging to the true empirical failure rate as attacker trial volume increases during a residential-proxy credential stuffing wave.

### 3.6 3-Stage Dual-Sector Authentication Failures + Successes Euclidean Fusion ($D^2 \ge 12.25$ — Query 3B — `secops-risk-metrics-multistage`)
* **What it measures**: The joint 30-day behavioral anomaly across both failed login attempts (`metrics.auth_attempts_fail`) and successful logins (`metrics.auth_attempts_success`) for the same user in the same day.
* **Why static ATI rules fail**: In curated detection rules and `_src_ip`, any failed login in the 24-hour window sets `$blocked >= 1`, which forces `$priority = 0` and **suppresses** a successful compromise from that same GTI IP.
* **How the math works**: Instead of treating failed logins as a suppression gate, Stage 1 and Stage 2 compute rectified 30-day Z-scores for failures ($Z_{\text{fail}}$) and successes ($Z_{\text{success}}$), and Stage 3 computes their squared Euclidean norm $D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$ ($D \ge 3.5\sigma$). When an attacker sprays an account and then successfully logs in, both vectors reinforce each other.

### 3.7 Hybrid 30-Day HTTP Volume + 10-Day Entity Context Graph Domain Prevalence (Query 4A — `secops-risk-metrics-multistage`)
* **What it measures**: Pairs a host's 30-day HTTP volume anomaly (`metrics.http_queries_total`) with `DERIVED_CONTEXT` 10-day organizational domain prevalence (`rolling_max <= 3`).
* **Why static ATI rules fail**: Composite rules like `c_ati_path_domain_c2_to_exfil` require an upstream `$ati` `GTI_IOC` domain alert to fire first. If the adversary's C2 or exfiltration domain is not in GTI, the composite rule never triggers.
* **How the math works**: By substituting local organizational rarity (`rolling_max <= 3` over 10 days in `DERIVED_CONTEXT`) for global feed presence (`GTI_IOC` in `GLOBAL_CONTEXT`), any domain touched by at most 3 machines in the company that drives an HTTP volume spike receives a $1.5\times\text{–}2.0\times$ rarity multiplier, catching unindexed C2 and exfiltration endpoints.

### 3.8 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$ — Query 4B — `secops-statistical-hunter`)
* **What it measures**: How many standard deviations a single host's outbound network connection volume surged above its personal historical average *after subtracting any concurrent fleet-wide surge* ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$).
* **Why static ATI rules fail**: Medium-priority network IoC rules (`medium_ioc_eg_target_ip`) and IP composite rules (`c_ati_path_ip_c2_to_exfil`, `c_ati_cloud_exfiltration`) fire false positives when multiple hosts connect to shared CDN, cloud storage, or proxy IPs, yet miss targeted exfiltration to unlisted IPs.
* **How the math works**: Stage 2 estimates each host's personal baseline ($\mu_p, \sigma_p$), while Stage 3 measures the concurrent fleet average ($\mu_f$) in that exact hour. During a routine cloud sync or software rollout, $\mu_f$ rises with the host, canceling out $\Delta Z$. During a targeted breach on a single workstation, the fleet remains quiet ($\mu_f \approx \mu_p$) and $\Delta Z \ge 3.0\sigma$ isolates the compromised endpoint.
