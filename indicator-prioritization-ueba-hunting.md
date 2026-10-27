# Extending Applied Threat Intelligence (ATI) Indicator Prioritization with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Applied Threat Intelligence (ATI) Curated Prioritization** suite enriches host, network, and authentication telemetry with Google Threat Intelligence (GTI) and Mandiant breach prioritization—surfacing matches against high-confidence active-breach and high-priority indicators of compromise (IoCs).

Because threat actors frequently deploy freshly compiled binaries, newly registered domains, or short-lived proxy infrastructure before static indicator feeds catalog them, this playbook supplements ATI indicator matching with **Behavioral Rarity, Prevalence, and Baseline Fusion** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). Rather than relying solely on known IoC reputation, these queries evaluate 10-day `DERIVED_CONTEXT` prevalence, WHOIS domain lifecycle age, C2 beaconing cadence, geodesic travel velocity, and 30-day behavioral baselines.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

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

#### Query 2B: 4-Stage UDM-Gated Inter-Arrival Jitter Coefficient of Variation on Outbound Network Callbacks (`secops-statistical-hunter`)
Evaluates hourly outbound network callback inter-arrival pacing ($\text{CV} = \sigma / \mu \le 0.25$) strictly on candidate hosts surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED INTER-ARRIVAL JITTER COEFFICIENT OF VARIATION PIPELINE
// Goal: Detect automated C2 callback cadence (CV <= 0.25) on candidate hosts from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Coefficient of Variation (CV = sigma / mu <= 0.25)
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
    target.ip = $target_ip
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    $target_ip != ""
    not net.ip_in_range_cidr($target_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($target_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($target_ip, "192.168.0.0/16")
    $ts = metadata.event_timestamp.seconds

  match:
    $host, $target_ip by 1h

  outcome:
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
    $hourly_sent = sum(network.sent_bytes)
}

stage timing_stats {
    $host = $host_intervals.host
    $target_ip = $host_intervals.target_ip

  match:
    $host, $target_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $total_sent_bytes = sum($host_intervals.hourly_sent)
    $active_hours = count($host_intervals.window_start)
}

$host = $stage1_upstream_2a_candidates.host
$host = $timing_stats.host
$target_ip = $timing_stats.target_ip

match:
  $host, $target_ip

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = 1
  $distinct_binaries = max($timing_stats.total_conns)
  $total_outbound_bytes = max($timing_stats.total_sent_bytes)

  $safe_mean = if($baseline_mean > 0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 20
  and $baseline_mean >= 2.0
  and $cv <= 0.25

order:
  $cv asc
```

---

---

### Scenario 3: Inbound Authentication from Suspicious / Proxy Infrastructure

* **Curated Detection Operational Focus**: Flags authentication events originating from known malicious or Tor/proxy IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day authentication baselines (`Option 1`) with geodesic impossible-travel velocity ($\ge 900\text{ km/h}$) and Beta-Binomial authentication failure-rate regularization.

#### Query 3A: 3-Stage Dual-Sector Authentication Failures + Authentication Successes Fusion (`secops-risk-metrics-multistage`)
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

#### Query 3B: 4-Stage UDM-Gated Beta-Binomial Empirical Bayes Authentication Failure Rate (`secops-statistical-hunter`)
Evaluates hourly authentication failure-rate anomalies via **Beta-Binomial Empirical Bayes Shrinkage** strictly on candidate accounts surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED BETA-BINOMIAL EMPIRICAL BAYES AUTH FAILURE RATE PIPELINE
// Goal: Detect credential stuffing and brute-force failure-rate surges on candidate identities from Query 3A (strictly gated by Query 3A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Beta-Binomial Empirical Bayes Shrinkage
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

$user = $stage1_upstream_3a_candidates.user
$user = $hourly_auth_stats.user
$user = $user_prior_stats.user
$ws = $hourly_auth_stats.window_start

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
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

#### Query 4B: 4-Stage UDM-Gated Personal & Upstream Delta-Z on Host Network Connections (`secops-statistical-hunter`)
Evaluates hourly outbound network connection surges against each host's hourly baseline strictly on candidate hosts surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED PERSONAL & UPSTREAM DELTA-Z PIPELINE
// Goal: Detect localized hourly outbound connection surges on candidate hosts from Query 4A (strictly gated by Query 4A UDM Loopback candidates).
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
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_val = count(metadata.id)
    $distinct_procs = count_distinct(target.ip)
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

### Scenario 5: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Point-in-time indicator matches evaluated per event.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral prioritization queries within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

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
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 Indicator Prioritization scenarios (1 through 4B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
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
