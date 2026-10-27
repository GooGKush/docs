# Hunting Linux Endpoint & Server Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Linux Threats** curated detection suite monitors server, cloud workload, and container host telemetry for dropper downloads (`curl`/`wget`), execution from ephemeral directories (`/tmp`, `/dev/shm`), privilege escalation, persistence (`cron`, `systemd`, `authorized_keys`), rootkits, and cryptominers.

This playbook supplements deterministic Linux detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By baselining 30-day host execution and network behavior alongside Markov daemon-to-child process lineage, Two-Part Hurdle privilege escalation models, and Zipfian binary rarity, the UEBA harness surfaces stealthy post-exploitation activity across diverse Linux server fleets.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Linux Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Dropper Staging, Downloader Abuse & Ephemeral Execution** | Detects `curl`/`wget` chains writing to `/tmp` or `/dev/shm` and execution of known malicious payloads. | Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`) and Markov 2-gram daemon-to-shell transition surprisal ($I \ge 3.5$). | `Query 1A` (30d Execution + 10d Prevalence)<br>`Query 1B` (Markov 2-Gram Daemon Surprisal) |
| **2. Privilege Escalation & Permission Modification** | Flags known privilege-escalation exploits, `sudo` abuse, and `chmod +s` / `chown` modifications. | Applies a Two-Part Zero-Inflated Hurdle model to identify hosts crossing from zero historical privilege-modification activity into active escalation, paired with 30-day Host Auth Failure + Success fusion. | `Query 2A` (Two-Part Escalation Hurdle)<br>`Query 2B` (30d Host Auth Fusion) |
| **3. Linux Persistence (`cron`, `systemd`, SSH Keys & Kernel Modules)** | Monitors modifications to scheduled tasks, service unit files, SSH `authorized_keys`, and kernel module loading. | Measures Zipfian power-law fleet rarity ($I = \ln(N/df) \ge 3.2$) across persistence-related binary/path invocations and Shannon character-class entropy ($H(X) \ge 3.9$) on shell and cron command lines. | `Query 3A` (Zipfian Persistence Rarity)<br>`Query 3B` (Command-Line Shannon Entropy) |
| **4. Cryptominers, Reverse Shells & Covert C2 Egress** | Matches known mining pools, reverse-shell one-liners, and high-confidence network indicators. | Unifies cold-start and 30-day outbound network byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and inter-arrival C2/stratum beaconing jitter ($\text{CV} \le 0.20$). | `Query 4A` (30d Egress + Producer Inversion)<br>`Query 4B` (C2/Stratum Jitter CV) |
| **5. Capstone Multi-Scenario Linux Host Convergence** | Point-in-time Linux detections evaluated independently per process or network event. | Correlates Linux hosts matching $\ge 2$ distinct behavioral scenarios in the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Linux Malware Downloads, Dropper Staging & Ephemeral Execution

* **Curated Detection Operational Focus**: Detects `curl`/`wget` chains writing to `/tmp` or `/dev/shm` and execution of known malicious payloads.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`) and Markov 2-gram daemon-to-shell transition surprisal ($I \ge 3.5$).

#### Query 1A: 2-Stage Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Compensates for honeypot command-line overfitting by scoring every Linux binary execution (`metrics.file_executions_total` per host and SHA-256) against its 30-day behavioral baseline and joining with the **Entity Context Graph (`DERIVED_CONTEXT`)** to isolate rare binaries seen on $\le 3$ hosts across the organization over a 10-day rolling window (`rolling_max <= 3`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution of rare or newly dropped Linux binaries (10-day org prevalence <= 3 hosts) with anomalous per-host execution frequency.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Linux Endpoint Process Execution + 30-Day Composite Baseline per (host, event_type, sha256)
stage process_metric_anomalies {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
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

#### Query 1B: Markov 2-Gram Parent-to-Child Process Transition Surprisal for Linux Daemons (`secops-statistical-hunter`)
Detects RCE exploitation, web shells, and dropper staging when Linux server daemons (`nginx`, `apache2`, `httpd`, `java`, `python`, `php-fpm`, `sshd`, `cron`) spawn shells or downloaders (`sh`, `bash`, `dash`, `curl`, `wget`) by evaluating **Markov 2-Gram conditional probability** $P(\text{Child} \mid \text{Parent})$ and **Information Surprisal** $I = -\ln P(\text{Child} \mid \text{Parent}) \ge 3.0$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions where Linux server daemons spawn shells or downloaders via Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln(P(Child | Parent)))
// ============================================================================

// Stage 1: Parent Daemon Process Launch Baseline Frequency per Linux host
stage parent_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""
    re.regex($parent, `(?i)/(nginx|apache2|httpd|tomcat|java|python|php|ruby|node|sshd|cron|crond)$`)

  match:
    $host, $parent by 1d

  outcome:
    $parent_total_launches = count(metadata.id)
}

// Stage 2: Child Shell / Downloader Transition Frequency per (host, parent, child)
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex($parent, `(?i)/(nginx|apache2|httpd|tomcat|java|python|php|ruby|node|sshd|cron|crond)$`)
    (
      re.regex($child, `(?i)/(sh|bash|dash|zsh|ksh|curl|wget|nc|ncat|socat|python|perl|php)$`)
      or re.regex($child, `(?i)/(tmp|var/tmp|dev/shm)/`)
    )

  match:
    $host, $parent, $child by 1d

  outcome:
    $transition_count = count(metadata.id)
    $sample_command = array_distinct(target.process.command_line)
}

// Root Stage: Markov Conditional Probability & Information Surprisal
$host = $parent_baseline.host
$host = $child_transition.host
$parent = $parent_baseline.parent
$parent = $child_transition.parent
$child = $child_transition.child

match:
  $host, $parent, $child by 1d

outcome:
  $parent_launches = max($parent_baseline.parent_total_launches)
  $transition_launches = max($child_transition.transition_count)
  $sample_commands = array_distinct($child_transition.sample_command)

  // 1. Safe Cardinalities
  $safe_parent = if($parent_launches > 0, $parent_launches, 1)
  $safe_trans = if($transition_launches > 0, $transition_launches, 1)

  // 2. Markov Transition Probability: P(Child | Parent) = Count(Parent -> Child) / Count(Parent)
  $transition_prob = $safe_trans / $safe_parent

  // 3. Information Surprisal: I = -ln(P) = ln(Parent) - ln(Transition)
  $log_parent = math.log($safe_parent)
  $log_trans = math.log($safe_trans)
  $surprisal_score = $log_parent - $log_trans

  // 4. Rare Sequence Multiplier (Amplifies singleton/doubleton transitions)
  $rare_multiplier = if($transition_launches <= 2, 2.0, 1.0)
  $markov_threat_score = $surprisal_score * $rare_multiplier

  // 6 Core Evidence Pillars
  $observation_count = $transition_launches
  $baseline_active_samples = $parent_launches
  $baseline_mean = $transition_prob
  $baseline_dispersion = $surprisal_score
  $fleet_prevalence = 0 - 1
  $distinct_binaries = 1

condition:
  $parent_launches >= 5
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

---

---

### Scenario 2: Linux Privilege Escalation Tools & `sudo`/`setuid`/`chown` Modifications

* **Curated Detection Operational Focus**: Flags known privilege-escalation exploits, `sudo` abuse, and `chmod +s` / `chown` modifications.
* **How Multi-Stage UEBA Extends Coverage**: Applies a Two-Part Zero-Inflated Hurdle model to identify hosts crossing from zero historical privilege-modification activity into active escalation, paired with 30-day Host Auth Failure + Success fusion.

#### Query 2A: 3-Stage Dual-Sector Host Authentication Failure + Success Fusion (`secops-risk-metrics-multistage`)
Addresses the hardcoded `#e > 10` threshold in curated detection rules and the uncorrelated single-event noise in curated detection rules by fusing 30-day behavioral baselines for **host authentication failures (`metrics.auth_attempts_fail`)** and **host authentication successes (`metrics.auth_attempts_success`)** keyed on `principal.asset.hostname` ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect Linux privilege escalation brute-forcing (su/sudo/ssh) followed by successful session elevation on the same host via 30-day Dual-Sector Auth Fusion.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D^2 = Z_fail^2 + Z_success^2 >= 12.25)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION (HOST-KEYED)
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

// --- STAGE 2: Sector B — Host Authentication Successes (UDM Source 2 of 2) ---
stage sector_b {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
    $b_avg = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
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

#### Query 2B: 4-Stage UDM-Gated Two-Part Zero-Inflated Hurdle Model on Linux Privilege Escalation & Recon (`secops-statistical-hunter`)
Evaluates Linux privilege-escalation and credential-access utility execution via a **Two-Part Zero-Inflated Hurdle Model** strictly on candidate Linux hosts surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED TWO-PART ZERO-INFLATED HURDLE PIPELINE
// Goal: Detect first-time or bursty Linux privilege-escalation utility execution on candidate hosts from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Two-Part Zero-Inflated Hurdle Model
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

stage daily_activity {
    metadata.event_type = "PROCESS_LAUNCH"
    re.regex(target.process.file.full_path, `(?i)/(sudo|su|pkexec|chage|usermod|useradd|visudo|setcap|chmod|chown|find|getcap)$`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1d

  outcome:
    $daily_events = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
}

stage personal_history {
    $host = $daily_activity.host

  match:
    $host

  outcome:
    $active_days = count($daily_activity.window_start)
    $mean_daily = avg($daily_activity.daily_events)
    $std_daily = stddev($daily_activity.daily_events)
}

$host = $stage1_upstream_2a_candidates.host
$host = $daily_activity.host
$host = $personal_history.host
$ws = $daily_activity.window_start

match:
  $host, $ws by 1d

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($daily_activity.daily_events)
  $baseline_active_samples = max($personal_history.active_days)
  $baseline_mean = max($personal_history.mean_daily)
  $baseline_dispersion = max($personal_history.std_daily)
  $fleet_prevalence = 1
  $distinct_binaries = max($daily_activity.distinct_cmds)

  $safe_std = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = ($observation_count - $baseline_mean) / $safe_std
  $hurdle_boost = if($baseline_active_samples <= 1, 2.5, 1.0)
  $hurdle_anomaly_score = (math.log($observation_count + 1.0) * $hurdle_boost) + if($intensity_z > 0, $intensity_z, 0.0)
  $z_score = $hurdle_anomaly_score

condition:
  $observation_count >= 2
  and $hurdle_anomaly_score >= 3.5

order:
  $hurdle_anomaly_score desc
```

---

---

### Scenario 3: Linux Persistence Mechanisms

* **Curated Detection Operational Focus**: Monitors modifications to scheduled tasks, service unit files, SSH `authorized_keys`, and kernel module loading.
* **How Multi-Stage UEBA Extends Coverage**: Measures Zipfian power-law fleet rarity ($I = \ln(N/df) \ge 3.2$) across persistence-related binary/path invocations and Shannon character-class entropy ($H(X) \ge 3.9$) on shell and cron command lines.

#### Query 3: Unified Personal Leave-One-Out Poisson Rarity & Zipfian Fleet Rarity on Linux Persistence, Kernel Modules & Rogue Daemons (`secops-statistical-hunter`)
Because both **Personal Leave-One-Out Discrete Poisson Rarity** (catching built-in Linux persistence and kernel-module commands like `crontab`, `systemctl`, `insmod`, `modprobe`, `chattr`, `authorized_keys`, `ld.so.preload` on quiet hosts with $\lambda \le 0.5\text{/day}$) and **Zipfian Power-Law Fleet Rarity** (catching custom persistent implants and masqueraded daemons executing on $\le 2$ Linux hosts across the fleet) operate on the exact same `PROCESS_LAUNCH` telemetry stream (`$entity, $tool by 1d`), this **Option 1 Unified Pipeline** evaluates both regimes inside a single 4-stage DAG (`$unified_threat_score = if($adopter_hosts <= 2, $zipf_rarity_score, $poisson_z)`):

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Unify fleet-rare persistent Linux implants/daemons (Zipfian tail <= 2 hosts) and personal Leave-One-Out Poisson rarity on Linux persistence & kernel module tools (crontab, systemctl, insmod, modprobe, ld.so.preload) in a single 4-stage pipeline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Option 1 Piecewise Leave-One-Out Discrete Poisson Rarity + Zipfian Inverse Host Frequency Rarity
// ============================================================================

// Stage 1: Daily execution counts per Linux host and binary path
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""

  match:
    $entity, $tool by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
    $sample_commands = array_distinct(target.process.command_line)
}

// Stage 2: Personal historical accumulation across active days per (host, tool) for Leave-One-Out Poisson rate
stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool

  match:
    $entity, $tool

  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $active_days = count($daily_tool_counts.window_start)
}

// Stage 3: Enterprise fleetwide Linux binary popularity & adopter host breadth per (tool, day) for Zipfian tail rarity
stage fleet_process_popularity {
    $tool = $daily_tool_counts.tool
    $ws = $daily_tool_counts.window_start

  match:
    $tool, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($daily_tool_counts.entity)
    $fleet_total_executions = sum($daily_tool_counts.daily_count)
}

// Root Stage: Option 1 Piecewise Personal LOO Poisson Rarity & Zipfian Fleet Rarity
$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool
$tool = $fleet_process_popularity.tool
$ws = $daily_tool_counts.window_start
$ws = $fleet_process_popularity.ws

match:
  $entity, $tool, $ws by 1d

outcome:
  $today_k = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $adopter_hosts = max($fleet_process_popularity.fleet_hosts)
  $fleet_volume = max($fleet_process_popularity.fleet_total_executions)
  $commands = array_distinct($daily_tool_counts.sample_commands)

  // Branch A: Leave-One-Out Discrete Poisson Rarity (Personal Baseline)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 29.0
  $poisson_z_raw = ($today_k - $lambda) / if($lambda > 0, $lambda, 0.01)
  $poisson_z = if($poisson_z_raw > 0, $poisson_z_raw, 0.0)

  // Branch B: Zipfian Power-Law Fleet Rarity (Enterprise Long Tail <= 2 adopter hosts)
  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $zipf_log_rank = math.log(if($fleet_volume > 0, $fleet_volume, 1)) - math.log($safe_hosts)
  $zipf_rarity_score = $zipf_log_rank * (1.0 + (1.0 / $safe_hosts))

  // Option 1 Piecewise Regime Switch
  $unified_threat_score = if($adopter_hosts <= 2, $zipf_rarity_score, $poisson_z)

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($baseline_accumulation.active_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $zipf_log_rank
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

condition:
  $observation_count >= 2
  and (
    ($adopter_hosts <= 2 and $observation_count >= 5 and $unified_threat_score >= 4.0)
    or ($adopter_hosts >= 3 and $baseline_mean <= 0.5 and $distinct_binaries >= 2 and $unified_threat_score >= 3.5)
  )

order:
  $unified_threat_score desc
```

---

---

### Scenario 4: Mandiant Frontline & Emerging Linux Threats (Cryptominers, Rootkits, Reverse Shells & Covert C2)

* **Curated Detection Operational Focus**: Matches known mining pools, reverse-shell one-liners, and high-confidence network indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day outbound network byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and inter-arrival C2/stratum beaconing jitter ($\text{CV} \le 0.20$).

#### Query 4A: Multi-Class Character Shannon Entropy ($H(X) \ge 3.8$) on Linux Shell & Interpreter Command Lines (`secops-statistical-hunter`)
Detects obfuscated reverse shells, encoded rootkit stagers, and fileless Python/Perl/OpenSSL/Bash one-liners across all Linux hosts—independent of whether `base64 -d` or `__OUT<hex>_S__` appears—by computing 4-class **Shannon character distribution entropy** ($H(X) = -\sum p_i \log_2 p_i$) and fleet host rarity ($\le 3$ hosts).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect obfuscated Linux reverse shells, encoded rootkit stagers, and high-entropy interpreter one-liners across the Linux fleet.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)) >= 3.8)
// ============================================================================

// Stage 1: Extract command-line length and 4-class character distributions for Linux shells and interpreters
stage cmd_feature_extraction {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $host
    $host != ""
    $cmd = target.process.command_line
    $cmd != ""
    strings.length($cmd) >= 64
    re.regex(target.process.file.full_path, `(?i)/(sh|bash|dash|zsh|ksh|python|python3|perl|ruby|php|openssl|base64|xxd|curl|wget)$`)

  match:
    $host, $cmd by 1d

  outcome:
    $execution_count = count(metadata.id)
    $raw_len = max(strings.length($cmd))
    $safe_len = if($raw_len > 0, $raw_len, 1)

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax for AST compliance)
    $len_no_lower = max(strings.length(re.replace($cmd, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($cmd, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($cmd, `\d`, "")))

    $c_lower = $raw_len - $len_no_lower
    $c_upper = $raw_len - $len_no_upper
    $c_digit = $raw_len - $len_no_digit
    $c_other_raw = $raw_len - ($c_lower + $c_upper + $c_digit)
    $c_other = if($c_other_raw > 0, $c_other_raw, 0)

    $p_lower = ($c_lower + 0.01) / ($safe_len + 0.04)
    $p_upper = ($c_upper + 0.01) / ($safe_len + 0.04)
    $p_digit = ($c_digit + 0.01) / ($safe_len + 0.04)
    $p_other = ($c_other + 0.01) / ($safe_len + 0.04)
}

// Stage 2: Enterprise fleet prevalence of each distinct command line across Linux hosts
stage cmd_fleet_prevalence {
    $cmd = $cmd_feature_extraction.cmd

  match:
    $cmd by 1d

  outcome:
    $fleet_hosts = count_distinct($cmd_feature_extraction.host)
}

// Root Stage: Compute 4-Class Shannon Entropy Equivalent & 6 Evidence Pillars
$host = $cmd_feature_extraction.host
$cmd = $cmd_feature_extraction.cmd
$cmd = $cmd_fleet_prevalence.cmd

match:
  $host, $cmd by 1d

outcome:
  $exec_count = max($cmd_feature_extraction.execution_count)
  $len = max($cmd_feature_extraction.raw_len)
  $p_lower = max($cmd_feature_extraction.p_lower)
  $p_upper = max($cmd_feature_extraction.p_upper)
  $p_digit = max($cmd_feature_extraction.p_digit)
  $p_other = max($cmd_feature_extraction.p_other)

  $h_lower = (0.0 - $p_lower) * (math.log($p_lower) / 0.693147)
  $h_upper = (0.0 - $p_upper) * (math.log($p_upper) / 0.693147)
  $h_digit = (0.0 - $p_digit) * (math.log($p_digit) / 0.693147)
  $h_other = (0.0 - $p_other) * (math.log($p_other) / 0.693147)

  $class_entropy = $h_lower + $h_upper + $h_digit + $h_other
  $length_bonus = if($len >= 160, 0.5, 0.0)
  $shannon_entropy_score = ($class_entropy * 2.25) + $length_bonus
  $z_score = $shannon_entropy_score

  // 6 Core Evidence Pillars
  $observation_count = $exec_count
  $baseline_active_samples = $len
  $baseline_mean = $class_entropy
  $baseline_dispersion = $shannon_entropy_score
  $fleet_prevalence = max($cmd_fleet_prevalence.fleet_hosts)
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 3.8

order:
  $shannon_entropy_score desc
```

#### Query 4B: 2-Stage Longitudinal CUSUM Behavioral Drift on Linux Host Outbound Network Traffic (`secops-risk-metrics-multistage`)
Catches covert C2 beacons, cryptominer stratum traffic, and low-and-slow archive exfiltration that evade curated detection rules by tracking the multi-day **Cumulative Sum (CUSUM)** of positive standardized outbound byte deviations ($S_t^+ = \sum \max(0, Z_t - 0.5) \ge 3.0$ across `drift_days >= 2`) against each Linux host's 30-day `metrics.network_bytes_outbound` baseline.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-and-slow Linux data exfiltration, covert C2 traffic, and sustained cryptominer pool communication via Longitudinal CUSUM drift on outbound bytes.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (k = 0.5 sigma slack, cusum_drift_score >= 3.0, drift_days >= 2)
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Deviation Tracker for Linux Host Outbound Network Bytes
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

### Scenario 5: Capstone Multi-Scenario Linux Host Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Point-in-time Linux detections evaluated independently per process or network event.
* **How Multi-Stage UEBA Extends Coverage**: Correlates Linux hosts matching $\ge 2$ distinct behavioral scenarios in the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–4 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 4 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 Linux Threats scenarios (1 through 4B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
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
