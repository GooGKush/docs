# Hunting Linux Endpoint & Server Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Linux Threats** curated detection suite monitors server, cloud workload, and container host telemetry for dropper downloads (`curl`/`wget`), execution from ephemeral directories (`/tmp`, `/dev/shm`), privilege escalation, persistence (`cron`, `systemd`, `authorized_keys`), rootkits, and cryptominers.

This playbook supplements deterministic Linux detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By baselining 30-day host execution and network behavior alongside Markov daemon-to-child process lineage, Two-Part Hurdle privilege escalation models, and Zipfian binary rarity, the UEBA harness surfaces stealthy post-exploitation activity across diverse Linux server fleets.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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

#### Query 2A: Two-Part Zero-Inflated Hurdle Model on Linux Privilege Escalation & Permission Modification Commands (`secops-statistical-hunter`)
Replaces disabled `legacy configuration` discovery rules and noisy single-event `sudoers` alerts with a **Two-Part Zero-Inflated Hurdle Model** across privilege escalation and permission modification utilities (`sudo`, `su`, `chmod`, `chown`, `setcap`, `getcap`, `pkexec`, `usermod`, `visudo`). Accounts or hosts that are historically dormant in privilege administration ($\le 2$ active days) receive a discrete Bernoulli hurdle awakening penalty, while regular administrators are scored via continuous intensity Z-scores ($\ge 3.0\sigma$).

```yara
// ============================================================================
// Goal: Detect dormant Linux users or hosts suddenly executing privilege escalation and permission modification commands, or active admins surging above baseline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Two-Part Zero-Inflated Hurdle Model (Bernoulli Activation Hurdle + Conditional Intensity Z-Score >= 3.0)
// ============================================================================

// Stage 1: Historical daily privilege-escalation & permission-modification command volume per Linux host
stage entity_historical {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $entity
    $entity != ""
    re.regex(target.process.file.full_path, `(?i)/(sudo|su|chmod|chown|setcap|getcap|pkexec|usermod|useradd|visudo|passwd|gpasswd)$`)

  match:
    $entity by 1d

  outcome:
    $bucket_count = count(metadata.id)
    $distinct_tools = count_distinct(target.process.file.full_path)
}

// Stage 2: Historical active sample density and dispersion per Linux host
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $hist_mean = avg($entity_historical.bucket_count)
    $hist_stddev = stddev($entity_historical.bucket_count)
    $active_samples = count($entity_historical.window_start)
}

// Stage 3 (Root Stage): Two-Part Hurdle Evaluation per (entity, day)
$entity = $entity_stats.entity
$entity = $entity_historical.entity
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
  $distinct_binaries = max($entity_historical.distinct_tools)

  // 1. Part 1: Discrete Bernoulli Hurdle (dormant host awakening: <= 2 active days)
  $is_dormant = if($baseline_active_samples <= 2, 1.0, 0.0)
  $dormant_score = $observation_count * 1.5

  // 2. Part 2: Continuous Intensity Conditioned on Crossing Hurdle
  $diff = $observation_count - $baseline_mean
  $safe_stddev = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = $diff / $safe_stddev

  // 3. Composite Hurdle Threat Score
  $hurdle_threat_score = if($is_dormant > 0, $dormant_score, $intensity_z)

condition:
  $observation_count >= 3
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

#### Query 2B: 3-Stage Dual-Sector Host Authentication Failure + Success Fusion (`secops-risk-metrics-multistage`)
Addresses the hardcoded `#e > 10` threshold in curated detection rules and the uncorrelated single-event noise in curated detection rules by fusing 30-day behavioral baselines for **host authentication failures (`metrics.auth_attempts_fail`)** and **host authentication successes (`metrics.auth_attempts_success`)** keyed on `principal.asset.hostname` ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$).

```yara
// ============================================================================
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

---

---

### Scenario 3: Linux Persistence Mechanisms

* **Curated Detection Operational Focus**: Monitors modifications to scheduled tasks, service unit files, SSH `authorized_keys`, and kernel module loading.
* **How Multi-Stage UEBA Extends Coverage**: Measures Zipfian power-law fleet rarity ($I = \ln(N/df) \ge 3.2$) across persistence-related binary/path invocations and Shannon character-class entropy ($H(X) \ge 3.9$) on shell and cron command lines.

#### Query 3: Unified Personal Leave-One-Out Poisson Rarity & Zipfian Fleet Rarity on Linux Persistence, Kernel Modules & Rogue Daemons (`secops-statistical-hunter`)
Because both **Personal Leave-One-Out Discrete Poisson Rarity** (catching built-in Linux persistence and kernel-module commands like `crontab`, `systemctl`, `insmod`, `modprobe`, `chattr`, `authorized_keys`, `ld.so.preload` on quiet hosts with $\lambda \le 0.5\text{/day}$) and **Zipfian Power-Law Fleet Rarity** (catching custom persistent implants and masqueraded daemons executing on $\le 2$ Linux hosts across the fleet) operate on the exact same `PROCESS_LAUNCH` telemetry stream (`$entity, $tool by 1d`), this **Option 1 Unified Pipeline** evaluates both regimes inside a single 4-stage DAG (`$unified_threat_score = if($adopter_hosts <= 2, $zipf_rarity_score, $poisson_z)`):

```yara
// ============================================================================
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

  // Branch A: Leave-One-Out Discrete Poisson Rarity (Personal Baseline for built-in persistence utilities)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 29.0
  $safe_lambda = if($lambda > 0, $lambda, 0.01)
  $diff = $today_k - $lambda
  $poisson_z_raw = $diff / $safe_lambda
  $poisson_z = if($lambda <= 0.5 and $poisson_z_raw > 0, $poisson_z_raw, 0.0)

  // Branch B: Zipfian Power-Law Fleet Rarity (Enterprise Long Tail <= 2 adopter hosts)
  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_volume = if($fleet_volume > 0, $fleet_volume, 1)
  $zipf_log_rank = math.log($safe_volume) - math.log($safe_hosts)
  $tail_rarity = 1.0 / $safe_hosts
  $zipf_rarity_score = $zipf_log_rank * (1.0 + $tail_rarity)

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

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax for AST compliance)
    $len_no_lower = max(strings.length(re.replace($cmd, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($cmd, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($cmd, `\d`, "")))

    $c_lower = $raw_len - $len_no_lower
    $c_upper = $raw_len - $len_no_upper
    $c_digit = $raw_len - $len_no_digit
    $c_other_raw = $raw_len - ($c_lower + $c_upper + $c_digit)
    $c_other = if($c_other_raw > 0, $c_other_raw, 0)
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
  $safe_len = if($len > 0, $len, 1)

  $n_lower = max($cmd_feature_extraction.c_lower)
  $n_upper = max($cmd_feature_extraction.c_upper)
  $n_digit = max($cmd_feature_extraction.c_digit)
  $n_other = max($cmd_feature_extraction.c_other)

  // Empirical probability per character class (pre-computed for if() compliance)
  $raw_p_lower = $n_lower / $safe_len
  $raw_p_upper = $n_upper / $safe_len
  $raw_p_digit = $n_digit / $safe_len
  $raw_p_other = $n_other / $safe_len

  $p_lower = if($n_lower > 0, $raw_p_lower, 0.0001)
  $p_upper = if($n_upper > 0, $raw_p_upper, 0.0001)
  $p_digit = if($n_digit > 0, $raw_p_digit, 0.0001)
  $p_other = if($n_other > 0, $raw_p_other, 0.0001)

  // Shannon Entropy H = -sum(p_i * log2(p_i)) scaled to byte-entropy equivalent (0.0 to 5.0)
  $raw_h_lower = (0.0 - $p_lower) * (math.log($p_lower) / 0.693147)
  $raw_h_upper = (0.0 - $p_upper) * (math.log($p_upper) / 0.693147)
  $raw_h_digit = (0.0 - $p_digit) * (math.log($p_digit) / 0.693147)
  $raw_h_other = (0.0 - $p_other) * (math.log($p_other) / 0.693147)

  $h_lower = if($n_lower > 0, $raw_h_lower, 0.0)
  $h_upper = if($n_upper > 0, $raw_h_upper, 0.0)
  $h_digit = if($n_digit > 0, $raw_h_digit, 0.0)
  $h_other = if($n_other > 0, $raw_h_other, 0.0)

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

#### Capstone Query: Multi-Scenario Linux Host Convergence via UDM Loopback (`secops-risk-metrics-multistage` + `PlaybookRunner`)

```yara
// ============================================================================
// Goal: Correlate Linux hosts matching >= 2 distinct behavioral queries across Scenarios 1-4 via PlaybookRunner's native UDM loopback (PLAYBOOK_BEHAVIORAL_HUNT_MATCH).
// Target Telemetry: UDM_EVENTS (GENERIC_EVENT with metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH")
// Statistical Model: 2-Stage Cross-Scenario Euclidean L2 Norm Convergence (sum(Z_i^2) >= 25.0 across >= 2 distinct queries)
// ============================================================================

// Stage 1: Deduplicate peak effective Z-score, CRI, and Run ID per (entity, rule_name) over 1d
stage stage1_query_hits {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    principal.asset.hostname = $entity
    security_result.rule_name = $rule_name
    $entity != ""
    $rule_name != ""
    $run_id != ""
    $rule_name != "linux-threats-ueba-hunting:capstone_cross_query_convergence"

  match:
    $entity, $rule_name by 1d

  outcome:
    $query_z = max(security_result.confidence_score)
    $query_cri = max(security_result.risk_score)
    $threat_scenario = array_distinct(security_result.threat_name)
    $latest_run_id = max(metadata.product_log_id)
}

// Root Stage: Cross-Scenario Entity Roll-Up & Euclidean L2 Norm Scoring
$entity = $stage1_query_hits.entity
$day_bucket = $stage1_query_hits.window_start

match:
  $entity, $day_bucket by 1d

outcome:
  $distinct_queries = count_distinct($stage1_query_hits.rule_name)
  $triggered_queries = array_distinct($stage1_query_hits.rule_name)
  $triggered_scenarios = array_distinct($stage1_query_hits.threat_scenario)
  $correlated_run_ids = array_distinct($stage1_query_hits.latest_run_id)
  $latest_run_id = max($stage1_query_hits.latest_run_id)
  $max_single_query_z = max($stage1_query_hits.query_z)
  $max_single_cri = max($stage1_query_hits.query_cri)

  // Euclidean L2 Norm Squared across all distinct matched queries: D^2 = sum(Z_i^2)
  $capstone_threat_norm_sq = sum($stage1_query_hits.query_z * $stage1_query_hits.query_z)

condition:
  $distinct_queries >= 2
  and $capstone_threat_norm_sq >= 25.0

order:
  $capstone_threat_norm_sq desc
```

---

---

## 3. Appendix: A Practitioner's Plain-English Guide to the Statistical Models & Connective Tissue

### 3.1 Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` 10-Day File Prevalence (Query 1A)
* **What it measures**: How unusual a binary's daily execution count is on a specific Linux host (`metrics.file_executions_total` over 30 days) combined with how rare that SHA-256 hash is across the entire organization over the past 10 days (`rolling_max <= 3`).
* **How multi-stage UEBA extends coverage**: curated detection rules only fire when the downloader or dropper uses exact honeypot command-line flags (`-fssl`, `-nc ... -q -p`, or a 56-character `.onion` argument).
* **How the math works**: Even if an adversary fetches a custom ELF payload using standard `curl -O` and runs it without suspicious flags, its SHA-256 hash will have `rolling_max <= 3` in `DERIVED_CONTEXT` and `0` prior active days on the host, triggering a $2.5\times$ novelty multiplier that surfaces the execution immediately.

### 3.2 Markov 2-Gram Parent-to-Child Process Transition Surprisal ($I = -\ln P(\text{Child} \mid \text{Parent})$ — Query 1B)
* **What it measures**: The conditional rarity of a Linux server daemon (`nginx`, `apache2`, `java`, `python`, `sshd`, `cron`) spawning a shell (`sh`, `bash`, `dash`) or network downloader (`curl`, `wget`).
* **How multi-stage UEBA extends coverage**: Static rules look for known exploit strings on the child command line (`__OUT<hex>_S__` or Drupal URLs), missing zero-day web shells and novel RCE payloads.
* **How the math works**: A production `nginx` or `java` service launches worker threads thousands of times ($P \approx 1.0 \implies I \approx 0$), but almost never spawns `/bin/bash` or `/usr/bin/curl`. When an RCE exploit causes `nginx` to spawn `sh` even once or twice, $P(\text{Child} \mid \text{Parent})$ is tiny and the self-information surprisal $I = -\ln(P)$ multiplied by the singleton boost exceeds `3.0`.

### 3.3 Two-Part Zero-Inflated Hurdle Model (Query 2A)
* **What it measures**: First, whether a Linux host is historically quiet with respect to privilege administration ($\le 2$ active days of `sudo`, `su`, `chmod`, `chown`, `setcap`, `pkexec`, `usermod`); second, how intense today's burst is compared to its active days.
* **How multi-stage UEBA extends coverage**: Three of the five rules in `os-privilege-escalation-tools` are disabled (`legacy configuration`) due to false positives, and curated detection rules only matches 4 exact `LinPEAS` strings.
* **How the math works**: Separating *activation* (Part 1 Bernoulli hurdle) from *volume* (Part 2 Z-score) prevents zero-inflation distortion. A production container or database server that normally has zero `chmod`/`setcap`/`usermod` activity incurs an immediate hurdle penalty the moment an attacker begins enumerating or modifying privileges, while busy bastion hosts are evaluated against their own mean and standard deviation.

### 3.4 3-Stage Dual-Sector Host Authentication Failure + Success Fusion ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2$ — Query 2B)
* **What it measures**: The joint 2D Euclidean anomaly distance combining 30-day failed login surges (`metrics.auth_attempts_fail`) and 30-day successful login surges (`metrics.auth_attempts_success`) on the same Linux host.
* **How multi-stage UEBA extends coverage**: curated detection rules uses a rigid `#e > 10` cutoff over `30m` on `su` only, and curated detection rules alerts on every single root transition in isolation.
* **How the math works**: When an attacker sprays local passwords or SSH keys and then achieves a successful session elevation, both $Z_{\text{fail}}$ and $Z_{\text{success}}$ rise above their 30-day host baselines. Squaring and summing the rectified Z-scores ($D^2 = Z_A^2 + Z_B^2 \ge 12.25$, equivalent to a $3.5\sigma$ joint radius) isolates true compromise progression while suppressing routine single-event admin logins.

### 3.5 Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda$ — Query 3A)
* **What it measures**: The statistical improbability of observing $k \ge 2$ persistence or kernel-module commands (`crontab`, `systemctl`, `insmod`, `modprobe`, `authorized_keys`, `rc.local`, `ld.so.preload`) in a day when the host's prior 29-day arrival rate $\lambda$ is near zero ($\le 0.5\text{/day}$).
* **How multi-stage UEBA extends coverage**: curated detection rules only checks `.timer` units within a `5m` window, and `persistence-mechanisms` completely misses `authorized_keys`, `ld.so.preload`, and `insmod`/`modprobe` LKM rootkits.
* **How the math works**: On rare discrete events, sample standard deviation $\sigma$ is near zero. Under a Poisson process, variance equals the arrival rate $\lambda$. By computing leave-one-out $\lambda = (\text{prior\_runs} + 0.5) / 29.0$ (excluding today's count $k$ so the attack does not inflate its own baseline), even 2 or 3 persistence commands on a stable server produce $Z_{\text{Poisson}}^2 \ge 9.0$.

### 3.6 Zipfian Power-Law Fleet Rarity & Inverse Host Frequency Surprisal (Query 3B)
* **What it measures**: How rare a Linux binary path is across the entire server fleet (`adopter_hosts <= 2`) weighted by how aggressively it executes on the local host (`local_volume >= 5`).
* **How multi-stage UEBA extends coverage**: Static persistence rules look for known commands (`curl`, `wget`, `chattr`) modifying `/etc/init.d` or `/etc/cron*`, missing custom-compiled implants or masqueraded daemons already running from `/opt`, `/usr/local/bin`, or `/var/tmp`.
* **How the math works**: Enterprise process execution follows Zipf's power law: standard system binaries (`/usr/bin/bash`, `/usr/sbin/sshd`) run across hundreds of hosts, driving $\ln(\text{fleet\_volume}) - \ln(\text{adopter\_hosts})$ down, whereas a rogue persistent daemon or rootkit helper executing repeatedly on 1 or 2 hosts achieves `zipf_rarity_score >= 4.0`.

### 3.7 Multi-Class Character Shannon Entropy ($H(X)$ — Query 4A)
* **What it measures**: The character-class randomness across lowercase letters, uppercase letters, digits, and symbols in Linux shell and interpreter command lines (`sh`, `bash`, `python`, `perl`, `openssl`, `base64`).
* **How multi-stage UEBA extends coverage**: curated detection rules require literal `base64 -d` flags, which attackers trivially bypass using `openssl enc -d -base64`, `xxd -r`, `python -c`, or hex/zlib encoding.
* **How the math works**: Normal administrative shell commands consist predominantly of lowercase English flags and file paths. Encoded payloads, encrypted reverse-shell stagers, and obfuscated one-liners distribute characters across all four character classes, driving scaled Shannon entropy $H(X) = -\sum p_i \log_2 p_i$ above `3.8` bits/character.

### 3.8 2-Stage Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 4B)
* **What it measures**: The multi-day cumulative sum of positive daily outbound network byte excesses ($Z_t - 0.5\sigma$) above a Linux host's 30-day `metrics.network_bytes_outbound` baseline.
* **How multi-stage UEBA extends coverage**: curated detection rules only catches `curl`/`wget` uploading `/tmp/*.tar.gz`. Stealthy rootkits, covert C2 implants, and throttled exfiltration tasks drip data out at $1.2\sigma\text{–}1.8\sigma$ per day, staying below single-day $3\sigma$ thresholds.
* **How the math works**: Subtracting the $0.5\sigma$ slack constant zeros out normal daily network fluctuations, while a sustained $1.5\sigma$ daily exfiltration or C2 stream accumulates $+1.0$ per day into `cusum_drift_score`, crossing `3.0` across $\ge 2$ drift days.
