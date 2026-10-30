# Hunting Linux Endpoint & Server Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Linux Threats** curated detection suite monitors server, cloud workload, and container host telemetry for dropper downloads (`curl`/`wget`), execution from ephemeral directories (`/tmp`, `/dev/shm`), privilege escalation, persistence (`cron`, `systemd`, `authorized_keys`), rootkits, and cryptominers.

This runbook supplements deterministic Linux detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` on the 30-day `metrics.*` macro plane and `secops-statistical-hunter` on bounded raw-event micro windows). By combining 30-day host execution, authentication failure-rate, and outbound byte baselines (with count dispersion floors $\max(\sigma, \sqrt{\max(\mu, 1)})$, fleet byte dispersion floors, and a 7-active-day maturity gate) alongside Laplace-smoothed Markov 2-gram daemon-to-child surprisal, Two-Part Hurdle privilege-escalation models, and host-prevalence Zipfian binary rarity, the harness surfaces post-exploitation activity across Linux server fleets.

### 1.1 Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)

* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on known indicators, explicit attack command syntax, and single-event threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Orchestrated by `PlaybookRunner` in `agentic_ueba`. Individual YARA-L 2.0 queries emit standardized Z-scores or Z-equivalent statistical scores rather than in-query CRI ladders; `PlaybookRunner` computes the Calibrated Risk Index (`ueba_constants.calculate_cri`) in Python when normalizing hunt matches:
  1. **Wave 1 — Macro 30-Day Baselines & Bounded Micro Statistical Screens (`Queries 1A, 1B, 2A, 3, 4A, 4B, 5A, 5B`)**: Executes Mode A (`[D, D+1)` against `[D-30, D)`, or `[D-2, D+1)` with event stages pinned to `D` for Entity Context Graph joins), multi-day Mode B Windowed Slack Sum drift (`Query 4B`), and bounded raw-telemetry statistical queries concurrently. Every host/entity match is written back to Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback, `Query 2B`)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, `Query 2B` reads `Query 2A`'s candidate Linux hosts in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`) to evaluate leave-one-out Two-Part Hurdle privilege-escalation surges without scanning every host in the fleet.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions upstream host scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_(1|2|3|4|5a)`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`, matching `LOOPBACK_MIN_DISTINCT_HITS` and `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`) in Stage 2, and pivots winning entities directly into raw endpoint, network, authentication, and cloud telemetry in Stage 3.

### 1.2 Optional Customization: Scoping Hunts with a Linux Server Watchlist Data Table (`%linux_server_watchlist`)

Platform security teams often maintain a **Crown-Jewel Linux Server / Production Workload Watchlist** (exported from CMDB, Kubernetes cluster inventories, or cloud production tags) listing high-criticality bastion hosts, CI/CD runners, and production database servers.

> [!TIP]
> **Why Data Table Filters Are Commented Out by Default**: In Google SecOps YARA-L 2.0, referencing a Data Table (`%linux_server_watchlist.hostname`) that has not yet been created and populated in `<CUSTOMER_ID>` (`<PROJECT_ID>`) causes an immediate compiler error. To ensure every query in this runbook compiles out-of-the-box and baselines the full Linux fleet by default, host-scoped queries include a commented-out placeholder (`// $host in %linux_server_watchlist.hostname` or `// $entity in %linux_server_watchlist.hostname`). Uncomment those lines only after creating and populating `%linux_server_watchlist`.

### Table 1: Scenario Coverage Matrix — Linux Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Dropper Staging, Downloader Abuse & Ephemeral Execution** | Detects `curl`/`wget` chains writing to `/tmp` or `/dev/shm` and execution of known malicious payloads. | Combines 30-day host file execution Z-scores (`metrics.file_executions_total`, `active_days >= 7`, count dispersion floor) joined with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`), plus whole-window Laplace-smoothed Markov 2-gram daemon-to-child transition surprisal ($\ge 3.0$). | `Query 1A` (30d Execution Z + 10d `DERIVED_CONTEXT` Prevalence)<br>`Query 1B` (Laplace Markov 2-Gram Daemon Surprisal) |
| **2. Privilege Escalation & Permission Modification** | Flags known privilege-escalation exploits, `sudo` abuse, and `chmod +s` / `chown` modifications. | Pairs 30-day Empirical Bayes Beta-Binomial host authentication failure-rate spikes (`metrics.auth_attempts_fail` / `auth_attempts_total`, Predictive $Z \ge 3.0$ with $\ge 1$ successful login) in Wave 1 with a Wave 2 UDM-gated Two-Part Hurdle model on privilege-escalation binaries. | `Query 2A` (30d Beta-Binomial Host Auth Failure Z + Login Gate)<br>`Query 2B` (Wave 2 UDM-Gated Two-Part Escalation Hurdle) |
| **3. Linux Persistence (`cron`, `systemd`, SSH Keys & Kernel Modules)** | Monitors modifications to scheduled tasks, service unit files, SSH `authorized_keys`, and kernel module loading. | Scores pure host-prevalence Zipfian inverse document frequency rarity ($\ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}}) \ge 2.5$) to isolate persistent Linux binaries, rogue daemons, and module tools executing on $\le 2$ hosts across an active Linux fleet ($\ge 10$ hosts). | `Query 3` (Host-Prevalence Zipfian IDF Rarity) |
| **4. Obfuscated One-Liners, Cryptominers & Low-and-Slow C2 Egress** | Matches known mining pools, reverse-shell one-liners, and high-confidence network indicators. | Screens long, rare shell/interpreter command lines (`LONG_STRING_SCREEN`: $\ln(\text{length}) + \ln(1 + N_{\text{total}}/N_{\text{token}}) \ge 5.5$ on $\le 3$ hosts) alongside a 3-stage multi-day **Windowed Slack Sum** ($\sum_t \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ drift days) on `metrics.network_bytes_outbound`. | `Query 4A` (Long-String & Rare-Token Command Screen)<br>`Query 4B` (3-Stage Outbound Bytes Windowed Slack Sum) |
| **5. Capstone Multi-Scenario Linux Host Convergence** | Point-in-time Linux detections evaluated independently per process or network event. | Correlates Linux entities matching $\ge 2$ distinct scenarios in the active run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) with $\sum Z_i^2 \ge 25.0$ and joins raw process, network, auth, and cloud telemetry for triage. | `Query 5` (Wave 3 UDM Loopback $L_2$ Convergence & Raw Pivot) |
| **6. Egress Per-Flow Quantile Shape & Ingestion-Lag Auditing** | Static byte volume thresholds without payload quantile shape or forwarder delay visibility. | Combines 30-day outbound byte Z-scores (`44,979`-byte dispersion floor) with intra-bucket per-flow $P_{90}/P_{50}$ ratio ($\ge 10.0$), and audits hourly ingestion-lag quantiles ($P_{10}..P_{90}$) and Bowley skewness per `log_type`. | `Query 5A` (30d Egress Z + Per-Flow $P_{90}/P_{50}$ Ratio)<br>`Query 5B` (2-Stage Ingestion-Lag & Clock-Skew Quantile Audit) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Linux Malware Downloads, Dropper Staging & Ephemeral Execution

* **Curated Detection Operational Focus**: Detects `curl`/`wget` chains writing to `/tmp` or `/dev/shm` and execution of known malicious payloads.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day per-host/per-hash file execution Z-scores (`metrics.file_executions_total` with count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ and `active_baseline_days >= 7`) inner-joined with 10-day `DERIVED_CONTEXT` file prevalence (`rolling_max <= 3`), paired with whole-window Laplace-smoothed Markov 2-gram parent-to-child surprisal on Linux server daemons.

#### Query 1A: 2-Stage Hybrid 30-Day File Execution Baseline + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Scores Linux binary executions (`metrics.file_executions_total` per host and SHA-256) on mature host-hash baselines (`$active_baseline_days >= 7`) against their 30-day historical mean and count dispersion floor, then inner-joins Stage 2 with the **Entity Context Graph (`DERIVED_CONTEXT`)** to keep only binaries seen on $\le 3$ hosts across the enterprise over a 10-day rolling window (`rolling_max <= 3`). In Mode A, run with `startTime = D - 2` (`2026-10-27T00:00:00Z`) and `endTime = D + 1` (`2026-10-30T00:00:00Z`) while pinning Stage 1 events to `D` (`"2026-10-29"`) so daily Entity Context Graph snapshots overlap the query window; entities absent from `DERIVED_CONTEXT` drop out of the inner join.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution surges of rare Linux binaries (10-day org DERIVED_CONTEXT prevalence <= 3 hosts) on hosts with mature 30-day execution baselines.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Linux Process Execution Baseline (pinned to Mode A target UTC day D)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    principal.process.file.sha256 = $sha256
    $host != ""
    $sha256 != ""
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $host in %linux_server_watchlist.hostname

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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Binary Prevalence <= 3 Hosts)
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

// Root Stage: Fuses Count-Floor Standardized Z-Score with Enterprise Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $safe_mean = if($mean_execs > 1.0, $mean_execs, 1.0)
  $dispersion_floor = math.sqrt($safe_mean)
  $safe_stddev = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_stddev
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Guarded first_seen novelty boost (disabled when first_seen = 0)
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

#### Query 1B: Whole-Window Laplace-Smoothed Markov 2-Gram Daemon-to-Child Transition Surprisal (`secops-statistical-hunter`)
Detects RCE exploitation, web shells, and unexpected child spawns from Linux server daemons (`nginx`, `apache2`, `httpd`, `tomcat`, `java`, `python`, `php-fpm`, `ruby`, `node`, `sshd`, `cron`, `crond`) by computing the whole-window **Laplace-smoothed Markov 2-gram conditional probability** $P(\text{Child} \mid \text{Parent}) = \frac{N_{\text{pair}} + 1}{N_{\text{parent}} + 100}$ and **Information Surprisal** $\ln\!\left(\frac{N_{\text{parent}} + 100}{N_{\text{pair}} + 1}\right) \ge 3.0$ across a single raw `PROCESS_LAUNCH` stage.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions spawned by Linux server daemons via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (MARKOV_2GRAM_TRANSITION_RARITY, Score = ln((N_parent + 100.0) / (N_pair + 1.0)))
// ============================================================================

// Stage 1: Bucketed Parent-Child Process Transition Activity for Linux Daemons
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    $etype = metadata.event_type
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex(principal.process.file.full_path, `(?i)/(nginx|apache2|httpd|tomcat|java|python|python3|php|php-fpm|ruby|node|sshd|cron|crond)$`)
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $host in %linux_server_watchlist.hostname

  match:
    $etype, $host, $parent, $child by 1h

  outcome:
    $transition_count = count(metadata.id)
    $sample_command = array_distinct(target.process.command_line)
}

// Stage 2: Whole-Window Pair Transition Totals per Host
stage pair_window_totals {
    $etype = $child_transition.etype
    $host = $child_transition.host
    $parent = $child_transition.parent
    $child = $child_transition.child

  match:
    $etype, $host, $parent, $child

  outcome:
    $total_pair_launches = sum($child_transition.transition_count)
}

// Stage 3: Whole-Window Parent Daemon Totals per Host
stage parent_window_totals {
    $etype = $child_transition.etype
    $host = $child_transition.host
    $parent = $child_transition.parent

  match:
    $etype, $host, $parent

  outcome:
    $total_parent_launches = sum($child_transition.transition_count)
}

// Root Stage: Laplace-Smoothed Markov Conditional Probability & Information Surprisal
$etype = $child_transition.etype
$etype = $pair_window_totals.etype
$etype = $parent_window_totals.etype
$host = $child_transition.host
$host = $pair_window_totals.host
$host = $parent_window_totals.host
$parent = $child_transition.parent
$parent = $pair_window_totals.parent
$parent = $parent_window_totals.parent
$child = $child_transition.child
$child = $pair_window_totals.child
$ws = $child_transition.window_start

match:
  $host, $parent, $child, $ws by 1h

outcome:
  $transition_launches = max($child_transition.transition_count)
  $window_pair_launches = max($pair_window_totals.total_pair_launches)
  $window_parent_launches = max($parent_window_totals.total_parent_launches)
  $sample_commands = array_distinct($child_transition.sample_command)

  // Laplace-Smoothed Conditional Transition Probability & Surprisal (V = 100.0)
  $num_smooth = $window_parent_launches + 100.0
  $den_smooth = $window_pair_launches + 1.0
  $transition_prob = $den_smooth / $num_smooth
  $inv_prob = $num_smooth / $den_smooth
  $markov_threat_score = math.log($inv_prob)

  // 6 Core Evidence Pillars
  $observation_count = $transition_launches
  $baseline_active_samples = $window_parent_launches
  $baseline_mean = $transition_prob
  $baseline_dispersion = $markov_threat_score
  $fleet_prevalence = 0 - 1
  $distinct_binaries = 1

condition:
  $window_parent_launches >= 3
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

---

### Scenario 2: Linux Privilege Escalation Tools & `sudo`/`setuid`/`chown` Modifications

* **Curated Detection Operational Focus**: Flags known privilege-escalation exploits, `sudo` abuse, and `chmod +s` / `chown` modifications.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates 30-day **Empirical Bayes Beta-Binomial** host authentication failure rates (`metrics.auth_attempts_fail` paired with `metrics.auth_attempts_total` on `principal.asset.hostname`, requiring `active_days >= 7` and at least one successful login on the same host) in Wave 1 (`Query 2A`), then feeds matched candidate hosts via UDM Loopback into a Wave 2 **Two-Part Hurdle** model on privilege-escalation binaries (`Query 2B`).

#### Query 2A: 2-Stage Empirical Bayes Beta-Binomial Host Authentication Failure Rate + Login Elevation Gate (`secops-risk-metrics-multistage`)
Replaces collinear same-family `AUTH` Euclidean fusion with a conjugate **Empirical Bayes Beta-Binomial** failure-rate model keyed on `principal.asset.hostname`. Stage 1 extracts today's total logins, failed logins, and successful logins alongside 30-day `metrics.auth_attempts_fail` and `metrics.auth_attempts_total` sums; the Root stage forms the pre-observation $\text{Beta}(1 + \text{hist\_fail}, 19 + \text{hist\_succ})$ prior, computes the Beta-Binomial posterior-predictive residual $Z$-score (`$beta_binomial_z >= 3.0` with variance floor `0.25`), and requires `$active_days >= 7` and `$obs_succ >= 1` so pure external scanner noise with zero successful logins is suppressed.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous Linux host authentication failure-rate spikes accompanied by successful session login via 30-day Empirical Bayes Beta-Binomial Predictive Z.
// Statistical Model: BAYESIAN_BETA_BINOMIAL (Empirical Bayes Paired Beta-Binomial Failure Rate Predictive Z >= 3.0, active_days >= 7, obs_succ >= 1)
// ARCHITECTURE: 2-STAGE CONJUGATE BETA-BINOMIAL HOST AUTHENTICATION PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Host Authentication Attempts & 30-Day Paired Failure/Total Baselines
stage stage1_extract {
    metadata.event_type = "USER_LOGIN"
    principal.asset.hostname = $host
    $host != ""
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $host in %linux_server_watchlist.hostname

  match:
    $host by 1d

  outcome:
    $obs_total = count(metadata.id)
    $obs_fail = sum(if(security_result.action = "ALLOW", 0, 1))
    $obs_succ = sum(if(security_result.action = "ALLOW", 1, 0))
    $distinct_source_ips = count_distinct(principal.ip)
    $distinct_users = count_distinct(target.user.userid)

    $historical_active_days = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_fail_sum = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: sum,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_total_sum = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: sum,
        principal.asset.hostname: principal.asset.hostname
    ))
}

// Stage 2 (Root Stage): Empirical Bayes Paired Beta-Binomial Failure Rate & Predictive Z
$host = $stage1_extract.host
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $obs_fail = sum($stage1_extract.obs_fail)
  $obs_succ = sum($stage1_extract.obs_succ)
  $obs_total = sum($stage1_extract.obs_total)
  $hist_fail_sum = max($stage1_extract.hist_fail_sum)
  $hist_total_sum = max($stage1_extract.hist_total_sum)
  $active_days = max($stage1_extract.historical_active_days)

  // 1. Historical Successes & Pre-Observation Conjugate Beta(alpha_pre, beta_pre) Prior
  $raw_hist_succ = $hist_total_sum - $hist_fail_sum
  $hist_succ_sum = if($raw_hist_succ > 0.0, $raw_hist_succ, 0.0)
  $alpha_pre = 1.0 + $hist_fail_sum
  $beta_pre = 19.0 + $hist_succ_sum
  $ab = $alpha_pre + $beta_pre
  $prior_fail_rate = $alpha_pre / $ab

  // 2. Conjugate Posterior Failure Rate & Beta-Binomial Posterior-Predictive Residual Z
  $posterior_fail_rate = ($alpha_pre + $obs_fail) / ($ab + $obs_total)
  $pred_mean = $obs_total * $prior_fail_rate
  $pred_var = $obs_total * $prior_fail_rate * ($beta_pre / $ab) * (($ab + $obs_total) / ($ab + 1.0))
  $safe_pred_var = if($pred_var > 0.25, $pred_var, 0.25)
  $safe_pred_sd = math.sqrt($safe_pred_var)
  $beta_binomial_z = ($obs_fail - $pred_mean) / $safe_pred_sd
  $z_score = $beta_binomial_z

condition:
  $active_days >= 7
  and $obs_succ >= 1
  and $beta_binomial_z >= 3.0

order:
  $beta_binomial_z desc
```

#### Query 2B: 4-Stage UDM-Gated Two-Part Hurdle Model on Linux Privilege Escalation & Recon (`secops-statistical-hunter`)
Evaluates Linux privilege-escalation and permission-modification utility execution (`sudo`, `su`, `pkexec`, `chage`, `usermod`, `useradd`, `visudo`, `setcap`, `chmod`, `chown`, `find`, `getcap`) via a **Two-Part Hurdle Model** (dormant awakening volume gate for `active_days <= 3` and positive-rectified leave-one-out intensity Z with $\sqrt{\max(\mu, 1)}$ dispersion floor for `active_days > 3`) strictly on candidate Linux hosts surfaced by `Query 2A` via Wave 2 UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED TWO-PART HURDLE PIPELINE
// Goal: Detect dormant awakening or leave-one-out surges in Linux privilege-escalation utility execution on candidate hosts gated by Query 2A UDM Loopback.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Two-Part Hurdle Outlier Model (TWO_PART_HURDLE)
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
    $daily_events_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
}

stage personal_history {
    $host = $daily_activity.host

  match:
    $host

  outcome:
    $sum_x = sum($daily_activity.daily_events)
    $sum_x2 = sum($daily_activity.daily_events_sq)
    $active_days = count($daily_activity.window_start)
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
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_activity.distinct_cmds)

  // Leave-One-Out Continuous Intensity Standardization (Positive-Rectified with sqrt(max(mean, 1.0)) floor)
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $raw_loo_sum = max($personal_history.sum_x) - $observation_count
  $loo_sum = if($raw_loo_sum > 0, $raw_loo_sum, 0)
  $baseline_mean = 1.0 * $loo_sum / $n_prior
  $raw_loo_var = ((max($personal_history.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $raw_intensity_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $intensity_z = if($raw_intensity_z > 0.0, $raw_intensity_z, 0.0)

  // Dormant Awakening Branch (Gated by observation_count >= 5 when active_days <= 3)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 5.0)
  $dormant_score = if($observation_count >= 5, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 3, $dormant_score, $intensity_z)

condition:
  $observation_count >= 3
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

### Scenario 3: Linux Persistence Mechanisms

* **Curated Detection Operational Focus**: Monitors modifications to scheduled tasks, service unit files, SSH `authorized_keys`, and kernel module loading.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates `PROCESS_LAUNCH` across bounded micro windows (up to 7–14 days) using pure **Host-Prevalence Zipfian Inverse Document Frequency** ($\ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}}) \ge 2.5$) to isolate persistent implants, custom service scripts, and rogue daemons executing on $\le 2$ Linux hosts across an active fleet of $\ge 10$ hosts.

#### Query 3: Host-Prevalence Zipfian IDF Rarity on Persistent Linux Binaries & Rogue Daemons (`secops-statistical-hunter`)
Scores pure host-prevalence inverse document frequency $\ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}})$ across the active Linux server population (`$safe_fleet_hosts >= 10`) without mixing total execution volume into host counts, ensuring chatty standard daemons never outrank persistent implants, cron/systemd helpers, or kernel-module utilities adopted by $\le 2$ Linux hosts.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare persistent Linux binaries, rogue daemons, and kernel-module tools in the enterprise Zipfian long tail via pure host-prevalence inverse document frequency.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Host-Prevalence Inverse Document Frequency Rarity (ZIPFIAN_PROCESS_RARITY, Zipf Score = ln(N_fleet_hosts / N_adopter_hosts) >= 2.5)
// ============================================================================

// Stage 1: Endpoint Local Linux Binary Execution Activity
stage endpoint_process_burst {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    $etype = metadata.event_type
    principal.asset.hostname = $host
    $binary = target.process.file.full_path
    $host != ""
    $binary != ""
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $host in %linux_server_watchlist.hostname

  match:
    $etype, $host, $binary by 1d

  outcome:
    $endpoint_executions = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
    $sample_commands = array_distinct(target.process.command_line)
}

// Stage 2: Enterprise Fleetwide Linux Binary Adopter Breadth across the Search Window
stage fleet_process_popularity {
    $etype = $endpoint_process_burst.etype
    $binary = $endpoint_process_burst.binary

  match:
    $etype, $binary

  outcome:
    $fleet_hosts = count_distinct($endpoint_process_burst.host)
    $fleet_total_executions = sum($endpoint_process_burst.endpoint_executions)
}

// Stage 3: Total Active Linux Fleet Host Population across the Search Window
stage fleet_host_total {
    $etype = $endpoint_process_burst.etype

  match:
    $etype

  outcome:
    $total_fleet_hosts = count_distinct($endpoint_process_burst.host)
}

// Root Stage: Host-Prevalence Zipfian Rarity Scoring
$etype = $endpoint_process_burst.etype
$etype = $fleet_process_popularity.etype
$etype = $fleet_host_total.etype
$binary = $endpoint_process_burst.binary
$binary = $fleet_process_popularity.binary
$host = $endpoint_process_burst.host
$ws = $endpoint_process_burst.window_start

match:
  $host, $binary, $ws by 1d

outcome:
  $adopter_hosts = max($fleet_process_popularity.fleet_hosts)
  $fleet_total_hosts = max($fleet_host_total.total_fleet_hosts)
  $local_volume = max($endpoint_process_burst.endpoint_executions)
  $commands = array_distinct($endpoint_process_burst.sample_commands)

  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_fleet_hosts = if($fleet_total_hosts > $safe_hosts, $fleet_total_hosts, $safe_hosts)
  $host_ratio = 1.0 * $safe_fleet_hosts / $safe_hosts
  $zipf_rarity_score = math.log($host_ratio)
  $z_score = $zipf_rarity_score

  // 6 Core Evidence Pillars
  $observation_count = $local_volume
  $baseline_active_samples = $safe_fleet_hosts
  $baseline_mean = 1.0 * $adopter_hosts / $safe_fleet_hosts
  $baseline_dispersion = $zipf_rarity_score
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = max($endpoint_process_burst.distinct_cmds)

condition:
  $safe_fleet_hosts >= 10
  and $adopter_hosts <= 2
  and $observation_count >= 2
  and $zipf_rarity_score >= 2.5

order:
  $zipf_rarity_score desc
```

---

### Scenario 4: Mandiant Frontline & Emerging Linux Threats (Obfuscated One-Liners, Cryptominers & Covert C2)

* **Curated Detection Operational Focus**: Matches known mining pools, reverse-shell one-liners, and high-confidence network indicators.
* **How Multi-Stage UEBA Extends Coverage**: Screens long, low-prevalence Linux shell and interpreter command lines in YARA-L (`LONG_STRING_SCREEN`, `Query 4A`) and tracks multi-day cumulative positive standardized drift on Linux host outbound bytes via a 3-stage **Windowed Slack Sum** (`Query 4B`).

#### Query 4A: Long-String & Rare-Token Command-Line Screen on Linux Shells & Interpreters (`secops-statistical-hunter`)
Because YARA-L 2.0 has no per-character iteration primitive (exact per-character Shannon entropy $H(s) = -\sum p(c)\log_2 p(c)$ requires external Python post-processing via `SHANNON_ENTROPY_CHARACTER`), this query implements the stateless **`LONG_STRING_SCREEN`** candidate filter across Linux shells and interpreters (`sh`, `bash`, `dash`, `zsh`, `ksh`, `python`, `python3`, `perl`, `ruby`, `php`, `openssl`, `base64`, `xxd`, `curl`, `wget`): it scores $\ln(\text{length}) + \ln\!\left(1 + \frac{N_{\text{host\_events}}}{N_{\text{token\_events}}}\right) \ge 5.5$ on command lines of length $\ge 64$ seen on $\le 3$ Linux hosts across the fleet.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long, rare Linux shell and interpreter command lines (length >= 64, fleet prevalence <= 3 hosts) for obfuscated reverse shells and encoded stagers.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on LINUX)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN, score = ln(length) + ln(1 + total_events / token_count) >= 5.5)
// ============================================================================

// Stage 1: Per-Host Linux Shell & Interpreter Event Volume
stage entity_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $entity
    $entity != ""
    re.regex(target.process.file.full_path, `(?i)/(sh|bash|dash|zsh|ksh|python|python3|perl|ruby|php|openssl|base64|xxd|curl|wget)$`)
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $entity in %linux_server_watchlist.hostname

  match:
    $entity by 1d

  outcome:
    $total_events = count(metadata.id)
}

// Stage 2: Distinct Command-Line Observation & Length Extraction (length >= 64)
stage token_observation {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.platform = "LINUX"
    principal.asset.hostname = $entity
    $entity != ""
    $token = target.process.command_line
    $token != ""
    strings.length(target.process.command_line) >= 64
    re.regex(target.process.file.full_path, `(?i)/(sh|bash|dash|zsh|ksh|python|python3|perl|ruby|php|openssl|base64|xxd|curl|wget)$`)
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $entity in %linux_server_watchlist.hostname

  match:
    $entity, $token by 1d

  outcome:
    $token_count = count(metadata.id)
    $token_length = max(strings.length(target.process.command_line))
}

// Stage 3: Enterprise Fleet Host Prevalence per Command-Line Token
stage token_fleet_prevalence {
    $token = $token_observation.token
    $ws = $token_observation.window_start

  match:
    $token, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($token_observation.entity)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring
$entity = $entity_baseline.entity
$entity = $token_observation.entity
$token = $token_observation.token
$token = $token_fleet_prevalence.token
$ws = $entity_baseline.window_start
$ws = $token_observation.window_start
$ws = $token_fleet_prevalence.ws

match:
  $entity, $token, $ws by 1d

outcome:
  $total_activity = max($entity_baseline.total_events)
  $token_executions = max($token_observation.token_count)
  $raw_length = max($token_observation.token_length)
  $safe_length = if($raw_length > 0, $raw_length, 1)
  $safe_total = if($total_activity > 0, $total_activity, 1)
  $safe_tok = if($token_executions > 0, $token_executions, 1)

  $log_len = math.log($safe_length)
  $freq_ratio = 1.0 + (1.0 * $safe_total / $safe_tok)
  $rarity_lift = math.log($freq_ratio)
  $shannon_entropy_score = $log_len + $rarity_lift
  $z_score = $shannon_entropy_score

  // 6 Core Evidence Pillars
  $observation_count = $token_executions
  $baseline_active_samples = $total_activity
  $baseline_mean = $raw_length
  $baseline_dispersion = $log_len
  $fleet_prevalence = max($token_fleet_prevalence.fleet_hosts)
  $distinct_binaries = 1

condition:
  $raw_length >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 5.5

order:
  $shannon_entropy_score desc
```

#### Query 4B: 3-Stage Multi-Day Windowed Slack Sum Drift on Linux Host Outbound Network Traffic (`secops-risk-metrics-multistage`)
Catches covert C2 beacons, cryptominer stratum traffic, and low-and-slow archive exfiltration across a multi-day Mode B evaluation window (`2–14` days). Because YARA-L 2.0 cannot carry recursive Page CUSUM state $S_{t-1}$ across buckets, Stage 2 standardizes each daily bucket against the host's 30-day `metrics.network_bytes_outbound` baseline using the `44,979`-byte dispersion floor with $k = 0.5\sigma$ slack (`max(0, Z_t - 0.5)` for mature baselines `$active_days >= 7`), and the Root stage computes the **Windowed Slack Sum** $W = \sum_t \max(0, Z_t - 0.5) \ge 3.0$ across `$drift_days >= 2` (sequential recursive Page CUSUM with zero-reset can be evaluated downstream in Python via `cusum_helper.py`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect multi-day low-and-slow Linux outbound byte drift, covert C2 traffic, and sustained cryptominer communication over a 3-to-14-day Mode B window via Windowed Slack Sum.
// Statistical Model: Multi-Day Cumulative Drift — Windowed Slack Sum (WINDOWED_SLACK_SUM, k = 0.5 sigma slack, cusum_drift_score >= 3.0, drift_days >= 2, active_days >= 7)
// ARCHITECTURE: 3-STAGE MULTI-DAY WINDOWED SLACK SUM PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Bytes & 30-Day Historical Baseline per Host
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    $sent = network.sent_bytes
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $entity in %linux_server_watchlist.hostname

  match:
    $entity by 1d

  outcome:
    $observed_val = sum($sent)
    $observed_connections = count(metadata.id)
    $distinct_dest_ips = count_distinct(target.ip)
    $distinct_dest_ports = count_distinct(target.port)

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
}

// Stage 2: Daily Standardized Slack-Excess Extraction (k = 0.5 sigma, 44979-byte floor)
stage stage2_daily_drift {
    $entity = $stage1_extract.entity
    $day_ws = $stage1_extract.window_start

  match:
    $entity, $day_ws by 1d

  outcome:
    $observed = max($stage1_extract.observed_val)
    $hist_avg = max($stage1_extract.historical_avg)
    $hist_stddev = max($stage1_extract.historical_stddev)
    $active_days = max($stage1_extract.historical_active_days)
    $hist_max = max($stage1_extract.historical_max)

    $raw_drift = $observed - $hist_avg
    $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
    $slack_allowance = 0.5 * $safe_stddev
    $slack_excess = $raw_drift - $slack_allowance
    $daily_z = $raw_drift / $safe_stddev
    $z_minus_slack = $daily_z - 0.5
    $daily_excess = if($active_days >= 7 and $z_minus_slack > 0.0, $z_minus_slack, 0.0)
}

// Stage 3 (Root Stage): Multi-Day Windowed Slack Sum Aggregation Across Evaluation Window
$entity = $stage2_daily_drift.entity

match:
  $entity

outcome:
  $observed = sum($stage2_daily_drift.observed)
  $peak_daily_observed = max($stage2_daily_drift.observed)
  $hist_avg = max($stage2_daily_drift.hist_avg)
  $hist_stddev = max($stage2_daily_drift.hist_stddev)
  $active_days = max($stage2_daily_drift.active_days)
  $hist_max = max($stage2_daily_drift.hist_max)

  // Windowed Slack Sum W = sum(max(0, Z_t - 0.5)) across daily buckets in window
  $cusum_drift = sum($stage2_daily_drift.daily_excess)
  $windowed_slack_sum = $cusum_drift
  $cusum_drift_score = $cusum_drift
  $drift_days = sum(if($stage2_daily_drift.daily_excess > 0.0, 1, 0))
  $max_daily_z = max($stage2_daily_drift.daily_z)
  $z_score = $cusum_drift_score

condition:
  $active_days >= 7
  and $cusum_drift_score >= 3.0
  and $drift_days >= 2

order:
  $cusum_drift_score desc
```

---

### Scenario 5: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

* **Curated Detection Operational Focus**: Point-in-time Linux detections evaluated independently per process or network event.
* **How Multi-Stage UEBA Extends Coverage**: Correlates Linux hosts matching $\ge 2$ distinct behavioral queries in the current run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$) and pivots directly into raw endpoint, network, authentication, and cloud telemetry.

Individual behavioral queries in Scenarios 1–4 and Section 3 can fire in isolation during maintenance windows or administrative bursts, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as process paths and cloud resource names.

**Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** and **Wave 2** (`Query 2B`) queries have written their matches to Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` across host-scoped queries (`re.regex(security_result.rule_name, `:q[0-9]+_query_(1|2|3|4|5a)`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, requiring `$distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) and `$capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Cross-Silo Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates per-silo event counts and sample artifacts across `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, and `USER_LOGIN` by `$entity`, joining them with Stage 2 in the Root stage.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Linux Threats host queries via UDM Loopback regex token union while joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_(1|2|3|4|5a)`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.asset.hostname, principal.user.userid, principal.ip[0])
    $entity != ""
    $run_id != ""
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $entity in %linux_server_watchlist.hostname

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
    $entity = strings.coalesce(principal.asset.hostname, principal.user.userid, principal.ip[0])
    $entity != ""

  match:
    $entity

  outcome:
    $raw_event_count = count(metadata.id)
    $process_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $network_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $auth_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
    $cloud_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
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
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $auth_events = max($stage3_raw_forensic_pivot.auth_events)
  $cloud_events = max($stage3_raw_forensic_pivot.cloud_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

  $raw_plus_one = $raw_event_count + 1.0
  $log_raw = math.log($raw_plus_one)
  $unified_threat_score = $capstone_threat_score + $log_raw

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $unified_threat_score desc
```

---

## 3. Linux Server Egress Quantile Shape ($P_{50}$ vs $P_{90}$) & Anti-Forensic Timestomp / Syslog Delay Auditing

Adversaries operating on compromised Linux servers frequently (1) blend staged archive exfiltration into routine background connections where median per-flow bytes stay small while $P_{90}$ spikes, or (2) skew system clocks / suspend `rsyslog` or `auditd` forwarding during privilege escalation.
* **Query 5A**: Combines 30-day `metrics.network_bytes_outbound` Z-scores (using the `44,979`-byte dispersion floor and `$active_days >= 7` maturity gate) with intra-bucket `window.percentile(network.sent_bytes, 50)` and `window.percentile(network.sent_bytes, 90)` (`$flow_tail_burst_ratio >= 10.0`).
* **Query 5B**: Evaluates `metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds` across `$p10, $p25, $p50, $p75, $p90` and Bowley quartile skewness (`$bowley_skew = ($p75 + $p25 - 2 * $p50) / max($p75 - $p25, 1.0)`) in a 2-stage hourly pipeline to catch future clock skew (`$clock_skew_sec > 60` when `$p10 < -60s`), severe ingestion delay (`$p90 >= 300s`), or right-skewed forwarder flush bursts (`$bowley_skew >= 0.75`).

#### Query 5A: 30-Day Outbound Bytes Z-Score + Intra-Bucket Per-Flow $P_{50}/P_{90}$ Tail Concentration (`secops-risk-metrics-multistage`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Combine 30-day metrics.network_bytes_outbound macro Z-score (44979-byte dispersion floor) with intra-bucket per-flow P90/P50 payload tail concentration.
// Statistical Model: STANDARD_Z_SCORE (metrics.network_bytes_outbound, active_days >= 7, personal_z >= 3.0) + Intra-Bucket Per-Flow P90/P50 Ratio (>= 10.0)
// Skill: secops-risk-metrics-multistage
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    $host != ""
    // Optional Linux Server Watchlist Data Table filter (unpopulated tables break compilation; see Section 1.2):
    // $host in %linux_server_watchlist.hostname

  match:
    $host by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $flow_count = count(metadata.id)
    $flow_p50_bytes = window.percentile(network.sent_bytes, 50)
    $flow_p90_bytes = window.percentile(network.sent_bytes, 90)
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

$host = $stage1_extract.host
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $flows = max($stage1_extract.flow_count)
  $p50_bytes = max($stage1_extract.flow_p50_bytes)
  $p90_bytes = max($stage1_extract.flow_p90_bytes)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  // Fleet byte dispersion floor for network_bytes_outbound (44,979 bytes)
  $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev
  $z_score = $personal_z

  $safe_p50 = if($p50_bytes > 1.0, $p50_bytes, 1.0)
  $flow_tail_burst_ratio = $p90_bytes / $safe_p50

condition:
  $active_days >= 7
  and $personal_z >= 3.0
  and $flow_tail_burst_ratio >= 10.0

order:
  $flow_tail_burst_ratio desc
```

#### Query 5B: 2-Stage Linux Telemetry Ingestion-Lag & Timestomp Quantile Audit (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Profile hourly telemetry ingestion-lag quantiles, Bowley quartile skewness, and negative clock-skew anomalies per log_type.
// Target Telemetry: UDM_EVENTS (all ingested Linux / infrastructure log types)
// Statistical Model: 2-Stage Ingestion-Lag Quantile Spread & Bowley Skewness Audit (p90 >= 300s, clock_skew_sec > 60s, or bowley_skew >= 0.75)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_lag_quantiles {
    metadata.event_timestamp.seconds > 0
    $log_type = metadata.log_type
    $log_type != ""

  match:
    $log_type by 1h

  outcome:
    $event_count = count(metadata.id)
    $p10 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 10)
    $p25 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 25)
    $p50 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 50)
    $p75 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 75)
    $p90 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 90)
}

$log_type = $stage1_lag_quantiles.log_type
$ws = $stage1_lag_quantiles.window_start

match:
  $log_type, $ws by 1h

outcome:
  $event_count = max($stage1_lag_quantiles.event_count)
  $p10 = max($stage1_lag_quantiles.p10)
  $p25 = max($stage1_lag_quantiles.p25)
  $p50 = max($stage1_lag_quantiles.p50)
  $p75 = max($stage1_lag_quantiles.p75)
  $p90 = max($stage1_lag_quantiles.p90)

  $iqr = $p75 - $p25
  $safe_iqr = if($iqr > 1.0, $iqr, 1.0)
  $bowley_num = $p75 + $p25 - (2.0 * $p50)
  $bowley_skew = $bowley_num / $safe_iqr
  $idr = $p90 - $p10
  $tail_heaviness = $idr / $safe_iqr
  $clock_skew_sec = 0.0 - $p10

  // 6 Core Evidence Pillars
  $observation_count = $event_count
  $baseline_active_samples = $event_count
  $baseline_mean = $p50
  $baseline_dispersion = $safe_iqr
  $fleet_prevalence = 0 - 1
  $distinct_binaries = 1

condition:
  $event_count >= 10
  and ($clock_skew_sec > 60.0 or $p90 >= 300.0 or $bowley_skew >= 0.75)

order:
  $p90 desc
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
