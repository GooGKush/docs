# Hunting macOS Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **macOS Threats** curated detection suite provides real-time coverage for macOS endpoints—including Gatekeeper bypasses (`xattr -d com.apple.quarantine`), AppleScript (`osascript`) execution chains, macOS info-stealers (AMOS, Poseidon, Banshee), Keychain and browser credential access, and `LaunchAgent`/`LaunchDaemon` persistence.

Because macOS adversaries rapidly rotate script wrappers, DMG/PKG installers, and stealer variants, this runbook extends curated detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). The queries below compute whole-window Laplace-smoothed Markov 2-gram process transition surprisal, 30-day file execution Z-scores fused with 10-day `DERIVED_CONTEXT` binary prevalence, stateless long-string and rare command-line screening, zero-inclusive hourly Poisson Fano burst dispersion, unified Two-Part Hurdle and empirical Zipfian host-prevalence rarity, dual-sector outbound byte and DNS fusion, cross-bucket outbound flow-gap regularity, and skewness-adjusted Tukey fences.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba` (which maps each query's native Z or Z-equivalent score to the `[0..100]` Calibrated Risk Index in Python via `ueba_constants.calculate_cri`):
  1. **Wave 1 — Macro `metrics.*` Baselines & Bounded Micro Screens**: Executes all Mode A (`[D T00:00:00Z, D+1 T00:00:00Z)`) 30-day `metrics.*` baselines (enforcing the $\ge 7$ active-day maturity gate, count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$, and per-metric fleet byte dispersion floors) alongside bounded raw-event statistical queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage-B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound hourly (`by 1h`) zero-inclusive Fano burst dispersion (`Query 2B`) and cross-bucket outbound flow-gap ratio screening (`Query 4B`) without hitting enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud/auth telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — macOS Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Gatekeeper Bypass, Unsigned Installers & Interactive Script Chains** | Detects quarantine attribute removal (`xattr`), suspicious disk image mounts, and terminal/browser `osascript` execution. | Computes whole-window Laplace-smoothed Markov 2-gram parent-to-child transition surprisal ($I = \ln\frac{N_{\text{parent}} + 100}{N_{\text{pair}} + 1} \ge 3.0$) and fuses 30-day file execution Z-scores ($\ge 3.0\sigma$, $\ge 7$ active days) with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`). | `Query 1A` (`MARKOV_2GRAM_TRANSITION_RARITY`)<br>`Query 1B` (30d Execution Z + 10d `DERIVED_CONTEXT` File Prevalence) |
| **2. macOS Info-Stealers & Keychain / Browser Credential Harvesting** | Matches known stealer command lines, `security` Keychain queries, and browser profile access. | Screens unusually long, rare shell/`osascript` command lines (`score >= 5.5`, length $\ge 64$, fleet prevalence $\le 3$) in Wave 1, then evaluates zero-inclusive hourly Poisson Fano dispersion ($F = \sigma^2/\mu \ge 4.0$ over $T = 24$ buckets) across Keychain and profiling utilities in Wave 2. | `Query 2A` (`LONG_STRING_SCREEN`)<br>`Query 2B` (UDM-Gated `POISSON_BURST_CLUSTERING`) |
| **3. macOS Persistence (`LaunchAgents`, `LaunchDaemons`, Cron & TCC)** | Alerts on new plist files in Launch directories, scheduled tasks, and TCC database tampering. | Combines a Two-Part Hurdle model (dormant volume gate $\ge 5$ vs. leave-one-out positive intensity Z) with empirical host-prevalence Zipfian IDF rarity ($\ln(N_{\text{fleet}}/df) \ge 2.5$ on $\le 2$ hosts) in a single pipeline. | `Query 3` (Unified `TWO_PART_HURDLE` + `ZIPFIAN_PROCESS_RARITY`) |
| **4. Covert C2 Callbacks & Staged Archive Exfiltration** | Flags known C2 domains and suspicious `curl` uploads of staged archives. | Fuses 30-day outbound network byte and DNS query Z-scores ($D^2 = Z_{\text{bytes}}^2 + Z_{\text{dns}}^2 \ge 12.25$, $\ge 7$ active days) in Wave 1, then screens candidate hosts for regular cross-bucket outbound flow-gap ratios ($\text{CV} = \sigma_{\text{gap}}/\mu_{\text{gap}} \le 0.20$) in Wave 2. | `Query 4A` (`DUAL_SECTOR_FUSION_3STAGE`)<br>`Query 4B` (UDM-Gated `FLOW_GAP_RATIO_SCREEN`) |
| **5. Capstone Multi-Scenario macOS Host Convergence** | Single-event macOS detections evaluated in isolation. | Correlates macOS entities triggering $\ge 2$ distinct behavioral queries within the current run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via a squared Euclidean $L_2$ norm ($\sum Z_i^2 \ge 25.0$) joined to raw telemetry. | `Query 5` (Wave 3 UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Gatekeeper Bypass, Unsigned DMG/PKG Execution & AppleScript ClickFix Chains

* **Curated Detection Operational Focus**: Detects quarantine attribute removal (`xattr`), suspicious disk image mounts, and terminal/browser `osascript` execution.
* **How Multi-Stage UEBA Extends Coverage**: Computes whole-window Laplace-smoothed Markov 2-gram parent-to-child transition surprisal ($I \ge 3.0$) and fuses 30-day per-binary file execution Z-scores ($\ge 3.0\sigma$, $\ge 7$ active days) with 10-day `DERIVED_CONTEXT` organizational file prevalence (`rolling_max <= 3`).

#### Query 1A: Markov 2-Gram Parent-to-Child Process Transition Surprisal on macOS Execution Chains (`secops-statistical-hunter`)
Compensates for brittle filename prefixes and static flag regexes by computing whole-window **Laplace-Smoothed Markov 2-Gram Transition Probability** $P(\text{Child} \mid \text{Parent}) = \frac{N_{\text{pair}} + 1}{N_{\text{parent}} + 100}$ and **Information Surprisal** $I = \ln\left(\frac{N_{\text{parent}} + 100}{N_{\text{pair}} + 1}\right) \ge 3.0$. Stage 1 records all child launches from macOS interactive applications (`Terminal`, `iTerm2`, `Finder`, `Safari`, `Chrome`, `Firefox`, `Brave`, `Arc`), `osascript`, and staging directories (`/Volumes/`, `/tmp/`, `Downloads`, `Users/Shared`, `Application Support`) so Stage 3 accumulates the unbiased parent launch total $N_{\text{parent}}$ before Root filters to post-exploitation child binaries (`sh`, `zsh`, `bash`, `dash`, `osascript`, `curl`, `xattr`, `hdiutil`, `screencapture`, `security`, `sqlite3`, `python3`, `nohup`, `xxd`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions on macOS endpoints (Terminal, Finder, browsers, osascript, or mounted DMGs spawning shells, xattr, curl, or security) via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on macOS endpoints)
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (MARKOV_2GRAM_TRANSITION_RARITY, Score = ln((N_parent + 100.0) / (N_pair + 1.0)) >= 3.0)
// ============================================================================

// Stage 1: Bucketed Parent-Child Process Transition Activity per macOS host
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex(principal.process.file.full_path, `(?i)(Terminal|iTerm|Finder|Safari|Chrome|Firefox|Brave|Arc|osascript|/Volumes/|/tmp/|/Downloads/|/Users/Shared/|/Library/Application Support/)`)

  match:
    $etype, $host, $parent, $child by 1d

  outcome:
    $transition_count = count(metadata.id)
    $is_suspicious_child = max(if(re.regex(target.process.file.full_path, `/(sh|zsh|bash|dash|osascript|curl|xattr|hdiutil|screencapture|security|sqlite3|python3|nohup|xxd)$`) nocase, 1, 0))
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

// Stage 3: Whole-Window Unbiased Parent Process Totals per Host
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
  $host, $parent, $child, $ws by 1d

outcome:
  $transition_launches = max($child_transition.transition_count)
  $is_suspicious_child = max($child_transition.is_suspicious_child)
  $window_pair_launches = max($pair_window_totals.total_pair_launches)
  $window_parent_launches = max($parent_window_totals.total_parent_launches)
  $sample_commands = array_distinct($child_transition.sample_command)

  // Laplace-Smoothed Conditional Transition Probability & Surprisal (V = 100.0)
  $transition_prob = ($window_pair_launches + 1.0) / ($window_parent_launches + 100.0)
  $markov_threat_score = math.log(($window_parent_launches + 100.0) / ($window_pair_launches + 1.0))

  // 6 Core Evidence Pillars
  $observation_count = $transition_launches
  $baseline_active_samples = $window_parent_launches
  $baseline_mean = $transition_prob
  $baseline_dispersion = $markov_threat_score
  $fleet_prevalence = 0 - 1
  $distinct_binaries = 1

condition:
  $is_suspicious_child = 1
  and $window_parent_launches >= 3
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

#### Query 1B: 2-Stage Hybrid 30-Day File Execution Baseline + 10-Day Entity Context Graph File Prevalence (`secops-risk-metrics-multistage`)
Scores daily per-(host, SHA256) process executions against a 30-day behavioral baseline (`metrics.file_executions_total`, requiring $\ge 7$ active baseline days and count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$) joined with `DERIVED_CONTEXT` **10-day organizational file prevalence** (`day_count = 10`, `rolling_max <= 3` and `rolling_max > 0`).

Because `DERIVED_CONTEXT` prevalence records lag roughly one day, Mode A searches run over `[D-2 T00:00:00Z, D+1 T00:00:00Z)` while Stage 1 pins `timestamp.get_date(metadata.event_timestamp.seconds)` to the scored UTC day `D` (shifting the 30-day `metrics.*` anchor to `[D-32, D-2)`). Stage 2 acts as an inner-join filter: binaries with no Entity Graph record yet (Day-0 unindexed droppers) drop out rather than matching `rolling_max <= 3`, and when `first_seen_time = 0` (unset), the `<7d` novelty boost is disabled (`1.5x` isolated-binary multiplier applies instead; use `first_seen_novelty_2stage.yl2` for Day-0 unseen hashes).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution surges of rare Mach-O binaries on macOS endpoints (10-day org prevalence <= 3 hosts) against a mature 30-day per-host/hash execution baseline.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total, count floor max(sigma, sqrt(max(mu, 1.0))), active_days >= 7) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total)
// Mode A Entity Graph Freshness: run with startTime = D-2 T00:00:00Z, endTime = D+1 T00:00:00Z, and pin Stage 1 to scored UTC date D.
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    $sha256 = strings.coalesce(target.process.file.sha256, principal.process.file.sha256)
    principal.process.file.sha256 != ""
    $host != ""
    $sha256 != ""

  match:
    $host, $sha256 by 1d

  outcome:
    $observed_val = count(metadata.id)
    $sample_command = array_distinct(principal.process.command_line)
    $sample_path = array_distinct(principal.process.file.full_path)
    $distinct_users = count_distinct(principal.user.userid)
    $event_timestamp = max(metadata.event_timestamp.seconds)

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
}

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day File Prevalence & First Seen)
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

// Stage 3 (Root): Fuse Personal Outlier Z-Score with Enterprise Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  // Count dispersion floor: max(sigma, sqrt(max(mu, 1.0)))
  $floor_arg = if($mean_execs > 1.0, $mean_execs, 1.0)
  $dispersion_floor = math.sqrt($floor_arg)
  $safe_sd = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_sd

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)

  // Guard binary age against unset epoch-zero first_seen_time = 0
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)
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

---

### Scenario 2: macOS Info-Stealers (AMOS, Poseidon, Banshee) & Keychain / Browser Credential Harvesting

* **Curated Detection Operational Focus**: Matches known stealer command lines, `security` Keychain queries, and browser profile access.
* **How Multi-Stage UEBA Extends Coverage**: Screens unusually long, rare shell and `osascript` command lines (`LONG_STRING_SCREEN`, `score >= 5.5`, length $\ge 64$, fleet prevalence $\le 3$) in Wave 1 (`Query 2A`), then evaluates zero-inclusive hourly Poisson Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$ over $T = 24$ buckets) across Keychain, clipboard, and discovery utilities on `Query 2A`'s candidate endpoints in Wave 2 (`Query 2B`).

#### Query 2A: Long-String & Rare Command-Line Candidate Screen on macOS `osascript`, `zsh` & `bash` (`secops-statistical-hunter`)
Because YARA-L 2.0 has no per-character iteration primitive (true character-level Shannon entropy uses `SHANNON_ENTROPY_CHARACTER` with `scripts/micro_python_helpers.py shannon`), `Query 2A` runs the stateless **`LONG_STRING_SCREEN`** candidate filter across `osascript`, `zsh`, `bash`, `sh`, and `dash` command lines. It scores each distinct command line by combining log string length with within-host rarity: $\text{score} = \ln(\text{length}) + \ln\!\left(1 + \frac{\text{total\_events}}{\text{token\_count}}\right) \ge 5.5$, gated by minimum length $\ge 64$ characters and enterprise fleet prevalence $\le 3$ hosts.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long, rare JXA/AppleScript stealer payloads and ClickFix shell one-liners on macOS endpoints via stateless log-length and within-host token rarity.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH for osascript, zsh, bash, sh, dash on macOS)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN, score = ln(length) + ln(1 + total_events / token_count) >= 5.5; true per-character entropy uses SHANNON_ENTROPY_CHARACTER + micro_python_helpers.py shannon)
// ============================================================================

// Stage 1: Target Command-Line Extraction & String Length Observation per (entity, token)
stage token_observation {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    re.regex(target.process.file.full_path, `(?i)/(osascript|zsh|bash|sh|dash)$`)
    $token = target.process.command_line
    $token != ""

  match:
    $entity, $token by 1d

  outcome:
    $token_count = count(metadata.id)
    $token_length = max(strings.length($token))
}

// Stage 2: Host Bucket Shell/Script Event Volume
stage entity_baseline {
    $entity = $token_observation.entity
    $ws = $token_observation.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $total_events = sum($token_observation.token_count)
}

// Stage 3: Enterprise Fleet Prevalence of Each Distinct Command Line
stage cmd_fleet_prevalence {
    $token = $token_observation.token
    $ws = $token_observation.window_start

  match:
    $token, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($token_observation.entity)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring & 6 Evidence Pillars
$entity = $token_observation.entity
$entity = $entity_baseline.entity
$token = $token_observation.token
$token = $cmd_fleet_prevalence.token
$ws = $token_observation.window_start
$ws = $entity_baseline.ws
$ws = $cmd_fleet_prevalence.ws

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
  $rarity_lift = math.log(1.0 + (1.0 * $safe_total / $safe_tok))
  $shannon_entropy_score = $log_len + $rarity_lift

  // 6 Core Evidence Pillars
  $observation_count = $token_executions
  $baseline_active_samples = $total_activity
  $baseline_mean = $raw_length
  $baseline_dispersion = $log_len
  $fleet_prevalence = max($cmd_fleet_prevalence.fleet_hosts)
  $distinct_binaries = 1

condition:
  $raw_length >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 5.5

order:
  $shannon_entropy_score desc
```

#### Query 2B: 4-Stage UDM-Gated Zero-Inclusive Poisson Fano Burst Clustering on macOS Keychain & Discovery Utilities (`secops-statistical-hunter`)
Evaluates hourly macOS Keychain, clipboard, and system profiling bursts (`security`, `osascript`, `screencapture`, `pbpaste`, `dscl`, `system_profiler`, `ioreg`, `sqlite3`, `plutil`, `defaults`) strictly on candidate macOS endpoints surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`). Stage 2 and Stage 3 accumulate $\sum x$ and $\sum x^2$ across active `1h` buckets so Root reconstructs **zero-inclusive** mean $\mu = \frac{\sum x}{24}$, variance $\sigma^2 = \frac{\sum x^2}{24} - \mu^2$, and **Fano Factor** $F = \sigma^2 / \mu \ge 4.0$ over a 24-hour ($T = 24$) window—capturing single-hour automated stealer sweeps that active-only `stddev()` misses.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED ZERO-INCLUSIVE POISSON FANO BURST DISPERSION PIPELINE
// Goal: Detect macOS info-stealer and Keychain harvesting bursts on candidate endpoints from Query 2A via zero-inclusive hourly Fano Factor dispersion over a 24h window.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Zero-Inclusive Poisson Fano Factor (POISSON_BURST_CLUSTERING, F = sigma^2 / mu >= 4.0 over T = 24.0 hourly buckets)
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

stage hourly_bursts {
    metadata.event_type = "PROCESS_LAUNCH"
    re.regex(target.process.file.full_path, `(?i)/(security|osascript|screencapture|pbpaste|dscl|system_profiler|ioreg|sqlite3|plutil|defaults)$`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $event_count = count(metadata.id)
    $event_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.process.file.full_path)
}

stage host_dispersion {
    $host = $hourly_bursts.host

  match:
    $host

  outcome:
    $sum_x = sum($hourly_bursts.event_count)
    $sum_x2 = sum($hourly_bursts.event_count_sq)
    $peak_hourly = max($hourly_bursts.event_count)
    $active_hours = count($hourly_bursts.window_start)
    $max_distinct_targets = max($hourly_bursts.distinct_targets)
}

$host = $stage1_upstream_2a_candidates.host
$host = $host_dispersion.host

match:
  $host

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $sum_x = max($host_dispersion.sum_x)
  $sum_x2 = max($host_dispersion.sum_x2)
  $peak_burst = max($host_dispersion.peak_hourly)

  // Zero-inclusive hourly mean, variance, and Fano Factor over T = 24.0 buckets (24h window)
  $zero_incl_mean = 1.0 * $sum_x / 24.0
  $mean_sq = 1.0 * $sum_x2 / 24.0
  $raw_var = $mean_sq - ($zero_incl_mean * $zero_incl_mean)
  $zero_incl_var = if($raw_var > 0.0, $raw_var, 0.0)
  $zero_incl_sd = math.sqrt($zero_incl_var)
  $safe_mean = if($zero_incl_mean > 0.0, $zero_incl_mean, 1.0)
  $raw_fano = $zero_incl_var / $safe_mean
  $fano_factor = if($zero_incl_mean > 0.0, $raw_fano, 0.0)

  // 6 Core Evidence Pillars
  $observation_count = $sum_x
  $baseline_active_samples = max($host_dispersion.active_hours)
  $baseline_mean = $zero_incl_mean
  $baseline_dispersion = $zero_incl_sd
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_dispersion.max_distinct_targets)

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 10
  and $baseline_mean >= 0.1
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

---

### Scenario 3: macOS Persistence (`LaunchAgents`, `LaunchDaemons`, Cron & TCC)

* **Curated Detection Operational Focus**: Alerts on new plist files in Launch directories, scheduled tasks, and TCC database tampering.
* **How Multi-Stage UEBA Extends Coverage**: Combines a Two-Part Hurdle model (dormant awakening volume gate vs. leave-one-out intensity Z) with empirical host-prevalence Zipfian IDF rarity ($\ln(N_{\text{fleet}}/df) \ge 2.5$ on $\le 2$ hosts) to surface rare persistence modifications and low-prevalence persistent helpers.

#### Query 3: Unified Two-Part Host Hurdle & Zipfian Fleet Rarity on macOS Persistence (`secops-statistical-hunter`)
Evaluates macOS persistence process launches and plist/`TCC.db` file writes (`$host, $actor_bin by 1d`, with explicit per-domain conditional sums separating process launches from file creation/modification) across two regimes in one 5-stage pipeline:
1. **Dormant / First-Time Regime (`$baseline_active_samples <= 2`)**: Applies the Two-Part Hurdle awakening gate (`$observation_count >= 5`, scoring $3.0 \times (\text{obs} / 5.0)$) so isolated 1–4 event trickle noise is suppressed.
2. **Mature / Persistent Regime (`$baseline_active_samples > 2`)**: Takes the maximum of the positive-rectified leave-one-out (LOO) intensity Z-score (floored by $\sqrt{\max(\mu_{\text{LOO}}, 1.0)}$) and pure empirical host-prevalence inverse document frequency $\ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}})$ computed from active persistence hosts in the window (`$fleet_prevalence <= 2`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Unify dormant macOS persistence awakening (Two-Part Hurdle with volume gate >= 5) and fleet-rare persistent binary activity (empirical host-prevalence Zipfian IDF <= 2 hosts) in a single pipeline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH, FILE_CREATION, FILE_MODIFICATION on macOS)
// Statistical Model: Unified Two-Part Hurdle (TWO_PART_HURDLE) + Host-Prevalence Inverse Document Frequency Rarity (ZIPFIAN_PROCESS_RARITY, ln(N_fleet_hosts / N_adopter_hosts) >= 2.5)
// ============================================================================

// Stage 1: Daily macOS persistence utility, plist/TCC modification, and user/tmp/Library binary activity per (host, actor_bin)
stage daily_persistence_activity {
    (metadata.event_type = "PROCESS_LAUNCH" or metadata.event_type = "FILE_CREATION" or metadata.event_type = "FILE_MODIFICATION")
    principal.asset.hostname = $host
    $host != ""
    $actor_bin = principal.process.file.full_path
    $actor_bin != ""
    (re.regex(target.process.file.full_path, `(?i)/(launchctl|plutil|crontab)$`) or re.regex(target.process.command_line, `(?i)(LaunchAgents|LaunchDaemons|LoginHook|TCC\.db|launchctl\s+(bootstrap|load|enable|kickstart|submit))`) or re.regex(target.file.full_path, `(?i)(/Library/LaunchAgents/|/Library/LaunchDaemons/|/Library/Application Support/com\.apple\.TCC/TCC\.db|\.plist$)`) or re.regex(principal.process.file.full_path, `(?i)(/Users/|/Library/|/private/tmp/|/tmp/|/var/tmp/|/Volumes/|/opt/)`))

  match:
    $host, $actor_bin by 1d

  outcome:
    $daily_events = count(metadata.id)
    $daily_events_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $process_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $file_create_events = sum(if(metadata.event_type = "FILE_CREATION", 1, 0))
    $file_mod_events = sum(if(metadata.event_type = "FILE_MODIFICATION", 1, 0))
    $distinct_targets = count_distinct(target.file.full_path)
}

// Stage 2: Historical moment accumulation across active windows for Leave-One-Out Hurdle Intensity
stage persistence_hurdle_baseline {
    $host = $daily_persistence_activity.host
    $actor_bin = $daily_persistence_activity.actor_bin

  match:
    $host, $actor_bin

  outcome:
    $active_days = count($daily_persistence_activity.window_start)
    $sum_x = sum($daily_persistence_activity.daily_events)
    $sum_x2 = sum($daily_persistence_activity.daily_events_sq)
    $raw_n_prior = $active_days - 1
    $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
}

// Stage 3: Total active persistence host population per window for empirical IDF denominator
stage persistence_fleet_total {
    $ws = $daily_persistence_activity.window_start

  match:
    $ws by 1d

  outcome:
    $total_fleet_hosts = count_distinct($daily_persistence_activity.host)
}

// Stage 4: Enterprise adopter host count & empirical Zipfian IDF per actor binary and window
stage persistence_fleet_context {
    $actor_bin = $daily_persistence_activity.actor_bin
    $ws = $daily_persistence_activity.window_start
    $ws = $persistence_fleet_total.ws

  match:
    $actor_bin, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($daily_persistence_activity.host)
    $total_fleet_hosts = max($persistence_fleet_total.total_fleet_hosts)
    $safe_adopters = if($fleet_hosts > 0, $fleet_hosts, 1)
    $safe_fleet = if($total_fleet_hosts > $safe_adopters, $total_fleet_hosts, $safe_adopters)
    $zipf_rarity_score = math.log(1.0 * $safe_fleet / $safe_adopters)
}

// Root Stage: Unified Two-Part Hurdle & Empirical Host-Prevalence Zipfian Rarity
$host = $daily_persistence_activity.host
$actor_bin = $daily_persistence_activity.actor_bin
$host = $persistence_hurdle_baseline.host
$actor_bin = $persistence_hurdle_baseline.actor_bin
$actor_bin = $persistence_fleet_context.actor_bin
$ws = $daily_persistence_activity.window_start
$ws = $persistence_fleet_context.ws

match:
  $host, $actor_bin, $ws by 1d

outcome:
  // 6 Core Evidence Pillars (mean & dispersion populated from Leave-One-Out Hurdle moments below)
  $observation_count = max($daily_persistence_activity.daily_events)
  $baseline_active_samples = max($persistence_hurdle_baseline.active_days)
  $fleet_prevalence = max($persistence_fleet_context.fleet_hosts)
  $distinct_binaries = max($daily_persistence_activity.distinct_targets)

  // Branch A: Positive-Rectified Leave-One-Out Intensity Z & Volume-Gated Dormant Awakening
  $total_sum_x = max($persistence_hurdle_baseline.sum_x)
  $total_sum_x2 = max($persistence_hurdle_baseline.sum_x2)
  $n_prior = max($persistence_hurdle_baseline.n_prior)
  $baseline_mean = 1.0 * ($total_sum_x - $observation_count) / $n_prior
  $raw_loo_var = (($total_sum_x2 - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $raw_intensity_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $intensity_z = if($raw_intensity_z > 0.0, $raw_intensity_z, 0.0)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 5.0)
  $dormant_score = if($observation_count >= 5, $dormant_raw, 0.0)

  // Branch B: Pure Empirical Host-Prevalence IDF Rarity + Piecewise Regime Score
  $zipf_rarity_score = max($persistence_fleet_context.zipf_rarity_score)
  $mature_score = if($intensity_z > $zipf_rarity_score, $intensity_z, $zipf_rarity_score)
  $unified_threat_score = if($baseline_active_samples <= 2, $dormant_score, $mature_score)

condition:
  $observation_count >= 2
  and $fleet_prevalence <= 2
  and $unified_threat_score >= 2.5

order:
  $unified_threat_score desc
```

---

### Scenario 4: macOS C2 Callbacks, EtherHiding & Staged Archive Exfiltration

* **Curated Detection Operational Focus**: Flags known C2 domains and suspicious `curl` uploads of staged archives.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day behavioral baselines for outbound network bytes and total DNS queries ($D^2 = Z_{\text{bytes}}^2 + Z_{\text{dns}}^2 \ge 12.25$, $\ge 7$ active days) in Wave 1 (`Query 4A`), then screens candidate hosts for regular cross-bucket outbound flow-gap ratios ($\text{CV} = \sigma_{\text{gap}}/\mu_{\text{gap}} \le 0.20$) in Wave 2 (`Query 4B`).

#### Query 4A: 3-Stage Dual-Sector Host Outbound Network Bytes + DNS Queries Fusion (`secops-risk-metrics-multistage`)
Detects staged `.zip`/`.tar.gz`/`.dmg` exfiltration accompanied by DNS resolution surges on the same macOS host (`principal.asset.hostname`) by combining 30-day baselines for **Outbound Network Bytes** (`metrics.network_bytes_outbound`, stabilized with the fleet byte dispersion floor of `44979.0` bytes) and **Total DNS Queries** (`metrics.dns_queries_total`, stabilized with the count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$). Both sectors enforce the $\ge 7$ active-day maturity gate before contributing to the squared Euclidean threat norm ($D^2 = \max(0, Z_{\text{bytes}})^2 + \max(0, Z_{\text{dns}})^2 \ge 12.25$). Note that Stage 1 and Stage 2 inner-join on `$entity, $ws by 1d` (requiring non-zero outbound bytes and DNS activity on the scored UTC day), and because network egress and DNS resolution are positively correlated planes, joint tail rates exceed independent $\chi^2_2$ expectations.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect staged macOS archive exfiltration and C2 domain resolution surges by fusing 30-day outbound network byte anomalies with DNS query anomalies on the same host.
// ADVISORY: Coupled network planes (network_bytes_outbound + dns_queries_total) exhibit positive inter-sector correlation and exceed independent chi-square tail rates; inner join requires activity in both sectors on the scored UTC day.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (DUAL_SECTOR_FUSION_3STAGE, D^2 = Z_bytes_out^2 + Z_dns_total^2 >= 12.25, active_days >= 7)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A — Outbound Network Bytes (UDM Source 1 of 2) ---
stage sector_a {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(network.sent_bytes)
    $a_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

// --- STAGE 2: Sector B — Total DNS Queries (UDM Source 2 of 2) ---
stage sector_b {
    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
    $b_avg = max(metrics.dns_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.dns_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.dns_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
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

  // Sector A (Outbound Bytes): fleet byte dispersion floor = 44979.0 bytes, maturity >= 7 days
  $safe_a_std = if($a_stddev > 44979.0, $a_stddev, 44979.0)
  $z_a_raw = ($a_observed - $a_mean) / $safe_a_std
  $z_a_pos = if($z_a_raw > 0.0, $z_a_raw, 0.0)
  $z_a = if($a_active_days >= 7, $z_a_pos, 0.0)

  // Sector B (DNS Queries): count dispersion floor = max(sigma, sqrt(max(mu, 1.0))), maturity >= 7 days
  $b_floor_arg = if($b_mean > 1.0, $b_mean, 1.0)
  $b_floor = math.sqrt($b_floor_arg)
  $safe_b_std = if($b_stddev > $b_floor, $b_stddev, $b_floor)
  $z_b_raw = ($b_observed - $b_mean) / $safe_b_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_active_days >= 7, $z_b_pos, 0.0)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $composite_threat_norm_sq = ($z_a * $z_a) + ($z_b * $z_b)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 4B: 4-Stage UDM-Gated Cross-Bucket Flow-Gap Ratio Screen on macOS Outbound Callbacks (`secops-statistical-hunter`)
Because stateless bucketed YARA-L cannot sort individual packet timestamps to compute consecutive inter-arrival $\Delta t$ intervals (true consecutive inter-arrival jitter uses `C2_BEACONING_JITTER` with `scripts/micro_python_helpers.py c2-jitter`), `Query 4B` runs **`FLOW_GAP_RATIO_SCREEN`** strictly on candidate macOS endpoints surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`). Stage 2 measures the within-hour span-to-count flow-gap ratio $\frac{\max(t) - \min(t)}{\text{count}}$ per external `(host, target_ip)` pair (excluding RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local space), and Root flags persistent pairs whose cross-bucket flow-gap ratio Coefficient of Variation satisfies $\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$ across $\ge 6$ active hours and $\ge 25$ outbound connections.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED CROSS-BUCKET FLOW-GAP RATIO DISPERSION PIPELINE
// Goal: Screen persistent external outbound callback pairs with uniform hourly flow-gap ratios (CV <= 0.20) on candidate macOS hosts surfaced by Query 4A.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN, CV = sigma_gap / mu_gap <= 0.20; true consecutive inter-arrival jitter uses C2_BEACONING_JITTER + micro_python_helpers.py c2-jitter)
// ============================================================================

stage stage1_upstream_4a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_4a_z = max(security_result.confidence_score)
}

stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 64
    target.ip = $target_ip
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    $target_ip != ""
    $target_ip != "::1"
    // Exclude internal RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local destinations
    not net.ip_in_range_cidr($target_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($target_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($target_ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($target_ip, "127.0.0.0/8")
    not net.ip_in_range_cidr($target_ip, "224.0.0.0/4")
    not net.ip_in_range_cidr($target_ip, "169.254.0.0/16")
    not net.ip_in_range_cidr($target_ip, "255.255.255.255/32")
    not net.ip_in_range_cidr($target_ip, "fe80::/10")
    not net.ip_in_range_cidr($target_ip, "ff00::/8")
    $ts = metadata.event_timestamp.seconds

  match:
    $host, $target_ip by 1h

  outcome:
    $conn_count = count(metadata.id)
    $avg_gap = 1.0 * (max($ts) - min($ts)) / count(metadata.id)
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

$host = $stage1_upstream_4a_candidates.host
$host = $timing_stats.host
$target_ip = $timing_stats.target_ip

match:
  $host, $target_ip

outcome:
  $upstream_z = max($stage1_upstream_4a_candidates.upstream_4a_z)
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($timing_stats.total_conns)
  $total_outbound_bytes = max($timing_stats.total_sent_bytes)

  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $baseline_mean >= 1.0
  and $cv <= 0.20

order:
  $cv asc
```

---

### Scenario 5: Capstone Multi-Scenario macOS Endpoint Convergence via Native UDM Loopback (`Option 3` Connective Tissue)

* **Curated Detection Operational Focus**: Single-event macOS detections evaluated in isolation.
* **How Multi-Stage UEBA Extends Coverage**: Correlates macOS entities triggering $\ge 2$ distinct behavioral queries within the current run (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$) while joining raw forensic telemetry in the same query.

Individual behavioral queries in Scenarios 1–4 can fire inside ambiguous operational overlap regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names. **Scenario 5 (`Query 5`)** executes in **Wave 3** after all **Wave 1** and **Wave 2** queries have exported their findings into Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 4 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct query tags (`$distinct_scenarios_matched >= 2`, `LOOPBACK_MIN_DISTINCT_HITS`) and summing their squared Z-equivalent scores (`$capstone_threat_norm_sq >= 25.0`, `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Separates raw process, network, and cloud/auth event counts via conditional sums per `$entity` and joins them with Stage 2 in Root to return the Euclidean $L_2$ norm (`$capstone_threat_score = math.sqrt($capstone_threat_norm_sq)`) alongside concrete process paths and resource names.

#### Query 5: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 macOS Threats scenarios (1A through 4B) via UDM Loopback regex token union while joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
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
    $process_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $network_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $cloud_auth_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS" or metadata.event_type = "USER_LOGIN", 1, 0))
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
  $capstone_threat_norm_sq = max($stage2_multi_scenario_rollup.capstone_threat_norm_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $cloud_auth_events = max($stage3_raw_forensic_pivot.cloud_auth_events)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

  // 6 Core Evidence Pillars
  $observation_count = $total_loopback_matches
  $baseline_active_samples = $distinct_scenarios_matched
  $baseline_mean = $peak_scenario_z
  $baseline_dispersion = $capstone_threat_score
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($stage3_raw_forensic_pivot.distinct_event_types)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_score desc
```

---

## 3. macOS Staged Archive Exfiltration via Empirical Quantile Envelope & Skewness-Adjusted Tukey Fence

Developer macOS endpoints routinely transfer large Xcode and container artifacts that right-skew their daily outbound byte distribution ($B_{\text{skew}} > 0.25$). Following `quantile_iqr_skew_3stage.yl2` (`QUANTILE_IQR_SKEW`), this pipeline computes the 5-point empirical quantile envelope (`$p10, $q25, $q50, $q75, $p90`) via `window.percentile` over a multi-day raw window (`14d–30d`, with `$in_scoring_window` gating scored days from `"2026-10-29"` onward), derives Bowley quartile skewness and the recalibrated Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence ($Q_3 + 1.5 \cdot \exp(1.35 \cdot \max(0, B_{\text{skew}})) \cdot \text{IQR}_{\text{safe}}$), and ranks hosts by robust scale-excess units (`$tukey_excess_z >= 1.0`, normalized by $\text{IQR}_{\text{safe}} / 1.349$) alongside a pre-scoring active-day Z cross-check (`44979.0` byte dispersion floor):

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect staged macOS archive exfiltration on right-skewed developer endpoints via 5-point empirical quantiles (window.percentile), Bowley quartile skewness, and the Hubert-Vandervieren Skewness-Adjusted Tukey Upper Fence.
// Statistical Model: Non-Parametric Quantile Envelope & Recalibrated Bowley Skewness-Adjusted Tukey Scale-Excess (QUANTILE_IQR_SKEW, tukey_excess_z >= 1.0, raw_active_days >= 7)
// Skill: secops-risk-metrics-multistage
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-29", 1, 0))
    $observed_events = count(metadata.id)
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

stage stage1_prescoring {
    $entity = $stage1_extract.entity
    $ws = $stage1_extract.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $observed_val = max($stage1_extract.observed_val)
    $in_scoring_window = max($stage1_extract.in_scoring_window)
    $historical_active_days = max($stage1_extract.historical_active_days)
    $obs_float = 1.0 * $observed_val
    $pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)
    $pre_obs_sq = $pre_obs * $pre_obs
    $pre_day = if($in_scoring_window = 0, 1, 0)
}

stage quantile_envelope {
    $entity = $stage1_prescoring.entity

  match:
    $entity

  outcome:
    $p10 = window.percentile($stage1_prescoring.observed_val, 10)
    $q25 = window.percentile($stage1_prescoring.observed_val, 25)
    $q50 = window.percentile($stage1_prescoring.observed_val, 50)
    $q75 = window.percentile($stage1_prescoring.observed_val, 75)
    $p90 = window.percentile($stage1_prescoring.observed_val, 90)
    $p90_p10_span = $p90 - $p10
    $raw_active_days = count_distinct($stage1_prescoring.ws)
    $pre_n = sum($stage1_prescoring.pre_day)
    $pre_sum = sum($stage1_prescoring.pre_obs)
    $pre_sum_sq = sum($stage1_prescoring.pre_obs_sq)
    $historical_active_days = max($stage1_prescoring.historical_active_days)
    $safe_pre_n = if($pre_n > 0, $pre_n, 1.0)
    $pre_avg = $pre_sum / $safe_pre_n
    $pre_df_raw = $pre_n - 1.0
    $safe_pre_df = if($pre_n > 1, $pre_df_raw, 1.0)
    $raw_var_num = $pre_sum_sq - ($pre_n * $pre_avg * $pre_avg)
    $pos_var_num = if($raw_var_num > 0.0, $raw_var_num, 0.0)
    $pre_sd = math.sqrt($pos_var_num / $safe_pre_df)
    $safe_pre_sd = if($pre_sd > 44979.0, $pre_sd, 44979.0)
}

$entity = $stage1_prescoring.entity
$entity = $quantile_envelope.entity
$ws = $stage1_prescoring.ws

match:
  $entity, $ws by 1d

outcome:
  $observed = max($stage1_prescoring.observed_val)
  $hist_avg = max($quantile_envelope.pre_avg)
  $safe_stddev = max($quantile_envelope.safe_pre_sd)
  $active_days = max($quantile_envelope.pre_n)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $p90_p10_span = max($quantile_envelope.p90_p10_span)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_prescoring.in_scoring_window)

  // 1. Pre-scoring raw active-day Z cross-check (byte dispersion floor = 44979.0)
  $raw_personal_z = ($observed - $hist_avg) / $safe_stddev
  $personal_z = if($active_days >= 7, $raw_personal_z, 0.0)

  // 2. Non-Parametric IQR, Bowley Quartile Skewness & Moors Tail-Heaviness Ratio
  $iqr = $q75_val - $q25_val
  $q50_floor = $q50_val * 0.05 + 1.0
  $safe_iqr = if($iqr > 0.0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $tail_heaviness = $p90_p10_span / $safe_iqr

  // 3. Hubert-Vandervieren Skewness-Adjusted Tukey Upper Fence (Bowley 1.35) & Robust Scale-Excess
  $pos_skew = if($bowley_skew > 0.0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
  $tukey_excess_z = ($observed - $adj_upper_fence) / ($safe_iqr / 1.349)

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0

order:
  $tukey_excess_z desc
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
