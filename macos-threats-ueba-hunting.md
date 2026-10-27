# Hunting macOS Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **macOS Threats** curated detection suite provides real-time coverage for macOS endpoints—including Gatekeeper bypasses (`xattr -d com.apple.quarantine`), AppleScript (`osascript`) execution chains, macOS info-stealers (AMOS, Poseidon, Banshee), Keychain and browser credential access, and `LaunchAgent`/`LaunchDaemon` persistence.

Because macOS adversaries rapidly rotate script wrappers, DMG/PKG installers, and stealer variants, this playbook extends curated detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). The queries below model parent-to-child process lineage surprisal, 10-day binary prevalence, Fano burst clustering across credential-access utilities, command-line entropy, and outbound exfiltration anomalies.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 5`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-4]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — macOS Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Gatekeeper Bypass, Unsigned Installers & Interactive Script Chains** | Detects quarantine attribute removal (`xattr`), suspicious disk image mounts, and terminal/browser `osascript` execution. | Calculates Markov 2-gram parent-to-child process transition surprisal ($I = -\ln P(\text{Child}\mid\text{Parent}) \ge 3.5$) and combines 30-day file execution baselines with 10-day `DERIVED_CONTEXT` binary prevalence. | `Query 1A` (Markov 2-Gram Surprisal)<br>`Query 1B` (30d Execution + 10d Prevalence) |
| **2. macOS Info-Stealers & Keychain / Browser Credential Harvesting** | Matches known stealer command lines, `security` Keychain queries, and browser profile access. | Detects rapid automated collection bursts across Keychain, system profiling, and archiving utilities via Poisson Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$) and Shannon command-line entropy ($H(X) \ge 3.8$). | `Query 2A` (Poisson Fano Burst)<br>`Query 2B` (Shannon Command-Line Entropy) |
| **3. macOS Persistence (`LaunchAgents`, `LaunchDaemons`, Cron & TCC)** | Alerts on new plist files in Launch directories, scheduled tasks, and TCC database tampering. | Combines Zipfian fleet rarity ($I = \ln(N/df) \ge 3.2$) with a Two-Part Zero-Inflated Hurdle model to surface rare persistence modifications on developer and corporate macOS workstations. | `Query 3A` (Zipfian Persistence Rarity)<br>`Query 3B` (Two-Part Persistence Hurdle) |
| **4. Covert C2 Beaconing & Staged Archive Exfiltration** | Flags known C2 domains and suspicious `curl` uploads of staged archives. | Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and inter-arrival C2 callback jitter ($\text{CV} \le 0.20$). | `Query 4A` (Piecewise 30d Egress + Inversion)<br>`Query 4B` (C2 Jitter CV) |
| **5. Capstone Multi-Scenario macOS Host Convergence** | Single-event macOS detections evaluated in isolation. | Correlates macOS hosts triggering $\ge 2$ distinct behavioral scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Gatekeeper Bypass, Unsigned DMG/PKG Execution & AppleScript ClickFix Chains

* **Curated Detection Operational Focus**: Detects quarantine attribute removal (`xattr`), suspicious disk image mounts, and terminal/browser `osascript` execution.
* **How Multi-Stage UEBA Extends Coverage**: Calculates Markov 2-gram parent-to-child process transition surprisal ($I = -\ln P(\text{Child}\mid\text{Parent}) \ge 3.5$) and combines 30-day file execution baselines with 10-day `DERIVED_CONTEXT` binary prevalence.

#### Query 1A: Markov 2-Gram Parent-to-Child Process Transition Surprisal on macOS Execution Chains (`secops-statistical-hunter`)
Compensates for brittle filename prefixes (`com.apple.*`), same-PID joins, and flag-bundle regexes by modeling **Markov 2-Gram conditional transition probabilities** $P(\text{Child} \mid \text{Parent})$ and **Information Surprisal** $I = -\ln P(\text{Child} \mid \text{Parent}) \ge 3.0$ across macOS user-facing applications (`Terminal`, `iTerm2`, `Finder`, `Safari`, `Google Chrome`, `Firefox`, `Arc`), script runners (`osascript`, `node`, `bun`), and staging paths (`/Volumes/`, `/tmp/`, `Downloads`, `Application Support`) spawning shells and post-exploitation utilities (`sh`, `zsh`, `bash`, `curl`, `xattr`, `hdiutil`, `screencapture`, `security`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions on macOS endpoints (Terminal, Finder, browsers, osascript, or mounted DMGs spawning shells, xattr, curl, or security) via Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on macOS endpoints)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln(P(Child | Parent)) >= 3.0)
// ============================================================================

// Stage 1: Parent Process Launch Baseline Frequency per macOS host
stage parent_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""
    re.regex($parent, `(?i)(Terminal|iTerm|Finder|Safari|Chrome|Firefox|Brave|Arc|osascript|/Volumes/|/tmp/|/Downloads/|/Users/Shared/|/Library/Application Support/)`)

  match:
    $host, $parent by 1d

  outcome:
    $parent_total_launches = count(metadata.id)
}

// Stage 2: Child Process Transition Frequency per (host, parent, child)
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex($parent, `(?i)(Terminal|iTerm|Finder|Safari|Chrome|Firefox|Brave|Arc|osascript|/Volumes/|/tmp/|/Downloads/|/Users/Shared/|/Library/Application Support/)`)
    re.regex($child, `(?i)/(sh|zsh|bash|dash|osascript|curl|xattr|hdiutil|screencapture|security|sqlite3|python3|nohup|xxd)$`)

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

#### Query 1B: 2-Stage Hybrid 30-Day File Execution Baseline + 10-Day Entity Context Graph File Prevalence (`secops-risk-metrics-multistage`)
Catches ad-hoc signed, unsigned, or quarantine-stripped Mach-O droppers (`BigMacho`, `KiteSurfer`, `PlotTwist`, AMOS, Poseidon) regardless of their directory name by scoring per-(host, SHA256) process executions against a 30-day behavioral baseline (`metrics.file_executions_total`) enriched with `DERIVED_CONTEXT` **10-day organizational file prevalence** (`rolling_max <= 3` hosts across the enterprise).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution of rare or newly dropped Mach-O binaries on macOS endpoints (10-day org prevalence <= 3 hosts) with anomalous per-host execution frequency.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: macOS Endpoint Process Execution + 30-Day Composite Baseline per (host, event_type, sha256)
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

### Scenario 2: macOS Info-Stealers (AMOS, Poseidon, Banshee) & Keychain / Browser Credential Harvesting

* **Curated Detection Operational Focus**: Matches known stealer command lines, `security` Keychain queries, and browser profile access.
* **How Multi-Stage UEBA Extends Coverage**: Detects rapid automated collection bursts across Keychain, system profiling, and archiving utilities via Poisson Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$) and Shannon command-line entropy ($H(X) \ge 3.8$).

#### Query 2A: Multi-Class Character Shannon Entropy ($H(X) \ge 3.8$) on macOS `osascript`, `zsh` & `bash` Command Lines (`secops-statistical-hunter`)
Compensates for the `> 5` `do shell script` cutoff and signature-specific deobfuscation rules by calculating **4-Class Character Distribution Shannon Entropy** ($H(X) = -\sum p_i \log_2 p_i$) across lowercase letters, uppercase letters, digits, and punctuation/operators on macOS `osascript`, `zsh`, `bash`, and `sh` command lines (`strings.length($cmd) >= 64`) that are rare across the fleet (`$fleet_prevalence <= 3`). Obfuscated JXA/AppleScript stealers, inline Base64/Hex `xxd` loaders, and character-code arrays drive `$shannon_entropy_score >= 3.8`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect obfuscated JXA/AppleScript stealer payloads, Base64/Hex command pipelines, and ClickFix shell one-liners on macOS via Multi-Class Character Shannon Entropy.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH for osascript, zsh, bash, sh on macOS)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)) >= 3.8)
// ============================================================================

// Stage 1: Extract command-line lengths and 4-class character counts per (host, cmd)
stage cmd_feature_extraction {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    re.regex(target.process.file.full_path, `(?i)/(osascript|zsh|bash|sh|dash)$`)
    $cmd = target.process.command_line
    $cmd != ""
    strings.length($cmd) >= 64

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

// Stage 2: Enterprise fleet prevalence of each distinct command line across macOS hosts
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

#### Query 2B: 4-Stage UDM-Gated Poisson Fano Factor Burst Clustering on macOS Keychain & Discovery Utilities (`secops-statistical-hunter`)
Evaluates hourly macOS Keychain, clipboard, and system discovery bursts ($F = \sigma^2 / \mu \ge 4.0$) strictly on candidate macOS endpoints surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED POISSON FANO FACTOR BURST DISPERSION PIPELINE
// Goal: Detect macOS info-stealer and Keychain harvesting bursts on candidate endpoints from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson Index of Dispersion (Fano Factor F = sigma^2 / mu >= 4.0)
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
    $distinct_targets = count_distinct(target.process.file.full_path)
}

stage host_dispersion {
    $host = $hourly_bursts.host

  match:
    $host

  outcome:
    $mean_hourly = avg($hourly_bursts.event_count)
    $stddev_hourly = stddev($hourly_bursts.event_count)
    $peak_hourly = max($hourly_bursts.event_count)
    $total_events = sum($hourly_bursts.event_count)
    $active_hours = count($hourly_bursts.window_start)
    $max_distinct_targets = max($hourly_bursts.distinct_targets)
}

$host = $stage1_upstream_2a_candidates.host
$host = $host_dispersion.host

match:
  $host

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $observation_count = max($host_dispersion.total_events)
  $baseline_active_samples = max($host_dispersion.active_hours)
  $baseline_mean = max($host_dispersion.mean_hourly)
  $baseline_dispersion = max($host_dispersion.stddev_hourly)
  $fleet_prevalence = 1
  $distinct_binaries = max($host_dispersion.max_distinct_targets)
  $peak_burst = max($host_dispersion.peak_hourly)

  $variance = $baseline_dispersion * $baseline_dispersion
  $safe_mean = if($baseline_mean > 0, $baseline_mean, 1.0)
  $fano_factor = $variance / $safe_mean
  $z_score = $fano_factor

condition:
  $baseline_active_samples >= 2
  and $peak_burst >= 5
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

---

---

### Scenario 3: macOS Persistence

* **Curated Detection Operational Focus**: Alerts on new plist files in Launch directories, scheduled tasks, and TCC database tampering.
* **How Multi-Stage UEBA Extends Coverage**: Combines Zipfian fleet rarity ($I = \ln(N/df) \ge 3.2$) with a Two-Part Zero-Inflated Hurdle model to surface rare persistence modifications on developer and corporate macOS workstations.

#### Query 3: Unified Two-Part Host Hurdle & Zipfian Fleet Rarity on macOS Persistence (`secops-statistical-hunter`)
Because both the **Two-Part Zero-Inflated Hurdle Model** (catching first-time or dormant processes modifying `LaunchAgents`, `LaunchDaemons`, `launchctl`, `plutil`, `crontab`, or `TCC.db`) and **Zipfian Power-Law Fleet Rarity** (catching persistent Mach-O implants and hidden helpers executing on $\le 2$ MacBooks across the fleet) operate on the same macOS endpoint execution and persistence telemetry stream (`$host, $actor_bin by 1d`), this **Option 1 Unified Pipeline** evaluates both regimes inside a single 4-stage DAG (`$unified_threat_score = if($baseline_active_samples <= 2, $hurdle_threat_score, $zipf_rarity_score)`):

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Unify first-time/dormant macOS persistence modification (Two-Part Hurdle) and fleet-rare persistent Mach-O execution (Zipfian IDF Rarity <= 2 hosts) in a single 4-stage pipeline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH, FILE_CREATION, FILE_MODIFICATION on macOS)
// Statistical Model: Option 1 Piecewise Two-Part Zero-Inflated Hurdle + Zipf-Mandelbrot Inverse Host Frequency (IDF) Surprisal
// ============================================================================

// Stage 1: Daily macOS persistence utility, plist/TCC modification, and user/tmp/Library binary activity per (host, actor_bin)
stage daily_persistence_activity {
    (
      metadata.event_type = "PROCESS_LAUNCH"
      or metadata.event_type = "FILE_CREATION"
      or metadata.event_type = "FILE_MODIFICATION"
    )
    principal.asset.hostname = $host
    $host != ""
    $actor_bin = principal.process.file.full_path
    $actor_bin != ""
    (
      re.regex(target.process.file.full_path, `(?i)/(launchctl|plutil|crontab)$`)
      or re.regex(target.process.command_line, `(?i)(LaunchAgents|LaunchDaemons|LoginHook|TCC\.db|launchctl\s+(bootstrap|load|enable|kickstart|submit))`)
      or re.regex(target.file.full_path, `(?i)(/Library/LaunchAgents/|/Library/LaunchDaemons/|/Library/Application Support/com\.apple\.TCC/TCC\.db|\.plist$)`)
      or re.regex($actor_bin, `(?i)(/Users/|/Library/|/private/tmp/|/tmp/|/var/tmp/|/Volumes/|/opt/)`)
    )

  match:
    $host, $actor_bin by 1d

  outcome:
    $daily_events = count(metadata.id)
    $distinct_targets = count_distinct(target.file.full_path)
}

// Stage 2: Historical presence (Part 1 Hurdle) and positive-activity baseline (Part 2 Intensity)
stage persistence_hurdle_baseline {
    $host = $daily_persistence_activity.host
    $actor_bin = $daily_persistence_activity.actor_bin

  match:
    $host, $actor_bin

  outcome:
    $active_days = count($daily_persistence_activity.window_start)
    $pos_mean = avg($daily_persistence_activity.daily_events)
    $pos_stddev = stddev($daily_persistence_activity.daily_events)
    $total_events = sum($daily_persistence_activity.daily_events)
}

// Stage 3: Enterprise fleet prevalence of the actor binary per window (Zipfian adopter breadth)
stage persistence_fleet_context {
    $actor_bin = $daily_persistence_activity.actor_bin
    $ws = $daily_persistence_activity.window_start

  match:
    $actor_bin, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($daily_persistence_activity.host)
}

// Root Stage: Option 1 Unified Two-Part Hurdle & Zipfian Fleet Rarity Scoring
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
  // 6 Core Evidence Pillars
  $observation_count = max($daily_persistence_activity.daily_events)
  $baseline_active_samples = max($persistence_hurdle_baseline.active_days)
  $baseline_mean = max($persistence_hurdle_baseline.pos_mean)
  $baseline_dispersion = max($persistence_hurdle_baseline.pos_stddev)
  $fleet_prevalence = max($persistence_fleet_context.fleet_hosts)
  $distinct_binaries = max($daily_persistence_activity.distinct_targets)

  // Branch A: Two-Part Hurdle Threat Score (Cold-Start / Dormant Persistence Modification <= 2 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 2, 3.0, 1.0)
  $safe_sd = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = ($observation_count - $baseline_mean) / $safe_sd
  $pos_intensity_z = if($intensity_z > 0, $intensity_z, 1.5)
  $hurdle_threat_score = $pos_intensity_z * $hurdle_rarity_boost

  // Branch B: Zipfian Fleet Rarity Score (Persistent Implant in Enterprise Tail <= 2 hosts)
  $safe_adopters = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $idf_surprisal = math.log(50.0) - math.log($safe_adopters)
  $local_intensity = math.log($observation_count + 1)
  $singleton_boost = if($fleet_prevalence = 1, 1.5, 1.0)
  $zipf_rarity_score = ($idf_surprisal + $local_intensity) * $singleton_boost

  // Option 1 Piecewise Regime Switch
  $unified_threat_score = if($baseline_active_samples <= 2, $hurdle_threat_score, $zipf_rarity_score)

condition:
  $observation_count >= 2
  and $fleet_prevalence <= 3
  and $unified_threat_score >= 3.5

order:
  $unified_threat_score desc
```

---

---

### Scenario 4: macOS C2 Beaconing, EtherHiding & Staged Archive Exfiltration

* **Curated Detection Operational Focus**: Flags known C2 domains and suspicious `curl` uploads of staged archives.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and inter-arrival C2 callback jitter ($\text{CV} \le 0.20$).

#### Query 4A: 3-Stage Dual-Sector Host Outbound Network Bytes + DNS Queries Fusion (`secops-risk-metrics-multistage`)
Catches staged `.zip`/`.tar.gz`/`.dmg` exfiltration and C2 domain resolution surges across any protocol or binary (`curl`, `python3`, `node`, `bun`, `SSFileCopyReceiver`, or native Mach-O stealers) by fusing 30-day behavioral baselines for **Outbound Network Bytes** (`metrics.network_bytes_outbound`) and **Total DNS Queries** (`metrics.dns_queries_total`) on the same macOS endpoint via the **Euclidean Vector Threat Norm** ($D^2 = Z_{\text{bytes}}^2 + Z_{\text{dns}}^2 \ge 12.25$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect staged macOS archive exfiltration and C2 domain resolution surges by fusing 30-day outbound network byte anomalies with DNS query anomalies on the same host.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D^2 = Z_bytes_out^2 + Z_dns_total^2 >= 12.25)
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

#### Query 4B: 4-Stage UDM-Gated Inter-Arrival Jitter Coefficient of Variation on macOS Outbound C2 Callbacks (`secops-statistical-hunter`)
Evaluates hourly outbound C2 callback inter-arrival pacing ($\text{CV} = \sigma / \mu \le 0.25$) strictly on candidate macOS endpoints surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED INTER-ARRIVAL JITTER COEFFICIENT OF VARIATION PIPELINE
// Goal: Detect Poseidon, Mythic, Sliver, and custom macOS C2 beaconing (CV <= 0.25) on candidate hosts from Query 4A (strictly gated by Query 4A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Coefficient of Variation (CV = sigma / mu <= 0.25)
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

### Scenario 5: Capstone Multi-Scenario macOS Endpoint Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Single-event macOS detections evaluated in isolation.
* **How Multi-Stage UEBA Extends Coverage**: Correlates macOS hosts triggering $\ge 2$ distinct behavioral scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

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
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 4 macOS Threats scenarios (1 through 4B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
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
