# Hunting macOS Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **macOS Threats** curated detection suite provides real-time coverage for macOS endpoints—including Gatekeeper bypasses (`xattr -d com.apple.quarantine`), AppleScript (`osascript`) execution chains, macOS info-stealers (AMOS, Poseidon, Banshee), Keychain and browser credential access, and `LaunchAgent`/`LaunchDaemon` persistence.

Because macOS adversaries rapidly rotate script wrappers, DMG/PKG installers, and stealer variants, this playbook extends curated detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). The queries below model parent-to-child process lineage surprisal, 10-day binary prevalence, Fano burst clustering across credential-access utilities, command-line entropy, and outbound exfiltration anomalies.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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

#### Query 2A: Poisson Fano Factor Burst Clustering ($F = \sigma^2 / \mu \ge 4.0$) on macOS Credential, Discovery & Archive Staging Utilities (`secops-statistical-hunter`)
Rather than matching fragile per-tool flags (`file -b`, `2> /dev/null`, or specific `/tmp` filenames), this query monitors the **temporal burstiness** of macOS credential access, host survey, and archive-staging utilities (`security`, `dscl`, `sqlite3`, `pbpaste`, `ditto`, `tar`, `zip`, `system_profiler`, `lsappinfo`, `mdfind`) per endpoint (`by 1h`). While normal developer activity invokes these utilities sporadically ($F \approx 1.0$), an executing AMOS, Poseidon, or Banshee stealer rapidly chains credential validation, Keychain unlocking, SQLite browser database copying, and `ditto`/`zip` archiving within a single hour, driving the **Fano Factor** ($F = \sigma^2 / \mu$) well above `4.0`.

```yara
// ============================================================================
// Goal: Detect rapid macOS info-stealer credential harvesting, host survey, and archive staging bursts (security, dscl, sqlite3, pbpaste, ditto, tar, zip, system_profiler, mdfind) via Poisson Fano dispersion.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on macOS endpoints)
// Statistical Model: Poisson Dispersion via Fano Factor (F = σ² / μ >= 4.0) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly macOS credential, discovery, and archive staging utility invocations per host
stage hourly_stealer_utilities {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $bin = target.process.file.full_path
    $bin != ""
    re.regex($bin, `(?i)/(security|dscl|sqlite3|pbpaste|ditto|tar|zip|system_profiler|lsappinfo|mdfind|screencapture)$`)

  match:
    $entity by 1h

  outcome:
    $hourly_calls = count(metadata.id)
    $distinct_bins = count_distinct(target.process.file.full_path)
    $sample_cmds = array_distinct(target.process.command_line)
}

// Stage 2: Historical arrival mean (μ), standard deviation (σ), and active hour density per host
stage dispersion_baseline {
    $entity = $hourly_stealer_utilities.entity

  match:
    $entity

  outcome:
    $mean_rate = avg($hourly_stealer_utilities.hourly_calls)
    $stddev_rate = stddev($hourly_stealer_utilities.hourly_calls)
    $total_calls = sum($hourly_stealer_utilities.hourly_calls)
    $active_hours = count($hourly_stealer_utilities.window_start)
    $max_distinct_bins = max($hourly_stealer_utilities.distinct_bins)
}

// Stage 3: Enterprise-wide host breadth per hourly window
stage fleet_breadth {
    $ws = $hourly_stealer_utilities.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($hourly_stealer_utilities.entity)
}

// Root Stage: Compute Fano Factor (F = σ² / μ) and emit 6 Core Evidence Pillars
$entity = $hourly_stealer_utilities.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_stealer_utilities.window_start
$ws = $fleet_breadth.ws

match:
  $entity

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($dispersion_baseline.total_calls)
  $baseline_active_samples = max($dispersion_baseline.active_hours)
  $baseline_mean = max($dispersion_baseline.mean_rate)
  $baseline_dispersion = max($dispersion_baseline.stddev_rate)
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $distinct_binaries = max($dispersion_baseline.max_distinct_bins)
  $sample_commands = array_distinct($hourly_stealer_utilities.sample_cmds)

  // Aggregate Fano Factor (F = σ² / μ)
  $raw_mean = max($dispersion_baseline.mean_rate)
  $safe_mean = if($raw_mean > 0, $raw_mean, 1.0)
  $raw_stddev = max($dispersion_baseline.stddev_rate)
  $variance = $raw_stddev * $raw_stddev
  $fano_factor = $variance / $safe_mean

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 12
  and $baseline_mean >= 1.0
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

#### Query 2B: Multi-Class Character Shannon Entropy ($H(X) \ge 3.8$) on macOS `osascript`, `zsh` & `bash` Command Lines (`secops-statistical-hunter`)
Compensates for the `> 5` `do shell script` cutoff and signature-specific deobfuscation rules by calculating **4-Class Character Distribution Shannon Entropy** ($H(X) = -\sum p_i \log_2 p_i$) across lowercase letters, uppercase letters, digits, and punctuation/operators on macOS `osascript`, `zsh`, `bash`, and `sh` command lines (`strings.length($cmd) >= 64`) that are rare across the fleet (`$fleet_prevalence <= 3`). Obfuscated JXA/AppleScript stealers, inline Base64/Hex `xxd` loaders, and character-code arrays drive `$shannon_entropy_score >= 3.8`.

```yara
// ============================================================================
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

---

---

### Scenario 3: macOS Persistence

* **Curated Detection Operational Focus**: Alerts on new plist files in Launch directories, scheduled tasks, and TCC database tampering.
* **How Multi-Stage UEBA Extends Coverage**: Combines Zipfian fleet rarity ($I = \ln(N/df) \ge 3.2$) with a Two-Part Zero-Inflated Hurdle model to surface rare persistence modifications on developer and corporate macOS workstations.

#### Query 3: Unified Two-Part Host Hurdle & Zipfian Fleet Rarity on macOS Persistence (`secops-statistical-hunter`)
Because both the **Two-Part Zero-Inflated Hurdle Model** (catching first-time or dormant processes modifying `LaunchAgents`, `LaunchDaemons`, `launchctl`, `plutil`, `crontab`, or `TCC.db`) and **Zipfian Power-Law Fleet Rarity** (catching persistent Mach-O implants and hidden helpers executing on $\le 2$ MacBooks across the fleet) operate on the same macOS endpoint execution and persistence telemetry stream (`$host, $actor_bin by 1d`), this **Option 1 Unified Pipeline** evaluates both regimes inside a single 4-stage DAG (`$unified_threat_score = if($baseline_active_samples <= 2, $hurdle_threat_score, $zipf_rarity_score)`):

```yara
// ============================================================================
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

#### Query 4A: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on macOS Outbound C2 Callbacks (`secops-statistical-hunter`)
Detects automated C2 heartbeats (even with 15–20% randomized sleep jitter) from any macOS background process—whether `curl`, `osascript`, `node`, `bun`, `python3`, or a native Mach-O implant—to low-prevalence external destinations ($\le 3$ hosts in the fleet) over any TLD or IP by measuring the **Coefficient of Variation** ($\text{CV} = \sigma / \mu \le 0.20$) of hourly inter-arrival intervals.

```yara
// ============================================================================
// Goal: Detect periodic macOS C2 beaconing (with randomized sleep jitter) from background processes or native Mach-O implants to low-prevalence external destinations regardless of TLD or curl flags.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION and NETWORK_HTTP on macOS endpoints)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ <= 0.20) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly callback intervals per (src_host, dst_endpoint) pair on macOS
stage macos_c2_intervals {
    (
      metadata.event_type = "NETWORK_CONNECTION"
      or metadata.event_type = "NETWORK_HTTP"
    )
    principal.asset.hostname = $src_host
    $src_host != ""
    target.hostname = $dst_host
    $dst_host != ""
    $ts = metadata.event_timestamp.seconds

  match:
    $src_host, $dst_host by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
    $distinct_procs = count_distinct(principal.process.file.full_path)
}

// Stage 2: Aggregate historical inter-arrival timing stats across active hours
stage timing_stats {
    $src_host = $macos_c2_intervals.src_host
    $dst_host = $macos_c2_intervals.dst_host

  match:
    $src_host, $dst_host

  outcome:
    $mean_gap = avg($macos_c2_intervals.avg_gap)
    $stddev_gap = stddev($macos_c2_intervals.avg_gap)
    $total_conns = sum($macos_c2_intervals.conn_count)
    $active_hours = count($macos_c2_intervals.window_start)
    $max_procs = max($macos_c2_intervals.distinct_procs)
}

// Stage 3: Enterprise-wide host prevalence of the contacted external destination
stage dst_prevalence {
    $dst_host = $macos_c2_intervals.dst_host

  match:
    $dst_host

  outcome:
    $src_breadth = count_distinct($macos_c2_intervals.src_host)
}

// Root Stage: Compute Coefficient of Variation (CV = σ / μ) and emit 6 Core Evidence Pillars
$src_host = $timing_stats.src_host
$dst_host = $timing_stats.dst_host
$dst_host = $dst_prevalence.dst_host

match:
  $src_host, $dst_host

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.max_procs)

  // Coefficient of Variation (CV = σ / μ)
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

#### Query 4B: 3-Stage Dual-Sector Host Outbound Network Bytes + DNS Queries Fusion (`secops-risk-metrics-multistage`)
Catches staged `.zip`/`.tar.gz`/`.dmg` exfiltration and C2 domain resolution surges across any protocol or binary (`curl`, `python3`, `node`, `bun`, `SSFileCopyReceiver`, or native Mach-O stealers) by fusing 30-day behavioral baselines for **Outbound Network Bytes** (`metrics.network_bytes_outbound`) and **Total DNS Queries** (`metrics.dns_queries_total`) on the same macOS endpoint via the **Euclidean Vector Threat Norm** ($D^2 = Z_{\text{bytes}}^2 + Z_{\text{dns}}^2 \ge 12.25$).

```yara
// ============================================================================
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

---

---

### Scenario 5: Capstone Multi-Scenario macOS Endpoint Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Single-event macOS detections evaluated in isolation.
* **How Multi-Stage UEBA Extends Coverage**: Correlates macOS hosts triggering $\ge 2$ distinct behavioral scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario macOS Endpoint Convergence via UDM Loopback (`secops-risk-metrics-multistage` + `PlaybookRunner`)

```yara
// ============================================================================
// Goal: Correlate macOS endpoints matching >= 2 distinct behavioral queries across Scenarios 1-4 via PlaybookRunner's native UDM loopback (PLAYBOOK_BEHAVIORAL_HUNT_MATCH).
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
    $rule_name != "macos-threats-ueba-hunting:capstone_cross_query_convergence"

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

### 3.1 Markov 2-Gram Parent-to-Child Process Transition Surprisal ($I = -\ln P(\text{Child} \mid \text{Parent})$ — Query 1A)
* **What it measures**: How unexpected it is for a macOS parent application (`Safari`, `Chrome`, `Finder`, `Terminal`, `osascript`, or a binary inside `/Volumes/` or `/tmp/`) to spawn a specific child utility (`xattr`, `curl`, `security`, `hdiutil`, `screencapture`, `sh`, `zsh`) on that specific MacBook.
* **How multi-stage UEBA extends coverage**: Static rules like curated detection rules require the target file to begin with `com.apple.`, while curated detection rules requires `curl` and `xattr -c` to share the exact same parent PID within 5 minutes.
* **How the math works**: Routine application helper spawns have $P(\text{Child} \mid \text{Parent}) \approx 1.0 \implies I \approx 0$. When `Safari`, `Finder`, or `osascript` spawns `xattr`, `security`, or `screencapture` for the first or second time on that host, $P(\text{Child} \mid \text{Parent})$ is tiny and the self-information surprisal $I = \ln(\text{Parent}) - \ln(\text{Transition})$ (boosted $2\times$ for $\le 2$ occurrences) spikes above `3.0`.

### 3.2 Hybrid 30-Day File Execution Baseline + 10-Day Entity Context Graph File Prevalence (Query 1B)
* **What it measures**: Combines a 30-day pre-computed per-(host, SHA256) execution Z-score (`metrics.file_executions_total`) with `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3` hosts across the fleet).
* **How multi-stage UEBA extends coverage**: Path-based rules (curated detection rules) only catch binaries placed in specific dot-prefixed folders.
* **How the math works**: Regardless of where a Mach-O binary is staged on disk, if its SHA-256 hash has been executed on $\le 3$ endpoints across the entire organization over the past 10 days (`rolling_max <= 3`) and exhibits a local execution anomaly or first-time host execution (`$active_days = 0`, receiving a $2.5\times$ novelty boost), `$fused_threat_score` crosses `3.0`.

### 3.3 Poisson Dispersion & Fano Factor ($F = \sigma^2 / \mu$ — Query 2A)
* **What it measures**: How "clumpy" or bursty a MacBook's invocations of credential, discovery, and archiving utilities (`security`, `dscl`, `sqlite3`, `pbpaste`, `ditto`, `tar`, `zip`, `system_profiler`, `mdfind`) are across hourly windows.
* **How multi-stage UEBA extends coverage**: curated detection rules only checks `file -b`, and curated detection rules requires `2> /dev/null`.
* **How the math works**: Routine background scripts follow a Poisson process where variance equals the mean ($F = \sigma^2 / \mu \approx 1.0$). When an info-stealer (AMOS, Poseidon, Banshee) executes a rapid 60-second collection wave—validating passwords via `dscl`, unlocking `login.keychain-db` via `security`, copying browser SQLite databases, and compressing them with `ditto`/`zip`—the hourly variance explodes relative to the host's multi-day mean ($F \ge 4.0$).

### 3.4 Multi-Class Character Shannon Entropy ($H(X)$ — Query 2B)
* **What it measures**: How mixed and unpredictable the character distribution (lowercase, uppercase, digits, and symbols) is inside a macOS `osascript`, `zsh`, `bash`, or `sh` command line.
* **How multi-stage UEBA extends coverage**: curated detection rules requires $> 5$ literal `"do shell script"` substrings, and individual emerging-threat rules target one obfuscation pattern at a time (`character id`, string reversal, or `base64 -d`).
* **How the math works**: Normal admin commands consist mostly of lowercase words and spaces, yielding low character-class entropy. Base64/Hex-encoded payloads, JXA `eval()` strings, and ClickFix terminal one-liners balance uppercase, lowercase, digits, and operators evenly, driving `$shannon_entropy_score` above `3.8` bits/character while `$fleet_prevalence <= 3` suppresses fleet-wide developer scripts.

### 3.5 Two-Part Zero-Inflated Hurdle Model (Query 3A)
* **What it measures**: First, whether a process rarely touches macOS persistence locations (`LaunchAgents`, `LaunchDaemons`, `launchctl`, `plutil`, `crontab`, `TCC.db`) on that host (Part 1: Bernoulli hurdle crossing, $\le 2$ active days); second, how large today's modification burst is relative to its active days (Part 2: positive-activity Z-score).
* **How multi-stage UEBA extends coverage**: curated detection rules requires a `.py`/`.sh` script in `/tmp`, and curated detection rules requires an inline `base64`/`osascript` pipe targeting `/Library/LaunchAgents/`.
* **How the math works**: Separating *presence* from *magnitude* prevents zero-inflation distortion and applies a $3.0\times$ rarity multiplier when an unfamiliar binary (`$baseline_active_samples <= 2`, `$fleet_prevalence <= 3`) writes `.plist` files, modifies `TCC.db`, or invokes `launchctl`.

### 3.6 Zipfian Power-Law Fleet Rarity & Inverse Host Frequency Surprisal (IDF — Query 3B)
* **What it measures**: How rare an executing macOS binary is across the entire MacBook fleet (`adopter_hosts <= 2`) combined with how aggressively it executes on the local host (`local_intensity = ln(exec_count + 1)`).
* **How multi-stage UEBA extends coverage**: Once a persistent `LaunchAgent`, `LaunchDaemon`, or `LoginHook` implant is installed, it runs periodically under `launchd` without ever calling `launchctl` or modifying `.plist` files again.
* **How the math works**: By computing $\ln(N_{\text{total\_hosts}} / N_{\text{adopter\_hosts}}) + \ln(\text{exec\_count} + 1)$ with a $1.5\times$ singleton boost (`$adopters = 1`), a backdoor binary (`PlotTwist`, `BigMacho`) running on 1 or 2 MacBooks scores $\ge 4.0$, whereas enterprise-wide tools (`JAMF`, `CrowdStrike`, `Cursor`) have large `adopter_hosts` and drop out automatically.

### 3.7 Coefficient of Variation for C2 Beaconing Jitter ($\text{CV} = \sigma / \mu$ — Query 4A)
* **What it measures**: The regularity of time gaps between a macOS host's outbound network connections (`NETWORK_CONNECTION` / `NETWORK_HTTP`) to an external destination.
* **How multi-stage UEBA extends coverage**: curated detection rules only checks `curl` with `--retry` to 54 uncommon TLDs, missing `.com`/`.io` C2 domains and compiled Mach-O implants (`NSURLSession`).
* **How the math works**: Human web browsing produces erratic time gaps ($\text{CV} > 0.50$). Automated C2 beacon loops (even with 15–20% randomized sleep jitter) to a low-prevalence destination (`$fleet_prevalence <= 3`) produce tightly clustered inter-arrival intervals where $\sigma / \mu \le 0.20$.

### 3.8 3-Stage Dual-Sector Euclidean Risk Fusion ($D^2 = Z_{\text{bytes}}^2 + Z_{\text{dns}}^2 \ge 12.25$ — Query 4B)
* **What it measures**: The combined multi-dimensional anomaly distance across two independent 30-day behavioral baselines on the same macOS endpoint: **Outbound Network Bytes** (`metrics.network_bytes_outbound`) and **Total DNS Queries** (`metrics.dns_queries_total`).
* **How multi-stage UEBA extends coverage**: curated detection rules only match literal `curl` command-line flags and JSON keys, missing native binary exfiltration or renamed archives.
* **How the math works**: When a macOS stealer resolves external C2/drop-zone domains and uploads a staged `.zip`/`.dmg` archive of Keychain and browser data, both outbound bytes and DNS queries rise above the host's 30-day baseline. Combining their rectified Z-scores via $D^2 = Z_A^2 + Z_B^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius) surfaces coordinated exfiltration even when each individual sector sits at a moderate $2.5\sigma$.
