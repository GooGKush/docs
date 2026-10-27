# Hunting Windows Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Windows Threats** curated detection suite provides extensive signature and behavioral coverage for Windows endpoints—spanning PowerShell and script-block execution, Living-off-the-Land Binaries (LOLBins), credential dumping, lateral movement, defense evasion, and ransomware staging.

Because adversaries frequently obfuscate command-line flags, rename utilities, or pace their post-exploitation activity across hours and days, this playbook supplements deterministic Windows detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). The queries below evaluate command-line character entropy, parent-to-child process transition surprisal, 30-day host authentication and file-execution baselines, and cross-scenario UDM Loopback convergence.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

### Table 1: Scenario Coverage Matrix — Windows Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Obfuscated PowerShell, Script-Block & LOLBin Execution** | Detects known malicious command-line flags, encoded PowerShell arguments, and common LOLBin invocation patterns. | Calculates multi-class character Shannon entropy ($H(X) \ge 4.1$) across script and LOLBin command lines to catch novel obfuscation, paired with Markov 2-gram parent-to-child process transition surprisal ($I \ge 3.8$). | `Query 1A` (Command-Line Shannon Entropy)<br>`Query 1B` (Markov 2-Gram Process Surprisal) |
| **2. Credential Dumping, Info-Stealers & Lateral Authentication** | Flags known credential-access tools, LSASS access patterns, and explicit pass-the-hash or brute-force signatures. | Fuses 30-day host authentication failure and success baselines ($D^2 \ge 12.25$) with Poisson Fano Factor burst dispersion ($F = \sigma^2/\mu \ge 4.0$) across credential and discovery utilities. | `Query 2A` (30d Host Auth Fusion)<br>`Query 2B` (Poisson Fano Burst Clustering) |
| **3. Emerging Malware, RATs & Trojanized Payload Drops** | Matches known malware family file paths, registry keys, and command-and-control signatures. | Unifies cold-start host execution with 30-day file execution baselines weighted by 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`), plus inter-arrival C2 beaconing jitter ($\text{CV} \le 0.20$). | `Query 3A` (30d Execution + 10d Prevalence)<br>`Query 3B` (C2 Jitter CV) |
| **4. Security Downgrade, Defender Tampering & Persistence** | Alerts on explicit commands that disable endpoint protection, modify services, or register scheduled tasks. | Applies a Two-Part Zero-Inflated Hurdle model and Zipfian fleet rarity ($I = \ln(N/df) \ge 3.5$) to surface rare administrative or registry/service modification activity on hosts where such actions are historically dormant. | `Query 4A` (Two-Part Persistence Hurdle)<br>`Query 4B` (Zipfian Fleet Rarity) |
| **5. Ransomware Staging, Mass Encryption & Exfiltration** | Monitors shadow-copy deletion, ransomware notes, and high-severity endpoint vendor alerts. | Combines 4-stage Roll-Up Endpoint Alert + Outbound Network Bytes fusion (`metrics.alert_event_name_count` + `metrics.network_bytes_outbound`) with EWMA kinetic burst velocity on file and process activity. | `Query 5A` (30d Alert + Egress Bytes Fusion)<br>`Query 5B` (EWMA Kinetic Burst Velocity) |
| **6. Capstone Multi-Scenario Windows Host Convergence** | Individual endpoint rules evaluated per event or within short tactical windows. | Correlates Windows hosts accumulating $\ge 2$ distinct behavioral hunt matches within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Obfuscated PowerShell, Script-Block Execution & LOLBin Command-Line Evasion

* **Curated Detection Operational Focus**: Detects known malicious command-line flags, encoded PowerShell arguments, and common LOLBin invocation patterns.
* **How Multi-Stage UEBA Extends Coverage**: Calculates multi-class character Shannon entropy ($H(X) \ge 4.1$) across script and LOLBin command lines to catch novel obfuscation, paired with Markov 2-gram parent-to-child process transition surprisal ($I \ge 3.8$).

#### Query 1A: Multi-Class Character Shannon Entropy Hunt on Windows Script & LOLBin Command Lines (`secops-statistical-hunter`)
Replaces brittle Base64 substring regexes by computing **4-class character Shannon entropy** ($H(X) = -\sum p_i \log_2 p_i \ge 3.8\text{ bits/char}$) and enterprise fleet prevalence ($\le 3$ hosts) across Windows script interpreters and LOLBins (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`).

```yara
// ============================================================================
// Goal: Detect obfuscated PowerShell, Base64/XOR-encoded scripts, and high-entropy LOLBin command lines across Windows endpoints.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on Windows script interpreters and LOLBins)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)) >= 3.8)
// ============================================================================

// Stage 1: Aggregate command-line string lengths and character-class distributions per host and command line
stage cmd_feature_extraction {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $cmd = target.process.command_line
    $cmd != ""
    strings.length($cmd) >= 64
    re.regex(target.process.file.full_path, `(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$`)

  match:
    $host, $cmd by 1d

  outcome:
    $execution_count = count(metadata.id)
    $distinct_bins = count_distinct(target.process.file.full_path)
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

// Stage 2: Enterprise fleet prevalence of each distinct command line across hosts
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
  $distinct_binaries = max($cmd_feature_extraction.distinct_bins)

condition:
  $baseline_active_samples >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 3.8

order:
  $shannon_entropy_score desc
```

#### Query 1B: Markov 2-Gram Parent-to-Child Process Transition Surprisal for Windows Services, Office & Browsers Spawning Shells/LOLBins (`secops-statistical-hunter`)
Detects living-off-the-land execution chains where Windows system services (`svchost.exe`, `wmiprvse.exe`, `services.exe`), Microsoft Office applications (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`), or browsers spawn shells and LOLBins by computing conditional transition probability $P(\text{Child} \mid \text{Parent})$ and **Information Surprisal** $I = -\ln P(\text{Child} \mid \text{Parent}) \ge 3.0$.

```yara
// ============================================================================
// Goal: Detect rare parent-to-child process transitions where Windows services, Office apps, or browsers spawn shells and LOLBins via Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln(P(Child | Parent)) >= 3.0)
// ============================================================================

// Stage 1: Parent Process Launch Baseline Frequency per host
stage parent_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""
    re.regex($parent, `(?i)(svchost|wmiprvse|services|taskeng|winword|excel|powerpnt|outlook|msaccess|chrome|msedge|firefox)\.exe$`)

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
    re.regex($parent, `(?i)(svchost|wmiprvse|services|taskeng|winword|excel|powerpnt|outlook|msaccess|chrome|msedge|firefox)\.exe$`)
    re.regex($child, `(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|cmstp|installutil|atbroker|certoc|cmdl32)\.exe$`)

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

  // 2. Markov Transition Probability: P(B | A) = Count(A -> B) / Count(A)
  $transition_prob = $safe_trans / $safe_parent

  // 3. Information Surprisal (Self-Information Rarity): I = -ln(P) = ln(Parent) - ln(Transition)
  $log_parent = math.log($safe_parent)
  $log_trans = math.log($safe_trans)
  $surprisal_score = $log_parent - $log_trans

  // 4. Rare Sequence Multiplier (Amplifies singleton or doubleton transitions)
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

### Scenario 2: Credential Dumping, Info-Stealers & Lateral Authentication Abuse

* **Curated Detection Operational Focus**: Flags known credential-access tools, LSASS access patterns, and explicit pass-the-hash or brute-force signatures.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day host authentication failure and success baselines ($D^2 \ge 12.25$) with Poisson Fano Factor burst dispersion ($F = \sigma^2/\mu \ge 4.0$) across credential and discovery utilities.

#### Query 2A: 3-Stage Dual-Sector Host Authentication Failure + Success Fusion (`secops-risk-metrics-multistage`)
Detects post-dump pass-the-hash, brute-force, and lateral authentication progression originating from or targeting a Windows endpoint by fusing 30-day baselines for `metrics.auth_attempts_fail` and `metrics.auth_attempts_success` keyed on `principal.asset.hostname` ($D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Detect post-credential-dump lateral authentication spraying and pass-the-hash progression on Windows hosts.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D_sq = Z_fail_sq + Z_success_sq >= 12.25)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION (HOST-KEYED)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Two metrics of the auth family (auth_attempts_fail + auth_attempts_success) keyed on principal.asset.hostname capture spray-then-login progression.
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

  // Euclidean Vector Threat Norm D_sq = Z_a_sq + Z_b_sq
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 2B: Poisson Fano Factor Burst Clustering on Windows Credential-Access & Discovery Activity (`secops-statistical-hunter`)
Detects automated info-stealers, LSASS/SAM credential dumping, and post-exploitation discovery bursts by computing the **Poisson Fano Dispersion Factor** ($F = \sigma^2 / \mu \ge 4.0$) across hourly (`by 1h`) credential-access and discovery process/file events per Windows host.

```yara
// ============================================================================
// Goal: Detect automated info-stealer credential harvesting and post-compromise discovery bursts on Windows hosts via Fano Factor dispersion.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH and FILE_OPEN/FILE_CREATION touching credential stores or discovery tools)
// Statistical Model: Poisson Dispersion via Fano Factor (F = variance / mean >= 4.0) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly credential-access and discovery event counts per Windows host
stage hourly_cred_bursts {
    (metadata.event_type = "PROCESS_LAUNCH" or metadata.event_type = "FILE_CREATION" or metadata.event_type = "FILE_OPEN")
    principal.asset.hostname = $entity
    $entity != ""
    (
      re.regex(target.process.file.full_path, `(?i)(rundll32|procdump|vaultcmd|cmdkey|ntdsutil|dsquery|adfind|nltest|net| net1|whoami|quser|qwinsta|klist)\.exe$`)
      or re.regex(target.process.command_line, `(?i)(lsass|comsvcs|minidump|sekurlsa|sam|system|security|ntds\.dit|Login Data|Local State|cookies\.sqlite|vaultcmd|cmdkey)`)
      or re.regex(target.file.full_path, `(?i)(lsass.*\.dmp|ntds\.dit|Login Data|Web Data|Local State|cookies\.sqlite)`)
    )

  match:
    $entity by 1h

  outcome:
    $hourly_events = count(metadata.id)
    $hourly_bins = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Calculate historical arrival mean, standard deviation, and active sample density per host
stage dispersion_baseline {
    $entity = $hourly_cred_bursts.entity

  match:
    $entity

  outcome:
    $mean_rate = avg($hourly_cred_bursts.hourly_events)
    $stddev_rate = stddev($hourly_cred_bursts.hourly_events)
    $total_events = sum($hourly_cred_bursts.hourly_events)
    $max_bins = max($hourly_cred_bursts.hourly_bins)
    $active_hours = count($hourly_cred_bursts.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of hosts exhibiting credential/discovery bursts per window
stage fleet_breadth {
    $ws = $hourly_cred_bursts.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($hourly_cred_bursts.entity)
}

// Root Stage: Join stages, calculate Fano Factor in outcome section, and emit 6 Evidence Pillars
$entity = $hourly_cred_bursts.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_cred_bursts.window_start
$ws = $fleet_breadth.ws

match:
  $entity

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($dispersion_baseline.total_events)
  $baseline_active_samples = max($dispersion_baseline.active_hours)
  $baseline_mean = max($dispersion_baseline.mean_rate)
  $baseline_dispersion = max($dispersion_baseline.stddev_rate)
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $distinct_binaries = max($dispersion_baseline.max_bins)
  $sample_commands = array_distinct($hourly_cred_bursts.sample_cmd)

  // Aggregate Fano Factor (F = variance / mean)
  $raw_mean = max($dispersion_baseline.mean_rate)
  $safe_mean = if($raw_mean > 0, $raw_mean, 1.0)
  $raw_stddev = max($dispersion_baseline.stddev_rate)
  $variance = $raw_stddev * $raw_stddev
  $fano_factor = $variance / $safe_mean

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 10
  and $baseline_mean >= 0.5
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

---

---

### Scenario 3: Named Malware, RATs, Emerging Threats & Trojanized Drops

* **Curated Detection Operational Focus**: Matches known malware family file paths, registry keys, and command-and-control signatures.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start host execution with 30-day file execution baselines weighted by 10-day `DERIVED_CONTEXT` binary prevalence (`day_max <= 3`), plus inter-arrival C2 beaconing jitter ($\text{CV} \le 0.20$).

#### Query 3A: 2-Stage Hybrid 30-Day Process Execution (`metrics.file_executions_total`) + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Catches newly compiled backdoors, polymorphic RAT droppers, and trojanized binaries regardless of family name by scoring per-(host, SHA256) process launches against a **30-day behavioral baseline (`metrics.file_executions_total`)** joined with the **Entity Context Graph (`DERIVED_CONTEXT` `FILE` 10-day `rolling_max <= 3`)**.

```yara
// ============================================================================
// Goal: Detect execution of rare or newly compiled Windows malware/RAT binaries (10-day org prevalence <= 3 hosts) with anomalous host execution frequency.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Windows Endpoint Process Execution + 30-Day Composite Baseline per (host, event_type, sha256)
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

#### Query 3B: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on Windows Outbound C2 Callbacks (`secops-statistical-hunter`)
Detects RATs (Cobalt Strike, Sliver, Brute Ratel, Havoc, custom implants) and unauthorized RMM beacons communicating with external infrastructure regardless of port, URI, or domain name by measuring the **Coefficient of Variation ($\text{CV} = \sigma / \mu \le 0.20$)** of hourly callback intervals and filtering to low-prevalence external destinations ($\le 3$ internal hosts).

```yara
// ============================================================================
// Goal: Detect persistent RAT and C2 beaconing from Windows endpoints to low-prevalence external IPs with robotic sleep jitter (CV <= 0.20).
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = stddev / mean <= 0.20) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Measure hourly timing intervals per (src_ip, dst_ip) pair on Windows endpoints
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    principal.asset.ip = $src_ip
    $src_ip != ""
    $dst_ip != ""
    // Exclude RFC 1918 internal destinations
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "127.0.0.0/8")
    $ts = metadata.event_timestamp.seconds

  match:
    $src_ip, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $distinct_procs = count_distinct(principal.process.file.full_path)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
}

// Stage 2: Aggregate historical timing statistics across active hours per (src_ip, dst_ip)
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip

  match:
    $src_ip, $dst_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $max_procs = max($host_intervals.distinct_procs)
    $active_hours = count($host_intervals.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of each external destination IP
stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip

  outcome:
    $src_breadth = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute CV, and emit standardized 6 Evidence Pillars
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
  $distinct_binaries = max($timing_stats.max_procs)

  // Aggregate Coefficient of Variation (CV = stddev / mean)
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

### Scenario 4: Security Downgrade, Defender Tampering & Persistence Mechanisms

* **Curated Detection Operational Focus**: Alerts on explicit commands that disable endpoint protection, modify services, or register scheduled tasks.
* **How Multi-Stage UEBA Extends Coverage**: Applies a Two-Part Zero-Inflated Hurdle model and Zipfian fleet rarity ($I = \ln(N/df) \ge 3.5$) to surface rare administrative or registry/service modification activity on hosts where such actions are historically dormant.

#### Query 4: Unified Personal Leave-One-Out Poisson Rarity & Zipfian Fleet Rarity on Windows Persistence, Tampering & Cryptominers (`secops-statistical-hunter`)
Because both **Personal Leave-One-Out Discrete Poisson Rarity** (catching built-in Windows tampering utilities like `sc.exe`, `schtasks.exe`, `wevtutil.exe`, `vssadmin.exe`, `bcdedit.exe` executing on a host where their prior 29-day rate $\lambda \le 0.5\text{/day}$) and **Zipfian Power-Law Fleet Rarity** (catching custom persistence services, BYOVD rootkit loaders, and rogue cryptominers executing on $\le 2$ hosts in the fleet) operate on the exact same `PROCESS_LAUNCH` telemetry stream (`$entity, $tool by 1d`), this **Option 1 Unified Pipeline** evaluates both regimes inside a single 4-stage DAG (`$unified_threat_score = if($adopter_hosts <= 2, $zipf_rarity_score, $poisson_z)`):
- **Regime 1 — Fleet-Rare Custom Persistence / Cryptominer Binaries ($\text{adopter\_hosts} \le 2$)**: Scores Zipfian log-rank departure and inverse host tail rarity (`$zipf_rarity_score >= 4.0`).
- **Regime 2 — Built-In Windows Tampering & Persistence Utilities ($\text{adopter\_hosts} \ge 3, \lambda \le 0.5\text{/day}$)**: Scores Leave-One-Out Poisson deviance (`$poisson_z >= 3.0`, equivalent to $Z_{\text{Poisson}}^2 \ge 9.0$) on quiet endpoints while filtering out noisy build servers.

```yara
// ============================================================================
// Goal: Unify fleet-rare persistence/cryptominer binaries (Zipfian tail <= 2 hosts) and personal Leave-One-Out Poisson rarity on Windows tampering tools (sc, schtasks, wevtutil, vssadmin, bcdedit) in a single 4-stage pipeline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Option 1 Piecewise Leave-One-Out Discrete Poisson Rarity + Zipfian Inverse Host Frequency Rarity
// ============================================================================

// Stage 1: Daily execution counts per Windows host and binary path
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
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

// Stage 3: Enterprise fleetwide binary popularity & adopter breadth per (tool, day) for Zipfian tail rarity
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

  // Branch A: Leave-One-Out Discrete Poisson Rarity (Personal Baseline for built-in utilities)
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
    ($adopter_hosts <= 2 and $observation_count >= 8 and $unified_threat_score >= 4.0)
    or ($adopter_hosts >= 3 and $baseline_mean <= 0.5 and $distinct_binaries >= 2 and $unified_threat_score >= 3.5)
  )

order:
  $unified_threat_score desc
```

---

---

### Scenario 5: Ransomware Staging, Mass File Encryption & Vendor Alert Escalation

* **Curated Detection Operational Focus**: Monitors shadow-copy deletion, ransomware notes, and high-severity endpoint vendor alerts.
* **How Multi-Stage UEBA Extends Coverage**: Combines 4-stage Roll-Up Endpoint Alert + Outbound Network Bytes fusion (`metrics.alert_event_name_count` + `metrics.network_bytes_outbound`) with EWMA kinetic burst velocity on file and process activity.

#### Query 5A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Windows File Modification, Creation & Deletion Churn (`secops-statistical-hunter`)
Detects ransomware file encryption, mass archive staging, and destructive wipers across all ransomware families by computing each Windows host's non-parametric **Median** and **Median Absolute Deviation (MAD)** over daily `FILE_MODIFICATION`, `FILE_CREATION`, and `FILE_DELETION` events—with the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) when $\text{MAD} = 0$.

```yara
// ============================================================================
// Goal: Detect ransomware mass file encryption, archive staging, and destructive wiper activity on Windows hosts via non-parametric MAD Modified Z-Score.
// Target Telemetry: UDM_EVENTS (FILE_MODIFICATION, FILE_CREATION, FILE_DELETION)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Modified Z-Score (Iglewicz & Hoaglin M_Z > 3.5)
// ============================================================================

// Stage 1: Daily observed file modification, creation, and deletion volume per Windows host
stage daily_stats {
    (metadata.event_type = "FILE_MODIFICATION" or metadata.event_type = "FILE_CREATION" or metadata.event_type = "FILE_DELETION")
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $daily_value = count(metadata.id)
    $distinct_sample_values = count_distinct(principal.process.file.full_path)
    $sample_data = array_distinct(target.file.full_path)
}

// Stage 2: Baseline median of daily file churn per host (active days only)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, mean absolute deviation (MAD=0 fallback), and baseline depth per host
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

// Root Stage: Modified Z-Score per host-day and the 6 Evidence Pillars
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
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 10.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

  // Option 1 Piecewise Cold-Start Hurdle (<= 4 active days) + Mature 30d MAD (>= 5 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 4, 2.0, 1.0)
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost
  $unified_threat_score = if($baseline_active_samples <= 4, $hurdle_threat_score, $m_z_score)

condition:
  $observation_count >= 250
  and $unified_threat_score > 3.5

order:
  $unified_threat_score desc
```

#### Query 5B: 4-Stage Roll-Up Endpoint Alert (`metrics.alert_event_name_count`) + Outbound Network Bytes (`metrics.network_bytes_outbound`) Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Replaces deprecated `ata_attack_progression_*` rules and fixes the `"SENTINELONE_ALERTS"` log-type coverage by rolling up 30-day per-rule EDR alert anomalies (`metrics.alert_event_name_count` across `CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, and `SENTINELONE_ALERTS`) and fusing them with 30-day outbound network exfiltration surges (`metrics.network_bytes_outbound`) on the same Windows host ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Fuse 30-day Windows EDR alert anomalies with outbound network byte surges on the same host to detect double-extortion ransomware and full kill-chain progression.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D_sq >= 12.25)
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

  // Euclidean Vector Threat Norm D_sq = Z_a_sq + Z_b_sq
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

### Scenario 6: Capstone Multi-Scenario Windows Endpoint Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Individual endpoint rules evaluated per event or within short tactical windows.
* **How Multi-Stage UEBA Extends Coverage**: Correlates Windows hosts accumulating $\ge 2$ distinct behavioral hunt matches within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Windows Endpoint Convergence via UDM Loopback (`secops-risk-metrics-multistage` + `PlaybookRunner`)

```yara
// ============================================================================
// Goal: Correlate Windows endpoints matching >= 2 distinct behavioral queries across Scenarios 1-5 via PlaybookRunner's native UDM loopback (PLAYBOOK_BEHAVIORAL_HUNT_MATCH).
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
    $rule_name != "windows-threats-ueba-hunting:capstone_cross_query_convergence"

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

### 3.1 Multi-Class Character Shannon Entropy ($H(X) \ge 3.8$ — Query 1A)
* **What it measures**: How mixed and unpredictable the characters inside a Windows command line are across lowercase letters, uppercase letters, digits, and symbols.
* **How multi-stage UEBA extends coverage**: Rules like curated detection rules search for 6 fixed Base64 substrings representing `" -bxor "`. Adding a single space, changing case, or switching to Gzip/AES/char-array obfuscation defeats the regex.
* **How the math works**: Routine administrative commands (`powershell.exe -File C:\Scripts\backup.ps1`) are dominated by lowercase characters and predictable words, yielding low class entropy. Base64 blobs, XOR-encoded shellcode loaders, and `Invoke-Obfuscation` token scrambles mix uppercase, lowercase, digits, and punctuation evenly across long command strings ($\ge 64$ chars), driving $H(X) = -\sum p_i \log_2 p_i$ (scaled to byte-entropy equivalent) above `3.8` on $\le 3$ hosts in the fleet.

### 3.2 Markov 2-Gram Parent-to-Child Transition Surprisal ($I = -\ln P(\text{Child} \mid \text{Parent}) \ge 3.0$ — Query 1B)
* **What it measures**: How unexpected it is for a specific parent process (`svchost.exe`, `wmiprvse.exe`, `winword.exe`, `excel.exe`, `chrome.exe`) to spawn a specific child interpreter or LOLBin (`powershell.exe`, `cmd.exe`, `rundll32.exe`, `mshta.exe`, `comsvcs.dll` host) on that endpoint.
* **How multi-stage UEBA extends coverage**: Static LOLBin rules (`lotl`) fire on single command-line flag matches without knowing if the parent-child lineage is normal for that machine, or miss attacks when arguments are passed via environment variables or renamed copies.
* **How the math works**: When `svchost.exe` spawns a routine child process hundreds of times a day, $P(\text{Child} \mid \text{Parent}) \approx 1.0 \implies I = -\ln(1.0) = 0$. When `winword.exe` or `wmiprvse.exe` suddenly spawns `mshta.exe` or `rundll32.exe` once or twice out of 100 parent launches, $P(\text{Child} \mid \text{Parent}) = 0.01$, and self-information surprisal $I = -\ln(0.01) = 4.605$ (amplified $2\times$ for singleton/doubleton transitions) immediately crosses the `3.0` threshold.

### 3.3 3-Stage Dual-Sector Host Authentication Failure + Success Fusion ($D^2 \ge 12.25$ — Query 2A)
* **What it measures**: The combined 30-day behavioral anomaly across both failed authentication attempts (`metrics.auth_attempts_fail`) and successful logons (`metrics.auth_attempts_success`) on the same Windows host (`principal.asset.hostname`).
* **How multi-stage UEBA extends coverage**: Credential-dumping and hacktool rules (curated detection rules) only inspect process command lines on the beachhead host and never check whether harvested NTLM hashes or Kerberos tickets were immediately used to authenticate across the domain.
* **How the math works**: Each sector is scored against its own 30-day host baseline ($\mu, \sigma$) with a 5-day maturity gate (`$active_days >= 5`). Combining the rectified Z-scores via Euclidean squared distance $D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius) catches spray-then-login and pass-the-hash lateral movement even when neither failures nor successes alone breach a high single-metric cutoff.

### 3.4 Poisson Fano Factor Burst Clustering ($F = \sigma^2 / \mu \ge 4.0$ — Query 2B)
* **What it measures**: The hourly "clumpiness" or burst variance ($\sigma^2 / \mu$) of credential-store touches (`lsass`, `SAM`, `ntds.dit`, Chrome/Edge `Login Data`) and discovery utilities (`vaultcmd`, `cmdkey`, `procdump`, `nltest`, `adfind`) on a Windows endpoint.
* **How multi-stage UEBA extends coverage**: Info-stealer and discovery rules either match static ports (curated detection rules on ports `447`/`449`) or fire on every single `whoami.exe` / `net.exe` execution, creating massive alert fatigue.
* **How the math works**: Routine background administrative scripts execute at a steady Poisson rate where variance equals the mean ($F = \sigma^2 / \mu \approx 1.0$). When an info-stealer or post-exploitation operator lands on a host and rapidly enumerates vaults, dumps LSASS, and queries Active Directory within a 1-hour window, the hourly variance explodes relative to the host's multi-day mean ($F \ge 4.0$).

### 3.5 2-Stage Hybrid 30-Day Process Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (Query 3A)
* **What it measures**: A binary's per-host execution anomaly against its 30-day history (`metrics.file_executions_total`) weighted by its 10-day organizational prevalence in the Entity Context Graph (`$g.graph.entity.file.prevalence.rolling_max <= 3`).
* **How multi-stage UEBA extends coverage**: The 1,090 rules in `mandiant-frontline-threats` and `mandiant-intel-emerging-threats` target known malware families and indicators; recompiling a backdoor produces a brand-new SHA256 hash that bypasses static hash and path rules.
* **How the math works**: Any `PROCESS_LAUNCH` whose SHA256 has been seen on $\le 3$ hosts across the entire enterprise over the past 10 days (`rolling_max <= 3`) and has either 0 prior active days on the host or singleton org prevalence (`rolling_max <= 1`) receives a $2.5\times$ novelty multiplier on its 30-day execution Z-score, surfacing zero-day droppers and custom RAT binaries immediately.

### 3.6 Inter-Arrival Jitter Coefficient of Variation ($\text{CV} = \sigma / \mu \le 0.20$ — Query 3B)
* **What it measures**: The regularity of time gaps between a Windows host's outbound `NETWORK_CONNECTION` callbacks to an external IP, paired with fleet destination rarity ($\le 3$ internal hosts).
* **How multi-stage UEBA extends coverage**: curated detection rules only checks 4 default named pipe prefixes, and `mandiant-frontline-threats` C2 rules only check static domains (`workers.dev`, `herokuapp.com`).
* **How the math works**: Human web browsing produces chaotic, wide-ranging inter-arrival gaps ($\text{CV} = \sigma / \mu > 0.50$). Automated C2 beacons (Cobalt Strike, Sliver, Brute Ratel) sleep on a fixed timer with 10%–20% random jitter, producing a tightly bounded standard deviation relative to the mean interval ($\text{CV} \le 0.20$).

### 3.7 Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$ — Query 4A)
* **What it measures**: The statistical improbability of observing $k \ge 2$ executions today of sensitive Windows persistence and security-downgrade binaries (`sc.exe`, `schtasks.exe`, `wevtutil.exe`, `vssadmin.exe`, `bcdedit.exe`, `auditpol.exe`, `icacls.exe`) when the host's prior 29-day rate $\lambda$ is near zero ($\le 0.5\text{/day}$).
* **How multi-stage UEBA extends coverage**: curated detection rules misses `wevtutil cl` or `/enabled:false`, curated detection rules only matches 3 literal task names (`blackball|blutea|rtsa`), and single-event alerts drown analysts in noise from build servers where `schtasks.exe` runs daily.
* **How the math works**: By subtracting today's count $k$ from the total historical runs (`$prior_runs = $total_hist - $today_k`) and applying Jeffreys smoothing ($\lambda = (\text{prior\_runs} + 0.5) / 29.0$), today's attack cannot inflate its own baseline. On a quiet workstation or server with 0 prior runs ($\lambda = 0.0172$), just $k = 2$ tampering commands yield $Z_{\text{Poisson}}^2 = (2 - 0.0172)^2 / 0.0172 = 228.5 \gg 9.0$, while noisy build servers ($\lambda > 0.5$) are automatically filtered out.

### 3.8 Zipfian Power-Law Fleet Rarity & Inverse Host Frequency (`zipf_rarity_score >= 4.0` — Query 4B)
* **What it measures**: How rare a Windows executable path is across all endpoints in the enterprise (`adopter_hosts <= 2`) multiplied by its local execution intensity on the host (`local_volume >= 8`).
* **How multi-stage UEBA extends coverage**: curated detection rules only checks for `/gmer\.bat/`, missing renamed rootkit loaders, custom persistence services, and uncataloged cryptominers.
* **How the math works**: Legitimate Windows binaries (`svchost.exe`, `conhost.exe`) run on thousands of hosts, making $\ln(\text{fleet\_volume}) - \ln(\text{adopter\_hosts})$ small and the tail multiplier $1 / N_{\text{hosts}} \approx 0$. A rogue persistence binary or cryptominer running repeatedly on only 1 or 2 hosts maximizes both the log-rank gap and the inverse host tail multiplier $(1 + 1/N_{\text{hosts}})$, pushing `zipf_rarity_score >= 4.0`.

### 3.9 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$ — Query 5A)
* **What it measures**: How many robust standard deviations a Windows host's daily file churn (`FILE_MODIFICATION`, `FILE_CREATION`, `FILE_DELETION`) sits above its historical median.
* **How multi-stage UEBA extends coverage**: All 7 rules in `ransomware` (curated detection rules) match family-specific strings and never measure mass file encryption or wiping.
* **How the math works**: Standard mean/stddev baselines are easily skewed by a single patch day. The 4-stage MAD pipeline computes each host's median daily file churn and Median Absolute Deviation ($\text{MAD} = \text{median}(|x_i - \text{median}|)$), falling back to $1.253314 \times \text{MeanAD}$ if $\text{MAD} = 0$. When a ransomware encryptor or wiper touches hundreds or thousands of files on a host, $M_Z = (x - \text{median}) / (\text{MAD} / 0.6745)$ surges well above `3.5`.

### 3.10 4-Stage Roll-Up Endpoint Alert + Outbound Network Bytes Fusion ($D^2 \ge 12.25$ — Query 5B)
* **What it measures**: The joint 30-day anomaly combining the sharpest per-rule EDR alert spike on a host (`metrics.alert_event_name_count` rolled up across `security_result.rule_name`) with a simultaneous 30-day surge in outbound network bytes (`metrics.network_bytes_outbound`).
* **How multi-stage UEBA extends coverage**: `ata_attack_progression_edr_initial_post_compromise` is deprecated (`legacy configuration`), `ata_exploitation_platforms_process_cli` misses `"SENTINELONE_ALERTS"` due to a singular log-type typo, and no rule checks whether an endpoint with low-severity EDR alerts is actively exfiltrating data.
* **How the math works**: Stage 1 scores each `(host, rule_name)` pair against its 30-day alert baseline; Stage 2 rolls those up to one row per host (`$z_a = max($d_z)`); Stage 3 scores the host's daily outbound bytes against `metrics.network_bytes_outbound` (`$z_b`); and the Root Stage computes $D^2 = Z_a^2 + Z_b^2 \ge 12.25$, immediately surfacing double-extortion ransomware and post-exploitation exfiltration.
