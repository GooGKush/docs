# Hunting Windows Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Windows Threats** curated detection suite provides extensive signature and behavioral coverage for Windows endpoints—spanning PowerShell and script-block execution, Living-off-the-Land Binaries (LOLBins), credential dumping, lateral movement, defense evasion, and ransomware staging.

Because adversaries frequently obfuscate command-line flags, rename utilities, or pace their post-exploitation activity across hours and days, this playbook supplements deterministic Windows detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). The queries below evaluate command-line character entropy, parent-to-child process transition surprisal, 30-day host authentication and file-execution baselines, and cross-scenario UDM Loopback convergence.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

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

#### Query 2B: 4-Stage UDM-Gated Poisson Fano Factor Burst Clustering on Windows Credential-Access & Discovery (`secops-statistical-hunter`)
Evaluates hourly credential-access and discovery command bursts ($F = \sigma^2 / \mu \ge 4.0$) strictly on candidate Windows endpoints surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED POISSON FANO FACTOR BURST DISPERSION PIPELINE
// Goal: Detect automated credential harvesting and post-exploitation discovery bursts on candidate Windows hosts from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
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
    re.regex(target.process.file.full_path, `(?i)(whoami|net1?|nltest|dsquery|cmdkey|vaultcmd|rundll32|procdump|ntdsutil|vssadmin|reg|quser|qwinsta|tasklist|systeminfo|ipconfig)\.exe$`)
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
  and $peak_burst >= 6
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

#### Query 3B: 4-Stage UDM-Gated Inter-Arrival Jitter Coefficient of Variation on Windows Outbound C2 Callbacks (`secops-statistical-hunter`)
Evaluates hourly outbound C2 callback inter-arrival pacing ($\text{CV} = \sigma / \mu \le 0.25$) strictly on candidate Windows endpoints surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED INTER-ARRIVAL JITTER COEFFICIENT OF VARIATION PIPELINE
// Goal: Detect Cobalt Strike, Sliver, Brute Ratel, and RMM C2 beaconing (CV <= 0.25) on candidate Windows hosts from Query 3A (strictly gated by Query 3A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Coefficient of Variation (CV = sigma / mu <= 0.25)
// ============================================================================

stage stage1_upstream_3a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_3a_z = max(security_result.confidence_score)
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

$host = $stage1_upstream_3a_candidates.host
$host = $timing_stats.host
$target_ip = $timing_stats.target_ip

match:
  $host, $target_ip

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
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

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–5 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 6 (`Query 6`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 5 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 5 Windows Threats scenarios (1 through 5B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)
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
