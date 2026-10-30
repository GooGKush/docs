# Hunting Windows Endpoint Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Windows Threats** curated detection suite provides deterministic signature and single-stage behavioral coverage for Windows endpoints—spanning PowerShell and script-block execution, Living-off-the-Land Binaries (LOLBins), credential access, lateral movement, defense evasion, and ransomware staging.

Because adversaries alter command-line syntax, rename utilities, or pace post-exploitation activity across hours and days, this runbook supplements deterministic Windows rules with cyclical **Multi-Stage Behavioral Analytics** across the macro 30-day `metrics.*` plane (`secops-risk-metrics-multistage`) and the bounded raw-event plane (`secops-statistical-hunter`). Each query emits a Z-score or Z-equivalent statistical score; `[0, 100]` Composite Risk Index (CRI) calibration is performed downstream in Python by `agentic_ueba` (`ueba_constants.calculate_cri`).

### Execution Windows & Baseline Guardrails
* **Mode A — 30-Day `metrics.*` Macro Queries (`Queries 2A, 5B, 7A`)**: Evaluate the last complete UTC day (`startTime = D T00:00:00Z`, `endTime = D+1 T00:00:00Z`) against the pre-computed `[D-30, D)` daily baseline. Every `metrics.*` sector enforces a $\ge 7$ active-day baseline maturity gate (`num_metric_periods >= 7`), a Poisson count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1)})$ on event-count metrics, and the `44979.0` byte dispersion floor on `metrics.network_bytes_outbound`.
* **Mode A with Entity Context Graph Joins (`Query 3A`)**: Run over `[D-2 T00:00:00Z, D+1 T00:00:00Z)` so `DERIVED_CONTEXT` prevalence snapshots are available, while pinning the UDM event stage to scored UTC day `D` with `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"`.
* **Bounded Raw-Event Micro / Mode B Queries (`Queries 1A, 1B, 2B, 3B, 4, 5A, 7B`)**: Run over bounded windows (`1h`–`24h` for high-volume process, network, and ingestion-lag telemetry; `14d` Mode B for daily host-tool rarity and host file-churn baselines).

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide low-latency alerting on explicit attack syntax, known tool indicators, and single-stage thresholds.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Orchestrated by `PlaybookRunner` in `agentic_ueba`:
  1. **Wave 1 — Upstream Macro & Bounded Raw-Event Hunts (`Queries 1A, 1B, 2A, 3A, 4, 5A, 5B, 7A`)**: Executes `by 1d` 30-day `metrics.*` baselines (and any upstream candidate-seeded `/* UPSTREAM_CANDIDATE_IPS */` templates) alongside bounded raw-telemetry statistical queries concurrently. `PlaybookRunner` exports every match into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and rule tag (`<playbook_id>:q<NN>_query_<id>`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Hunts (`Queries 2B, 3B`)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 queries join upstream candidate hosts from Chronicle UDM in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)` and `:q[0-9]+_query_3a`) so hourly (`by 1h`) burst dispersion and flow-gap screening run only on anomalous endpoints.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_(?:[1-5]|7)`)`), deduplicates per `(entity, scenario_tag)` in Stage 1, enforces `distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) and `capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`) in Stage 2, and joins raw Windows endpoint telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Windows Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Obfuscated PowerShell, Script-Block & LOLBin Execution** | Detects known malicious command-line flags, encoded PowerShell arguments, and common LOLBin invocation patterns. | Screens unusually long, rare command lines ($\ln(\text{len}) + \ln(1 + N_{\text{host}}/N_{\text{cmd}}) \ge 5.0$, fleet prevalence $\le 3$) and scores Laplace-smoothed Markov 2-gram parent-to-child process transition surprisal ($\ge 3.8$). | `Query 1A` (`LONG_STRING_SCREEN`)<br>`Query 1B` (`MARKOV_2GRAM_TRANSITION_RARITY`) |
| **2. Credential Dumping, Info-Stealers & Lateral Authentication** | Flags known credential-access tools, LSASS access patterns, and explicit pass-the-hash or brute-force signatures. | Fuses 30-day host authentication failure and success Z-scores on a shared union spine ($D^2 \ge 12.25$, $\ge 7$ active days) with Wave 2 zero-inclusive hourly Poisson Fano burst clustering ($F = \sigma^2/\mu \ge 4.0$ over $T = 24$ hours). | `Query 2A` (`DUAL_SECTOR_FUSION_3STAGE`)<br>`Query 2B` (`POISSON_BURST_CLUSTERING`) |
| **3. Emerging Malware, RATs & Trojanized Payload Drops** | Matches known malware family file paths, registry keys, and command-and-control signatures. | Joins 30-day per-(host, SHA256) `metrics.file_executions_total` Z-scores ($Z \ge 3.0$, $\ge 7$ active days) with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`), paired with Wave 2 cross-bucket flow-gap ratio screening ($\text{CV}_{\text{gap}} \le 0.20$). | `Query 3A` (`HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE`)<br>`Query 3B` (`FLOW_GAP_RATIO_SCREEN`) |
| **4. Security Downgrade, Defender Tampering & Persistence** | Alerts on explicit commands that disable endpoint protection, modify services, or register scheduled tasks. | Unifies pure host-prevalence Zipfian IDF rarity ($\ln(N_{\text{fleet}}/N_{\text{adopters}}) \ge 3.5$ for binaries on $\le 2$ hosts) with 14-day Leave-One-Out discrete Poisson rarity ($Z \ge 3.0$) on dormant Windows administrative utilities. | `Query 4` (`POISSON_RARE_SURGE` + `ZIPFIAN_PROCESS_RARITY`) |
| **5. Ransomware Staging, Mass Encryption & Vendor Alert Escalation** | Monitors shadow-copy deletion, ransomware notes, and high-severity endpoint vendor alerts. | Combines 14-day non-parametric MAD Modified Z-Score ($M_Z > 3.5$, $\ge 7$ active days) on daily file modification/creation/deletion volume with Roll-Up EDR Alert + Outbound Network Bytes fusion ($D^2 \ge 12.25$ with $\sqrt{2\ln K_{\text{eff}}}$ multiplicity offset). | `Query 5A` (`MAD_MODIFIED_Z`)<br>`Query 5B` (`ROLLUP_SECTOR_FUSION`) |
| **6. Capstone Multi-Scenario Windows Host Convergence** | Individual endpoint rules evaluated per event or within short tactical windows. | Correlates entities matching $\ge 2$ distinct upstream hunt queries within the active `run_id` (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) with $\sum Z_i^2 \ge 25.0$ and pivots directly into raw process, network, file, and login telemetry. | `Query 6` (Wave 3 UDM Loopback $L_2$ Capstone) |
| **7. EventLog Delay Tampering & Staged Egress Quantile Shape** | Static volume thresholds on outbound transfers or missing-log heartbeats. | Combines 30-day `metrics.network_bytes_outbound` ($Z \ge 3.0$) with per-flow $P_{90}/P_{50}$ tail burst ratios ($\ge 10.0$), plus single-stage `window.percentile` ingestion-lag and Bowley skewness auditing per `log_type`. | `Query 7A` (30d Egress Z + $P_{90}/P_{50}$ Shape)<br>`Query 7B` (Ingestion-Lag & Clock-Skew Audit) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Obfuscated PowerShell, Script-Block Execution & LOLBin Command-Line Evasion

* **Curated Detection Operational Focus**: Detects known malicious command-line flags, encoded PowerShell arguments, and common LOLBin invocation patterns.
* **How Multi-Stage UEBA Extends Coverage**: Screens unusually long, host-rare and fleet-rare script/LOLBin command lines (`LONG_STRING_SCREEN`), paired with whole-window Laplace-smoothed Markov 2-gram parent-to-child process transition surprisal (`MARKOV_2GRAM_TRANSITION_RARITY`).

#### Query 1A: Long-String & Rare-Token Candidate Screen on Windows Script & LOLBin Command Lines (`secops-statistical-hunter`)
Because YARA-L 2.0 cannot split strings into per-character frequency distributions inline, `Query 1A` implements the `LONG_STRING_SCREEN` pre-filter across Windows script interpreters and LOLBins (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`): it combines log command-line byte length ($\ln(\text{length})$ for $\text{length} \ge 64$) with within-host inverse token frequency ($\ln(1 + \text{total\_events} / \text{token\_count})$) and enterprise fleet prevalence ($\le 3$ hosts) to surface candidate obfuscated commands ($\text{score} \ge 5.0$). Exact per-character Shannon entropy ($H(X) = -\sum p_i \log_2 p_i$) is evaluated post-query via `SHANNON_ENTROPY_CHARACTER` (`micro_python_helpers.py shannon`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long and rare Windows script interpreter and LOLBin command lines across endpoints.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH on Windows script interpreters and LOLBins)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN: score = ln(length) + ln(1 + total_events / token_count) >= 5.0; exact per-character entropy uses SHANNON_ENTROPY_CHARACTER + micro_python_helpers.py shannon)
// ============================================================================

// Stage 1: Windows script and LOLBin daily event volume per host
stage entity_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    re.regex(target.process.file.full_path, `(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$`)

  match:
    $entity by 1d

  outcome:
    $total_events = count(metadata.id)
}

// Stage 2: Command-line token frequency and length observation per (host, command_line)
stage token_observation {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $token = target.process.command_line
    $token != ""
    strings.length($token) >= 64
    re.regex(target.process.file.full_path, `(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$`)

  match:
    $entity, $token by 1d

  outcome:
    $token_count = count(metadata.id)
    $token_length = max(strings.length($token))
    $distinct_bins = count_distinct(target.process.file.full_path)
}

// Stage 3: Enterprise fleet prevalence of each distinct command-line token across hosts
stage token_fleet_prevalence {
    $token = $token_observation.token
    $ws = $token_observation.window_start

  match:
    $token, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($token_observation.entity)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring & 6 Evidence Pillars
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
  $rarity_lift = math.log(1.0 + (1.0 * $safe_total / $safe_tok))
  $shannon_entropy_score = $log_len + $rarity_lift

  // 6 Core Evidence Pillars
  $observation_count = $token_executions
  $baseline_active_samples = $total_activity
  $baseline_mean = $raw_length
  $baseline_dispersion = $log_len
  $fleet_prevalence = max($token_fleet_prevalence.fleet_hosts)
  $distinct_binaries = max($token_observation.distinct_bins)

condition:
  $raw_length >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 5.0

order:
  $shannon_entropy_score desc
```

#### Query 1B: Markov 2-Gram Parent-to-Child Process Transition Surprisal for Windows Services, Office & Browsers Spawning Shells/LOLBins (`secops-statistical-hunter`)
Detects rare execution chains where Windows system services (`svchost.exe`, `wmiprvse.exe`, `services.exe`, `taskeng.exe`), Microsoft Office applications (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `msaccess.exe`), or browsers spawn shells and LOLBins by computing whole-window Laplace-smoothed conditional transition probability $P(\text{Child} \mid \text{Parent}) = (N_{\text{pair}} + 1.0) / (N_{\text{parent}} + 100.0)$ and **Information Surprisal** $\ln((N_{\text{parent}} + 100.0) / (N_{\text{pair}} + 1.0)) \ge 3.8$ on parents with at least 5 launches in the window.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process transitions where Windows services, Office apps, or browsers spawn shells and LOLBins via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (MARKOV_2GRAM_TRANSITION_RARITY: Score = ln((N_parent + 100.0) / (N_pair + 1.0)) >= 3.8)
// ============================================================================

// Stage 1: Whole-window parent process launch totals per host across all child spawns
stage parent_window_totals {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""
    re.regex(principal.process.file.full_path, `(?i)(svchost|wmiprvse|services|taskeng|winword|excel|powerpnt|outlook|msaccess|chrome|msedge|firefox)\.exe$`)

  match:
    $host, $parent

  outcome:
    $total_parent_launches = count(metadata.id)
}

// Stage 2: Bucketed suspicious child transition activity per (host, parent, child)
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex(principal.process.file.full_path, `(?i)(svchost|wmiprvse|services|taskeng|winword|excel|powerpnt|outlook|msaccess|chrome|msedge|firefox)\.exe$`)
    re.regex(target.process.file.full_path, `(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|cmstp|installutil|atbroker|certoc|cmdl32)\.exe$`)

  match:
    $host, $parent, $child by 1d

  outcome:
    $transition_count = count(metadata.id)
    $sample_command = array_distinct(target.process.command_line)
}

// Stage 3: Whole-window pair transition totals per (host, parent, child)
stage pair_window_totals {
    $host = $child_transition.host
    $parent = $child_transition.parent
    $child = $child_transition.child

  match:
    $host, $parent, $child

  outcome:
    $total_pair_launches = sum($child_transition.transition_count)
}

// Root Stage: Laplace-Smoothed Markov Conditional Probability & Information Surprisal
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
  $window_pair_launches = max($pair_window_totals.total_pair_launches)
  $window_parent_launches = max($parent_window_totals.total_parent_launches)
  $sample_commands = array_distinct($child_transition.sample_command)

  // Laplace-Smoothed Conditional Transition Probability P(Child | Parent) & Surprisal (V = 100.0)
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
  $window_parent_launches >= 5
  and $markov_threat_score >= 3.8

order:
  $markov_threat_score desc
```

---

### Scenario 2: Credential Dumping, Info-Stealers & Lateral Authentication Abuse

* **Curated Detection Operational Focus**: Flags known credential-access tools, LSASS access patterns, and explicit pass-the-hash or brute-force signatures.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day host authentication failure and success Z-scores on a shared single-stage union spine ($D^2 \ge 12.25$), then uses Wave 2 UDM Loopback to evaluate zero-inclusive hourly Poisson Fano burst clustering ($F = \sigma^2/\mu \ge 4.0$) across credential and discovery tools on candidate hosts.

#### Query 2A: Dual-Sector Host Authentication Failure + Success Fusion (`secops-risk-metrics-multistage`)
Evaluates `metrics.auth_attempts_fail` and `metrics.auth_attempts_success` keyed on `principal.asset.hostname` over a single `USER_LOGIN` union spine so extreme single-sector spikes survive even if the companion sector records zero events on scored day `D`. Each sector applies the $\sqrt{\max(\mu, 1)}$ count dispersion floor, positive rectification, and $\ge 7$ active-day maturity gate before computing $D^2 = Z_{\text{fail}}^2 + Z_{\text{success}}^2 \ge 12.25$ (note that both metrics belong to the authentication family, so correlated spray-then-login bursts exceed independent $\chi^2_2$ tail rates).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect post-credential-dump lateral authentication spraying and pass-the-hash progression on Windows hosts without dropping single-sector outliers.
// Statistical Model: Dual-Sector Euclidean Risk Fusion (DUAL_SECTOR_FUSION_3STAGE: D^2 = Z_fail^2 + Z_success^2 >= 12.25)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (SINGLE-STAGE UNION: HOST AUTH FAIL + HOST AUTH SUCCESS)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Inter-sector correlation (WS7-03): 'auth_attempts_fail' and 'auth_attempts_success' both belong to the auth family, so correlated bursts exceed independent chi-square tail rates.
// ============================================================================

// --- STAGE 1: Single-Stage Sector Union (UDM Source 1 of 2; preserves single-sector outliers) ---
stage sector_union {
    ((metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW") or (metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW"))
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if(metadata.event_type = "USER_LOGIN" and not security_result.action = "ALLOW", 1, 0))
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

    $b_obs = sum(if(metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW", 1, 0))
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

// --- STAGE 2: Per-Sector Dispersion Floor, Rectification & 7-Day Maturity Gate (Stage-to-Stage) ---
stage sector_scores {
    $entity = $sector_union.entity
    $ws = $sector_union.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = max($sector_union.a_obs)
    $a_avg = max($sector_union.a_avg)
    $a_std = max($sector_union.a_std)
    $a_days = max($sector_union.a_days)
    $a_floor = math.sqrt(if($a_avg > 1.0, $a_avg, 1.0))
    $a_safe_std = if($a_std > $a_floor, $a_std, $a_floor)
    $z_a_raw = ($a_obs - $a_avg) / $a_safe_std
    $z_a_pos = if($z_a_raw > 0, $z_a_raw, 0.0)
    $z_a = if($a_obs > 0 and $a_days >= 7, $z_a_pos, 0.0)

    $b_obs = max($sector_union.b_obs)
    $b_avg = max($sector_union.b_avg)
    $b_std = max($sector_union.b_std)
    $b_days = max($sector_union.b_days)
    $b_floor = math.sqrt(if($b_avg > 1.0, $b_avg, 1.0))
    $b_safe_std = if($b_std > $b_floor, $b_std, $b_floor)
    $z_b_raw = ($b_obs - $b_avg) / $b_safe_std
    $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
    $z_b = if($b_obs > 0 and $b_days >= 7, $z_b_pos, 0.0)
}

// --- ROOT STAGE: Dual-Sector Threat Fusion & Euclidean Distance Scoring ---
$entity = $sector_scores.entity
$ws = $sector_scores.ws

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_scores.a_obs)
  $a_mean = max($sector_scores.a_avg)
  $a_active_days = max($sector_scores.a_days)
  $b_observed = max($sector_scores.b_obs)
  $b_mean = max($sector_scores.b_avg)
  $b_active_days = max($sector_scores.b_days)

  $z_a_gated = max($sector_scores.z_a)
  $z_b_gated = max($sector_scores.z_b)

  // Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $z_a_sq = $z_a_gated * $z_a_gated
  $z_b_sq = $z_b_gated * $z_b_gated
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

#### Query 2B: 4-Stage UDM-Gated Zero-Inclusive Poisson Fano Factor Burst Clustering on Windows Credential-Access & Discovery (`secops-statistical-hunter`)
Executes in **Wave 2** strictly on candidate Windows hosts surfaced by `Query 2A` (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`), aggregates credential-access and discovery `PROCESS_LAUNCH` activity `by 1h`, and reconstructs the **zero-inclusive** mean $\mu = \sum x_h / 24$ and variance $\sigma^2 = (\sum x_h^2 / 24) - \mu^2$ across $T = 24$ hourly slots so concentrated discovery flurries separated by quiet hours produce a high Fano factor ($F = \sigma^2 / \mu \ge 4.0$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED ZERO-INCLUSIVE POISSON FANO FACTOR BURST CLUSTERING PIPELINE
// Goal: Detect automated credential harvesting and post-exploitation discovery bursts on candidate Windows hosts from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Zero-Inclusive Poisson Index of Dispersion (POISSON_BURST_CLUSTERING: F = sigma^2 / mu >= 4.0 over T = 24 hourly buckets)
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
    $hourly_events = count(metadata.id)
    $hourly_events_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.process.file.full_path)
    $sample_tools = array_distinct(target.process.file.full_path)
}

stage host_dispersion {
    $host = $hourly_bursts.host

  match:
    $host

  outcome:
    $sum_x = sum($hourly_bursts.hourly_events)
    $sum_x2 = sum($hourly_bursts.hourly_events_sq)
    $peak_hourly = max($hourly_bursts.hourly_events)
    $active_hours = count($hourly_bursts.window_start)
    $max_distinct_targets = max($hourly_bursts.distinct_targets)
}

$host = $stage1_upstream_2a_candidates.host
$host = $hourly_bursts.host
$host = $host_dispersion.host

match:
  $host

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
  $sum_x = max($host_dispersion.sum_x)
  $sum_x2 = max($host_dispersion.sum_x2)

  // Reconstruct zero-inclusive mean and variance across T = 24 hourly buckets
  $zero_incl_mean = 1.0 * $sum_x / 24.0
  $mean_sq = 1.0 * $sum_x2 / 24.0
  $raw_var = $mean_sq - ($zero_incl_mean * $zero_incl_mean)
  $zero_incl_var = if($raw_var > 0.0, $raw_var, 0.0)
  $zero_incl_sd = math.sqrt($zero_incl_var)
  $safe_mean = if($zero_incl_mean > 0.0, $zero_incl_mean, 1.0)
  $raw_fano = $zero_incl_var / $safe_mean
  $fano_factor = if($zero_incl_mean > 0.0, $raw_fano, 0.0)

  // 6 Core Evidence Pillars (fleet_prevalence = -1 sentinel: candidate-gated pipeline has no fleet stage)
  $observation_count = $sum_x
  $baseline_active_samples = max($host_dispersion.active_hours)
  $baseline_mean = $zero_incl_mean
  $baseline_dispersion = $zero_incl_sd
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_dispersion.max_distinct_targets)
  $peak_burst = max($host_dispersion.peak_hourly)
  $sample_commands = array_distinct($hourly_bursts.sample_tools)

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 6
  and $baseline_mean >= 0.25
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

---

### Scenario 3: Named Malware, RATs, Emerging Threats & Trojanized Drops

* **Curated Detection Operational Focus**: Matches known malware family file paths, registry keys, and command-and-control signatures.
* **How Multi-Stage UEBA Extends Coverage**: Scores per-(host, SHA256) process execution surges against mature 30-day `metrics.file_executions_total` baselines joined with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`), paired with Wave 2 UDM-gated cross-bucket flow-gap ratio screening ($\text{CV}_{\text{gap}} \le 0.20$) on external outbound connections.

#### Query 3A: 2-Stage Hybrid 30-Day Process Execution (`metrics.file_executions_total`) + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Runs over the Mode A Entity Graph freshness window (`startTime = D-2 T00:00:00Z`, `endTime = D+1 T00:00:00Z`) with Stage 1 pinned to scored UTC day `D` (`timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"`). Stage 1 compares per-(host, SHA256) `PROCESS_LAUNCH` counts against `metrics.file_executions_total` ($\ge 7$ active baseline days, $\sqrt{\max(\mu, 1)}$ dispersion floor, $Z \ge 3.0$), Stage 2 inner-joins `DERIVED_CONTEXT` `FILE` 10-day prevalence (`day_count = 10`, `0 < rolling_max <= 3`), and Root applies an epoch-zero-guarded binary age multiplier (`2.5x` when `first_seen_time > 0` and binary age $\le 7$ days; `1.5x` otherwise). Because `DERIVED_CONTEXT` is an inner join, Day-0 binaries not yet materialized in the Entity Graph drop out and are covered by `Query 4`'s fleet-rarity branch.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect execution surges of rare Windows binaries (10-day org DERIVED_CONTEXT prevalence <= 3 hosts) on mature host-binary baselines.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence (HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE)
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ENTITY GRAPH WINDOW: Run with startTime = D-2 T00:00:00Z, endTime = D+1 T00:00:00Z; pin Stage 1 to scored UTC day D (YYYY-MM-DD).
// FILTER NOTE: Stage 2 is an inner join; Day-0 binaries absent from DERIVED_CONTEXT drop out (pair with first_seen_novelty_2stage.yl2).
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total) pinned to Mode A scored UTC day D
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29" // Mode A scored UTC day D (YYYY-MM-DD)
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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Binary Prevalence & First Seen)
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

// Stage 3 (Root Stage): Fuses Personal Outlier Z-Score with Enterprise Prevalence Multiplier
$host = $stage1_process_baseline.host
$sha256 = $stage1_process_baseline.sha256
$sha256 = $stage2_file_derived_context.sha256

match:
  $host, $sha256 by 1d

outcome:
  $observed_execs = max($stage1_process_baseline.observed_val)
  $mean_execs = max($stage1_process_baseline.hist_mean)
  $stddev_execs = max($stage1_process_baseline.hist_stddev)
  $dispersion_floor = math.sqrt(if($mean_execs > 1.0, $mean_execs, 1.0))
  $safe_std = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_std
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  // Guarded binary age: when first_seen_time = 0 (unpopulated), <7d ECG novelty boost is disabled (WS1-08)
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

#### Query 3B: 4-Stage UDM-Gated Cross-Bucket Flow-Gap Ratio Screen on Windows Outbound Callbacks (`secops-statistical-hunter`)
Executes in **Wave 2** on candidate Windows endpoints surfaced by `Query 3A` (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`), excludes internal RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local destinations, computes the hourly span-to-count flow-gap proxy $(\max(t) - \min(t)) / N$ per `(host, target_ip)`, and screens persistent external destinations ($\ge 6$ active hours, $\ge 20$ connections) whose cross-hour flow-gap dispersion satisfies $\text{CV}_{\text{gap}} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$. Exact consecutive inter-arrival C2 sleep jitter requires event-level sorted timestamps via `C2_BEACONING_JITTER` (`micro_python_helpers.py c2-jitter`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED CROSS-BUCKET FLOW-GAP RATIO SCREEN PIPELINE
// Goal: Screen persistent external callback pairs with uniform hourly flow-gap ratios (CV_gap <= 0.20) on candidate Windows hosts from Query 3A (strictly gated by Query 3A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN: CV = sigma_gap / mu_gap <= 0.20; exact consecutive inter-arrival C2 jitter uses C2_BEACONING_JITTER + micro_python_helpers.py c2-jitter)
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
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($timing_stats.total_conns)
  $total_outbound_bytes = max($timing_stats.total_sent_bytes)

  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 20
  and $baseline_mean >= 1.0
  and $cv <= 0.20

order:
  $cv asc
```

---

### Scenario 4: Security Downgrade, Defender Tampering & Persistence Mechanisms

* **Curated Detection Operational Focus**: Alerts on explicit commands that disable endpoint protection, modify services, or register scheduled tasks.
* **How Multi-Stage UEBA Extends Coverage**: Unifies pure host-prevalence Zipfian Inverse Document Frequency rarity ($\ln(N_{\text{fleet}} / N_{\text{adopters}}) \ge 3.5$) on fleet-rare binaries with Leave-One-Out discrete Poisson rarity ($Z \ge 3.0$) on dormant built-in Windows utilities over a bounded 14-day Mode B window.

#### Query 4: Unified Personal Leave-One-Out Poisson Rarity & Host-Prevalence Zipfian IDF on Windows Persistence, Tampering & Cryptominers (`secops-statistical-hunter`)
Evaluates daily `PROCESS_LAUNCH` telemetry (`$entity, $tool by 1d`) over a bounded 14-day Mode B window (with an optional commented-out `%windows_admin_jump_hosts.hostname` Data Table exclusion for build or jump servers) and combines two regimes in Root (`$unified_threat_score = if($fleet_prevalence <= 2, $zipf_rarity_score, $poisson_z)`):
- **Branch B — Fleet-Rare Custom Persistence / Cryptominer Binaries (`$fleet_prevalence <= 2` across $\ge 35$ active Windows hosts)**: Scores pure host-prevalence Zipfian IDF $\ln(N_{\text{fleet\_hosts}} / N_{\text{adopter\_hosts}}) \ge 3.5$ with `$observation_count >= 5`.
- **Branch A — Dormant Built-In Tampering Utilities (`$fleet_prevalence >= 3`, prior rate $\lambda \le 0.5\text{/day}$)**: Computes Leave-One-Out standardized Poisson Z-score $(k - \lambda) / \sqrt{\max(\lambda, 0.01)} \ge 3.0$ where $\lambda = (\text{prior\_runs} + 0.5) / 13.0$ over the 13 prior days and `$distinct_binaries >= 2` distinct command lines.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Unify fleet-rare persistence/cryptominer binaries (Zipfian host IDF <= 2 hosts) and personal Leave-One-Out Poisson rarity on Windows tampering utilities (sc, schtasks, wevtutil, vssadmin, bcdedit) in a single pipeline.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH over bounded 14-day Mode B window)
// Statistical Model: Option 1 Piecewise Leave-One-Out Discrete Poisson Rarity (POISSON_RARE_SURGE) + Host-Prevalence Zipfian IDF Rarity (ZIPFIAN_PROCESS_RARITY: ln(N_fleet_hosts / N_adopter_hosts))
// ============================================================================

// Stage 1: Daily execution counts per Windows host and binary path (UDM Source 1 of 2)
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""
    // Optional build / jump-host allowlist Data Table filter (commented out so unpopulated tables never break compilation):
    // not $entity in %windows_admin_jump_hosts.hostname

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

// Stage 3: Daily active Windows fleet host population (UDM Source 2 of 2)
stage fleet_host_total {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $etype = metadata.event_type

  match:
    $etype by 1d

  outcome:
    $total_fleet_hosts = count_distinct($host)
}

// Stage 4: Enterprise fleetwide binary adopter breadth joined with daily fleet population
stage fleet_process_popularity {
    $tool = $daily_tool_counts.tool
    $ws = $daily_tool_counts.window_start
    $ws = $fleet_host_total.window_start

  match:
    $tool, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($daily_tool_counts.entity)
    $total_fleet_hosts = max($fleet_host_total.total_fleet_hosts)
}

// Root Stage: Option 1 Piecewise Personal LOO Poisson Rarity & Pure Host-Prevalence Zipfian IDF
$entity = $daily_tool_counts.entity
$entity = $baseline_accumulation.entity
$tool = $daily_tool_counts.tool
$tool = $baseline_accumulation.tool
$tool = $fleet_process_popularity.tool
$ws = $daily_tool_counts.window_start
$ws = $fleet_process_popularity.ws

match:
  $entity, $tool, $ws by 1d

outcome:
  $observation_count = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $baseline_active_samples = max($baseline_accumulation.active_days)
  $fleet_prevalence = max($fleet_process_popularity.fleet_hosts)
  $fleet_total_hosts = max($fleet_process_popularity.total_fleet_hosts)
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)
  $commands = array_distinct($daily_tool_counts.sample_commands)

  // Branch A: Standardized Leave-One-Out Discrete Poisson Z over 14-day Mode B window (13 prior calendar days)
  $raw_prior_runs = $total_hist - $observation_count
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $baseline_mean = ($prior_runs + 0.5) / 13.0
  $safe_lambda = if($baseline_mean > 0.01, $baseline_mean, 0.01)
  $sqrt_lambda = math.sqrt($safe_lambda)
  $poisson_z_raw = ($observation_count - $baseline_mean) / $sqrt_lambda
  $poisson_z = if($poisson_z_raw > 0.0, $poisson_z_raw, 0.0)

  // Branch B: Pure Host-Prevalence Zipfian Inverse Document Frequency Rarity ln(N_fleet_hosts / N_adopter_hosts)
  $safe_hosts = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $safe_fleet_hosts = if($fleet_total_hosts > $safe_hosts, $fleet_total_hosts, $safe_hosts)
  $zipf_rarity_score = math.log(1.0 * $safe_fleet_hosts / $safe_hosts)
  $baseline_dispersion = $zipf_rarity_score

  // Option 1 Piecewise Regime Switch
  $unified_threat_score = if($fleet_prevalence <= 2, $zipf_rarity_score, $poisson_z)

condition:
  $observation_count >= 2
  and (
    ($fleet_prevalence <= 2 and $safe_fleet_hosts >= 35 and $observation_count >= 5 and $unified_threat_score >= 3.5)
    or ($fleet_prevalence >= 3 and $baseline_mean <= 0.5 and $distinct_binaries >= 2 and $unified_threat_score >= 3.0)
  )

order:
  $unified_threat_score desc
```

---

### Scenario 5: Ransomware Staging, Mass File Encryption & Vendor Alert Escalation

* **Curated Detection Operational Focus**: Monitors shadow-copy deletion, ransomware notes, and high-severity endpoint vendor alerts.
* **How Multi-Stage UEBA Extends Coverage**: Pairs a 14-day non-parametric MAD Modified Z-Score ($M_Z > 3.5$) on daily Windows file churn (`Query 5A`) with a Roll-Up Sector Fusion combining per-rule EDR alert velocity (`metrics.alert_event_name_count` with Gaussian multiplicity adjustment $\sqrt{2\ln K_{\text{eff}}}$) and 30-day outbound byte surges (`metrics.network_bytes_outbound`) on the same host (`Query 5B`).

#### Query 5A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Windows File Modification, Creation & Deletion Churn (`secops-statistical-hunter`)
Computes each Windows host's active-day **Median** and **Median Absolute Deviation (MAD)** over daily `FILE_MODIFICATION`, `FILE_CREATION`, and `FILE_DELETION` volume across a bounded 14-day Mode B window—using the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) when $\text{MAD} = 0$, a `10.0` constant-history scale floor, and a $\ge 7$ active-day baseline maturity gate ($\ge 250$ daily events, $M_Z > 3.5$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect ransomware mass file encryption, archive staging, and destructive wiper activity on Windows hosts via non-parametric MAD Modified Z-Score.
// Target Telemetry: UDM_EVENTS (FILE_MODIFICATION, FILE_CREATION, FILE_DELETION over bounded 14-day Mode B window)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Modified Z-Score (MAD_MODIFIED_Z: Iglewicz & Hoaglin M_Z > 3.5, Active Days >= 7)
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
    $mod_events = sum(if(metadata.event_type = "FILE_MODIFICATION", 1, 0))
    $create_events = sum(if(metadata.event_type = "FILE_CREATION", 1, 0))
    $delete_events = sum(if(metadata.event_type = "FILE_DELETION", 1, 0))
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

// Stage 3: MAD, mean absolute deviation (Iglewicz-Hoaglin MAD=0 fallback), and baseline depth per host
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
  $mod_count = max($daily_stats.mod_events)
  $create_count = max($daily_stats.create_events)
  $delete_count = max($daily_stats.delete_events)
  $sample_commands = array_distinct($daily_stats.sample_data)

  // Robust scale with Iglewicz-Hoaglin MAD=0 fallback and 10.0 constant-history floor
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 10.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 250
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

#### Query 5B: Roll-Up Endpoint Alert (`metrics.alert_event_name_count`) + Outbound Network Bytes (`metrics.network_bytes_outbound`) Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Fuses 30-day per-rule EDR alert baselines (`metrics.alert_event_name_count` across `CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, and `SENTINELONE_ALERTS`) with 30-day outbound byte surges (`metrics.network_bytes_outbound`) on a shared union spine so single-sector outliers survive when the companion sector is inactive. Sector A applies a $\sqrt{\max(\mu, 1)}$ dispersion floor and $\ge 7$ active-day gate per `(host, rule_name)`, rolls up the maximum per-rule Z per host, and subtracts the Gaussian multiplicity offset $\sqrt{2\ln K_{\text{eff}}}$ across $K_{\text{eff}}$ active alert rules; Sector B applies the `44979.0` fleet byte dispersion floor and $\ge 7$ active-day gate; Root fires on $D^2 = Z_a^2 + Z_b^2 \ge 12.25$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day Windows EDR alert anomalies with outbound network byte surges on the same host to detect double-extortion ransomware and full kill-chain progression.
// Statistical Model: Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D^2 = Z_a^2 + Z_b^2 >= 12.25)
// ARCHITECTURE: ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC ON SHARED UNION SPINE)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A rolls alert_event_name_count up from per-(security_result.rule_name) baselines with Gaussian expected-maximum offset sqrt(2*ln(K_eff)) (WS7-03); its Z is the largest adjusted per-rule Z for the host, not total alert volume.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2, union spine): one row per host and companion rule_name ---
stage sector_a_detail {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""
    security_result.rule_name = $security_result_rule_name

  match:
    $entity, $security_result_rule_name by 1d

  outcome:
    $d_obs = sum(if((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "", 1, 0))
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
}

// --- STAGE 2: Sector A per-rule Z-scores with Poisson dispersion floor & 7-day maturity gate (stage-to-stage) ---
stage sector_a_scores {
    $entity = $sector_a_detail.entity
    $security_result_rule_name = $sector_a_detail.security_result_rule_name
    $ws = $sector_a_detail.window_start

  match:
    $entity, $security_result_rule_name, $ws by 1d

  outcome:
    $d_obs = max($sector_a_detail.d_obs)
    $d_avg = max($sector_a_detail.d_avg)
    $d_std = max($sector_a_detail.d_std)
    $d_days = max($sector_a_detail.d_days)
    $d_floor = math.sqrt(if($d_avg > 1.0, $d_avg, 1.0))
    $d_safe_std = if($d_std > $d_floor, $d_std, $d_floor)
    $d_z_raw = ($d_obs - $d_avg) / $d_safe_std
    $d_z_pos = if($d_z_raw > 0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

// --- STAGE 3: Sector A roll-up (stage-to-stage): one row per host with K-key multiplicity offset ---
stage sector_a {
    $entity = $sector_a_scores.entity
    $ws = $sector_a_scores.ws

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_scores.d_obs)
    $a_keys = count_distinct($sector_a_scores.security_result_rule_name)
    $a_active_keys = sum($sector_a_scores.d_active)
    $a_hot_keys = sum($sector_a_scores.d_hot)
    $a_novel_keys = sum($sector_a_scores.d_novel)
    $a_days = max($sector_a_scores.d_days)
    $z_a_max = max($sector_a_scores.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

// --- STAGE 4: Sector B — Outbound Network Bytes (UDM Source 2 of 2, union spine so single-sector Sector A rows survive) ---
stage sector_b {
    (((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, network.sent_bytes, 0.0))
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
}

// --- ROOT STAGE: Roll-Up Sector Fusion & Distance Scoring ---
$entity = $sector_a.entity
$entity = $sector_b.entity
$ws = $sector_a.ws
$ws = $sector_b.window_start

match:
  $entity, $ws by 1d

outcome:
  $a_observed = max($sector_a.a_obs)
  $a_keys = max($sector_a.a_keys)
  $a_hot_keys = max($sector_a.a_hot_keys)
  $a_novel_keys = max($sector_a.a_novel_keys)
  $b_observed = max($sector_b.b_obs)
  $b_mean = max($sector_b.b_avg)
  $b_stddev = max($sector_b.b_std)
  $b_active_days = max($sector_b.b_days)

  // Sector A multiplicity-adjusted Z + Sector B byte-floor-guarded Z (44979.0 B fleet floor, >= 7 active days)
  $z_a = max($sector_a.z_a)
  $b_floor = 44979.0
  $b_safe_std = if($b_stddev > 44979.0, $b_stddev, 44979.0)
  $z_b_raw = ($b_observed - $b_mean) / $b_safe_std
  $z_b_pos = if($z_b_raw > 0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

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

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` UDM Loopback)

* **Curated Detection Operational Focus**: Individual endpoint rules evaluated per event or within short tactical windows.
* **How Multi-Stage UEBA Extends Coverage**: Correlates Windows entities accumulating $\ge 2$ distinct behavioral hunt matches within the active `run_id` (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean norm ($\sum Z_i^2 \ge 25.0$) and bridges matching entities into raw endpoint telemetry for immediate triage.

**`Query 6`** executes in **Wave 3** after all **Wave 1** (`Queries 1A, 1B, 2A, 3A, 4, 5A, 5B, 7A`) and **Wave 2** (`Queries 2B, 3B`) stages have exported their findings into Chronicle's `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Per-Scenario Deduplication (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for `$run_id` across `re.regex(security_result.rule_name, `:q[0-9]+_query_(?:[1-5]|7)`)` and deduplicates per `($entity, $scenario_tag)`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct matched query tags (`$distinct_scenarios_matched >= 2`) and summing squared Z-scores (`$capstone_threat_norm_sq >= 25.0`, emitting `$capstone_threat_score = math.sqrt($capstone_threat_norm_sq)`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Aggregates raw `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `FILE_MODIFICATION`, and `USER_LOGIN` events by `$entity` and joins with Stage 2 in Root to surface per-domain event counts, distinct process paths, and total outbound bytes.

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all upstream Windows Threats queries via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_(?:[1-5]|7)`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.asset.hostname, principal.user.userid, principal.ip[0])
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
        metadata.event_type = "FILE_MODIFICATION" or
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
    $file_events = sum(if(metadata.event_type = "FILE_MODIFICATION", 1, 0))
    $auth_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
    $distinct_event_types = count_distinct(metadata.event_type)
    $sample_processes = array_distinct(target.process.file.full_path)
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
  $file_events = max($stage3_raw_forensic_pivot.file_events)
  $auth_events = max($stage3_raw_forensic_pivot.auth_events)
  $distinct_event_types = max($stage3_raw_forensic_pivot.distinct_event_types)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_score desc
```

---

## 3. Windows Event Log (`WINEVTLOG`) Delay Tampering & Staged Egress Quantile Shape (`window.percentile`)

Windows intruders frequently (1) exfiltrate staged `.cab`/`.7z` archives over heavy-tailed outbound flows (`$p90_bytes / $p50_bytes >= 10.0`) or (2) suspend EventLog threads, stall log forwarders, or roll back system clocks during credential access.
* **`Query 7A`**: Combines 30-day `metrics.network_bytes_outbound` ($Z \ge 3.0$ with the `44979.0` fleet byte dispersion floor over $\ge 7$ active baseline days) with intra-bucket per-flow `$p50_bytes` and `$p90_bytes` (`window.percentile(network.sent_bytes, 50/90)`).
* **`Query 7B`**: Single-stage hourly quantile audit over `metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds` (`$p10, $p25, $p50, $p75, $p90`), Bowley quartile skewness $(P_{75} + P_{25} - 2P_{50}) / \text{IQR}$, and inter-decile tail heaviness $(P_{90} - P_{10}) / \text{IQR}$ per `$log_type` to flag negative clock skew ($P_{10} < 0$), forwarder stalls ($P_{90} \ge 300\text{ s}$), or heavy right-skewed buffering ($\text{Bowley skew} \ge 0.75$).

#### Query 7A: Windows Outbound Egress 30-Day Z + Intra-Bucket Per-Flow $P_{50}/P_{90}$ Shape (`secops-risk-metrics-multistage`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Combine 30-day metrics.network_bytes_outbound macro Z-score with intra-bucket per-flow P50/P90 payload quantile shape fingerprinting on Windows hosts.
// Statistical Model: Standard 30-Day Z-Score with Fleet Byte Dispersion Floor (44979.0 B) + Intra-Bucket Per-Flow P90/P50 Tail Burst Ratio
// Skill: secops-risk-metrics-multistage
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    $host != ""

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

  // Fleet byte dispersion floor for outbound network bytes: 44979.0 B
  $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  $safe_p50 = if($p50_bytes > 0, $p50_bytes, 1.0)
  $flow_tail_burst_ratio = $p90_bytes / $safe_p50

condition:
  $active_days >= 7
  and $personal_z >= 3.0
  and $flow_tail_burst_ratio >= 10.0

order:
  $personal_z desc
```

#### Query 7B: Windows Event Log Ingestion-Lag & Clock-Skew Quantile Audit (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Profile telemetry ingestion lag quantiles, Bowley skewness, and negative clock-skew / timestomp anomalies per log_type.
// Statistical Model: Single-Stage Non-Parametric Ingestion-Lag Quantile & Bowley Skewness Audit (window.percentile P10/P25/P50/P75/P90)
// Skill: secops-statistical-hunter
// ============================================================================

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

  $iqr = $p75 - $p25
  $bowley_num = $p75 + $p25 - (2 * $p50)
  $safe_iqr = if($iqr > 0, $iqr, 1.0)
  $bowley_skew = $bowley_num / $safe_iqr
  $idr = $p90 - $p10
  $tail_heaviness = $idr / $safe_iqr

condition:
  $event_count >= 10
  and ($p10 < 0 or $p90 >= 300 or $bowley_skew >= 0.75)

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
