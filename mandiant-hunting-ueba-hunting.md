# Extending Mandiant Hunting Rules with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Mandiant Hunting Rules** suite encodes frontline incident-response tradecraft across endpoint, cloud, network, and threat-intelligence domains—surfacing suspicious process lineage, living-off-the-land techniques, cloud control-plane anomalies, and reconnaissance patterns.

Because hunting rules are designed to surface investigative leads across diverse enterprise environments, combining them with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`) provides automatic per-entity baselining and statistical noise reduction. This playbook pairs Mandiant hunting domains with Markov 2-gram process surprisal, Shannon command-line entropy, Piecewise Hurdle + 30-day Cloud baselines, WHOIS lifecycle weighting, C2 jitter analysis, and UDM Loopback Capstone correlation.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Mandiant Hunting Rules & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Endpoint Process Lineage & Command-Line Tradecraft** | Hunts for suspicious parent-child process relationships, encoded scripts, and defense-evasion utilities on endpoints. | Quantifies parent-to-child process transition rarity via Markov 2-gram surprisal ($I = -\ln P(\text{Child}\mid\text{Parent}) \ge 3.5$) and measures multi-class character Shannon entropy ($H(X) \ge 4.0$) on command lines. | `Query 1A` (Markov 2-Gram Surprisal)<br>`Query 1B` (Command-Line Shannon Entropy) |
| **2. Cloud Control-Plane Hunting & Cross-Resource Scope** | Identifies anomalous cloud IAM, storage, and compute administration patterns across AWS, GCP, and Azure. | Unifies cold-start cloud identities (Two-Part Hurdle) with 30-day Cloud CRUD baselines (`Option 1`) and evaluates cross-service API transition surprisal. | `Query 2A` (Piecewise Hurdle + 30d Cloud CRUD)<br>`Query 2B` (Cloud API Markov Surprisal) |
| **3. Threat Intelligence & Newly Observed Infrastructure** | Correlates endpoint and network activity with emerging threat-intelligence context. | Combines 30-day HTTP volume baselines with event-relative WHOIS domain registration age and 30-day file execution baselines with 10-day `DERIVED_CONTEXT` binary prevalence. | `Query 3A` (30d HTTP + WHOIS Lifecycle)<br>`Query 3B` (30d Execution + 10d Prevalence) |
| **4. Covert C2 Beaconing & Fleet-Normalized Reconnaissance** | Hunts for periodic callback patterns and internal discovery bursts. | Detects robotic C2 beaconing with jitter via inter-arrival Coefficient of Variation ($\text{CV} \le 0.20$) and isolates host-specific discovery spikes via 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$). | `Query 4A` (C2 Inter-Arrival CV)<br>`Query 4B` (Dual-Baseline Fleet Delta-Z) |
| **5. Cross-Plane Exfiltration Drift & Multi-Signal Escalation** | Tracks staged data transfers and multi-signal hunt classifications. | Applies 4-stage non-parametric 30-day Median Absolute Deviation (MAD) and Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) to surface stealthy data exfiltration. | `Query 5A` (4-Stage 30d MAD Egress)<br>`Query 5B` (Producer-Consumer Inversion) |
| **6. Capstone Multi-Scenario Hunt Entity Convergence** | Individual hunting leads evaluated per telemetry domain. | Correlates entities matching $\ge 2$ distinct behavioral hunting scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Endpoint Identification & Classification — Process Lineage & Command-Line Entropy

* **Curated Detection Operational Focus**: Hunts for suspicious parent-child process relationships, encoded scripts, and defense-evasion utilities on endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Quantifies parent-to-child process transition rarity via Markov 2-gram surprisal ($I = -\ln P(\text{Child}\mid\text{Parent}) \ge 3.5$) and measures multi-class character Shannon entropy ($H(X) \ge 4.0$) on command lines.

#### Query 1A: Markov 2-Gram Parent-to-Child Process Transition Surprisal (`secops-statistical-hunter`)
Replaces hundreds of static parent-child identification rules by computing empirical conditional transition probability $P(\text{Child} \mid \text{Parent}) = \text{Count}(\text{Parent} \rightarrow \text{Child}) / \text{Count}(\text{Parent})$ and **Markov self-information surprisal** ($I = -\ln P(\text{Child} \mid \text{Parent}) \ge 3.0$) across all endpoint `PROCESS_LAUNCH` events.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare, anomalous parent-to-child process execution chains across endpoints via Markov 2-Gram Transition Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln P(Child | Parent) >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Parent Process Launch Baseline Frequency per Host
stage parent_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""

  match:
    $host, $parent by 1d

  outcome:
    $parent_total_launches = count(metadata.id)
}

// Stage 2: Parent-to-Child Process Transition Frequency per Host
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""

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

  // 3. Information Surprisal (Self-Information Rarity): I = -ln(P) = ln(Parent) - ln(Transition)
  $log_parent = math.log($safe_parent)
  $log_trans = math.log($safe_trans)
  $surprisal_score = $log_parent - $log_trans

  // 4. Rare Sequence Multiplier (Amplifies singleton/doubleton transitions from established parents)
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
  $parent_launches >= 20
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

#### Query 1B: Multi-Class Character Shannon Entropy on Endpoint Command Lines (`secops-statistical-hunter`)
Compensates for brittle command-line obfuscation regexes (`-enc`, `base64 -d`, PowerShell globbing) by computing 4-class character Shannon entropy ($H(X) = -\sum p_i \log_2 p_i$, scaled to byte-entropy equivalent $\ge 3.8$) and fleet host prevalence ($\le 3$ hosts) across endpoint `PROCESS_LAUNCH` command lines.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect obfuscated, Base64/Hex-encoded, or glob-masked process command lines across endpoints via Multi-Class Character Shannon Entropy.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) >= 3.8)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Extract command-line lengths and character-class counts per host and command line
stage cmd_feature_extraction {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""
    $cmd = target.process.command_line
    $cmd != ""
    strings.length($cmd) >= 64

  match:
    $host, $cmd by 1d

  outcome:
    $execution_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $raw_len = max(strings.length($cmd))
    $safe_len = if($raw_len > 0, $raw_len, 1)

    // Character-class counts via bracket-free regex replacement length deltas
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

// Root Stage: Compute 4-Class Shannon Entropy Score & 6 Core Evidence Pillars
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

  // 6 Core Evidence Pillars
  $observation_count = $exec_count
  $baseline_active_samples = $len
  $baseline_mean = $class_entropy
  $baseline_dispersion = $shannon_entropy_score
  $fleet_prevalence = max($cmd_fleet_prevalence.fleet_hosts)
  $distinct_binaries = max($cmd_feature_extraction.distinct_procs)

condition:
  $baseline_active_samples >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 3.8

order:
  $shannon_entropy_score desc
```

---

---

### Scenario 2: Cloud Identification & Classification — Multi-Cloud Resource Scope & Hurdle Crossing

* **Curated Detection Operational Focus**: Identifies anomalous cloud IAM, storage, and compute administration patterns across AWS, GCP, and Azure.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start cloud identities (Two-Part Hurdle) with 30-day Cloud CRUD baselines (`Option 1`) and evaluates cross-service API transition surprisal.

#### Query 2A: 2-Stage Dual-Branch Cloud Repository Scope & 4-Family CRUD Outlier Pipeline (`secops-risk-metrics-multistage`)
Closes the BigQuery `5–100` table hole, the GitHub `> 50` clone cliff, and unscored cloud CRUD noise by evaluating every cloud user and service account across all four 30-day CRUD metric families (`metrics.resource_read_total`, `metrics.resource_written_total`, `metrics.resource_deletion_total`, `metrics.resource_creation_total`) and caller origin IP (`$composite_risk >= 3.5`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect cloud identities and service accounts accessing or modifying cloud data repositories out of normal 30-day CRUD scope or from anomalous caller IPs.
// ARCHITECTURE: 2-STAGE DUAL-BRANCH CLOUD REPOSITORY SCOPE & ORIGIN OUTLIER PIPELINE
// Statistical Model: 4-Family Cloud CRUD + Origin IP Local-Baseline Isolation ($composite_risk >= 3.5)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Dynamic Cloud Repository Extraction & Pre-Computed 30d CRUD Baseline Lookups ---
stage stage1_extract {
    (
        metadata.event_type = "RESOURCE_READ" or
        metadata.event_type = "USER_RESOURCE_ACCESS" or
        metadata.event_type = "RESOURCE_DELETION" or
        metadata.event_type = "USER_RESOURCE_DELETION" or
        metadata.event_type = "RESOURCE_WRITTEN" or
        metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT" or
        metadata.event_type = "RESOURCE_CREATION" or
        metadata.event_type = "USER_RESOURCE_CREATION"
    )
    $sa = principal.user.userid
    $vendor = metadata.vendor_name
    $product = metadata.product_name
    $resource = target.resource.name
    $ip = principal.ip

    // Identity & resource non-null filtering (caret-free RE2 syntax for AST compliance)
    $sa != ""
    $vendor != ""
    $product != ""
    $resource != ""

  match:
    $sa, $vendor, $product, $resource, $ip by 1d

  outcome:
    $observed_reads = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $observed_writes = sum(if(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT", 1, 0))
    $observed_deletes = sum(if(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION", 1, 0))
    $observed_creates = sum(if(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION", 1, 0))

    // 1. Destination Resource Read Baseline
    $dest_avg = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_stddev = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    // 1b. Destination Resource Write, Deletion & Creation Baselines (4-Family Cloud CRUD Isolation)
    $dest_write_avg = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_write_stddev = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_del_avg = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_del_stddev = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_create_avg = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_create_stddev = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    // 2. Caller Origin IP Baseline
    $origin_avg = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_stddev = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))

    $dest_active_days = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
    $dest_z = ($observed_reads - $dest_avg) / if($dest_stddev > 0, $dest_stddev, 1.0)
    $write_z = ($observed_writes - $dest_write_avg) / if($dest_write_stddev > 0, $dest_write_stddev, 1.0)
    $del_z = ($observed_deletes - $dest_del_avg) / if($dest_del_stddev > 0, $dest_del_stddev, 1.0)
    $create_z = ($observed_creates - $dest_create_avg) / if($dest_create_stddev > 0, $dest_create_stddev, 1.0)
    $origin_z = ($observed_reads - $origin_avg) / if($origin_stddev > 0, $origin_stddev, 1.0)
}

// --- STAGE 2: Caller Origin IP Rollup across target repositories ---
stage stage2_origin_rollup {
    $sa = $stage1_extract.sa
    $product = $stage1_extract.product
    $ip = $stage1_extract.ip
    $ws = $stage1_extract.window_start

  match:
    $sa, $product, $ip, $ws by 1d

  outcome:
    $ip_total_reads = sum($stage1_extract.observed_reads)
    $origin_avg = max($stage1_extract.origin_avg)
    $origin_stddev = max($stage1_extract.origin_stddev)
    $ip_origin_z = ($ip_total_reads - $origin_avg) / if($origin_stddev > 0, $origin_stddev, 1.0)
}

// --- ROOT STAGE: Dual-Branch Evaluation & Composite Risk Ranking ---
$sa = $stage1_extract.sa
$product = $stage1_extract.product
$resource = $stage1_extract.resource
$ip = $stage1_extract.ip
$ws = $stage1_extract.window_start
$sa = $stage2_origin_rollup.sa
$product = $stage2_origin_rollup.product
$ip = $stage2_origin_rollup.ip
$ws = $stage2_origin_rollup.ws

match:
  $sa, $product, $resource, $ws by 1d

outcome:
  $obs = sum($stage1_extract.observed_reads)
  $obs_writes = sum($stage1_extract.observed_writes)
  $obs_deletes = sum($stage1_extract.observed_deletes)
  $obs_creates = sum($stage1_extract.observed_creates)
  $dest_days = max($stage1_extract.dest_active_days)
  $distinct_ips = count_distinct($stage1_extract.ip)

  $dest_z = ($obs - max($stage1_extract.dest_avg)) / if(max($stage1_extract.dest_stddev) > 0, max($stage1_extract.dest_stddev), 1.0)
  $write_z = ($obs_writes - max($stage1_extract.dest_write_avg)) / if(max($stage1_extract.dest_write_stddev) > 0, max($stage1_extract.dest_write_stddev), 1.0)
  $del_z = ($obs_deletes - max($stage1_extract.dest_del_avg)) / if(max($stage1_extract.dest_del_stddev) > 0, max($stage1_extract.dest_del_stddev), 1.0)
  $create_z = ($obs_creates - max($stage1_extract.dest_create_avg)) / if(max($stage1_extract.dest_create_stddev) > 0, max($stage1_extract.dest_create_stddev), 1.0)
  $origin_z = max($stage2_origin_rollup.ip_origin_z)
  $composite_risk = if($dest_z > 0, $dest_z, 0.0) + if($write_z > 0, $write_z, 0.0) + if($del_z > 0, $del_z, 0.0) + if($create_z > 0, $create_z, 0.0) + if($origin_z > 0, $origin_z, 0.0)

condition:
  $composite_risk >= 3.5 and ($dest_days >= 7 or $dest_days = 0 or $obs_deletes > 0 or $obs_writes > 0)

order:
  $composite_risk desc
```

#### Query 2B: Two-Part Zero-Inflated Hurdle Model on Cloud Control-Plane & Secret-Access API Calls (`secops-statistical-hunter`)
Addresses zero-inflated cloud administrative and secret-access telemetry (`RESOURCE_READ`, `RESOURCE_WRITTEN`, `USER_RESOURCE_ACCESS`) where dormant service principals or break-glass admins suddenly wake up (Part 1: discrete Bernoulli hurdle for $\le 2$ active days) or active automation principals surge far above their historical mean (Part 2: continuous intensity Z-score $\ge 3.0\sigma$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant cloud principals suddenly awakening or active principals surging across cloud resource and secret-access APIs via a Two-Part Zero-Inflated Hurdle Model.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS)
// Statistical Model: Two-Part Hurdle Outlier Model for Zero-Inflated Cloud Telemetry ($hurdle_threat_score >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily cloud control-plane and resource access activity per principal user
stage entity_historical {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "RESOURCE_WRITTEN"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
    )
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $bucket_count = count(metadata.id)
    $distinct_resources = count_distinct(target.resource.name)
    $sample_resource = array_distinct(target.resource.name)
}

// Stage 2: Historical active sample density and dispersion per principal user
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $hist_mean = avg($entity_historical.bucket_count)
    $hist_stddev = stddev($entity_historical.bucket_count)
    $active_samples = count($entity_historical.window_start)
}

// Root Stage: Two-Part Hurdle Evaluation & 6 Core Evidence Pillars
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
  $distinct_binaries = max($entity_historical.distinct_resources)
  $sample_commands = array_distinct($entity_historical.sample_resource)

  // 1. Part 1: Discrete Bernoulli Hurdle (dormant cloud identity awakening: <= 2 active days)
  $is_dormant = if($baseline_active_samples <= 2, 1.0, 0.0)
  $dormant_score = $observation_count * 0.75

  // 2. Part 2: Continuous Intensity Conditioned on Crossing Hurdle
  $diff = $observation_count - $baseline_mean
  $safe_stddev = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = $diff / $safe_stddev

  // 3. Composite Hurdle Threat Score
  $hurdle_threat_score = if($is_dormant > 0, $dormant_score, $intensity_z)

condition:
  $observation_count >= 5
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

---

### Scenario 3: Intel Identification — WHOIS Lifecycle & Binary Prevalence Fusion

* **Curated Detection Operational Focus**: Correlates endpoint and network activity with emerging threat-intelligence context.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day HTTP volume baselines with event-relative WHOIS domain registration age and 30-day file execution baselines with 10-day `DERIVED_CONTEXT` binary prevalence.

#### Query 3A: 2-Stage Hybrid 30-Day HTTP Volume + `GLOBAL_CONTEXT` WHOIS Domain Lifecycle (`secops-risk-metrics-multistage`)
Fuses 30-day host-to-domain HTTP query baselines (`metrics.http_queries_total`) with `GLOBAL_CONTEXT` WHOIS registration and expiration timestamps to amplify outbound HTTP anomalies targeting Newly Registered Domains ($\le 30\text{d}$ relative to event timestamp, $2.5\times$ multiplier) or expired/hijacked domains ($3.0\times$ multiplier).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day HTTP query baselines with GLOBAL_CONTEXT WHOIS lifecycle metadata to detect anomalous traffic to newly registered or expired domains.
// ARCHITECTURE: 2-STAGE DUAL-PLANE WHOIS DOMAIN LIFECYCLE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.http_queries_total) + WHOIS Lifecycle Multiplier ($z_score >= 3.0)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day HTTP Query Baseline (metrics.http_queries_total)
stage stage1_egress_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = count(metadata.id)
    $distinct_ports = count_distinct(target.port)

    $hist_mean = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $historical_avg = $hist_mean
    $hist_stddev = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $historical_stddev = $hist_stddev
    $hist_active_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $historical_active_days = $hist_active_days
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Global Context WHOIS Lookup (Creation & Expiration Timestamps)
stage stage2_whois_lifecycle {
    $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $whois.graph.metadata.vendor_name = "WHOIS"
    $whois.graph.metadata.entity_type = "DOMAIN_NAME"
    $whois.graph.entity.domain.name = $domain
    $domain != ""

  match:
    $domain

  outcome:
    $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)
    $expiration_ts = min($whois.graph.entity.domain.expiration_time.seconds)
}

// Stage 3 (Root Stage): Fuses Query Outlier Z-Score with WHOIS NRD and Expiration Scoring
$host = $stage1_egress_baseline.host
$domain = $stage1_egress_baseline.domain
$domain = $stage2_whois_lifecycle.domain

match:
  $host, $domain by 1d

outcome:
  $observed = max($stage1_egress_baseline.observed_val)
  $mean = max($stage1_egress_baseline.hist_mean)
  $stddev = max($stage1_egress_baseline.hist_stddev)
  $z_score = ($observed - $mean) / if($stddev > 0, $stddev, 1.0)
  $active_baseline_days = max($stage1_egress_baseline.hist_active_days)

  $obs_ts = max($stage1_egress_baseline.event_timestamp)
  $created = max($stage2_whois_lifecycle.creation_ts)
  $expires = max($stage2_whois_lifecycle.expiration_ts)

  // Domain Age (in days) data-anchored to event telemetry (guarded against missing $created = 0)
  $raw_age_days = ($obs_ts - $created) / 86400.0
  $domain_age_days = if($created > 0, $raw_age_days, 9999.0)
  $is_nrd = if($created > 0 and $domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)

  // Expiration Status (expired registration / lapsed certificate)
  $is_expired = if($expires <= $obs_ts and $expires > 0, 1.0, 0.0)
  $days_to_expiration = ($expires - $obs_ts) / 86400.0

  // Risk Multiplier: 3.0x for expired domains, 2.5x for NRD (<= 30d)
  $whois_multiplier = if($is_expired = 1.0, 3.0, if($is_nrd = 1.0, 2.5, 1.0))
  $fused_threat_score = $z_score * $whois_multiplier

condition:
  $z_score >= 3.0
  and ($is_nrd = 1.0 or ($is_expired = 1.0 and $active_baseline_days >= 5))

order:
  $fused_threat_score desc
```

#### Query 3B: 2-Stage Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Replaces static filename regexes (`/(setup\.exe|update\.js|...)/`) and unenforced `$producer_risk_score` heuristics by fusing each endpoint's 30-day process execution baseline (`metrics.file_executions_total`) with `DERIVED_CONTEXT` 10-day organizational file prevalence (`day_count = 10`, `rolling_max <= 3`), isolating rare or novel binaries (`$z_score >= 3.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day host binary execution baselines with DERIVED_CONTEXT 10-day file prevalence to detect execution surges of rare or novel binaries.
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.file_executions_total) + ECG File Rarity (rolling_max <= 3)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    $event_type = metadata.event_type
    principal.asset.hostname = $host
    principal.process.file.sha256 = $sha256
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
    $historical_avg = $hist_mean
    $hist_stddev = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        metadata.event_type: metadata.event_type,
        principal.asset.hostname: principal.asset.hostname,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $historical_stddev = $hist_stddev
    $hist_active_days = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        metadata.event_type: metadata.event_type,
        principal.asset.hostname: principal.asset.hostname,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $historical_active_days = $hist_active_days
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (Binary Prevalence & First Seen)
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
  $z_score = ($observed_execs - $mean_execs) / if($stddev_execs > 0, $stddev_execs, 1.0)
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier: 2.5x threat score boost for binaries first seen <= 7 days ago, 1.5x for isolated binaries
  $is_novel_binary = if($first_seen > 0 and $binary_age_days <= 7.0 and $binary_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_binary = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

  $sample_commands = array_distinct($stage1_process_baseline.sample_command)
  $sample_paths = array_distinct($stage1_process_baseline.sample_path)

condition:
  $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

---

---

### Scenario 4: Core Hunt Rules — C2 Beaconing Jitter & Fleet-Normalized Reconnaissance

* **Curated Detection Operational Focus**: Hunts for periodic callback patterns and internal discovery bursts.
* **How Multi-Stage UEBA Extends Coverage**: Detects robotic C2 beaconing with jitter via inter-arrival Coefficient of Variation ($\text{CV} \le 0.20$) and isolates host-specific discovery spikes via 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$).

#### Query 4A: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on Outbound C2 Callbacks (`secops-statistical-hunter`)
Detects automated C2 implants (Cobalt Strike, Sliver, Brute Ratel, Mythic) by measuring hourly inter-arrival gap regularity ($\text{CV} = \sigma / \mu \le 0.20$) across external `NETWORK_CONNECTION` events restricted to low-prevalence external IPs ($\le 3$ internal hosts).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect persistent Command & Control (C2) beaconing with randomized sleep jitter to low-prevalence external IPs via Coefficient of Variation.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = sigma / mu <= 0.20) & Fleet Prevalence Filter (<= 3 hosts)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Measure hourly timing intervals per (src_ip, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    $dst_ip != ""
    // Exclude internal RFC 1918 subnets for destination
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    $ts = metadata.event_timestamp.seconds

  match:
    $host, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
}

// Stage 2: Aggregate historical timing statistics across active hours
stage timing_stats {
    $host = $host_intervals.host
    $dst_ip = $host_intervals.dst_ip

  match:
    $host, $dst_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $active_hours = count($host_intervals.window_start)
}

// Stage 3: Measure enterprise-wide host prevalence of the destination IP
stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip

  outcome:
    $src_breadth = count_distinct($host_intervals.host)
}

// Root Stage: Combine timing stats, compute CV, and emit 6 Core Evidence Pillars
$host = $timing_stats.host
$dst_ip = $timing_stats.dst_ip
$dst_ip = $dst_prevalence.dst_ip

match:
  $host, $dst_ip

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.total_conns)

  // Aggregate Coefficient of Variation (CV = sigma / mu)
  $raw_mean = max($timing_stats.mean_gap)
  $safe_mean = if($raw_mean > 0, $raw_mean, 1.0)
  $raw_stddev = max($timing_stats.stddev_gap)
  $cv = $raw_stddev / $safe_mean

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 24
  and $baseline_mean >= 1.0
  and $fleet_prevalence <= 3
  and $cv <= 0.20

order:
  $cv asc
```

#### Query 4B: 4-Stage UDM-Gated Personal & Upstream Delta-Z on Host Discovery & Enumeration (`secops-statistical-hunter`)
Evaluates hourly host discovery and network enumeration surges strictly on candidate hosts surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED PERSONAL & UPSTREAM DELTA-Z PIPELINE
// Goal: Detect localized post-exploitation discovery & lateral reconnaissance surges on candidate hosts from Query 4A (strictly gated by Query 4A UDM Loopback candidates).
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
    (
      metadata.event_type = "PROCESS_LAUNCH"
      or metadata.event_type = "NETWORK_CONNECTION"
    )
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_val = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
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

### Scenario 5: Cross-Plane Hunt Signal Aggregation & Exfiltration Drift

* **Curated Detection Operational Focus**: Tracks staged data transfers and multi-signal hunt classifications.
* **How Multi-Stage UEBA Extends Coverage**: Applies 4-stage non-parametric 30-day Median Absolute Deviation (MAD) and Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) to surface stealthy data exfiltration.

#### Query 5A: 2-Stage Longitudinal CUSUM Behavioral Drift on 30-Day Outbound Network Bytes (`secops-risk-metrics-multistage`)
Catches low-and-slow multi-day exfiltration across any protocol by accumulating positive daily standardized excesses above a $k = 0.5\sigma$ slack reference ($S_t^+ = \sum \max(0, Z_t - 0.5) \ge 3.0$ across `drift_days >= 2`) against the host's 30-day `metrics.network_bytes_outbound` baseline.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-and-slow multi-day outbound data exfiltration drift across endpoints via Longitudinal CUSUM on 30-day network_bytes_outbound.
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Statistical Model: Cumulative Sum Control Chart (S_t^+ = sum(max(0, Z_t - 0.5)) >= 3.0, drift_days >= 2)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Deviation Tracker on Outbound Network Bytes
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
    $historical_max = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: max,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_sum = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: sum,
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

condition:
  $cusum_drift_score >= 3.0 and $drift_days >= 2

order:
  $cusum_drift_score desc
```

#### Query 5B: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Outbound Network Transfers (`secops-statistical-hunter`)
Provides a 50%-breakdown-point non-parametric outlier detector over raw `NETWORK_CONNECTION` outbound byte volumes per host, using the **Iglewicz-Hoaglin Modified Z-Score** ($M_Z = 0.6745 \cdot (x - \text{Median}) / \text{MAD} > 3.5$) with an automatic Mean Absolute Deviation ($1.253314 \times \text{MeanAD}$) fallback when $\text{MAD} = 0$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect acute outbound data exfiltration spikes on skewed host baselines via 4-Stage Non-Parametric Median Absolute Deviation (MAD / Modified Z-Score).
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Iglewicz-Hoaglin Modified Z-Score (M_Z > 3.5) with MeanAD Fallback
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily observed outbound byte volume per host
stage daily_stats {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $daily_value = sum(network.sent_bytes)
    $distinct_sample_values = count_distinct(target.ip)
    $sample_data = array_distinct(target.ip)
}

// Stage 2: Baseline median of daily outbound bytes per host (active days)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, Mean Absolute Deviation (MAD=0 fallback), and active day count per host
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

// Root Stage: Modified Z-Score per host-day and the 6 Core Evidence Pillars
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
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1048576.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 4 active days) + Mature Robust MAD (>= 5 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 4, 2.0, 1.0)
  $hurdle_threat_score = (math.log($observation_count + 1.0) * $hurdle_rarity_boost) / 3.0
  $unified_threat_score = if($baseline_active_samples <= 4, $hurdle_threat_score, $m_z_score)

condition:
  $observation_count >= 10485760
  and $unified_threat_score > 3.5

order:
  $unified_threat_score desc
```

---

---

### Scenario 6: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual hunting leads evaluated per telemetry domain.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral hunting scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–5 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 6 (`Query 6`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 5 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-5]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 5 Mandiant Hunting scenarios (1 through 5B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
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
---

---

## 4. Mandiant Frontline Anti-Forensics & Stealth Exfiltration: Ingestion-Lag Quantiles & Per-Flow Payload Shape (`v2.2.0` / `v2.9.0`)

Mandiant Frontline investigations frequently encounter threat actors who (1) buffer or delay EDR/syslog telemetry during hands-on-keyboard operations or (2) exfiltrate staged archives over a handful of high-volume flows (`$p90_bytes`) while keeping median flows (`$p50_bytes`) at normal heartbeat sizes.
* **Query 5A**: Pairs 30-day `metrics.network_bytes_outbound` with intra-bucket `$p50_bytes` and `$p90_bytes` (`$flow_tail_burst_ratio = $p90_bytes / $safe_p50`).
* **Query 5B**: Computes the 5-point ingestion-lag quantile profile (`$p10, $p25, $p50, $p75, $p90` of `ingested_timestamp.seconds - event_timestamp.seconds`) and Bowley skewness (`$bowley_skew`) to detect sensor blinding and batch replay.

#### Query 5A: Macro 30-Day Outbound Egress Z + Intra-Bucket Per-Flow $P_{50}/P_{90}$ Shape (`secops-risk-metrics-multistage`)
```yara
// Goal: Combine 30-day metrics.network_bytes_outbound macro Z-score with intra-bucket per-flow P50/P90 payload quantile shape fingerprinting
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

  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  $safe_p50 = if($p50_bytes > 0, $p50_bytes, 1.0)
  $flow_tail_burst_ratio = $p90_bytes / $safe_p50

condition:
  $active_days >= 7 and $personal_z >= 2.0 and $flow_tail_burst_ratio >= 10.0

order:
  $flow_tail_burst_ratio desc
```

#### Query 5B: Telemetry Ingestion-Lag & Clock-Skew Quantile Audit (`secops-statistical-hunter`)
```yara
// Goal: Profile telemetry ingestion lag quantiles, Bowley skewness, and negative clock-skew / timestomp anomalies per log_type
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
  $event_count >= 10 and ($p10 < 0 or $p90 >= 300 or $bowley_skew >= 0.75)

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
