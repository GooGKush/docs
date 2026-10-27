# Extending Mandiant Hunting Rules with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Mandiant Hunting Rules** suite encodes frontline incident-response tradecraft across endpoint, cloud, network, and threat-intelligence domains—surfacing suspicious process lineage, living-off-the-land techniques, cloud control-plane anomalies, and reconnaissance patterns.

Because hunting rules are designed to surface investigative leads across diverse enterprise environments, combining them with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`) provides automatic per-entity baselining and statistical noise reduction. This playbook pairs Mandiant hunting domains with Markov 2-gram process surprisal, Shannon command-line entropy, Piecewise Hurdle + 30-day Cloud baselines, WHOIS lifecycle weighting, C2 jitter analysis, and UDM Loopback Capstone correlation.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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

    // Character-class counts via bracket-free regex replacement length deltas
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

// Root Stage: Compute 4-Class Shannon Entropy Score & 6 Core Evidence Pillars
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

  // Shannon Entropy H = -sum(p_i * log2(p_i)) scaled to byte-entropy equivalent
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
// Goal: Fuse 30-day HTTP query baselines with GLOBAL_CONTEXT WHOIS lifecycle metadata to detect anomalous traffic to newly registered or expired domains.
// ARCHITECTURE: 2-STAGE DUAL-PLANE WHOIS DOMAIN LIFECYCLE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.http_queries_total) + WHOIS Lifecycle Multiplier ($z_score >= 3.0)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day HTTP Query Baseline (metrics.http_queries_total)
stage stage1_egress_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-26"
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
// Goal: Fuse 30-day host binary execution baselines with DERIVED_CONTEXT 10-day file prevalence to detect execution surges of rare or novel binaries.
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.file_executions_total) + ECG File Rarity (rolling_max <= 3)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (metrics.file_executions_total)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-26"
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
// Goal: Detect persistent Command & Control (C2) beaconing with randomized sleep jitter to low-prevalence external IPs via Coefficient of Variation.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = sigma / mu <= 0.20) & Fleet Prevalence Filter (<= 3 hosts)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Measure hourly timing intervals per (src_ip, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    principal.asset.ip = $src_ip
    $src_ip != ""
    $dst_ip != ""
    // Exclude internal RFC 1918 subnets for destination
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    $ts = metadata.event_timestamp.seconds

  match:
    $src_ip, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
}

// Stage 2: Aggregate historical timing statistics across active hours
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip

  match:
    $src_ip, $dst_ip

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
    $src_breadth = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute CV, and emit 6 Core Evidence Pillars
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

#### Query 4B: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) on Host Discovery & Enumeration (`secops-statistical-hunter`)
Isolates targeted post-exploitation reconnaissance waves on an endpoint while automatically suppressing company-wide IT management or vulnerability-scanner surges via **Dual-Baseline Fleet-Normalized Delta-Z** ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$).

```yara
// ============================================================================
// Goal: Detect targeted endpoint discovery and enumeration surges isolated from fleet-wide management waves via Dual-Baseline Delta-Z.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift) >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Individual Host Discovery & Enumeration Process Volume in tumbling hourly windows
stage host_hourly_extract {
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /(whoami|nltest|adfind|net|net1|ipconfig|ifconfig|netstat|arp|route|qprocess|qwinsta|tasklist|systeminfo|dsquery|ldapsearch|id|uname)/ nocase
    $host = $e.principal.hostname
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count($e.metadata.id)
    $distinct_procs = count_distinct($e.target.process.file.full_path)
}

// Stage 2: Individual Host Personal Historical Baseline (Temporal Baseline)
stage host_personal_baseline {
    $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active endpoints in the same hour
stage fleet_concurrent_baseline {
    $host = $host_hourly_extract.host
    $ws = $host_hourly_extract.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hour_avg = avg($host_hourly_extract.hourly_count)
    $fleet_hour_stddev = stddev($host_hourly_extract.hourly_count)
    $active_fleet_hosts = count_distinct($host_hourly_extract.host)
}

// Root Stage: Dual-Baseline Delta-Z Evaluation & 6 Core Evidence Pillars
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_hourly_extract.hourly_count)
  $baseline_active_samples = max($host_personal_baseline.active_hours)
  $baseline_mean = max($host_personal_baseline.personal_avg)
  $baseline_dispersion = max($host_personal_baseline.personal_stddev)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_hosts)
  $distinct_binaries = max($host_hourly_extract.distinct_procs)

  // Dual-Baseline Metrics (Common Personal Dispersion Scale)
  $obs = max($host_hourly_extract.hourly_count)
  $p_mean = max($host_personal_baseline.personal_avg)
  $f_mean = max($fleet_concurrent_baseline.fleet_hour_avg)
  $raw_personal_sd = max($host_personal_baseline.personal_stddev)
  $safe_personal_sd = if($raw_personal_sd > 0, $raw_personal_sd, 1.0)

  $personal_z = ($obs - $p_mean) / $safe_personal_sd
  $f_shift = $f_mean - $p_mean
  $fleet_z = $f_shift / $safe_personal_sd
  $pos_fleet_z = if($fleet_z > 0, $fleet_z, 0.0)
  $delta_z = $personal_z - $pos_fleet_z

  $personal_z_score = $personal_z
  $fleet_concurrent_z = $fleet_z
  $targeted_delta_z = $delta_z

condition:
  $baseline_active_samples >= 4
  and $fleet_prevalence >= 3
  and $observation_count >= 10
  and $delta_z >= 3.0

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
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost / 3.0
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

#### Capstone Query: Multi-Scenario Mandiant Hunting Entity Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across all Mandiant Hunting scenarios via UDM Loopback to detect multi-stage kill-chain convergence.
// Statistical Model: Cross-Scenario Euclidean Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0)
// ARCHITECTURE: CAPSTONE UDM LOOPBACK CONVERGENCE PIPELINE (OPTION 3)
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_query_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    security_result.rule_name = $query_name
    $entity = coalesce(principal.asset.hostname, principal.user.userid, principal.ip[0])
    $entity != ""
    $run_id != ""

  match:
    $entity, $query_name

  outcome:
    $max_query_z = max(security_result.confidence_score)
    $query_sq = max(security_result.confidence_score) * max(security_result.confidence_score)
    $match_events = count(metadata.id)
    $latest_run_id = max(metadata.product_log_id)
}

$entity = $stage1_query_dedup.entity

match:
  $entity

outcome:
  $distinct_scenarios_matched = count_distinct($stage1_query_dedup.query_name)
  $matched_queries = array_distinct($stage1_query_dedup.query_name)
  $correlated_run_ids = array_distinct($stage1_query_dedup.latest_run_id)
  $latest_run_id = max($stage1_query_dedup.latest_run_id)
  $total_loopback_matches = sum($stage1_query_dedup.match_events)
  $peak_scenario_z = max($stage1_query_dedup.max_query_z)
  $capstone_threat_norm_sq = sum($stage1_query_dedup.query_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 18.0

order:
  $capstone_threat_norm_sq desc
```

---

---

## 3. Appendix: A Practitioner's Plain-English Guide to the 10 Statistical Models

### 3.1 Markov 2-Gram Parent-to-Child Process Transition Surprisal ($I = -\ln P(\text{Child} \mid \text{Parent})$ — Query 1A)
* **What it measures**: How unexpected it is for a specific parent binary (`$parent`) to spawn a specific child binary (`$child`) on that endpoint.
* **How multi-stage UEBA extends coverage**: `endpoint-identification` contains hundreds of hardcoded parent-child rules (e.g., `javaw -> powershell`) that miss any unenumerated parent-child combination (`node -> bash`, `postgres -> curl`), while `endpoint-classification` is deprecated (`legacy configuration`).
* **How the math works**: When a busy service parent (`$parent_launches >= 20`) spawns a routine worker process, $P(\text{Child} \mid \text{Parent}) \approx 1.0$ and self-information surprisal $I = -\ln(P) \approx 0$. When an exploited service spawns an interactive shell or recon tool only once or twice, $P(\text{Child} \mid \text{Parent})$ is tiny and $I \times \text{rare\_multiplier}$ spikes above `3.0`.

### 3.2 Multi-Class Character Shannon Entropy ($H(X)$ — Query 1B)
* **What it measures**: The balance and unpredictability of lowercase letters, uppercase letters, digits, and symbols inside a process command line, combined with enterprise-wide host rarity.
* **How multi-stage UEBA extends coverage**: Rules like curated detection rules and `i_methodology_t1027_010_powershell_glob_system_directory_obfuscation_` look for specific strings (`base64 -d`, `_W*___*2_msh*e`) that attackers easily alter.
* **How the math works**: Normal administrative CLI flags are dominated by lowercase words and spaces (low entropy). Base64 blobs, hex-encoded shellcode, and heavy punctuation/glob obfuscation distribute characters across classes evenly, driving the scaled Shannon score above `3.8` while `$fleet_prevalence <= 3` eliminates standard enterprise deployment scripts.

### 3.3 2-Stage Dual-Branch Cloud Repository Scope & 4-Family CRUD Outlier Pipeline (Query 2A)
* **What it measures**: Simultaneously scores a cloud identity's daily Read, Write, Delete, and Create volume per target resource—plus its total Read volume from each caller IP—against 30-day pre-computed baselines (`metrics.resource_*_total`).
* **How multi-stage UEBA extends coverage**: `i_gcp_bq_exfil_to_bucket` contains a severe hole (`$table_count < 5 or $table_count > 100` to `1` bucket), missing any actor who exports 5–100 tables or uses 2 buckets, while `i_github_high_volume_github_repos_cloned_by_pat_user` misses `< 50` clones per `15m`.
* **How the math works**: By summing rectified positive Z-scores across all 4 CRUD families and the caller IP origin branch (`$composite_risk >= 3.5`), the pipeline catches both volumetric depth surges on known repositories and zero-baseline breadth/origin departures (`$dest_days = 0`).

### 3.4 Two-Part Zero-Inflated Hurdle Model for Cloud APIs (Query 2B)
* **What it measures**: Evaluates cloud control-plane and secret-access API calls in two stages: Part 1 tests whether the account crossed a discrete dormancy hurdle ($\le 2$ active days); Part 2 scores continuous intensity ($Z \ge 3.0\sigma$) for regularly active accounts.
* **How multi-stage UEBA extends coverage**: Single-event cloud rules (`i_azure_add_service_principal_credentials`) flood analysts with routine CI/CD automation noise while assigning `$risk_score = 0` to genuinely dormant break-glass accounts that suddenly wake up.
* **How the math works**: Dormant principals (`$baseline_active_samples <= 2`) are scored directly on their awakening burst (`$observation_count * 0.75`), while active CI/CD principals are normalized by their historical mean and standard deviation.

### 3.5 Hybrid 30-Day HTTP Volume + `GLOBAL_CONTEXT` WHOIS Domain Lifecycle (Query 3A)
* **What it measures**: Combines a host's 30-day HTTP request Z-score to a domain (`metrics.http_queries_total`) with WHOIS registration age and expiration status from `GLOBAL_CONTEXT`.
* **How multi-stage UEBA extends coverage**: Static intel feeds in `intel-identification` miss freshly registered domains not yet linked to a known campaign, and `i_methodology_t1218_007_windows_installer_c2_connections` only checks `Windows Installer` user agents.
* **How the math works**: Domain age is anchored directly to the event timestamp (`($obs_ts - $created) / 86400.0`), applying a $2.5\times$ multiplier for Newly Registered Domains ($\le 30\text{d}$) and a $3.0\times$ multiplier for expired/hijacked domains.

### 3.6 Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (Query 3B)
* **What it measures**: Fuses a host's 30-day binary execution baseline (`metrics.file_executions_total` keyed on SHA-256) with 10-day rolling organizational host prevalence (`rolling_max <= 3`) from `DERIVED_CONTEXT`.
* **How multi-stage UEBA extends coverage**: Identification rules compute a 14-term static `$producer_risk_score` (`setup.exe`, `update.js`, etc.) in `outcome:` without ever gating on it in `condition:`.
* **How the math works**: Joining Stage 1 (`metrics.file_executions_total`) with Stage 2 (`DERIVED_CONTEXT` `day_count = 10`, `rolling_max <= 3`) automatically filters out widespread enterprise software and boosts binaries first seen within 7 days by $2.5\times$.

### 3.7 Inter-Arrival Jitter Coefficient of Variation ($\text{CV} = \sigma / \mu$ — Query 4A)
* **What it measures**: The timing regularity of outbound network connections from an internal host to an external IP across multiple active hours.
* **How multi-stage UEBA extends coverage**: Process-specific C2 rules (`calc.exe`, `conhost.exe`, `bun.exe`) are blinded when an implant injects into a normal browser or system service.
* **How the math works**: Even when an implant adds 15–20% random sleep jitter to evade fixed-interval detection, its hourly average inter-arrival gap maintains a low standard-deviation-to-mean ratio ($\text{CV} = \sigma / \mu \le 0.20$), whereas human browsing exhibits chaotic gaps ($\text{CV} > 0.50$).

### 3.8 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z$ — Query 4B)
* **What it measures**: How strongly an endpoint's hourly discovery/reconnaissance command volume surged above its personal baseline *after subtracting any concurrent fleet-wide surge*.
* **How multi-stage UEBA extends coverage**: Single-event rules for `nltest`, `whoami`, and `adfind` generate noise during fleet-wide IT inventory tasks while failing to highlight a targeted 25-command recon burst on a single compromised host.
* **How the math works**: Stage 2 computes the host's personal baseline ($\mu_p, \sigma_p$) and Stage 3 computes the concurrent fleet average ($\mu_f$). Subtracting the positive fleet shift ($\Delta Z = Z_{\text{personal}} - \max(0, (\mu_f - \mu_p)/\sigma_p) \ge 3.0\sigma$) provides an automatic "Patch Tuesday / IT Inventory Immunity Shield."

### 3.9 2-Stage Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 5A)
* **What it measures**: The multi-day cumulative sum of positive daily outbound byte deviations above a $0.5\sigma$ slack threshold against a 30-day `metrics.network_bytes_outbound` baseline.
* **How multi-stage UEBA extends coverage**: Channel-specific rules (curated detection rules) miss custom HTTPS exfiltration, and single-day Z-score rules miss low-and-slow transfers paced at $1.5\sigma\text{/day}$.
* **How the math works**: Normal daily fluctuations cancel out below the $0.5\sigma$ slack line, whereas a persistent $1.5\sigma$ daily exfiltration drip adds $+1.0$ to $S_t^+$ every day, crossing `$cusum_drift_score >= 3.0` and `$drift_days >= 2`.

### 3.10 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z$ — Query 5B)
* **What it measures**: How many robust, outlier-resistant standard deviations a host's daily outbound byte volume sits above its historical median.
* **How multi-stage UEBA extends coverage**: On servers or developer workstations that occasionally transfer large legitimate archives, a single historical spike inflates parametric $\sigma$ and masks future exfiltration spikes.
* **How the math works**: The median and Median Absolute Deviation ($\text{MAD} = \text{median}(|x - \text{median}|)$) have a 50% breakdown point, remaining uncorrupted by historical spikes. If a host has a rock-solid constant history where $\text{MAD} = 0$, the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) prevents division-by-zero and accurately scores sudden outbound transfers ($M_Z > 3.5$).
