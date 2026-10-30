# Extending Mandiant Hunting Rules with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Mandiant Hunting Rules** suite encodes frontline incident-response tradecraft across endpoint, cloud, network, and threat-intelligence domains—surfacing suspicious process lineage, living-off-the-land techniques, cloud control-plane anomalies, and reconnaissance patterns.

Because hunting rules are designed to surface investigative leads across diverse enterprise environments, combining them with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`) provides automatic per-entity baselining and statistical noise reduction. This runbook pairs Mandiant hunting domains with Laplace-smoothed Markov 2-gram process surprisal, long-string and rare-token command-line screening (`LONG_STRING_SCREEN`), 30-day 4-family Cloud CRUD and caller-origin baselines, Two-Part Hurdle cloud control-plane awakening, WHOIS domain lifecycle and `DERIVED_CONTEXT` binary prevalence fusion, cross-bucket flow-gap regularity screening (`FLOW_GAP_RATIO_SCREEN`), multi-day Windowed Slack Sum egress drift, non-parametric outbound byte MAD, and UDM Loopback Capstone convergence.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba` (which computes the `[0..100]` Calibrated Risk Index in Python via `ueba_constants.calculate_cri` from the Z and Z-equivalent scores emitted by each query):
  1. **Wave 1 — Upstream 30-Day Macro Baselines & Pre-Filtered Statistical Screens**: Executes all `by 1d` `metrics.*` baselines (enforcing the 7-active-day maturity gate `$active_days >= 7`, the Poisson count dispersion floor `max(sigma, math.sqrt(max(mu, 1.0)))`, and fleet byte dispersion floors such as `44979.0` bytes on `metrics.network_bytes_outbound`) alongside bounded raw-event statistical hunter screens concurrently. In Mode A (scoring the last complete UTC day `D`), Entity Context Graph hybrid queries (`Query 3A`, `Query 3B`) scan `[D-2, D+1)` to accommodate daily graph build lag while pinning the raw event stage to `D` via `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"`. Every match is written back to Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies UDM indexing via `verify_udm_run_indexed()`, Wave 2 `Query 4B` reads `Query 4A`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`) to bound hourly (`by 1h`) raw discovery and enumeration leave-one-out Z-score calculations without scanning the full enterprise fleet.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 6`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-7]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean $L_2$ convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 25.0`) in Stage 2, and joins winning entities directly with raw endpoint, network, authentication, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Mandiant Hunting Rules & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Endpoint Process Lineage & Command-Line Tradecraft** | Hunts for suspicious parent-child process relationships, encoded scripts, and defense-evasion utilities on endpoints. | Quantifies whole-window parent-to-child transition rarity via Laplace-smoothed Markov 2-gram surprisal ($\ln((N_{\text{parent}} + 100) / (N_{\text{pair}} + 1)) \ge 3.0$) and screens long, low-prevalence command lines via log-length plus within-host token rarity (`LONG_STRING_SCREEN` $\ge 5.5$). | `Query 1A` (Markov 2-Gram Surprisal)<br>`Query 1B` (`LONG_STRING_SCREEN` Command-Line Screen) |
| **2. Cloud Control-Plane Hunting & Cross-Resource Scope** | Identifies anomalous cloud IAM, storage, and compute administration patterns across AWS, GCP, and Azure. | Evaluates mature ($\ge 7\text{d}$) 30-day Cloud CRUD baselines across both destination repositories and caller origin IPs, paired with a Two-Part Hurdle model for dormant cloud principal awakenings ($\le 2$ active days, $\ge 10$ events) and leave-one-out intensity spikes. | `Query 2A` (30d 4-Family Cloud CRUD + Origin Scope)<br>`Query 2B` (Two-Part Hurdle Cloud Control-Plane) |
| **3. Threat Intelligence & Newly Observed Infrastructure** | Correlates endpoint and network activity with emerging threat-intelligence context. | Combines 30-day HTTP volume Z-scores ($\ge 7\text{d}$ baseline) with event-anchored `GLOBAL_CONTEXT` WHOIS domain registration age ($\le 30\text{d}$) or expiration, and 30-day binary execution Z-scores with 10-day `DERIVED_CONTEXT` file prevalence (`rolling_max <= 3`). | `Query 3A` (30d HTTP + WHOIS Lifecycle)<br>`Query 3B` (30d Execution + 10d File Prevalence) |
| **4. External Callback Regularity & Candidate-Gated Discovery** | Hunts for periodic callback patterns and internal discovery bursts. | Screens persistent low-prevalence external pairs via cross-bucket span-to-count flow-gap ratio dispersion (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$) in Wave 1, then evaluates hourly post-exploitation discovery surges on matched hosts via UDM-gated leave-one-out personal Z-scores in Wave 2. | `Query 4A` (`FLOW_GAP_RATIO_SCREEN`)<br>`Query 4B` (UDM-Gated LOO Personal Z Fusion) |
| **5. Multi-Day Outbound Egress Drift & Robust Byte Spikes** | Tracks staged data transfers and acute outbound exfiltration spikes. | Accumulates positive daily standardized slack excesses above $0.5\sigma$ (`Windowed Slack Sum` $\ge 3.0$ across $\ge 2$ drift days) on 30-day `metrics.network_bytes_outbound`, alongside a 4-stage non-parametric Iglewicz-Hoaglin Modified Z-Score ($M_Z > 3.5$) on raw daily outbound bytes. | `Query 5A` (Windowed Slack Sum Outbound Bytes)<br>`Query 5B` (4-Stage Raw Outbound Byte MAD) |
| **6. Capstone Multi-Scenario Hunt Entity Convergence** | Individual hunting leads evaluated per telemetry domain. | Correlates entities matching $\ge 2$ distinct behavioral hunting scenarios within the active run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean norm ($\sum Z_i^2 \ge 25.0$) joined to raw forensic artifacts. | `Query 6` (Capstone UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Endpoint Identification & Classification — Process Lineage & Command-Line Screening

* **Curated Detection Operational Focus**: Hunts for suspicious parent-child process relationships, encoded scripts, and defense-evasion utilities on endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Quantifies whole-window parent-to-child process transition rarity via Laplace-smoothed Markov 2-gram surprisal (`MARKOV_2GRAM_TRANSITION_RARITY`) and screens unusually long, low-prevalence command lines via `LONG_STRING_SCREEN` (log-length plus within-host token rarity; exact per-character Shannon entropy requires post-query evaluation via `SHANNON_ENTROPY_CHARACTER` and `micro_python_helpers.py shannon`).

#### Query 1A: Markov 2-Gram Parent-to-Child Process Transition Surprisal (`secops-statistical-hunter`)
Computes the whole-window Laplace-smoothed conditional transition probability $P(\text{Child} \mid \text{Parent}) = (N_{\text{pair}} + 1) / (N_{\text{parent}} + 100)$ and **Markov self-information surprisal** $\ln((N_{\text{parent}} + 100) / (N_{\text{pair}} + 1)) \ge 3.0$ across endpoint `PROCESS_LAUNCH` events for established parent binaries ($N_{\text{parent}} \ge 20$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions across endpoints via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (MARKOV_2GRAM_TRANSITION_RARITY, Score = ln((N_parent + 100.0) / (N_pair + 1.0)) >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Bucketed Parent-Child Process Transition Activity
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    principal.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""

  match:
    $etype, $host, $parent, $child by 1d

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

// Stage 3: Whole-Window Parent Process Totals per Host
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
  $window_parent_launches >= 20
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

#### Query 1B: Long-String & Rare-Token Command-Line Candidate Screen (`secops-statistical-hunter`)
Because YARA-L 2.0 has no per-character iteration primitive, this stateless in-query screen (`LONG_STRING_SCREEN`) isolates unusually long command lines ($\ge 64$ characters) that are both rare within the host's daily process volume and restricted to $\le 3$ hosts across the enterprise, scoring $\ln(\text{length}) + \ln(1 + N_{\text{host}} / N_{\text{cmd}}) \ge 5.5$. To compute exact per-character Shannon entropy ($H(X) = -\sum p_i \log_2 p_i$ bits/char) on candidate strings, pipe extracted command lines through `SHANNON_ENTROPY_CHARACTER` (`micro_python_helpers.py shannon`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long, rare, low-prevalence process command lines across endpoints via Long-String & Rare-Token Candidate Screening.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN, score = ln(length) + ln(1 + total_events / token_count) >= 5.5, fleet_prevalence <= 3)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Host Daily Process Launch Volume
stage entity_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $total_events = count(metadata.id)
}

// Stage 2: Command-Line Token Extraction & String Length Observation
stage token_observation {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""
    $token = target.process.command_line
    $token != ""
    strings.length($token) >= 64

  match:
    $entity, $token by 1d

  outcome:
    $token_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $token_length = max(strings.length($token))
}

// Stage 3: Enterprise Fleet Host Prevalence per Command Line
stage cmd_fleet_prevalence {
    $token = $token_observation.token
    $ws = $token_observation.window_start

  match:
    $token, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($token_observation.entity)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring & 6 Core Evidence Pillars
$entity = $entity_baseline.entity
$entity = $token_observation.entity
$token = $token_observation.token
$token = $cmd_fleet_prevalence.token
$ws = $entity_baseline.window_start
$ws = $token_observation.window_start
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
  $distinct_binaries = max($token_observation.distinct_procs)

condition:
  $raw_length >= 64
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 5.5

order:
  $shannon_entropy_score desc
```

---

### Scenario 2: Cloud Identification & Classification — Multi-Cloud Resource Scope & Hurdle Crossing

* **Curated Detection Operational Focus**: Identifies anomalous cloud IAM, storage, and compute administration patterns across AWS, GCP, and Azure.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates mature ($\ge 7$ active baseline days per CRUD branch) 30-day Cloud CRUD baselines across both destination repositories and caller origin IPs (`Query 2A`), paired with a Two-Part Hurdle outlier model (`Query 2B`) that scores dormant cloud identity awakenings ($\le 2$ active days with $\ge 10$ events) alongside leave-one-out continuous intensity surges ($\ge 3.0\sigma$).

#### Query 2A: 3-Stage Dual-Branch Cloud Repository Scope & 4-Family CRUD Outlier Pipeline (`secops-risk-metrics-multistage`)
Evaluates profiled cloud users and service accounts (GCP service accounts, AWS IAM/STS ARNs, Azure AD UUIDs, and human cloud UPNs, excluding Windows `$` machine accounts and local OS identities) across all four 30-day CRUD metric families (`metrics.resource_read_total`, `metrics.resource_written_total`, `metrics.resource_deletion_total`, `metrics.resource_creation_total`) on both destination repositories and caller origin IPs. Each branch requires $\ge 7$ active baseline days and applies the Poisson count dispersion floor `max(sigma, math.sqrt(max(mu, 1.0)))` (`$composite_risk >= 3.0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect profiled cloud identities and service accounts accessing or modifying cloud data repositories out of normal 30-day CRUD scope or from anomalous caller IPs.
// ARCHITECTURE: 3-STAGE DUAL-BRANCH CLOUD REPOSITORY SCOPE & ORIGIN OUTLIER PIPELINE
// Statistical Model: 4-Family Cloud CRUD + Origin IP Local-Baseline Isolation ($composite_risk >= 3.0, >= 7 active days per branch, sqrt(max(mu, 1.0)) dispersion floor)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Dynamic Cloud Repository Extraction & 4-CRUD Destination Baselines ---
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

    // Cloud principal profiling (GCP SAs, AWS/GovCloud/China ARNs, Azure UUIDs, human cloud emails/UPNs)
    // while excluding Windows computer accounts ($) and local OS service identities
    $sa != ""
    $sa = /@.*gserviceaccount\.com$|^arn:aws:(iam|sts)::|arn:aws-(cn|us-gov):(iam|sts)::|^[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$|@[a-z0-9.-]+\.[a-z][a-z]+$/ nocase
    not re.regex(principal.user.userid, `(?i)^(system|local service|network service|.*\$$)`)
    $vendor != ""
    $product != ""
    $resource != ""
    $ip != ""

  match:
    $sa, $vendor, $product, $resource, $ip by 1d

  outcome:
    $observed_reads = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $observed_writes = sum(if(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT", 1, 0))
    $observed_deletes = sum(if(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION", 1, 0))
    $observed_creates = sum(if(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION", 1, 0))

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
    $dest_active_days = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))

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
    $dest_write_days = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
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
    $dest_del_days = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
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
    $dest_create_days = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name,
        target.resource.name: target.resource.name
    ))
}

// --- STAGE 2: Caller Origin IP 4-CRUD Extraction & Pre-Computed Baselines ---
stage stage2_origin_rollup {
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
    $ip = principal.ip

    $sa != ""
    $sa = /@.*gserviceaccount\.com$|^arn:aws:(iam|sts)::|arn:aws-(cn|us-gov):(iam|sts)::|^[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$|@[a-z0-9.-]+\.[a-z][a-z]+$/ nocase
    not re.regex(principal.user.userid, `(?i)^(system|local service|network service|.*\$$)`)
    $vendor != ""
    $product != ""
    $ip != ""

  match:
    $sa, $vendor, $product, $ip by 1d

  outcome:
    $ip_total_reads = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $ip_total_writes = sum(if(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT", 1, 0))
    $ip_total_deletes = sum(if(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION", 1, 0))
    $ip_total_creates = sum(if(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION", 1, 0))

    $origin_read_avg = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_read_stddev = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_read_days = max(metrics.resource_read_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))

    $origin_write_avg = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_write_stddev = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_write_days = max(metrics.resource_written_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))

    $origin_del_avg = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_del_stddev = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_del_days = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))

    $origin_create_avg = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_create_stddev = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $origin_create_days = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        principal.ip: principal.ip,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
}

// --- STAGE 3: Caller Origin IP 4-CRUD Maturity-Gated Z-Score Rollup ---
stage stage3_origin_score {
    $sa = $stage2_origin_rollup.sa
    $vendor = $stage2_origin_rollup.vendor
    $product = $stage2_origin_rollup.product
    $ip = $stage2_origin_rollup.ip
    $ws = $stage2_origin_rollup.window_start

  match:
    $sa, $vendor, $product, $ip, $ws by 1d

  outcome:
    $r_fl = math.sqrt(if(max($stage2_origin_rollup.origin_read_avg) > 1.0, max($stage2_origin_rollup.origin_read_avg), 1.0))
    $w_fl = math.sqrt(if(max($stage2_origin_rollup.origin_write_avg) > 1.0, max($stage2_origin_rollup.origin_write_avg), 1.0))
    $d_fl = math.sqrt(if(max($stage2_origin_rollup.origin_del_avg) > 1.0, max($stage2_origin_rollup.origin_del_avg), 1.0))
    $c_fl = math.sqrt(if(max($stage2_origin_rollup.origin_create_avg) > 1.0, max($stage2_origin_rollup.origin_create_avg), 1.0))

    $r_safe_sd = if(max($stage2_origin_rollup.origin_read_stddev) > $r_fl, max($stage2_origin_rollup.origin_read_stddev), $r_fl)
    $w_safe_sd = if(max($stage2_origin_rollup.origin_write_stddev) > $w_fl, max($stage2_origin_rollup.origin_write_stddev), $w_fl)
    $d_safe_sd = if(max($stage2_origin_rollup.origin_del_stddev) > $d_fl, max($stage2_origin_rollup.origin_del_stddev), $d_fl)
    $c_safe_sd = if(max($stage2_origin_rollup.origin_create_stddev) > $c_fl, max($stage2_origin_rollup.origin_create_stddev), $c_fl)

    $r_raw = (max($stage2_origin_rollup.ip_total_reads) - max($stage2_origin_rollup.origin_read_avg)) / $r_safe_sd
    $w_raw = (max($stage2_origin_rollup.ip_total_writes) - max($stage2_origin_rollup.origin_write_avg)) / $w_safe_sd
    $d_raw = (max($stage2_origin_rollup.ip_total_deletes) - max($stage2_origin_rollup.origin_del_avg)) / $d_safe_sd
    $c_raw = (max($stage2_origin_rollup.ip_total_creates) - max($stage2_origin_rollup.origin_create_avg)) / $c_safe_sd

    $r_z = if(max($stage2_origin_rollup.origin_read_days) >= 7 and $r_raw > 0.0, $r_raw, 0.0)
    $w_z = if(max($stage2_origin_rollup.origin_write_days) >= 7 and $w_raw > 0.0, $w_raw, 0.0)
    $d_z = if(max($stage2_origin_rollup.origin_del_days) >= 7 and $d_raw > 0.0, $d_raw, 0.0)
    $c_z = if(max($stage2_origin_rollup.origin_create_days) >= 7 and $c_raw > 0.0, $c_raw, 0.0)

    $ip_origin_z = $r_z + $w_z + $d_z + $c_z
}

// --- ROOT STAGE: Per-Branch Maturity-Gated Evaluation & Composite Risk Ranking ---
$sa = $stage1_extract.sa
$vendor = $stage1_extract.vendor
$product = $stage1_extract.product
$resource = $stage1_extract.resource
$ip = $stage1_extract.ip
$ws = $stage1_extract.window_start
$sa = $stage3_origin_score.sa
$vendor = $stage3_origin_score.vendor
$product = $stage3_origin_score.product
$ip = $stage3_origin_score.ip
$ws = $stage3_origin_score.ws

match:
  $sa, $vendor, $product, $resource, $ws by 1d

outcome:
  $obs = sum($stage1_extract.observed_reads)
  $obs_writes = sum($stage1_extract.observed_writes)
  $obs_deletes = sum($stage1_extract.observed_deletes)
  $obs_creates = sum($stage1_extract.observed_creates)
  $distinct_ips = count_distinct($stage1_extract.ip)

  $dest_safe_sd = if(max($stage1_extract.dest_stddev) > math.sqrt(if(max($stage1_extract.dest_avg) > 1.0, max($stage1_extract.dest_avg), 1.0)), max($stage1_extract.dest_stddev), math.sqrt(if(max($stage1_extract.dest_avg) > 1.0, max($stage1_extract.dest_avg), 1.0)))
  $write_safe_sd = if(max($stage1_extract.dest_write_stddev) > math.sqrt(if(max($stage1_extract.dest_write_avg) > 1.0, max($stage1_extract.dest_write_avg), 1.0)), max($stage1_extract.dest_write_stddev), math.sqrt(if(max($stage1_extract.dest_write_avg) > 1.0, max($stage1_extract.dest_write_avg), 1.0)))
  $del_safe_sd = if(max($stage1_extract.dest_del_stddev) > math.sqrt(if(max($stage1_extract.dest_del_avg) > 1.0, max($stage1_extract.dest_del_avg), 1.0)), max($stage1_extract.dest_del_stddev), math.sqrt(if(max($stage1_extract.dest_del_avg) > 1.0, max($stage1_extract.dest_del_avg), 1.0)))
  $create_safe_sd = if(max($stage1_extract.dest_create_stddev) > math.sqrt(if(max($stage1_extract.dest_create_avg) > 1.0, max($stage1_extract.dest_create_avg), 1.0)), max($stage1_extract.dest_create_stddev), math.sqrt(if(max($stage1_extract.dest_create_avg) > 1.0, max($stage1_extract.dest_create_avg), 1.0)))

  $dest_raw = ($obs - max($stage1_extract.dest_avg)) / $dest_safe_sd
  $write_raw = ($obs_writes - max($stage1_extract.dest_write_avg)) / $write_safe_sd
  $del_raw = ($obs_deletes - max($stage1_extract.dest_del_avg)) / $del_safe_sd
  $create_raw = ($obs_creates - max($stage1_extract.dest_create_avg)) / $create_safe_sd

  $dest_z = if(max($stage1_extract.dest_active_days) >= 7 and $dest_raw > 0.0, $dest_raw, 0.0)
  $write_z = if(max($stage1_extract.dest_write_days) >= 7 and $write_raw > 0.0, $write_raw, 0.0)
  $del_z = if(max($stage1_extract.dest_del_days) >= 7 and $del_raw > 0.0, $del_raw, 0.0)
  $create_z = if(max($stage1_extract.dest_create_days) >= 7 and $create_raw > 0.0, $create_raw, 0.0)
  $origin_z = max($stage3_origin_score.ip_origin_z)
  $composite_risk = $dest_z + $write_z + $del_z + $create_z + $origin_z

condition:
  $composite_risk >= 3.0

order:
  $composite_risk desc
```

#### Query 2B: Two-Part Zero-Inflated Hurdle Model on Cloud Control-Plane & Secret-Access API Calls (`secops-statistical-hunter`)
Addresses zero-inflated cloud administrative and secret-access telemetry (`RESOURCE_READ`, `RESOURCE_WRITTEN`, `USER_RESOURCE_ACCESS`) over bounded raw windows: Part 1 requires dormant principals ($\le 2$ active days) to cross an awakening volume gate ($\ge 10$ events, scoring $3.0 \times (\text{obs} / 10.0)$), while Part 2 evaluates active principals using leave-one-out mean and variance with a `math.sqrt(max(loo_mean, 1.0))` dispersion floor and positive rectification.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant cloud principals awakening above a minimum volume gate or active principals surging across cloud resource and secret-access APIs via a Two-Part Hurdle Model.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, RESOURCE_WRITTEN, USER_RESOURCE_ACCESS)
// Statistical Model: Two-Part Hurdle Outlier Model (TWO_PART_HURDLE, Dormant Awakening Gate >= 10 & Positive-Rectified LOO Intensity Z >= 3.0)
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
    $read_access_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $write_events = sum(if(metadata.event_type = "RESOURCE_WRITTEN", 1, 0))
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_resources = count_distinct(target.resource.name)
    $sample_resource = array_distinct(target.resource.name)
}

// Stage 2: Historical moment accumulation across active windows per principal user
stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity

  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

// Root Stage: Two-Part Hurdle Evaluation (Dormant Awakening Gate + LOO Positive Intensity Z)
$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_resources)
  $sample_commands = array_distinct($entity_historical.sample_resource)

  // Leave-One-Out Continuous Intensity Standardization (Positive-Rectified)
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $raw_loo_sum = max($entity_stats.sum_x) - $observation_count
  $loo_sum = if($raw_loo_sum > 0, $raw_loo_sum, 0)
  $baseline_mean = 1.0 * $loo_sum / $n_prior
  $raw_loo_var = ((max($entity_stats.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $raw_intensity_z = ($observation_count - $baseline_mean) / $baseline_dispersion
  $intensity_z = if($raw_intensity_z > 0.0, $raw_intensity_z, 0.0)

  // Dormant Awakening Branch (Gated by >= 10 events for <= 2 active days)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 10.0)
  $dormant_score = if($observation_count >= 10, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 2, $dormant_score, $intensity_z)

condition:
  $observation_count >= 5
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

### Scenario 3: Intel Identification — WHOIS Lifecycle & Binary Prevalence Fusion

* **Curated Detection Operational Focus**: Correlates endpoint and network activity with emerging threat-intelligence context.
* **How Multi-Stage UEBA Extends Coverage**: Combines mature ($\ge 7$ active baseline days) 30-day HTTP volume Z-scores with event-anchored `GLOBAL_CONTEXT` WHOIS domain registration age ($\le 30\text{d}$) or expiration (`Query 3A`), and mature 30-day file execution Z-scores with 10-day `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`, `Query 3B`). Because Entity Context Graph snapshots lag ~24 hours, Mode A searches run over `[D-2, D+1)` while pinning Stage 1 events to `D` (`"2026-10-29"`).

#### Query 3A: 2-Stage Hybrid 30-Day HTTP Volume + `GLOBAL_CONTEXT` WHOIS Domain Lifecycle (`secops-risk-metrics-multistage`)
Fuses 30-day host-to-domain HTTP query baselines (`metrics.http_queries_total` with `math.sqrt(max(mean, 1.0))` dispersion floor and `$active_baseline_days >= 7`) with `GLOBAL_CONTEXT` WHOIS creation and expiration timestamps to amplify outbound HTTP surges targeting Newly Registered Domains ($\le 30\text{d}$ relative to the observed event timestamp, $2.5\times$ multiplier) or expired domains ($3.0\times$ multiplier). Entities without a WHOIS graph record drop out of the inner join.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day HTTP query baselines with GLOBAL_CONTEXT WHOIS lifecycle metadata to detect anomalous traffic to newly registered or expired domains.
// ARCHITECTURE: 2-STAGE DUAL-PLANE WHOIS DOMAIN LIFECYCLE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.http_queries_total, >= 7 active days, sqrt(max(mean, 1.0)) floor) + WHOIS Lifecycle Multiplier ($z_score >= 3.0)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day HTTP Query Baseline (pinned to Mode A scored UTC day D = 2026-10-29; search window [D-2, D+1))
stage stage1_egress_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)

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
    $hist_stddev = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
    $hist_active_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        target.hostname: target.hostname
    ))
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
  $dispersion_floor = math.sqrt(if($mean > 1.0, $mean, 1.0))
  $safe_stddev = if($stddev > $dispersion_floor, $stddev, $dispersion_floor)
  $z_score = ($observed - $mean) / $safe_stddev
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
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and ($is_nrd = 1.0 or $is_expired = 1.0)

order:
  $fused_threat_score desc
```

#### Query 3B: 2-Stage Hybrid 30-Day File Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Fuses each endpoint's 30-day process execution baseline (`metrics.file_executions_total` with `math.sqrt(max(mean_execs, 1.0))` dispersion floor and `$active_baseline_days >= 7`) with `DERIVED_CONTEXT` 10-day organizational file prevalence (`day_count = 10`, `rolling_max <= 3`), isolating execution surges of low-prevalence binaries (`$z_score >= 3.0`). Note that Stage 2 is an inner join against `DERIVED_CONTEXT`, so hashes without a graph record drop out; when `first_seen_time = 0`, the `< 7d` novelty boost is disabled (`1.5x` isolated-binary multiplier only).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day host binary execution baselines with DERIVED_CONTEXT 10-day file prevalence to detect execution surges of rare binaries.
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Statistical Model: 30d Parametric Z-Score (metrics.file_executions_total, >= 7 active days, sqrt(max(mean, 1.0)) floor) + ECG File Rarity (day_count = 10, rolling_max <= 3)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (pinned to Mode A scored UTC day D = 2026-10-29; search window [D-2, D+1))
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
  $dispersion_floor = math.sqrt(if($mean_execs > 1.0, $mean_execs, 1.0))
  $safe_stddev = if($stddev_execs > $dispersion_floor, $stddev_execs, $dispersion_floor)
  $z_score = ($observed_execs - $mean_execs) / $safe_stddev
  $active_baseline_days = max($stage1_process_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_file_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_file_derived_context.enterprise_day_count)
  $first_seen = min($stage2_file_derived_context.first_seen_ts)
  $obs_ts = max($stage1_process_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $binary_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Binary Multiplier: 2.5x boost when first_seen_time > 0 and age <= 7d; 1.5x otherwise
  $ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)
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

### Scenario 4: Core Hunt Rules — External Flow-Gap Regularity Screen & Candidate-Gated Discovery

* **Curated Detection Operational Focus**: Hunts for periodic callback patterns and internal discovery bursts.
* **How Multi-Stage UEBA Extends Coverage**: Screens persistent low-prevalence external host-to-IP pairs with uniform hourly span-to-count flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$) in Wave 1 (`Query 4A`), then evaluates hourly post-exploitation process and network discovery surges strictly on candidate hosts surfaced by `Query 4A` via UDM Loopback leave-one-out personal Z-scores in Wave 2 (`Query 4B`).

#### Query 4A: Cross-Bucket Flow-Gap Ratio Dispersion Screen ($\text{CV} \le 0.20$) on External Callbacks (`secops-statistical-hunter`)
Screens external `NETWORK_CONNECTION` pairs (excluding RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local ranges) by measuring the cross-bucket Coefficient of Variation ($\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$) of within-hour span-to-count flow-gap ratios `1.0 * (max($ts) - min($ts)) / count(metadata.id)` restricted to low-prevalence external IPs ($\le 3$ internal hosts). For exact consecutive inter-arrival sleep jitter on candidate pairs, run `C2_BEACONING_JITTER` (`c2_beaconing_jitter_2stage.yl2` + `micro_python_helpers.py c2-jitter`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen persistent low-prevalence external host-to-IP pairs with uniform cross-bucket flow-gap ratios via Coefficient of Variation.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN, CV = sigma_gap / mu_gap <= 0.20, fleet_prevalence <= 3 hosts)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Measure hourly bucket span-to-count flow-gap ratio per (host, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    $dst_ip != ""
    $dst_ip != "::1"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
    // Exclude internal RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local destinations
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "127.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "224.0.0.0/4")
    not net.ip_in_range_cidr($dst_ip, "169.254.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "255.255.255.255/32")
    not net.ip_in_range_cidr($dst_ip, "fe80::/10")
    not net.ip_in_range_cidr($dst_ip, "ff00::/8")
    $ts = metadata.event_timestamp.seconds

  match:
    $host, $dst_ip by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = 1.0 * (max($ts) - min($ts)) / count(metadata.id)
}

// Stage 2: Aggregate flow-gap ratio statistics across active hours per pair
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

// Root Stage: Explicit (host, dst_ip) pair grain, unbiased flow-gap ratio CV, and 6 Evidence Pillars
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

  // Unbiased Flow-Gap Ratio CV = sigma_gap / mu_gap
  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 24
  and $baseline_mean >= 1.0
  and $fleet_prevalence <= 3
  and $cv <= 0.20

order:
  $cv asc
```

#### Query 4B: 4-Stage UDM-Gated Leave-One-Out Personal Z & Upstream Fusion on Host Discovery (`secops-statistical-hunter`)
Executes in **Wave 2** strictly on candidate hosts surfaced by `Query 4A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`), computing each candidate host's leave-one-out hourly personal Z-score (`math.sqrt(max(loo_mean, 1.0))` dispersion floor) across separated `PROCESS_LAUNCH` and `NETWORK_CONNECTION` discovery activity combined with `Query 4A`'s upstream Z-equivalent score.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED PERSONAL LOO Z & UPSTREAM FUSION PIPELINE
// Goal: Detect localized post-exploitation discovery and lateral reconnaissance surges on candidate hosts surfaced by Query 4A via UDM Loopback.
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Hourly Leave-One-Out Personal Z-Score Fusion ($delta_z >= 3.5)
// Skill: secops-statistical-hunter
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
    $proc_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $net_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $hourly_val = count(metadata.id)
    $hourly_val_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
}

stage personal_baseline {
    $host = $hourly_counts.host

  match:
    $host

  outcome:
    $sum_x = sum($hourly_counts.hourly_val)
    $sum_x2 = sum($hourly_counts.hourly_val_sq)
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
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($hourly_counts.distinct_procs)

  // Leave-One-Out Personal Standardization with Poisson Dispersion Floor
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $raw_loo_sum = max($personal_baseline.sum_x) - $observation_count
  $loo_sum = if($raw_loo_sum > 0, $raw_loo_sum, 0)
  $baseline_mean = 1.0 * $loo_sum / $n_prior
  $raw_loo_var = ((max($personal_baseline.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)

  $z_personal = ($observation_count - $baseline_mean) / $baseline_dispersion
  $delta_z = $z_personal + ($upstream_z * 0.25)
  $z_score = $delta_z

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 5
  and $delta_z >= 3.5

order:
  $delta_z desc
```

---

### Scenario 5: Cross-Plane Hunt Signal Aggregation & Exfiltration Drift

* **Curated Detection Operational Focus**: Tracks staged data transfers and multi-signal hunt classifications.
* **How Multi-Stage UEBA Extends Coverage**: Accumulates multi-day positive standardized slack excesses (`Windowed Slack Sum` $W = \sum \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ drift days) against 30-day `metrics.network_bytes_outbound` (`Query 5A`), paired with a 4-stage non-parametric Iglewicz-Hoaglin Modified Z-Score ($M_Z > 3.5$) over raw daily outbound `NETWORK_CONNECTION` byte volumes (`Query 5B`).

#### Query 5A: 3-Stage Windowed Slack Sum Prefilter on 30-Day Outbound Network Bytes (`secops-risk-metrics-multistage`)
Catches low-and-slow multi-day outbound data exfiltration across multi-day Mode B windows (e.g., 7–14 days; single-day Mode A returns 0 rows by construction because `$drift_days >= 2`) by summing daily standardized positive excesses above a $k = 0.5\sigma$ slack allowance ($W = \sum \max(0, Z_t - 0.5) \ge 3.0$) using the `44979.0`-byte `metrics.network_bytes_outbound` dispersion floor and `$active_days >= 7`. Because YARA-L 2.0 does not carry recursive $S_{t-1}$ state across buckets, exact sequential Page's CUSUM ($S_t = \max(0, S_{t-1} + Z_t - k)$) is evaluated post-query via `longitudinal_cusum_series_3stage.yl2` and `cusum_helper.py`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect low-and-slow multi-day outbound data exfiltration drift across endpoints via a 3-Stage Windowed Slack Sum on 30-day network_bytes_outbound.
// ARCHITECTURE: 3-STAGE WINDOWED SLACK SUM DRIFT PREFILTER PIPELINE
// Statistical Model: Windowed Slack Sum (W = sum(max(0, Z_t - 0.5)) >= 3.0, drift_days >= 2, active_days >= 7, 44979.0 byte dispersion floor)
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Raw Daily Outbound Byte Volume & 30-Day Baseline Extraction
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
}

// Stage 2: Daily Standardized Slack-Excess Drift Extraction (by 1d, 44979.0 byte dispersion floor)
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
    $daily_z = $raw_drift / $safe_stddev
    $z_minus_slack = $daily_z - 0.5
    $daily_excess = if($active_days >= 7 and $z_minus_slack > 0.0, $z_minus_slack, 0.0)
}

// Stage 3 (Root Stage): Multi-Day Windowed Slack Sum Aggregation Across Window
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

  $cusum_drift = sum($stage2_daily_drift.daily_excess)
  $windowed_slack_sum = $cusum_drift
  $cusum_drift_score = $cusum_drift
  $drift_days = sum(if($stage2_daily_drift.daily_excess > 0.0, 1, 0))
  $max_daily_z = max($stage2_daily_drift.daily_z)

condition:
  $active_days >= 7
  and $cusum_drift_score >= 3.0
  and $drift_days >= 2

order:
  $cusum_drift_score desc
```

#### Query 5B: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Daily Outbound Network Transfers (`secops-statistical-hunter`)
Provides a 50%-breakdown-point non-parametric outlier detector over raw `NETWORK_CONNECTION` outbound byte volumes per host across active baseline days ($\ge 7$ active days, $\ge 10\text{ MiB}$ daily outbound volume), using the **Iglewicz-Hoaglin Modified Z-Score** ($M_Z = 0.6745 \cdot (x - \text{Median}) / \text{MAD} > 3.5$) with an automatic Mean Absolute Deviation ($1.253314 \times \text{MeanAD}$) fallback when $\text{MAD} = 0$ and a `44979.0`-byte constant-history dispersion floor.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect acute outbound data exfiltration spikes on skewed host baselines via 4-Stage Non-Parametric Median Absolute Deviation (MAD / Modified Z-Score).
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Iglewicz-Hoaglin Modified Z-Score (MAD_MODIFIED_Z, M_Z > 3.5, active_days >= 7, MeanAD & 44979.0 byte floor fallback)
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

// Stage 2: Baseline median of daily outbound bytes per host (active days only)
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

  // Robust scale with Iglewicz-Hoaglin MAD=0 fallback and 44979.0 byte dispersion floor
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 44979.0, $robust_scale, 44979.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 10485760
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

---

### Scenario 6: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual hunting leads evaluated per telemetry domain.
* **How Multi-Stage UEBA Extends Coverage**: Correlates entities matching $\ge 2$ distinct behavioral hunting scenarios within the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 6: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–5 can fire inside ambiguous overlap regimes when evaluated in isolation, and 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud resource names.

**Scenario 6 (`Query 6`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query 4B` Stage B) queries have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across Upstream Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-7]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean $L_2$ Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-equivalent scores (`$capstone_threat_norm_sq >= 25.0`, i.e., $L_2$ norm $\ge 5.0$).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Separately counts per-domain raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to surface both the cross-scenario Euclidean $L_2$ convergence score and raw forensic artifacts in a single query.

#### Query 6: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across Mandiant Hunting scenarios via UDM Loopback regex token union while joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-7]`)
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
    $proc_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $net_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $cloud_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $auth_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
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

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_score desc
```

---

## 3. Mandiant Frontline Anti-Forensics & Stealth Exfiltration: Per-Flow Payload Shape & Ingestion-Lag Quantiles

Mandiant Frontline investigations frequently encounter threat actors who (1) exfiltrate staged archives over a handful of heavy outbound flows (`$p90_bytes`) while keeping median flows (`$p50_bytes`) at normal heartbeat sizes, or (2) buffer, delay, or timestomp EDR/syslog telemetry during hands-on-keyboard operations.
* **Query 7A**: Pairs a 30-day `metrics.network_bytes_outbound` Z-score ($\ge 7$ active baseline days, `44979.0`-byte dispersion floor) with intra-bucket per-flow `$p50_bytes` and `$p90_bytes` (`$flow_tail_burst_ratio = $p90_bytes / $safe_p50 >= 10.0`).
* **Query 7B**: Single-stage hourly diagnostic audit computing the 5-point ingestion-lag quantile profile (`$p10, $p25, $p50, $p75, $p90` of `metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds`) and Bowley quartile skewness (`$bowley_skew`) per `log_type` to surface sensor buffering, batch replay, or negative clock-skew anomalies.

#### Query 7A: Macro 30-Day Outbound Egress Z + Intra-Bucket Per-Flow $P_{50}/P_{90}$ Shape (`secops-risk-metrics-multistage`)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Combine 30-day metrics.network_bytes_outbound macro Z-score with intra-bucket per-flow P50/P90 payload quantile shape fingerprinting.
// Statistical Model: 30d Parametric Z-Score (metrics.network_bytes_outbound, >= 7 active days, 44979.0 byte floor) + Intra-Bucket P90/P50 Tail Ratio (>= 10.0)
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

#### Query 7B: Telemetry Ingestion-Lag & Clock-Skew Quantile Audit (`secops-statistical-hunter`)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Profile hourly telemetry ingestion-lag quantiles, Bowley skewness, and negative clock-skew anomalies per log_type.
// Statistical Model: Single-Stage 5-Point Ingestion-Lag Quantiles (P10..P90) & Bowley Quartile Skewness
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
