# Contextualizing Non-Prioritized Domain, File & IP IOC Matching with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Non-Prioritized IOC Matching** curated detection pack provides broad indicator matching across domain, file hash, and IP address feeds where indicators may carry lower static confidence or broader infrastructure overlap (such as shared hosting, CDNs, or aged threat feeds).

To help analysts separate true compromises from benign shared-infrastructure noise—and to catch novel infrastructure before it appears on static lists—this playbook pairs indicator-adjacent telemetry with **30-Day Behavioral Baselines (`secops-risk-metrics-multistage`)**, **`DERIVED_CONTEXT` Local Prevalence**, **Shannon Subdomain Entropy**, **Leave-One-Out Discrete Poisson Arrival Rarity**, and **Empirical Bayes Connection Shrinkage**.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 4`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Applied Threat Intelligence — Non-Prioritized IOC Matching & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Domain Indicator Contextualization & DGA / Tunneling Detection** | Broad matching of DNS queries and HTTP requests against non-prioritized domain indicators. | Combines 30-day HTTP/DNS volume baselines with 10-day `DERIVED_CONTEXT` local domain prevalence (`day_max <= 3`) and multi-class character Shannon entropy ($H(X) \ge 3.9$) to isolate rare, high-entropy DGA or DNS-tunneling domains. | `Query 1A` (30d HTTP + 10d Domain Prevalence)<br>`Query 1B` (Subdomain Shannon Entropy) |
| **2. File Hash Contextualization & Rare Binary Arrival** | Matches endpoint process and file events against broad file-hash indicator feeds. | Pairs 30-day host file execution baselines (`metrics.file_executions_total`) and 10-day `DERIVED_CONTEXT` prevalence with Leave-One-Out Discrete Poisson arrival rarity across the enterprise fleet. | `Query 2A` (30d Execution + 10d Prevalence)<br>`Query 2B` (Discrete Poisson Arrival Rarity) |
| **3. IP Indicator Contextualization & Anomalous Egress Flows** | Matches network connections against non-prioritized IP indicators. | Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Empirical Bayes Gamma-Poisson connection shrinkage so shared CDN/cloud IPs are suppressed while true host-level egress anomalies surface. | `Query 3A` (Piecewise 30d Egress Baseline)<br>`Query 3B` (Empirical Bayes IP Shrinkage) |
| **4. Capstone Multi-Scenario IOC Entity Convergence** | Individual domain, file, or IP indicator matches evaluated independently. | Correlates endpoints matching $\ge 2$ distinct behavioral domain, file, or IP scenarios in the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Domain-Based Indicator Matching — Behavioral Rarity & Subdomain Entropy

* **Curated Detection Operational Focus**: Broad matching of DNS queries and HTTP requests against non-prioritized domain indicators.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day HTTP/DNS volume baselines with 10-day `DERIVED_CONTEXT` local domain prevalence (`day_max <= 3`) and multi-class character Shannon entropy ($H(X) \ge 3.9$) to isolate rare, high-entropy DGA or DNS-tunneling domains.

#### Query 1A: 2-Stage Hybrid 30-Day HTTP Volume (`metrics.http_queries_total`) + `DERIVED_CONTEXT` 10-Day Domain Prevalence (`secops-risk-metrics-multistage`)
Replaces flat, unprioritized domain IOC matching with a 2-stage hybrid pipeline that scores per-(host, domain) HTTP traffic against its 30-day behavioral baseline (`metrics.http_queries_total`) and joins with Chronicle's `DERIVED_CONTEXT` Entity Context Graph (`day_count = 10`, `rolling_max <= 3`). Ubiquitous CDN, SaaS, and sinkholed domains contacted by $>3$ hosts across the enterprise are automatically pruned, while rare external domains accompanied by an HTTP request surge (`$z_score >= 3.0`) receive a $2.5\times$ novelty boost when first seen within the last 7 days.

```yara
// ============================================================================
// Goal: Suppress ubiquitous CDN/sinkhole domain false positives while detecting rare external domain contacts (10-day rolling_max <= 3 hosts) accompanied by a 30-day HTTP volume surge.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Destination HTTP Query Baseline per (host, domain)
stage stage1_query_baseline {
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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Domain Prevalence & First Seen)
stage stage2_domain_derived_context {
    $dom.graph.metadata.source_type = "DERIVED_CONTEXT"
    $dom.graph.metadata.entity_type = "DOMAIN_NAME"
    $dom.graph.entity.domain.name = $domain
    $dom.graph.entity.domain.prevalence.day_count = 10
    $dom.graph.entity.domain.prevalence.rolling_max <= 3
    $dom.graph.entity.domain.prevalence.rolling_max > 0
    $domain != ""

  match:
    $domain

  outcome:
    $enterprise_day_count = min($dom.graph.entity.domain.prevalence.day_count)
    $enterprise_rolling_max = max($dom.graph.entity.domain.prevalence.rolling_max)
    $first_seen_ts = min($dom.graph.entity.domain.first_seen_time.seconds)
    $last_seen_ts = max($dom.graph.entity.domain.last_seen_time.seconds)
}

// Root Stage: Fuse Personal HTTP Query Z-Score with Enterprise Domain Prevalence Multiplier
$host = $stage1_query_baseline.host
$domain = $stage1_query_baseline.domain
$domain = $stage2_domain_derived_context.domain

match:
  $host, $domain by 1d

outcome:
  $observed_queries = max($stage1_query_baseline.observed_val)
  $mean_queries = max($stage1_query_baseline.hist_mean)
  $stddev_queries = max($stage1_query_baseline.hist_stddev)
  $z_score = ($observed_queries - $mean_queries) / if($stddev_queries > 0, $stddev_queries, 1.0)
  $active_baseline_days = max($stage1_query_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_domain_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_domain_derived_context.enterprise_day_count)
  $first_seen = min($stage2_domain_derived_context.first_seen_ts)
  $obs_ts = max($stage1_query_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $domain_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Rare Domain Multiplier: 2.5x threat score boost for novel destinations first seen <= 7 days ago, 1.5x for <= 3 hosts
  $is_novel_domain = if($first_seen > 0 and $domain_age_days <= 7.0 and $domain_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_domain = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

condition:
  $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

#### Query 1B: Multi-Class Character Shannon Entropy ($H(X) \ge 3.8$) on DNS Queries (`secops-statistical-hunter`)
Closes the zero-day DGA, DNS tunneling, and mixed-case evasion gap by computing information-theoretic **Multi-Class Character Shannon Entropy** ($H(X) = -\sum p_i \log_2 p_i$ scaled to byte-entropy equivalent) across lowercase, uppercase, digit, and symbol/delimiter character classes on `network.dns.questions.name`, paired with an enterprise fleet prevalence gate (`$fleet_prevalence <= 3` hosts) so internal service-discovery domains are ignored.

```yara
// ============================================================================
// Goal: Detect unindexed DGA domains, DNS tunneling payloads, and high-entropy C2 subdomains in NETWORK_DNS traffic across the fleet.
// Target Telemetry: UDM_EVENTS (NETWORK_DNS: network.dns.questions.name)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)) >= 3.8)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Extract DNS query lengths and character-class distributions per host and queried domain
stage dns_feature_extraction {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.hostname = $host
    $host != ""
    $domain = network.dns.questions.name
    $domain != ""
    strings.length($domain) >= 24

  match:
    $host, $domain by 1d

  outcome:
    $query_count = count(metadata.id)
    $raw_len = max(strings.length($domain))
    $safe_len = if($raw_len > 0, $raw_len, 1)

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax for AST compliance)
    $len_no_lower = max(strings.length(re.replace($domain, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($domain, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($domain, `\d`, "")))

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

// Stage 2: Enterprise fleet prevalence of each distinct queried DNS domain across hosts
stage dns_fleet_prevalence {
    $domain = $dns_feature_extraction.domain

  match:
    $domain by 1d

  outcome:
    $fleet_hosts = count_distinct($dns_feature_extraction.host)
}

// Root Stage: Compute 4-Class Shannon Entropy Equivalent & Emit 6 Core Evidence Pillars
$host = $dns_feature_extraction.host
$domain = $dns_feature_extraction.domain
$domain = $dns_fleet_prevalence.domain

match:
  $host, $domain by 1d

outcome:
  $q_count = max($dns_feature_extraction.query_count)
  $len = max($dns_feature_extraction.raw_len)
  $p_lower = max($dns_feature_extraction.p_lower)
  $p_upper = max($dns_feature_extraction.p_upper)
  $p_digit = max($dns_feature_extraction.p_digit)
  $p_other = max($dns_feature_extraction.p_other)

  $h_lower = (0.0 - $p_lower) * (math.log($p_lower) / 0.693147)
  $h_upper = (0.0 - $p_upper) * (math.log($p_upper) / 0.693147)
  $h_digit = (0.0 - $p_digit) * (math.log($p_digit) / 0.693147)
  $h_other = (0.0 - $p_other) * (math.log($p_other) / 0.693147)

  $class_entropy = $h_lower + $h_upper + $h_digit + $h_other
  $length_bonus = if($len >= 48, 0.5, 0.0)
  $shannon_entropy_score = ($class_entropy * 2.25) + $length_bonus
  $z_score = $shannon_entropy_score

  // 6 Core Evidence Pillars
  $observation_count = $q_count
  $baseline_active_samples = $len
  $baseline_mean = $class_entropy
  $baseline_dispersion = $shannon_entropy_score
  $fleet_prevalence = max($dns_fleet_prevalence.fleet_hosts)
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 24
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 3.8

order:
  $shannon_entropy_score desc
```

---

---

### Scenario 2: File-Based Indicator Matching — Rare Binary Prevalence & Discrete Poisson Arrival Rarity

* **Curated Detection Operational Focus**: Matches endpoint process and file events against broad file-hash indicator feeds.
* **How Multi-Stage UEBA Extends Coverage**: Pairs 30-day host file execution baselines (`metrics.file_executions_total`) and 10-day `DERIVED_CONTEXT` prevalence with Leave-One-Out Discrete Poisson arrival rarity across the enterprise fleet.

#### Query 2A: 2-Stage Hybrid 30-Day Process Execution (`metrics.file_executions_total`) + `DERIVED_CONTEXT` 10-Day File Prevalence (`secops-risk-metrics-multistage`)
Eliminates dependence on static `GCTI Feed` hash lists and suppresses sanctioned fleet-wide RMM noise by scoring per-(host, SHA256) process execution volume against its 30-day behavioral baseline (`metrics.file_executions_total`) and joining with `DERIVED_CONTEXT` 10-day `FILE` prevalence (`rolling_max <= 3`). Binaries deployed across $>3$ hosts (such as sanctioned IT agents) are automatically filtered out, while rare binaries ($\le 3$ hosts) exhibiting an execution surge receive a $2.5\times$ novelty multiplier if first seen within 7 days.

```yara
// ============================================================================
// Goal: Detect anomalous execution surges of rare binaries (10-day org prevalence rolling_max <= 3 hosts) while suppressing sanctioned fleet-wide RMM/admin tools.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
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

// Root Stage: Fuse Personal Outlier Z-Score with Enterprise File Prevalence Multiplier
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

#### Query 2B: Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 \ge 9.0$) on Rare Process Executions (`secops-statistical-hunter`)
Detects rare or newly introduced RMM tools, cryptominers, and suspicious Linux/Windows binaries on `$e.target.process.file.full_path` (fixing the `principal` vs. `target` process constraint) even when their SHA-256 hash is modified or absent from threat feeds. Using a **Leave-One-Out Discrete Poisson Arrival Model** ($\lambda = (\text{prior\_runs} + 0.5) / 29.0$, $Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$), it surfaces tools with a near-zero historical rate ($\lambda \le 0.5\text{/day}$) that suddenly execute on an endpoint.

```yara
// ============================================================================
// Goal: Detect statistically improbable surges in rare RMM, cryptomining, or administrative binaries per host via Leave-One-Out Discrete Poisson Rarity.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH: target.process.file.full_path)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (Z_Poisson^2 = (k - lambda)^2 / lambda >= 9.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Daily execution counts per host and target process binary (by 1d)
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""
    (
      re.regex(target.process.file.full_path, `(?i)(anydesk|teamviewer|screenconnect|atera|splashtop|rustdesk|ngrok|chisel|cloudflared|xmrig|minerd|tmate|socat|/tmp/|/dev/shm/|/var/tmp/)`)
      or re.regex(target.process.command_line, `(?i)(stratum\+tcp|stratum\+ssl|xmrig|cryptonight|randomx|anydesk|screenconnect|rustdesk|ngrok|cloudflared|chmod\s+\+x\s+/tmp/)`)
    )

  match:
    $entity, $tool by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
}

// Stage 2: Historical accumulation across all active days per host and binary
stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool

  match:
    $entity, $tool

  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $active_days = count($daily_tool_counts.window_start)
}

// Root Stage: Calculate Leave-One-Out Discrete Poisson Score & Emit 6 Core Evidence Pillars
$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool

match:
  $entity, $tool by 1d

outcome:
  // Leave-one-out prior runs & Jeffreys-smoothed daily arrival rate over 29 prior calendar days
  $today_k = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 29.0

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($baseline_accumulation.active_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $lambda
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

  // Aggregate Poisson Squared Score (Z^2 = (k - lambda)^2 / lambda)
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 2
  and $baseline_mean > 0.0
  and $baseline_mean <= 0.5
  and $baseline_dispersion > 0.0
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 9.0

order:
  $poisson_z_sq desc
```

---

---

### Scenario 3: IP-Based Indicator Matching — Outbound Byte Anomalies & Bayesian Connection Shrinkage

* **Curated Detection Operational Focus**: Matches network connections against non-prioritized IP indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Empirical Bayes Gamma-Poisson connection shrinkage so shared CDN/cloud IPs are suppressed while true host-level egress anomalies surface.

#### Query 3A: 2-Stage Hybrid 30-Day Outbound Network Bytes (`metrics.network_bytes_outbound`) + `DERIVED_CONTEXT` Infant Asset Age (`secops-risk-metrics-multistage`)
Replaces static IP list matching with a 2-stage hybrid pipeline that scores every endpoint's daily outbound byte volume against its 30-day behavioral baseline (`metrics.network_bytes_outbound`) and joins with `DERIVED_CONTEXT` asset `first_seen_time` (`<= 7.0` days). Newly commissioned or rogue assets (`$asset_age_days <= 7.0`) exhibiting immediate outbound byte anomalies (`$z_score >= 3.0`) receive a $2.5\times$ threat multiplier, catching C2, proxy tunneling, and exfiltration even when the target IP is not in `GCTI Feed`.

```yara
// ============================================================================
// Goal: Detect anomalous outbound network byte surges on newly provisioned or rogue infant assets (first_seen_time <= 7 days) regardless of static IP feed coverage.
// Statistical Model: 2-Stage Hybrid 30-Day Behavioral Z-Score (metrics.network_bytes_outbound) + DERIVED_CONTEXT Infant Asset Age Multiplier
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT ASSET AGE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Host Outbound Network Byte Baseline (metrics.network_bytes_outbound)
stage stage1_asset_baseline {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)

    $hist_mean = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $hist_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $event_timestamp = max(metadata.event_timestamp.seconds)
}

// Stage 2: Chronicle Derived Context Graph Lookup (Asset First Seen)
stage stage2_asset_derived_context {
    $asset.graph.metadata.source_type = "DERIVED_CONTEXT"
    $asset.graph.metadata.entity_type = "ASSET"
    $asset.graph.entity.asset.hostname = $host
    $host != ""

  match:
    $host

  outcome:
    $first_seen_ts = min($asset.graph.entity.asset.first_seen_time.seconds)
}

// Root Stage: Fuse Host Outbound Byte Z-Score with Infant Asset Age Multiplier
$host = $stage1_asset_baseline.host
$host = $stage2_asset_derived_context.host

match:
  $host by 1d

outcome:
  $observed = max($stage1_asset_baseline.observed_val)
  $mean = max($stage1_asset_baseline.hist_mean)
  $stddev = max($stage1_asset_baseline.hist_stddev)
  $z_score = ($observed - $mean) / if($stddev > 0, $stddev, 1.0)
  $active_baseline_days = max($stage1_asset_baseline.hist_active_days)

  $first_seen = min($stage2_asset_derived_context.first_seen_ts)
  $obs_ts = max($stage1_asset_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $asset_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Infant Asset Multiplier: 2.5x threat score boost for machines first seen <= 7 days ago
  $is_infant_asset = if($first_seen > 0 and $asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $threat_multiplier = if($is_infant_asset = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $threat_multiplier

condition:
  $z_score >= 3.0
  and $asset_age_days <= 7.0

order:
  $threat_score desc
```

#### Query 3B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Outbound Network Connection Bursts (`secops-statistical-hunter`)
Evaluates hourly outbound network connection bursts via **Poisson-Gamma Bayesian Conjugate Updating** strictly on candidate endpoints surfaced by `Query 3A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`).

```yara
// ============================================================================
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect hourly outbound network connection bursts on candidate endpoints from Query 3A (strictly gated by Query 3A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson-Gamma Bayesian Conjugate Updating
// ============================================================================

stage stage1_upstream_3a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_3a_z = max(security_result.confidence_score)
}

stage host_hourly_activity {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_exts = count_distinct(target.ip)
}

stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
    $active_hours = count($host_hourly_activity.window_start)
}

$host = $stage1_upstream_3a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_3a_candidates.upstream_3a_z)
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = 1
  $distinct_binaries = max($host_hourly_activity.distinct_exts)

  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $alpha_0 = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $beta_0 = max($host_prior_stats.hist_mean) / $safe_var
  $credibility_z = $baseline_active_samples / ($baseline_active_samples + $beta_0 + 1.0)
  $posterior_rate = ($alpha_0 + $observation_count) / ($beta_0 + 1.0)
  $safe_mean = if($baseline_mean > 0, $baseline_mean, 1.0)
  $gamma_shrinkage_score = ($posterior_rate / $safe_mean) * (1.0 + $credibility_z)
  $z_score = $gamma_shrinkage_score

condition:
  $baseline_active_samples >= 2
  and $observation_count >= 10
  and $gamma_shrinkage_score >= 3.5

order:
  $gamma_shrinkage_score desc
```

---

---

### Scenario 4: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual domain, file, or IP indicator matches evaluated independently.
* **How Multi-Stage UEBA Extends Coverage**: Correlates endpoints matching $\ge 2$ distinct behavioral domain, file, or IP scenarios in the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 4: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–3 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 4 (`Query 4`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 3 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 4: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 3 Non-Prioritized IOC Matching scenarios (1 through 3B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0) + Cross-Plane Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-3]`)
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
