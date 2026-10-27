# Contextualizing Non-Prioritized Domain, File & IP IOC Matching with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Non-Prioritized IOC Matching** curated detection pack provides broad indicator matching across domain, file hash, and IP address feeds where indicators may carry lower static confidence or broader infrastructure overlap (such as shared hosting, CDNs, or aged threat feeds).

To help analysts separate true compromises from benign shared-infrastructure noise—and to catch novel infrastructure before it appears on static lists—this playbook pairs indicator-adjacent telemetry with **30-Day Behavioral Baselines (`secops-risk-metrics-multistage`)**, **`DERIVED_CONTEXT` Local Prevalence**, **Shannon Subdomain Entropy**, **Leave-One-Out Discrete Poisson Arrival Rarity**, and **Empirical Bayes Connection Shrinkage**.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax for AST compliance)
    $len_no_lower = max(strings.length(re.replace($domain, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($domain, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($domain, `\d`, "")))

    $c_lower = $raw_len - $len_no_lower
    $c_upper = $raw_len - $len_no_upper
    $c_digit = $raw_len - $len_no_digit
    $c_other_raw = $raw_len - ($c_lower + $c_upper + $c_digit)
    $c_other = if($c_other_raw > 0, $c_other_raw, 0)
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
  $safe_len = if($len > 0, $len, 1)

  $n_lower = max($dns_feature_extraction.c_lower)
  $n_upper = max($dns_feature_extraction.c_upper)
  $n_digit = max($dns_feature_extraction.c_digit)
  $n_other = max($dns_feature_extraction.c_other)

  // Empirical probability per character class (pre-computed for outcome if() compliance)
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

#### Query 3B: Empirical Bayes Gamma-Poisson Credibility Shrinkage on Outbound Network Connection Bursts (`secops-statistical-hunter`)
Replaces the rigid `#e > 100` hourly connection cliff in curated detection rules with **Method-of-Moments Empirical Bayes Gamma-Poisson Credibility Shrinkage** (`by 1h`). By estimating each host's Gamma prior parameters ($\alpha_0 = \mu^2 / \sigma^2, \beta_0 = \mu / \sigma^2$) across active hours and filtering out blocked connections (`not security_result.action = "BLOCK"`), noisy proxy/NAT hosts are automatically shrunk toward their prior mean while a sudden connection burst on a stable endpoint triggers a high posterior belief shift ($\text{anomaly\_score} \ge 3.0$) well below 100 events.

```yara
// ============================================================================
// Goal: Replace rigid #e > 100 hourly connection cutoffs with host-adaptive Empirical Bayes Gamma-Poisson Credibility Shrinkage over unblocked outbound network connections.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting (by 1h, anomaly_score >= 3.0)
// Skill: secops-statistical-hunter
// ============================================================================

// Stage 1: Hourly unblocked outbound network connection volume and target IP diversity per host
stage host_hourly_activity {
    metadata.event_type = "NETWORK_CONNECTION"
    not security_result.action = "BLOCK"
    principal.asset.hostname = $host
    $host != ""
    target.ip != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_targets = count_distinct(target.ip)
}

// Stage 2: Historical Parameter Estimation (Method of Moments Gamma Prior per host)
stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
    $active_hours = count($host_hourly_activity.window_start)
}

// Stage 3: Organizational Peer Prevalence Baseline per hourly window
stage fleet_context {
    $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($host_hourly_activity.host)
}

// Root Stage: Bayesian Conjugate Updating, Credibility Scoring & 6 Core Evidence Pillars
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_targets)

  // Method-of-Moments Gamma Prior (alpha_0 = mu^2 / sigma^2, beta_0 = mu / sigma^2)
  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $beta_prior = max($host_prior_stats.hist_mean) / $safe_var
  $alpha_prior = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $posterior_arrival_rate = ($alpha_prior + max($host_hourly_activity.hourly_count)) / ($beta_prior + 1.0)
  $prior_weight_pct = $beta_prior / ($beta_prior + 1.0)
  $evidence_weight_pct = 1.0 / ($beta_prior + 1.0)
  $safe_hist_mean = if(max($host_prior_stats.hist_mean) > 0, max($host_prior_stats.hist_mean), 1.0)
  $anomaly_score = $posterior_arrival_rate / $safe_hist_mean

  // Option 1 Piecewise Unification: Cold-Start Hurdle (<= 3 active hours) + Mature Empirical Bayes Shrinkage (>= 4 active hours)
  $hurdle_rarity_boost = if($baseline_active_samples <= 3, 2.5, 1.0)
  $hurdle_threat_score = math.log($observation_count + 1) * $hurdle_rarity_boost
  $unified_threat_score = if($baseline_active_samples <= 3, $hurdle_threat_score, $anomaly_score)

condition:
  $observation_count >= 15
  and $unified_threat_score >= 3.0

order:
  $unified_threat_score desc
```

---

---

### Scenario 4: Capstone Multi-Scenario Entity Convergence via UDM Loopback

* **Curated Detection Operational Focus**: Individual domain, file, or IP indicator matches evaluated independently.
* **How Multi-Stage UEBA Extends Coverage**: Correlates endpoints matching $\ge 2$ distinct behavioral domain, file, or IP scenarios in the current run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) via an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Endpoint Convergence via UDM Loopback (`secops-statistical-hunter`)

```yara
// ============================================================================
// Goal: Correlate normalized UEBA hunt matches across Domain, Binary, and Network IOC scenarios via UDM Loopback to detect multi-plane host compromise.
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

## 3. Appendix: A Practitioner's Plain-English Guide to the 6 Statistical Models

### 3.1 Hybrid 30-Day HTTP Volume + `DERIVED_CONTEXT` 10-Day Domain Prevalence (Query 1A)
* **What it measures**: How unusual today's HTTP request volume is for a specific `(host, domain)` pair compared to its 30-day behavioral baseline (`metrics.http_queries_total`), restricted strictly to external domains seen on **3 or fewer hosts** across the entire enterprise over the past 10 days (`rolling_max <= 3`).
* **Why static IOC rules fail**: curated detection rules alert on every single DNS lookup to a domain on a threat feed. When a shared CDN, cloud load balancer, or sinkholed domain is listed on a feed, hundreds of endpoints trigger false-positive alerts simultaneously.
* **How the math works**: Stage 1 computes the host's 30-day Z-score $Z = (\text{obs} - \mu_{30\text{d}}) / \max(\sigma_{30\text{d}}, 1.0)$, while Stage 2 performs an inner join against Chronicle's `DERIVED_CONTEXT` Entity Context Graph (`day_count = 10`, `rolling_max <= 3`). Popular domains (`rolling_max > 3`) are dropped automatically, while domains first seen within the last 7 days (`$domain_age_days <= 7.0`) receive a $2.5\times$ rarity multiplier.

### 3.2 Multi-Class Character Shannon Entropy ($H(X)$ — Query 1B)
* **What it measures**: How mixed and unpredictable the characters inside a queried DNS hostname (`network.dns.questions.name`) are across lowercase letters, uppercase letters, digits, and punctuation/hyphens, combined with how few endpoints in the fleet resolved that domain (`$fleet_prevalence <= 3`).
* **Why static IOC rules fail**: Static domain feeds only contain *known* malicious domains. Domain Generation Algorithms (DGAs), DNS tunneling tools (`iodine`, `dnscat2`), and newly registered C2 domains are absent from `C2Domains` and `CryptominingDomains`, and mixed-case DNS queries bypass curated detection rules's lowercase regex.
* **How the math works**: Human-readable domains (`api.payments.example.com`) consist mostly of lowercase letters, concentrating probability mass in a single character class and yielding low entropy. Algorithmic DGA domains and Base32/Base64/Hex-encoded DNS tunneling queries mix character classes and long labels, driving the scaled 4-class Shannon entropy score $H(X) = -\sum_{i=1}^4 p_i \log_2 p_i$ above `3.8` bits/character.

### 3.3 Hybrid 30-Day Process Execution + `DERIVED_CONTEXT` 10-Day File Prevalence (Query 2A)
* **What it measures**: A host's daily execution surge for a specific binary SHA-256 (`metrics.file_executions_total`) compared to its 30-day baseline, gated on `DERIVED_CONTEXT` 10-day organizational file prevalence (`rolling_max <= 3` hosts).
* **Why static IOC rules fail**: curated detection rules fires every hour on sanctioned corporate RMM tools deployed across thousands of machines, while curated detection rules checks the *parent* hash (`principal.process.file.sha256`) and only looks at user-level history.
* **How the math works**: By requiring `file.prevalence.rolling_max <= 3` over `day_count = 10`, any sanctioned RMM agent or IT utility installed across the enterprise fleet is suppressed. Only binaries present on $\le 3$ machines that also exhibit a per-host execution anomaly ($Z \ge 3.0\sigma$) surface, with binaries first seen in the environment $\le 7$ days ago receiving a $2.5\times$ threat boost.

### 3.4 Leave-One-Out Discrete Poisson Arrival Rarity ($Z_{\text{Poisson}}^2$ — Query 2B)
* **What it measures**: The mathematical improbability of observing $k \ge 2$ executions today of a sensitive RMM, tunneling, or cryptomining binary (`target.process.file.full_path`) on an endpoint where the binary's historical arrival rate $\lambda$ over the prior 29 days is near zero ($\lambda \le 0.5\text{ runs/day}$).
* **Why static IOC rules fail**: Recompiling an open-source miner (`xmrig`) or repacking an RMM binary changes its SHA-256 hash, defeating `Cryptomining Hash`, `Remote Access Tools`, and `Bad Linux Binary` hash feeds. Furthermore, standard Z-scores fail on rare binaries because a 30-day sample standard deviation $\sigma \approx 0$ causes divide-by-zero distortion.
* **How the math works**: For rare discrete events, Poisson theory establishes that the variance equals the mean arrival rate ($\sigma^2 = \lambda$). Computing the leave-one-out Jeffreys-smoothed rate $\lambda = (\text{total\_hist} - k + 0.5) / 29.0$ ensures today's surge $k$ does not contaminate its own baseline, and scoring $Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$ ($Z_{\text{Poisson}} \ge 3.0\sigma$) cleanly isolates first-time or rare binary bursts.

### 3.5 Hybrid 30-Day Outbound Network Bytes + `DERIVED_CONTEXT` Infant Asset Age (Query 3A)
* **What it measures**: How many standard deviations a host's daily outbound byte volume (`network.sent_bytes`) exceeds its 30-day behavioral baseline (`metrics.network_bytes_outbound`), intersected with `DERIVED_CONTEXT` asset age (`first_seen_time` within $\le 7.0$ days of the event).
* **Why static IOC rules fail**: Static IP rules only inspect connection counts to known `GCTI Feed` IPs, ignoring both outbound data volume (`sent_bytes`) and whether the source machine is a newly spun-up rogue VM, shadow container, or unmanaged appliance communicating with unlisted adversary infrastructure.
* **How the math works**: Stage 1 computes the 30-day outbound byte Z-score per host, and Stage 2 retrieves `min(asset.first_seen_time.seconds)` from `DERIVED_CONTEXT`. Computing event-relative asset age `$asset_age_days = ($obs_ts - $first_seen) / 86400.0` (safe for historical retrohunts) and gating on `$asset_age_days <= 7.0` with a $2.5\times$ multiplier immediately spotlights infant assets performing C2 or exfiltration.

### 3.6 Empirical Bayes Gamma-Poisson Credibility Shrinkage (Query 3B)
* **What it measures**: The ratio of a host's Bayesian posterior hourly connection rate to its historical mean (`$anomaly_score >= 3.0`), where the host's observed hourly spike is weighted by how stable and predictable that host's historical network traffic is.
* **Why static IOC rules fail**: curated detection rules enforce a rigid `#e > 100` connections/hour cliff—missing 60-connection/hour C2 beacons on quiet servers while still false-alerting on busy NAT gateways or developer build hosts.
* **How the math works**: Stage 2 estimates a Gamma prior ($\alpha_0 = \mu^2 / \sigma^2, \beta_0 = \mu / \sigma^2$) from each host's hourly connection history. Volatile, noisy hosts have high variance ($\sigma^2 \gg \mu$), which drives $\beta_0 \to 0$ and shrinks their anomaly score unless the surge is massive. Conversely, a predictable server with low variance has high prior credibility, allowing a moderate burst of 15–30 unblocked connections in an hour to cross `anomaly_score >= 3.0` without waiting for `#e > 100`.
