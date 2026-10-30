# Hunting Chrome Enterprise Premium Browser & Extension Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Chrome Enterprise Premium Threats** curated detection pack provides high-confidence, real-time alerting for browser-layer threats, including corporate password reuse, phishing navigation, malicious Chrome extension installations, data loss prevention (DLP) policy violations, and hazardous browser downloads across both corporate-managed workstations and unmanaged Bring-Your-Own-Device (BYOD) browser profiles.

This runbook supplements those point-in-time and single-stage browser detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By combining **30-day behavioral baselines (`metrics.*`)** with **multi-stage statistical models over raw Chrome Enterprise telemetry (`metadata.log_type = "CHROME_MANAGEMENT"`)**, the UEBA harness extends visibility beyond the window and state constraints of single-event rules—capturing long/rare credential-harvesting URLs, sideloaded or rare extension adoption across the fleet, deliberate DLP warn-decline-then-paste circumvention, cumulative "under-the-cap" sensitive paste volume, automated extension callback regularity, and coordinated multi-user download campaigns.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit policy violations, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic_ueba`:
  1. **Wave 1 — Consolidated Upstream Baselines & Parallel Pairs (`16 Queries`)**: Executes all `by 1d` 30-day `metrics.*` baselines (enforcing the 7-active-day maturity gate, `$active_days >= 7`, and continuous dispersion floors: `max(sigma, sqrt(max(mu, 1.0)))` for count metrics and empirical fleet byte floors such as `44979.0` bytes for `metrics.network_bytes_outbound`), Entity Context Graph (`DERIVED_CONTEXT` / `GLOBAL_CONTEXT`) hybrid joins, inline `Option 1` Piecewise Cold-Start Hurdle + Zipfian Fleet Rarity queries, and bounded `CHROME_MANAGEMENT` statistical models concurrently. Every query emits native Z or Z-equivalent scores (`SCORE_SEMANTICS_REGISTRY`); the `[0..100]` Calibrated Risk Index (CRI) is computed in Python by `agentic_ueba` via `ueba_constants.calculate_cri` rather than in-query piecewise ladders. Matched entities are written back into Chronicle UDM as `GENERIC_EVENT` records (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback, `2 Queries`)**: After `PlaybookRunner` flushes Wave 1 findings and confirms UDM indexing via `verify_udm_run_indexed()`, Wave 2 queries (`Query 3B` and `Query 4B`) read their upstream Stage A candidates (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)` and `:q[0-9]+_query_4a`) directly in Stage 1 to bound sub-day (`by 1h`) Gamma-Poisson rate shrinkage and cross-bucket flow-gap ratio screening without scanning the full enterprise raw stream.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 10`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-9]`)`), deduplicates per scenario in Stage 1, evaluates cross-scenario $L_2$ convergence requiring at least 2 distinct scenarios (`$distinct_scenarios_matched >= 2`, `LOOPBACK_MIN_DISTINCT_HITS`) and squared Z-equivalent sum $\sum Z_i^2 \ge 25.0$ (`$capstone_threat_norm_sq >= 25.0`, `LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`) in Stage 2, and pivots winning entities directly into raw browser (`SCAN_FILE`), endpoint, network, and cloud telemetry in Stage 3.

> [!NOTE]
> **Evaluation Window & Entity Graph Freshness Conventions (Mode A)**:
> * **30-Day `metrics.*` Macro Queries (`Mode A`)**: Evaluate the last complete UTC day `[D T00:00:00Z, D+1 T00:00:00Z)` against the trailing 30-day `[D-30, D)` `metrics.*` baseline.
> * **Entity Context Graph Joins (`Queries 4A, 5A, 6A`, and `Section 4`)**: Daily `DERIVED_CONTEXT` (`day_count = 10`, `rolling_max <= 3`, `rolling_max > 0`) and `GLOBAL_CONTEXT` (`WHOIS`) records lag ~24 hours. Start the search window at `D-2 T00:00:00Z` (`endTime = D+1 T00:00:00Z`) and pin each event stage to the scored UTC date via `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"`. Because the graph stage is an inner join, entities absent from the Entity Context Graph drop out; pair with `metrics.*` `first_seen` or raw prevalence queries for Day-0 unindexed artifacts.

### 1.1 Chrome Enterprise Premium (CEP) DLP & BYOD Behavioral Telemetry Patterns

Chrome Enterprise Core and Chrome Enterprise Premium stream browser security and Data Protection Rule (DPR) events into Google SecOps (`metadata.log_type = "CHROME_MANAGEMENT"`, `metadata.product_name = "Chrome Management"`) with ~2-minute ingestion latency across `sensitiveDataEvent`, `contentTransferEvent`, `extensionTelemetryEvent`, `browserExtensionInstallEvent`, `urlFilteringInterstitialEvent`, `badNavigationEvent`, `passwordReuseEvent`, `passwordBreachEvent`, `dangerousDownloadEvent`, and `unscannedFileEvent`. Four operational DLP and BYOD patterns anchor the behavioral queries below:

1. **Managed Corporate Devices vs. Unmanaged BYOD Browser Profiles**: On corporate-managed endpoints, `principal.user.userid` carries the normalized enterprise identity; on unmanaged BYOD endpoints (for example, contractor or personal desktops governed by Chrome Enterprise profile policies), `principal.user.userid` can be unset while `principal.user.user_display_name` records the OS/profile principal. Raw `CHROME_MANAGEMENT` stages coalesce `strings.coalesce(principal.user.userid, principal.user.user_display_name)` so unmanaged BYOD sessions are baselined alongside managed corporate profiles.
2. **Demonstrating Intent via Warn-Decline-Then-Paste Circumvention (`Scenario 8`)**: When a user attempts to upload a sensitive PII/PCI document and receives a Chrome DLP warning (`EVENT_RESULT_WARNED`) or block (`EVENT_RESULT_BLOCKED`), electing *not* to bypass (`EVENT_RESULT_BYPASSED` absent) and immediately switching to clipboard text pastes (`CLIPBOARD_PASTE` / `FILE_PASTE`) breaks file-hash continuity. Aggregating upload/paste event counts and payload bytes (`sum(target.file.size)`) per user-day against a non-parametric **Median Absolute Deviation (MAD)** baseline surfaces deliberate policy circumvention.
3. **Cumulative "Under-the-Cap" Allowed DLP Activity (`Scenario 8`)**: Organizations routinely permit employees to copy, paste, or upload small snippets of sensitive data (for example, up to a `10 KB` single-action threshold) under audit-only DLP rules (`EVENT_RESULT_ALLOWED` / `EVENT_RESULT_DETECTED`), while no single rule stops piecemeal accumulation across a workday. Pairing per-user daily MAD Modified Z-scores (`Query 8A`) with multi-day outbound byte **Windowed Slack Sum** (`Query 8B`) catches piecemeal exfiltration exceeding daily norms.
4. **Attributing Extension Activity & SafeBrowsing Push-Throughs (`Scenarios 2, 3, 4, 5`)**: Chrome batches `extensionTelemetryEvent` records (`COOKIES_GET_ALL_INFO`, `TABS_API_INFO`, `REMOTE_HOST_CONTACTED_INFO`) roughly every five minutes and logs user click-throughs on phishing/malware interstitials (`urlFilteringInterstitialEvent`). Combining burst dispersion (`Query 3A`), UDM-gated Gamma-Poisson rate shrinkage (`Query 3B`), rare/newly registered destination domain context (`Queries 4A, 5A`), and HTTP-failure/DNS multi-sector fusion (`Query 5B`) separates malicious extension surveillance and interstitial push-through chains from routine browsing.

### 1.2 Optional Customization: Scoping or Enriching Hunts with a CEP DLP / BYOD Watchlist Data Table (`%cep_dlp_watchlist`)

Security and Insider Risk teams often maintain a **CEP DLP / BYOD Watchlist Data Table** (`%cep_dlp_watchlist`) containing users in high-risk PII/PCI handling roles, unmanaged BYOD contractor cohorts, or departing employees under post-notice DLP review (`<PROJECT_ID>` / `<CUSTOMER_ID>`).

> [!TIP]
> **Why Data Table References Are Commented Out by Default**: In Google SecOps YARA-L 2.0, referencing a Data Table (`%cep_dlp_watchlist.userid` or `%cep_dlp_watchlist.hostname`) that has not yet been created and populated in the target tenant causes an immediate compiler failure. To guarantee every query in this runbook compiles out-of-the-box—and to preserve fleet-wide baseline discovery for unlisted users and BYOD profiles—all Data Table filters are commented out with a 2-line placeholder (`// Optional CEP DLP / BYOD Watchlist Data Table filter:` followed by `// $user in %cep_dlp_watchlist.userid` or `// $entity in %cep_dlp_watchlist.hostname`). Uncomment those lines in Stage 1 for targeted cohort audits or in **Stage 10 (`Query 10`)** for watchlist-filtered executive digests.

### Table 1: Scenario Coverage Matrix — Chrome Enterprise Premium Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Credential Reuse, Phishing Redirects & Lateral Auth** | Real-time detection of corporate password reuse on non-corporate domains, phishing warnings, and suspicious login redirects across managed and BYOD profiles. | Screens unusually long, rare phishing and password-event URLs via log-length plus within-user token rarity (`LONG_STRING_SCREEN`, $\text{score} \ge 4.8$, fleet prevalence $\le 3$) and fuses 30-day failed and successful login baselines ($D^2 \ge 12.25$) to detect post-phishing credential replay. | `Query 1A` (`LONG_STRING_SCREEN` + URL Fleet Prevalence)<br>`Query 1B` (30d Auth Fail + Success Fusion) |
| **2. Malicious, Sideloaded & Uncategorized Chrome Extensions** | Point-in-time detection of known-malicious extension IDs, sideloaded unpacked extensions, and unauthorized extension installs. | Unifies cold-start first-time host extension activations (Two-Part Hurdle with awakening volume gate) and fleet-wide host-prevalence Inverse Document Frequency ($\ln(N_{\text{fleet}} / N_{\text{adopters}})$) in one piecewise DAG (`Option 1`). | `Query 2` (Piecewise Two-Part Hurdle + Zipfian Host-IDF Rarity) |
| **3. Session Cookie Harvesting, Extension API Bursts & Rate Shrinkage** | Detection of browser session theft indicators, sensitive tab screen captures, and anomalous extension telemetry activity. | Measures zero-inclusive hourly Fano Factor burst dispersion ($F = \sigma^2/\mu \ge 4.0$ over $T = 24$ buckets) on extension surveillance APIs in Wave 1, then applies UDM-gated Leave-One-Out Conjugate Gamma-Poisson shrinkage ($Z_{\text{Bayes}} \ge 3.0\sigma$) on candidate entities in Wave 2. | `Query 3A` (`POISSON_BURST_CLUSTERING` Fano Factor)<br>`Query 3B` (Wave 2 UDM-Gated `BAYESIAN_GAMMA_SHRINKAGE`) |
| **4. Browser Extension C2 Callbacks & Rare External Domains** | Alerts on browser connections to known C2 indicators and suspicious external endpoints. | Fuses per-(host, domain) 30-day `metrics.http_queries_total` Z-scores with 10-day `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3`) in Wave 1, then screens Wave 1 candidate hosts in Wave 2 for uniform cross-bucket flow-gap ratios (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$). | `Query 4A` (30d HTTP Z + 10d `DERIVED_CONTEXT` Domain Prevalence)<br>`Query 4B` (Wave 2 UDM-Gated `FLOW_GAP_RATIO_SCREEN`) |
| **5. SafeBrowsing Push-Throughs, Newly Registered & Expired Domains** | Detects user click-throughs on browser security interstitials and navigation to newly registered or hijacked domains. | Weights per-(host, domain) 30-day `metrics.http_queries_total` Z-scores ($\ge 3.0\sigma$) by event-relative `GLOBAL_CONTEXT` WHOIS domain registration age ($\le 30\text{d}$) or expiration status, and fuses same-host 30-day HTTP failure and DNS query baselines ($D^2 \ge 12.25$). | `Query 5A` (30d HTTP Z + Event-Relative WHOIS Lifecycle)<br>`Query 5B` (30d HTTP Fail + DNS Total Fusion) |
| **6. Drive-By Malware Downloads & Browser-Spawned Process Lineages** | Identifies hazardous file downloads and suspicious payload delivery through the browser. | Fuses 30-day per-(host, SHA256) `metrics.file_executions_total` Z-scores with 10-day `DERIVED_CONTEXT` file prevalence (`rolling_max <= 3`) and scores whole-window Laplace-smoothed Markov 2-gram parent-to-child transition surprisal ($\ge 3.0$) for browser/download-spawned processes. | `Query 6A` (30d File Execution Z + 10d `DERIVED_CONTEXT` File Prevalence)<br>`Query 6B` (`MARKOV_2GRAM_TRANSITION_RARITY`) |
| **7. Coordinated Multi-User Download Campaigns & Paced Hazardous Transfers** | Tracks high-risk browser download events, unscanned files, and shared payload hashes across endpoints. | Subtracts mature-cohort historical-referenced fleet shift from leave-one-out personal download surges (`DUAL_BASELINE_DELTA_Z`, $\Delta Z \ge 3.0\sigma$) to suppress enterprise software rollouts, paired with Leave-One-Out Jeffreys-smoothed Poisson rarity ($Z_{\text{Poisson}}^2 \ge 9.0$) on rare dangerous/unscanned downloads. | `Query 7A` (`DUAL_BASELINE_DELTA_Z` Chrome Downloads)<br>`Query 7B` (`POISSON_RARE_SURGE` Hazardous Downloads) |
| **8. Browser DLP Upload/Paste Circumvention & Multi-Day Outbound Drift** | Monitors sensitive file uploads, clipboard pastes, warn-decline circumvention, and cumulative daily byte egress in the browser. | Evaluates daily Chrome DLP `sensitiveDataEvent` and `contentTransferEvent` activity via 4-stage Iglewicz-Hoaglin Modified Z-Score (`MAD_MODIFIED_Z`, $M_Z > 3.5$) alongside a 30-day `metrics.network_bytes_outbound` Windowed Slack Sum prefilter ($W = \sum \max(0, Z_t - 0.5) \ge 4.0$, $\ge 2$ drift days). | `Query 8A` (`MAD_MODIFIED_Z` Chrome Uploads & Pastes)<br>`Query 8B` (`WINDOWED_SLACK_SUM` Outbound Bytes) |
| **9. Post-Compromise Workspace Hoarding & Alert-to-Egress Progression** | Correlates browser security warnings and endpoint/DLP alerts with downstream Google Workspace downloads and network egress. | Scores users simultaneously against personal 30-day baselines and leave-one-out enterprise peers across the Workspace Activity Triad ($D_{\text{vs fleet}}^2 \ge 12.25$), and fuses multiplicity-adjusted per-rule security alerts (`metrics.alert_event_name_count`) with 30-day outbound byte surges ($D^2 \ge 12.25$). | `Query 9A` (3-Metric Multilevel Workspace Triad)<br>`Query 9B` (4-Stage Multiplicity-Adjusted Alert + Outbound Bytes Roll-Up Fusion) |
| **10. Capstone Multi-Scenario Browser & Endpoint Entity Convergence** | Individual browser, Workspace, and endpoint alerts evaluated in isolation within separate telemetry planes. | Deduplicates `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` records across Scenarios 1–9 in Wave 3, requiring $\ge 2$ distinct scenarios and $\sum Z_i^2 \ge 25.0$, while joining raw `SCAN_FILE`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, and `USER_LOGIN` context. | `Query 10` (Wave 3 UDM Loopback Capstone Convergence & Forensic Bridge) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Credential Reuse, Breached Passwords & Long/Rare Phishing Redirect URLs

* **Curated Detection Operational Focus**: Real-time detection of corporate password reuse on non-corporate domains, phishing warnings, interstitial push-throughs, and suspicious login redirects across corporate and BYOD Chrome profiles.
* **How Multi-Stage UEBA Extends Coverage**: Screens unusually long, rare navigation and password-event URLs per user via log-length plus within-user token rarity (`LONG_STRING_SCREEN`) combined with enterprise URL prevalence ($\le 3$ users), and fuses 30-day failed and successful authentication baselines ($D^2 \ge 12.25$) on a single union spine to detect post-phishing credential replay without dropping single-sector surges.

#### Query 1A: Long-String & Rare-Token URL Candidate Screen on Chrome Navigation & Password Events (`secops-statistical-hunter`)
Because YARA-L 2.0 has no per-character iteration primitive, this stateless in-query screen (`LONG_STRING_SCREEN`) computes $\text{score} = \ln(\text{length}) + \ln(1 + N_{\text{user events}} / N_{\text{url}})$ across `passwordReuseEvent`, `passwordBreachEvent`, `badNavigationEvent`, `urlFilteringInterstitialEvent`, and SafeBrowsing social-engineering/malware navigation events—coalescing `principal.user.userid` and `principal.user.user_display_name` so unmanaged BYOD sessions are included—and restricts output to URLs seen on $\le 3$ users across the fleet. *(For true per-character Shannon entropy $H(X) = -\sum p_i \log_2 p_i$, pass candidate URLs to `micro_python_helpers.py shannon` under `SHANNON_ENTROPY_CHARACTER`.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen unusually long, rare phishing, interstitial, and password-reuse URLs across managed and BYOD Chrome profiles.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT navigation, interstitial, passwordReuseEvent, passwordBreachEvent)
// Statistical Model: Long-String & Rare-Token Candidate Screen (LONG_STRING_SCREEN: score = ln(length) + ln(1 + total_events / token_count)) + Fleet URL Prevalence
// ============================================================================

// Stage 1: User daily Chrome security navigation & password-event volume
stage entity_baseline {
    metadata.log_type = "CHROME_MANAGEMENT"
    (
      metadata.product_event_type = "passwordReuseEvent"
      or metadata.product_event_type = "passwordBreachEvent"
      or metadata.product_event_type = "badNavigationEvent"
      or metadata.product_event_type = "urlFilteringInterstitialEvent"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_SOCIAL_ENGINEERING"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_MALWARE"
    )
    $user = strings.coalesce(principal.user.userid, principal.user.user_display_name)
    $user != ""
    target.url != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $user in %cep_dlp_watchlist.userid

  match:
    $user by 1d

  outcome:
    $total_events = count(metadata.id)
}

// Stage 2: Target URL extraction & string length observation (>= 48 chars)
stage token_observation {
    metadata.log_type = "CHROME_MANAGEMENT"
    (
      metadata.product_event_type = "passwordReuseEvent"
      or metadata.product_event_type = "passwordBreachEvent"
      or metadata.product_event_type = "badNavigationEvent"
      or metadata.product_event_type = "urlFilteringInterstitialEvent"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_SOCIAL_ENGINEERING"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_MALWARE"
    )
    $user = strings.coalesce(principal.user.userid, principal.user.user_display_name)
    $user != ""
    $url = target.url
    $url != ""
    strings.length(target.url) >= 48
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $user in %cep_dlp_watchlist.userid

  match:
    $user, $url by 1d

  outcome:
    $token_count = count(metadata.id)
    $token_length = max(strings.length(target.url))
}

// Stage 3: Enterprise fleet prevalence of each distinct URL across users
stage url_fleet_prevalence {
    $url = $token_observation.url
    $ws = $token_observation.window_start

  match:
    $url, $ws by 1d

  outcome:
    $fleet_users = count_distinct($token_observation.user)
}

// Root Stage: Long-String & Rare-Token Candidate Scoring + 6 Core Evidence Pillars
$user = $entity_baseline.user
$user = $token_observation.user
$url = $token_observation.url
$url = $url_fleet_prevalence.url
$ws = $entity_baseline.window_start
$ws = $token_observation.window_start
$ws = $url_fleet_prevalence.ws

match:
  $user, $url, $ws by 1d

outcome:
  $total_activity = max($entity_baseline.total_events)
  $token_executions = max($token_observation.token_count)
  $raw_length = max($token_observation.token_length)
  $safe_length = if($raw_length > 0, $raw_length, 1)
  $safe_total = if($total_activity > 0, $total_activity, 1)
  $safe_tok = if($token_executions > 0, $token_executions, 1)

  $log_len = math.log($safe_length)
  $activity_ratio = 1.0 * $safe_total / $safe_tok
  $rarity_lift = math.log(1.0 + $activity_ratio)
  $shannon_entropy_score = $log_len + $rarity_lift

  // 6 Core Evidence Pillars
  $observation_count = $token_executions
  $baseline_active_samples = $total_activity
  $baseline_mean = $raw_length
  $baseline_dispersion = $log_len
  $fleet_prevalence = max($url_fleet_prevalence.fleet_users)
  $distinct_binaries = 1

condition:
  $raw_length >= 48
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 4.8

order:
  $shannon_entropy_score desc
```

#### Query 1B: 30-Day Dual-Sector Authentication Failure & Login Success Fusion (`secops-risk-metrics-multistage`)
Fuses 30-day behavioral baselines for failed logins (`metrics.auth_attempts_fail`) and successful logins (`metrics.auth_attempts_success`) per user (`target.user.userid`) inside a single `sector_union` stage (`dual_sector_fusion_3stage.yl2`). Using a single union stage preserves single-sector outliers (for example, pure credential-stuffing failure bursts with zero successes today), applies the continuous Poisson dispersion floor `math.sqrt(if($mean > 1.0, $mean, 1.0))` and 7-active-day maturity gate, and half-rectifies each sector Z-score before computing $D^2 = \max(0, Z_{\text{fail}})^2 + \max(0, Z_{\text{succ}})^2 \ge 12.25$. *(Because both metrics come from the authentication family, inter-sector correlation increases tail rates relative to independent sectors.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect post-password-reuse and post-breach credential stuffing or account takeover across all users without dropping single-sector surges.
// Statistical Model: Dual-Sector Euclidean Risk Fusion (D^2 = max(0, Z_fail)^2 + max(0, Z_success)^2 >= 12.25, min_baseline_days = 7)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (SINGLE-STAGE UNION)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Intra-family authentication pairing (auth_attempts_fail + auth_attempts_success); false-positive rates depend on inter-sector correlation.
// ============================================================================

// --- STAGE 1: Single-Stage Auth Sector Union (UDM Source 1 of 2; preserves single-sector outliers) ---
stage sector_union {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $entity
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.userid

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if(not security_result.action = "ALLOW", 1, 0))
    $a_avg = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: target.user.userid
    ))
    $a_std = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: target.user.userid
    ))
    $a_days = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        target.user.userid: target.user.userid
    ))

    $b_obs = sum(if(security_result.action = "ALLOW", 1, 0))
    $b_avg = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: target.user.userid
    ))
    $b_std = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: target.user.userid
    ))
    $b_days = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        target.user.userid: target.user.userid
    ))
}

// --- ROOT STAGE: Continuous Dispersion Floor, 7-Day Maturity Gate & Rectified Euclidean Fusion ---
$entity = $sector_union.entity

match:
  $entity by 1d

outcome:
  $a_observed = max($sector_union.a_obs)
  $a_mean = max($sector_union.a_avg)
  $a_stddev = max($sector_union.a_std)
  $a_active_days = max($sector_union.a_days)

  $b_observed = max($sector_union.b_obs)
  $b_mean = max($sector_union.b_avg)
  $b_stddev = max($sector_union.b_std)
  $b_active_days = max($sector_union.b_days)

  // Sector A (Auth Failures): continuous sqrt(max(mu, 1)) dispersion floor + >= 7 active-day gate
  $a_floor = math.sqrt(if($a_mean > 1.0, $a_mean, 1.0))
  $a_safe_std = if($a_stddev > $a_floor, $a_stddev, $a_floor)
  $z_a_raw = ($a_observed - $a_mean) / $a_safe_std
  $z_a_pos = if($z_a_raw > 0.0, $z_a_raw, 0.0)
  $z_a = if($a_observed > 0 and $a_active_days >= 7, $z_a_pos, 0.0)

  // Sector B (Auth Successes): continuous sqrt(max(mu, 1)) dispersion floor + >= 7 active-day gate
  $b_floor = math.sqrt(if($b_mean > 1.0, $b_mean, 1.0))
  $b_safe_std = if($b_stddev > $b_floor, $b_stddev, $b_floor)
  $z_b_raw = ($b_observed - $b_mean) / $b_safe_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  // Rectified Euclidean Vector Threat Norm D^2 = Z_a^2 + Z_b^2
  $composite_threat_norm_sq = ($z_a * $z_a) + ($z_b * $z_b)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

### Scenario 2: Malicious & Uncategorized Chrome Extensions (Sideloading & Rare Fleet Adoption)

* **Curated Detection Operational Focus**: Point-in-time detection of known-malicious extension IDs, sideloaded unpacked extensions, and unauthorized extension installs.
* **How Multi-Stage UEBA Extends Coverage**: Combines a **Two-Part Hurdle** model (`two_part_hurdle_2stage.yl2`) for first-time or dormant host extension activations with **Host-Prevalence Inverse Document Frequency (IDF)** (`zipfian_process_rarity_2stage.yl2`, $\ln(N_{\text{fleet hosts}} / N_{\text{adopter hosts}})$) in a single piecewise query (`Option 1`), measuring true active Chrome fleet host breadth dynamically rather than assuming a fixed fleet size.

#### Query 2: Piecewise Two-Part Host Hurdle & Host-Prevalence Zipfian IDF on Chrome Extensions (`secops-statistical-hunter`)
Evaluates `CHROME_MANAGEMENT` extension install and telemetry events (`extensionTelemetryEvent`, `browserExtensionInstallEvent`) per `($host, $ext_id)` across two regimes:
- **Regime 1 — Dormant / First-Time Host Activation ($\text{active days} \le 2$)**: Requires an explicit awakening volume gate (`$observation_count >= 5`) and scores `3.0 * ($observation_count / 5.0)`, suppressing low-volume single-event noise.
- **Regime 2 — Rare Persistent Fleet Extension ($\text{active days} \ge 3, \text{adopters} \le 3$)**: Computes pure host-prevalence IDF $\ln(N_{\text{fleet hosts}} / N_{\text{adopter hosts}})$ against the empirical Chrome host population in `fleet_host_total` so chatty extensions cannot manufacture false rarity unless genuinely restricted to $\le 3$ hosts.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant/first-time Chrome extension awakenings (Two-Part Hurdle) and fleet-rare extension adoption (Host-Prevalence Zipfian IDF) across corporate and BYOD endpoints.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT extensionTelemetryEvent, browserExtensionInstallEvent)
// Statistical Model: Option 1 Piecewise Two-Part Hurdle (TWO_PART_HURDLE) + Host-Prevalence Zipfian IDF Rarity (ZIPFIAN_PROCESS_RARITY)
// ============================================================================

// Stage 1: Daily extension activity counts and squared moments per (host, extension_id)
stage daily_extension_activity {
    metadata.log_type = "CHROME_MANAGEMENT"
    $vname = metadata.vendor_name
    $vname != ""
    (
      metadata.product_event_type = "extensionTelemetryEvent"
      or metadata.product_event_type = "browserExtensionInstallEvent"
      or additional.fields["extension_source"] != ""
    )
    additional.fields["extension_action"] != "UNINSTALL"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname)
    $host != ""
    $ext_id = target.resource.product_object_id
    $ext_id != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

  match:
    $vname, $host, $ext_id by 1d

  outcome:
    $daily_events = count(metadata.id)
    $daily_events_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_apis = count_distinct(target.resource.name)
    $sample_actions = array_distinct(target.resource.name)
}

// Stage 2: Per-(host, extension_id) historical moment accumulation for Leave-One-Out Hurdle
stage extension_hurdle_baseline {
    $vname = $daily_extension_activity.vname
    $host = $daily_extension_activity.host
    $ext_id = $daily_extension_activity.ext_id

  match:
    $vname, $host, $ext_id

  outcome:
    $active_days = count($daily_extension_activity.window_start)
    $sum_x = sum($daily_extension_activity.daily_events)
    $sum_x2 = sum($daily_extension_activity.daily_events_sq)
}

// Stage 3: Total active Chrome fleet host population across the search window
stage fleet_host_total {
    $vname = $daily_extension_activity.vname

  match:
    $vname

  outcome:
    $total_fleet_hosts = count_distinct($daily_extension_activity.host)
}

// Stage 4: Enterprise adopter host breadth per extension ID joined with fleet host total
stage extension_fleet_context {
    $vname = $daily_extension_activity.vname
    $vname = $fleet_host_total.vname
    $ext_id = $daily_extension_activity.ext_id

  match:
    $vname, $ext_id

  outcome:
    $adopter_hosts = count_distinct($daily_extension_activity.host)
    $total_fleet_hosts = max($fleet_host_total.total_fleet_hosts)
}

// Root Stage: Piecewise Two-Part Hurdle & Empirical Host-Prevalence Zipfian IDF Scoring
$vname = $daily_extension_activity.vname
$vname = $extension_hurdle_baseline.vname
$vname = $extension_fleet_context.vname
$host = $daily_extension_activity.host
$host = $extension_hurdle_baseline.host
$ext_id = $daily_extension_activity.ext_id
$ext_id = $extension_hurdle_baseline.ext_id
$ext_id = $extension_fleet_context.ext_id
$ws = $daily_extension_activity.window_start

match:
  $host, $ext_id, $ws by 1d

outcome:
  $observation_count = max($daily_extension_activity.daily_events)
  $baseline_active_samples = max($extension_hurdle_baseline.active_days)
  $fleet_prevalence = max($extension_fleet_context.adopter_hosts)
  $distinct_binaries = max($daily_extension_activity.distinct_apis)
  $sample_commands = array_distinct($daily_extension_activity.sample_actions)

  // Leave-One-Out Continuous Intensity Baseline with sqrt(max(loo_mean, 1.0)) floor
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $baseline_mean = 1.0 * (max($extension_hurdle_baseline.sum_x) - $observation_count) / $n_prior
  $raw_loo_var = ((max($extension_hurdle_baseline.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)

  // Branch A: Dormant / First-Time Awakening Gate (<= 2 active days requires >= 5 events)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 5.0)
  $dormant_score = if($observation_count >= 5, $dormant_raw, 0.0)

  // Branch B: Pure Host-Prevalence Zipfian IDF Surprisal ln(N_fleet_hosts / N_adopter_hosts)
  $safe_adopters = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $safe_fleet_hosts = if(max($extension_fleet_context.total_fleet_hosts) > $safe_adopters, max($extension_fleet_context.total_fleet_hosts), $safe_adopters)
  $zipf_rarity_score = math.log(1.0 * $safe_fleet_hosts / $safe_adopters)
  $hurdle_threat_score = if($baseline_active_samples <= 2, $dormant_score, $zipf_rarity_score)

condition:
  $observation_count >= 5
  and $fleet_prevalence <= 3
  and $hurdle_threat_score >= 2.5

order:
  $hurdle_threat_score desc
```

---

### Scenario 3: Chrome Extension Session Cookie Harvesting, Screen Capture & Remote Host Bursts

* **Curated Detection Operational Focus**: Detection of sensitive content copy/paste events, tab screen capture actions, and browser session theft indicators.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates zero-inclusive hourly Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$ over $T = 24.0$ hourly buckets) on `extensionTelemetryEvent` cookie, tab-capture, and remote-host telemetry in Wave 1 (`Query 3A`), then feeds matched entities via `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` loopback into Wave 2 (`Query 3B`) for Leave-One-Out Conjugate Gamma-Poisson rate shrinkage ($Z_{\text{Bayes}} \ge 3.0\sigma$).

#### Query 3A: Zero-Inclusive Poisson Fano Factor Burst Clustering on Extension Surveillance APIs (`secops-statistical-hunter`)
Rebuilt from `poisson_burst_clustering_2stage.yl2` to compute the **Zero-Inclusive Fano Factor** ($\mu = \sum x / 24.0$, $\sigma^2 = \sum x^2 / 24.0 - \mu^2$, $F = \sigma^2 / \mu \ge 4.0$) across a 24-hour (`T = 24.0` `by 1h`) micro window over `COOKIES_GET_ALL_INFO`, `TABS_API_INFO` (`CAPTURE_VISIBLE_TAB`), and `REMOTE_HOST_CONTACTED_INFO` extension telemetry events. Including silent zero-event hours in $\mu$ and $\sigma^2$ isolates extensions that wake up in concentrated harvesting bursts (for example, after a sensitive paste into an extension popup) rather than trickling uniformly.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect synchronized hourly bursts of Chrome extension cookie harvesting, tab screen captures, and batched external host contacts via zero-inclusive Fano dispersion.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT extensionTelemetryEvent: COOKIES_GET_ALL_INFO, TABS_API_INFO, REMOTE_HOST_CONTACTED_INFO)
// Statistical Model: Zero-Inclusive Poisson Dispersion via Fano Factor (POISSON_BURST_CLUSTERING: F = σ² / μ >= 4.0 over T = 24.0 hourly buckets)
// ============================================================================

// Stage 1: Hourly extension surveillance & remote-contact event counts and squared counts per entity
stage hourly_surveillance_calls {
    metadata.log_type = "CHROME_MANAGEMENT"
    metadata.product_event_type = "extensionTelemetryEvent"
    (
      target.resource.name = "COOKIES_GET_ALL_INFO"
      or target.resource.name = "REMOTE_HOST_CONTACTED_INFO"
      or (
        target.resource.name = "TABS_API_INFO"
        and additional.fields["tabs_api_method"] = "CAPTURE_VISIBLE_TAB"
      )
    )
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname)
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.entity_id

  match:
    $entity by 1h

  outcome:
    $hourly_calls = count(metadata.id)
    $hourly_calls_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $sample_exts = array_distinct(target.resource.product_object_id)
}

// Stage 2: Purely numeric accumulation of Σx, Σx², and active hour count per entity
stage dispersion_baseline {
    $entity = $hourly_surveillance_calls.entity

  match:
    $entity

  outcome:
    $sum_x = sum($hourly_surveillance_calls.hourly_calls)
    $sum_x2 = sum($hourly_surveillance_calls.hourly_calls_sq)
    $active_hours = count($hourly_surveillance_calls.window_start)
}

// Stage 3: Enterprise-wide prevalence of entities experiencing burst hours (>= 5 calls/h) per hourly bucket
stage fleet_breadth {
    $ws = $hourly_surveillance_calls.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_entities = sum(if($hourly_surveillance_calls.hourly_calls >= 5, 1, 0))
}

// Root Stage: Rebuild zero-inclusive Fano Factor over T = 24.0 hourly buckets and emit 6 Evidence Pillars
$entity = $hourly_surveillance_calls.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_surveillance_calls.window_start
$ws = $fleet_breadth.ws

match:
  $entity

outcome:
  $sum_x = max($dispersion_baseline.sum_x)
  $sum_x2 = max($dispersion_baseline.sum_x2)
  $zero_incl_mean = 1.0 * $sum_x / 24.0
  $mean_sq = 1.0 * $sum_x2 / 24.0
  $raw_var = $mean_sq - ($zero_incl_mean * $zero_incl_mean)
  $zero_incl_var = if($raw_var > 0.0, $raw_var, 0.0)
  $zero_incl_sd = math.sqrt($zero_incl_var)
  $safe_mean = if($zero_incl_mean > 0.0, $zero_incl_mean, 1.0)
  $raw_fano = $zero_incl_var / $safe_mean
  $fano_factor = if($zero_incl_mean > 0.0, $raw_fano, 0.0)

  // 6 Core Evidence Pillars
  $observation_count = $sum_x
  $baseline_active_samples = max($dispersion_baseline.active_hours)
  $baseline_mean = $zero_incl_mean
  $baseline_dispersion = $zero_incl_sd
  $fleet_prevalence = max($fleet_breadth.fleet_entities)
  $distinct_binaries = $sum_x
  $sample_commands = array_distinct($hourly_surveillance_calls.sample_exts)

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 12
  and $baseline_mean >= 0.5
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

#### Query 3B: Wave 2 UDM-Gated Conjugate Gamma-Poisson Rate Shrinkage on Chrome Extension & DLP Velocity (`secops-statistical-hunter`)
Rebuilt from `bayesian_gamma_shrinkage_4stage.yl2` and gated in Stage 1 on `Query 3A` UDM Loopback candidates (`re.regex(security_result.rule_name, `:q[0-9]+_query_3a`)`). Updates a `Gamma(alpha_0 = 0.5, beta_0 = 0.1)` prior with leave-one-out prior volume across `23.0` prior hourly buckets and incorporates empirical excess overdispersion variance $\max(0, \mathbb{E}[X^2]_{\text{prior}} - \mu_{\text{prior}}^2 - \mu_{\text{prior}})$ so chronically noisy developer profiles are shrunk while genuine surges on predictable profiles achieve `$bayesian_z >= 3.0`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED CONJUGATE GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect abnormal hourly Chrome extension & content-transfer surges on candidate entities surfaced by Query 3A via UDM Loopback.
// Statistical Model: UDM Loopback Candidate Gate + Leave-One-Out Conjugate Gamma-Poisson Predictive Z-Score (BAYESIAN_GAMMA_SHRINKAGE: bayesian_z >= 3.0)
// ============================================================================

// Stage 1: Wave 2 UDM Loopback Candidate Gate from Query 3A
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

// Stage 2: Hourly Chrome Management telemetry volume and squared counts per entity
stage host_hourly_activity {
    metadata.log_type = "CHROME_MANAGEMENT"
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_evts = count_distinct(metadata.product_event_type)
}

// Stage 3: Historical moment accumulation across hourly buckets per entity
stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly_activity.hourly_count)
    $sum_x2 = sum($host_hourly_activity.hourly_count_sq)
    $active_hours = count($host_hourly_activity.window_start)
}

// Root Stage: Leave-One-Out Conjugate Gamma-Poisson Updating & Excess Overdispersion Z-Score
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
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($host_hourly_activity.distinct_evts)

  // Leave-One-Out Gamma(0.5, 0.1) prior + empirical excess overdispersion over 23.0 prior hourly buckets
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 0.5 + $prior_sum
  $beta_prior = 0.1 + 23.0
  $baseline_mean = $alpha_prior / $beta_prior
  $prior_emp_mean = 1.0 * $prior_sum / 23.0
  $raw_excess_var = (1.0 * $prior_sum_sq / 23.0) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * ($beta_prior + 1.0) / $beta_prior) + $excess_var
  $safe_pred_var = if($raw_pred_var > 1.0, $raw_pred_var, 1.0)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $bayesian_z = ($observation_count - $baseline_mean) / $baseline_dispersion

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 10
  and $bayesian_z >= 3.0

order:
  $bayesian_z desc
```

---

### Scenario 4: Chrome Extension Command-and-Control (C2) Callbacks & Rare External Domains

* **Curated Detection Operational Focus**: Alerts on browser connections to known C2 indicators and suspicious external endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Fuses per-`(host, domain)` 30-day `metrics.http_queries_total` Z-scores ($\ge 3.0\sigma$, $\ge 7$ active days) with 10-day `DERIVED_CONTEXT` organizational domain prevalence (`rolling_max <= 3`) in Wave 1 (`Query 4A`), then screens candidate hosts in Wave 2 (`Query 4B`) for low cross-bucket flow-gap ratio dispersion (`FLOW_GAP_RATIO_SCREEN`, $\text{CV} \le 0.20$).

#### Query 4A: Hybrid 30-Day HTTP Destination Baseline + 10-Day `DERIVED_CONTEXT` Domain Prevalence (`secops-risk-metrics-multistage`)
Rebuilt from `hybrid_metric_derived_domain_prevalence_2stage.yl2`. Stage 1 pins HTTP telemetry to the scored Mode A UTC day (`2026-10-29`, run with `startTime = D-2 T00:00:00Z`) and evaluates per-`(host, domain)` `metrics.http_queries_total` baselines; Stage 2 isolates the `DERIVED_CONTEXT` `DOMAIN_NAME` lookup (`day_count = 10`, `rolling_max <= 3`, `rolling_max > 0`). Root applies the continuous dispersion floor `math.sqrt(if($mean_queries > 1.0, $mean_queries, 1.0))`, enforces `$active_baseline_days >= 7` and `$z_score >= 3.0`, and disables `<7d` `first_seen_time` novelty whenever `$first_seen <= 0`. *(Because Stage 2 is an inner join, domains not yet indexed in `DERIVED_CONTEXT` drop out.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect endpoints generating HTTP request surges to rare external domains (10-day DERIVED_CONTEXT rolling_max <= 3 hosts).
// Statistical Model: 2-Stage Hybrid 30-Day Per-(Host, Domain) Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Domain Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Per-(Host, Domain) HTTP Query Baseline (pinned to Mode A scored UTC day; run search window from D-2)
stage stage1_query_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day Domain Prevalence <= 3)
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
}

// Stage 3 (Root Stage): Continuous Dispersion Floor, 7-Day Maturity Gate & Rare Domain Multiplier
$host = $stage1_query_baseline.host
$domain = $stage1_query_baseline.domain
$domain = $stage2_domain_derived_context.domain

match:
  $host, $domain by 1d

outcome:
  $observed_queries = max($stage1_query_baseline.observed_val)
  $mean_queries = max($stage1_query_baseline.hist_mean)
  $stddev_queries = max($stage1_query_baseline.hist_stddev)
  $dispersion_floor = math.sqrt(if($mean_queries > 1.0, $mean_queries, 1.0))
  $safe_stddev = if($stddev_queries > $dispersion_floor, $stddev_queries, $dispersion_floor)
  $z_score = ($observed_queries - $mean_queries) / $safe_stddev
  $active_baseline_days = max($stage1_query_baseline.hist_active_days)

  $fleet_prevalence = max($stage2_domain_derived_context.enterprise_rolling_max)
  $prevalence_days = min($stage2_domain_derived_context.enterprise_day_count)
  $first_seen = min($stage2_domain_derived_context.first_seen_ts)
  $obs_ts = max($stage1_query_baseline.event_timestamp)
  $raw_age_days = ($obs_ts - $first_seen) / 86400.0
  $domain_age_days = if($first_seen > 0, $raw_age_days, 9999.0)

  // Guarded novelty boost: disabled when first_seen_time = 0
  $is_novel_domain = if($first_seen > 0 and $domain_age_days <= 7.0 and $domain_age_days >= 0.0, 1.0, 0.0)
  $rarity_multiplier = if($is_novel_domain = 1.0, 2.5, 1.5)
  $threat_score = $z_score * $rarity_multiplier

condition:
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and $fleet_prevalence <= 3

order:
  $threat_score desc
```

#### Query 4B: Wave 2 UDM-Gated Cross-Bucket Flow-Gap Ratio Dispersion Screen on Browser/Extension Callbacks (`secops-statistical-hunter`)
Rebuilt from `flow_gap_ratio_screen_2stage.yl2` (`FLOW_GAP_RATIO_SCREEN`) and gated on `Query 4A` UDM Loopback candidates (`re.regex(security_result.rule_name, `:q[0-9]+_query_4a`)`). Because stateless bucketed YARA-L cannot sort individual packet timestamps inside an hour, Stage 2 computes the within-bucket span-to-count ratio `1.0 * (max($ts) - min($ts)) / count(metadata.id)` per `($host, $dst_ip)` hour (excluding RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local ranges), and Stage 3 / Root measures the Coefficient of Variation ($\text{CV} = \sigma_{\text{gap}} / \mu_{\text{gap}} \le 0.20$) across active hours. *(For true consecutive inter-arrival $\Delta t$ jitter, pass `array_distinct($ts)` to `micro_python_helpers.py c2-jitter` under `C2_BEACONING_JITTER`.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED CROSS-BUCKET FLOW-GAP RATIO DISPERSION PIPELINE
// Goal: Screen candidate hosts from Query 4A for persistent external connections with uniform hourly span-to-count flow-gap ratios (CV <= 0.20).
// Statistical Model: UDM Loopback Candidate Gate + Cross-Bucket Flow-Gap Ratio Dispersion (FLOW_GAP_RATIO_SCREEN: CV = sigma_gap / mu_gap <= 0.20)
// ============================================================================

// Stage 1: Wave 2 UDM Loopback Candidate Gate from Query 4A
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

// Stage 2: Hourly span-to-count flow-gap ratio per (host, external dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 128
    target.ip = $dst_ip
    $dst_ip != ""
    $dst_ip != "::1"
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.asset.ip[0], principal.ip[0])
    $host != ""
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
    $conn_count = count(metadata.id)
    $avg_gap = 1.0 * (max($ts) - min($ts)) / count(metadata.id)
    $hourly_sent = sum(network.sent_bytes)
}

// Stage 3: Aggregate flow-gap ratio mean and stddev across active hourly buckets per pair
stage timing_stats {
    $host = $host_intervals.host
    $dst_ip = $host_intervals.dst_ip

  match:
    $host, $dst_ip

  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $total_sent_bytes = sum($host_intervals.hourly_sent)
    $active_hours = count($host_intervals.window_start)
}

// Root Stage: Join Query 4A candidate hosts, compute unbiased Flow-Gap Ratio CV, and emit 6 Evidence Pillars
$host = $stage1_upstream_4a_candidates.host
$host = $timing_stats.host
$dst_ip = $timing_stats.dst_ip

match:
  $host, $dst_ip

outcome:
  $upstream_z = max($stage1_upstream_4a_candidates.upstream_4a_z)
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
  $baseline_active_samples >= 3
  and $observation_count >= 20
  and $baseline_mean >= 1.0
  and $cv <= 0.20

order:
  $cv asc
```

---

### Scenario 5: SafeBrowsing Interstitial Push-Throughs, Newly Registered & Expired Domains

* **Curated Detection Operational Focus**: Detects user click-throughs on Chrome SafeBrowsing interstitials (`urlFilteringInterstitialEvent`) and navigation to newly registered, expired, or shortened URLs.
* **How Multi-Stage UEBA Extends Coverage**: Pairs a 30-day per-`(host, domain)` HTTP query Z-score ($\ge 3.0\sigma$, $\ge 7$ active days) enriched with event-relative `GLOBAL_CONTEXT` WHOIS creation/expiration timestamps (`Query 5A`) alongside a single-stage union fusion of 30-day HTTP error responses (`metrics.http_queries_fail`) and total DNS resolutions (`metrics.dns_queries_total`) on the same endpoint (`Query 5B`, $D^2 \ge 12.25$).

#### Query 5A: Hybrid 30-Day Host HTTP Baseline + Event-Relative WHOIS Domain Lifecycle (`secops-risk-metrics-multistage`)
Rebuilt from `hybrid_metric_whois_domain_lifecycle_2stage.yl2`. Stage 1 pins HTTP activity to the Mode A scored UTC day (`2026-10-29`, run with `startTime = D-2 T00:00:00Z`) and extracts per-`(host, domain)` 30-day `metrics.http_queries_total` statistics alongside `max(metadata.event_timestamp.seconds)` (avoiding `timestamp.current_seconds()` wall-clock drift); Stage 2 isolates the `GLOBAL_CONTEXT` `WHOIS` lookup; Root applies the continuous dispersion floor, requires `$active_baseline_days >= 7` and `$z_score >= 3.0`, and multiplies $Z$ by `3.0x` for expired domains or `2.5x` for newly registered domains ($\le 30$ days old at event time, guarded against `$created = 0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous per-(host, domain) HTTP volume targeting newly registered (<= 30d at event time) or expired WHOIS domains.
// Statistical Model: 2-Stage Hybrid 30-Day Per-(Host, Domain) Z-Score (metrics.http_queries_total) + GLOBAL_CONTEXT Event-Relative WHOIS Lifecycle
// ARCHITECTURE: 2-STAGE DUAL-PLANE WHOIS DOMAIN LIFECYCLE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Per-(Host, Domain) HTTP Query Baseline (pinned to Mode A scored UTC day; run search window from D-2)
stage stage1_egress_baseline {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

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

// Stage 3 (Root Stage): Continuous Dispersion Floor, 7-Day Maturity Gate & Event-Relative WHOIS Multiplier
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

  // Event-relative domain age in days (guarded against missing $created = 0)
  $raw_age_days = ($obs_ts - $created) / 86400.0
  $domain_age_days = if($created > 0, $raw_age_days, 9999.0)
  $is_nrd = if($created > 0 and $domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)
  $is_expired = if($expires > 0 and $expires <= $obs_ts, 1.0, 0.0)

  $nrd_mult = if($is_nrd = 1.0, 2.5, 1.0)
  $whois_multiplier = if($is_expired = 1.0, 3.0, $nrd_mult)
  $fused_threat_score = $z_score * $whois_multiplier

condition:
  $active_baseline_days >= 7
  and $z_score >= 3.0
  and ($is_nrd = 1.0 or $is_expired = 1.0)

order:
  $fused_threat_score desc
```

#### Query 5B: Same-Host Dual-Sector HTTP Failure & DNS Resolution Union Fusion (`secops-risk-metrics-multistage`)
Rebuilt from `dual_sector_fusion_3stage.yl2` to fuse 30-day anomalies in failed HTTP responses (`metrics.http_queries_fail`) and total DNS query volume (`metrics.dns_queries_total`) on `principal.asset.hostname` within a single `sector_union` stage, applying the continuous `math.sqrt(if($mean > 1.0, $mean, 1.0))` floor, 7-active-day maturity gate, and positive half-rectification ($D^2 \ge 12.25$). *(Because HTTP navigation triggers DNS lookups on the same host, inter-sector correlation increases joint tail rates relative to independent sectors.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Correlate browser redirect/interstitial push-through chains by fusing 30-day HTTP failure surges with DNS resolution surges on the same host.
// Statistical Model: Dual-Sector Euclidean Risk Fusion (D^2 = max(0, Z_http_fail)^2 + max(0, Z_dns_total)^2 >= 12.25, min_baseline_days = 7)
// ARCHITECTURE: DUAL-SECTOR THREAT FUSION (SINGLE-STAGE UNION)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Coupled web/DNS host telemetry (http_queries_fail + dns_queries_total); false-positive rates depend on inter-sector correlation.
// ============================================================================

// --- STAGE 1: Single-Stage HTTP Fail + DNS Total Union (UDM Source 1 of 2; preserves single-sector outliers) ---
stage sector_union {
    (
      ((network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "") and network.http.response_code >= 400)
      or (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    )
    principal.asset.hostname = $entity
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.hostname

  match:
    $entity by 1d

  outcome:
    $a_obs = sum(if((network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "") and network.http.response_code >= 400, 1, 0))
    $a_avg = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_std = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $a_days = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))

    $b_obs = sum(if(network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0, 1, 0))
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

// --- ROOT STAGE: Continuous Dispersion Floor, 7-Day Maturity Gate & Rectified Euclidean Fusion ---
$entity = $sector_union.entity

match:
  $entity by 1d

outcome:
  $a_observed = max($sector_union.a_obs)
  $a_mean = max($sector_union.a_avg)
  $a_stddev = max($sector_union.a_std)
  $a_active_days = max($sector_union.a_days)

  $b_observed = max($sector_union.b_obs)
  $b_mean = max($sector_union.b_avg)
  $b_stddev = max($sector_union.b_std)
  $b_active_days = max($sector_union.b_days)

  $a_floor = math.sqrt(if($a_mean > 1.0, $a_mean, 1.0))
  $a_safe_std = if($a_stddev > $a_floor, $a_stddev, $a_floor)
  $z_a_raw = ($a_observed - $a_mean) / $a_safe_std
  $z_a_pos = if($z_a_raw > 0.0, $z_a_raw, 0.0)
  $z_a = if($a_observed > 0 and $a_active_days >= 7, $z_a_pos, 0.0)

  $b_floor = math.sqrt(if($b_mean > 1.0, $b_mean, 1.0))
  $b_safe_std = if($b_stddev > $b_floor, $b_stddev, $b_floor)
  $z_b_raw = ($b_observed - $b_mean) / $b_safe_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  $composite_threat_norm_sq = ($z_a * $z_a) + ($z_b * $z_b)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

### Scenario 6: Drive-By & File-Hosting Malware Downloads

* **Curated Detection Operational Focus**: Identifies hazardous file downloads and suspicious payload delivery through the browser.
* **How Multi-Stage UEBA Extends Coverage**: Fuses 30-day per-`(host, SHA256)` file execution baselines (`metrics.file_executions_total`, $\ge 7$ active days) with 10-day `DERIVED_CONTEXT` organizational file prevalence (`rolling_max <= 3`) (`Query 6A`), and measures whole-window Laplace-smoothed **Markov 2-Gram** parent-to-child transition surprisal ($\ge 3.0$) for browser and download-directory child spawns (`Query 6B`).

#### Query 6A: Hybrid 30-Day Endpoint Process Execution Baseline + `DERIVED_CONTEXT` Binary Prevalence (`secops-risk-metrics-multistage`)
Rebuilt from `hybrid_metric_derived_file_prevalence_2stage.yl2`. Stage 1 pins `PROCESS_LAUNCH` events to the Mode A scored UTC day (`2026-10-29`, run with `startTime = D-2 T00:00:00Z`) and extracts the composite `metrics.file_executions_total` baseline (`metadata.event_type`, `principal.asset.hostname`, `principal.process.file.sha256`); Stage 2 isolates the `DERIVED_CONTEXT` `FILE` prevalence lookup (`day_count = 10`, `rolling_max <= 3`, `rolling_max > 0`). Root enforces `$active_baseline_days >= 7`, applies the continuous `math.sqrt(if($mean_execs > 1.0, $mean_execs, 1.0))` floor, and guards `first_seen_time = 0` so missing graph timestamps never trigger spurious `<7d` novelty boosts. *(Day-0 binaries with `<7` active days or absent from `DERIVED_CONTEXT` are handled by `first_seen_novelty_2stage.yl2` or `Query 6B`.)*

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous per-(host, SHA256) execution surges of rare binaries (10-day DERIVED_CONTEXT rolling_max <= 3 hosts).
// Statistical Model: 2-Stage Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Process Execution Baseline (pinned to Mode A scored UTC day; run search window from D-2)
stage stage1_process_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"
    principal.asset.hostname = $host
    $sha256 = strings.coalesce(target.process.file.sha256, principal.process.file.sha256)
    principal.process.file.sha256 != ""
    $host != ""
    $sha256 != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

  match:
    $host, $sha256 by 1d

  outcome:
    $observed_val = count(metadata.id)
    $sample_command = array_distinct(principal.process.command_line)
    $sample_path = array_distinct(principal.process.file.full_path)
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

// Stage 2: Chronicle Derived Context Graph Lookup (10-Day File Prevalence <= 3)
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
}

// Stage 3 (Root Stage): Continuous Dispersion Floor, 7-Day Maturity Gate & Rare Binary Multiplier
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

  // Guarded novelty boost: disabled when first_seen_time = 0
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

#### Query 6B: Whole-Window Laplace-Smoothed Markov 2-Gram Transition Surprisal for Browser-Spawned Processes (`secops-statistical-hunter`)
Rebuilt from `markov_2gram_transition_rarity_2stage.yl2`. Evaluates whole-window conditional transition probability $P(\text{Child} \mid \text{Parent}) = (N_{\text{pair}} + 1) / (N_{\text{parent}} + 100.0)$ and information surprisal $I = \ln((N_{\text{parent}} + 100.0) / (N_{\text{pair}} + 1.0)) \ge 3.0$ across parent binaries running from browser paths (`chrome`, `msedge`, `brave`, `firefox`) or user download/temp directories (`Downloads`, `AppData\Local\Temp`, `/tmp/`), eliminating arbitrary step-function cliffs on rare living-off-the-land spawns.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-child process execution transitions spawned by Chrome or user download directories via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (MARKOV_2GRAM_TRANSITION_RARITY: Score = ln((N_parent + 100.0) / (N_pair + 1.0)) >= 3.0)
// ============================================================================

// Stage 1: Bucketed Parent-Child Process Transition Activity for Browser & Download Paths
stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    $host = strings.coalesce(principal.asset.hostname, principal.hostname)
    $host != ""
    $parent = principal.process.file.full_path
    $child = target.process.file.full_path
    $parent != ""
    $child != ""
    re.regex(principal.process.file.full_path, `(?i)(chrome|msedge|brave|firefox|Downloads|AppData\\Local\\Temp|/tmp/)`)
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

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
  $window_parent_launches >= 5
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

---

### Scenario 7: Multi-User / Multi-Hash Download Campaigns & Paced Hazardous Transfers

* **Curated Detection Operational Focus**: Tracks high-risk browser download events, unscanned archives, and shared file hashes across endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Applies Leave-One-Out **Dual-Baseline Delta-Z** (`dual_baseline_delta_z_3stage.yl2`, $\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$) across mature Chrome endpoints ($\ge 7$ active days) to suppress company-wide tool rollouts (`Query 7A`), paired with **Leave-One-Out Discrete Poisson Rarity** (`poisson_rare_surge_2stage.yl2`, $Z_{\text{Poisson}}^2 \ge 9.0$) for paced dangerous/unscanned downloads on profiles with near-zero prior rates (`Query 7B`).

#### Query 7A: 3-Stage Leave-One-Out Dual-Baseline Delta-Z ($\Delta Z \ge 3.0\sigma$) on Chrome File Downloads (`secops-statistical-hunter`)
Rebuilt from `dual_baseline_delta_z_3stage.yl2`. Computes leave-one-out personal standardization (`$personal_z`) with a continuous `sqrt(max(loo_mean, 1.0))` floor over `CHROME_MANAGEMENT` download and content-transfer events (`target.file.sha256`), and subtracts the concurrent fleet shift (`$fleet_z`) evaluated strictly across mature peer endpoints (`active_days >= 7`) relative to their historical expected mean and spread.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Isolate targeted host Chrome download surges while suppressing fleet-wide software rollouts via Leave-One-Out Dual-Baseline Delta-Z.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT dangerousDownloadEvent, malwareTransferEvent, contentTransferEvent, unscannedFileEvent)
// Statistical Model: Leave-One-Out Personal Z Minus Mature-Cohort Fleet Historical Shift Z (DUAL_BASELINE_DELTA_Z: Delta-Z >= 3.0)
// ============================================================================

// Stage 1: Individual Host Chrome Download Volume and Squared Moments in daily buckets
stage host_hourly_extract {
    metadata.log_type = "CHROME_MANAGEMENT"
    (
      metadata.product_event_type = "dangerousDownloadEvent"
      or metadata.product_event_type = "malwareTransferEvent"
      or metadata.product_event_type = "contentTransferEvent"
      or metadata.product_event_type = "unscannedFileEvent"
    )
    $host = strings.coalesce(principal.asset.hostname, principal.hostname)
    $host != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

  match:
    $host by 1d

  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(target.file.sha256)
}

// Stage 2: Individual Host Personal Historical Baseline
stage host_personal_baseline {
    $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly_extract.hourly_count)
    $sum_x2 = sum($host_hourly_extract.hourly_count_sq)
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Mature-Fleet Shift Baseline (excludes cold-start hosts < 7 active days)
stage fleet_concurrent_baseline {
    $host = $host_hourly_extract.host
    $host = $host_personal_baseline.host
    $ws = $host_hourly_extract.window_start

  match:
    $ws by 1d

  outcome:
    $active_fleet_hosts = sum(if($host_personal_baseline.active_hours >= 7, 1, 0))
    $sum_fleet_obs = sum(if($host_personal_baseline.active_hours >= 7, $host_hourly_extract.hourly_count, 0))
    $sum_fleet_exp = sum(if($host_personal_baseline.active_hours >= 7, $host_personal_baseline.personal_avg, 0.0))
    $sum_fleet_sd = sum(if($host_personal_baseline.active_hours >= 7, $host_personal_baseline.personal_stddev, 0.0))
}

// Root Stage: Leave-One-Out Personal Z & Mature-Cohort Fleet Shift Subtraction
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $host, $ws by 1d

outcome:
  $observation_count = max($host_hourly_extract.hourly_count)
  $baseline_active_samples = max($host_personal_baseline.active_hours)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_hosts)
  $distinct_binaries = max($host_hourly_extract.distinct_procs)

  // Leave-One-Out Personal Standardization with sqrt(max(loo_mean, 1.0)) floor
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $baseline_mean = 1.0 * (max($host_personal_baseline.sum_x) - $observation_count) / $n_prior
  $raw_loo_var = ((max($host_personal_baseline.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $personal_z = ($observation_count - $baseline_mean) / $baseline_dispersion

  // Mature-Cohort Historical-Referenced Fleet Shift Z
  $safe_hosts = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $fleet_exp_mean = 1.0 * max($fleet_concurrent_baseline.sum_fleet_exp) / $safe_hosts
  $raw_fleet_var = (1.0 * max($fleet_concurrent_baseline.sum_fleet_sd) / $safe_hosts) * (1.0 * max($fleet_concurrent_baseline.sum_fleet_sd) / $safe_hosts)
  $fleet_floor_var = if($fleet_exp_mean > 1.0, $fleet_exp_mean, 1.0)
  $safe_fleet_var = if($raw_fleet_var > $fleet_floor_var, $raw_fleet_var, $fleet_floor_var)
  $fleet_z = ((1.0 * max($fleet_concurrent_baseline.sum_fleet_obs) / $safe_hosts) - $fleet_exp_mean) / math.sqrt($safe_fleet_var)
  $pos_fleet_z = if($fleet_z > 0.0, $fleet_z, 0.0)
  $delta_z = $personal_z - $pos_fleet_z

condition:
  $baseline_active_samples >= 7
  and $fleet_prevalence >= 3
  and $observation_count >= 5
  and $delta_z >= 3.0

order:
  $delta_z desc
```

#### Query 7B: Leave-One-Out Discrete Poisson Rarity on User Dangerous & Unscanned Downloads (`secops-statistical-hunter`)
Rebuilt from `poisson_rare_surge_2stage.yl2` over a bounded 14-day micro window (`13.0` prior calendar days). Computes Leave-One-Out Jeffreys-smoothed daily arrival rate $\lambda = (\text{prior\_runs} + 0.5) / 13.0$ across `dangerousDownloadEvent`, `malwareTransferEvent`, and `unscannedFileEvent` (`target.file.full_path`), while verifying online profile maturity (`$online_days >= 7`) across all `CHROME_MANAGEMENT` activity in Stage 3 (`host_online_baseline`) so first-time dangerous download surges on mature corporate or BYOD profiles fire cleanly on the latest active day (`$is_latest_day = 1`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect multi-hour paced dangerous or unscanned Chrome downloads on mature browser profiles (>= 7 online days) with near-zero prior rates.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT dangerousDownloadEvent, malwareTransferEvent, unscannedFileEvent)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (POISSON_RARE_SURGE: Poisson Z^2 = (k - λ)^2 / λ >= 9.0 over 13 prior days)
// ============================================================================

// Stage 1: Daily dangerous/unscanned download counts per user profile and event type
stage daily_download_counts {
    metadata.log_type = "CHROME_MANAGEMENT"
    (
      metadata.product_event_type = "dangerousDownloadEvent"
      or metadata.product_event_type = "malwareTransferEvent"
      or metadata.product_event_type = "unscannedFileEvent"
    )
    $entity = strings.coalesce(principal.user.userid, principal.user.user_display_name)
    $entity != ""
    $evt_type = metadata.product_event_type
    $evt_type != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.userid

  match:
    $entity, $evt_type by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_files = count_distinct(target.file.full_path)
    $bucket_max_ts = max(metadata.event_timestamp.seconds)
}

// Stage 2: Historical event-type accumulation per user profile
stage baseline_accumulation {
    $entity = $daily_download_counts.entity
    $evt_type = $daily_download_counts.evt_type

  match:
    $entity, $evt_type

  outcome:
    $total_hist_runs = sum($daily_download_counts.daily_count)
    $tool_active_days = count($daily_download_counts.window_start)
}

// Stage 3: User browser profile online calendar-day maturity across all CHROME_MANAGEMENT events
stage host_online_baseline {
    metadata.log_type = "CHROME_MANAGEMENT"
    $entity = strings.coalesce(principal.user.userid, principal.user.user_display_name)
    $entity != ""
    $utc_date = timestamp.get_date(metadata.event_timestamp.seconds, "UTC")

  match:
    $entity

  outcome:
    $online_days = count_distinct($utc_date)
    $host_max_ts = max(metadata.event_timestamp.seconds)
}

// Root Stage: Leave-One-Out Discrete Poisson Score on Latest Active Day + 6 Evidence Pillars
$entity = $daily_download_counts.entity
$evt_type = $daily_download_counts.evt_type
$entity = $baseline_accumulation.entity
$evt_type = $baseline_accumulation.evt_type
$entity = $host_online_baseline.entity
$ws = $daily_download_counts.window_start

match:
  $entity, $evt_type, $ws by 1d

outcome:
  $today_k = max($daily_download_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 13.0

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($host_online_baseline.online_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $lambda
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_download_counts.distinct_files)

  // Poisson Squared Score & Latest-Day Gate
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0.01, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda
  $lag_seconds = max($host_online_baseline.host_max_ts) - max($daily_download_counts.bucket_max_ts)
  $is_latest_day = if($lag_seconds < 86400, 1, 0)

condition:
  $baseline_active_samples >= 7
  and $is_latest_day = 1
  and $observation_count >= 2
  and $baseline_mean <= 0.5
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 9.0

order:
  $poisson_z_sq desc
```

---

### Scenario 8: Browser DLP Upload/Paste Circumvention & Multi-Day Outbound Drift

* **Curated Detection Operational Focus**: Monitors sensitive file uploads, clipboard pastes, DLP warn/block outcomes, and cumulative daily byte egress across managed and BYOD Chrome sessions.
* **How Multi-Stage UEBA Extends Coverage**: Scores each user's daily Chrome upload and clipboard paste activity (`sensitiveDataEvent` and `contentTransferEvent`) against their own 4-stage non-parametric **Median Absolute Deviation (MAD)** baseline (`Query 8A`, $M_Z > 3.5$, surfacing both cumulative "under-the-cap" allowed pastes and warn-decline-then-paste circumvention), paired with a 30-day `metrics.network_bytes_outbound` **Windowed Slack Sum** prefilter (`Query 8B`, $W = \sum \max(0, Z_t - 0.5) \ge 4.0$ over $\ge 2$ drift days).

#### Query 8A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Chrome DLP Uploads & Clipboard Pastes (`secops-statistical-hunter`)
Rebuilt from `mad_modified_z_4stage.yl2` over `CHROME_MANAGEMENT` `sensitiveDataEvent` and `contentTransferEvent` (`trigger_type != "FILE_DOWNLOAD"`), coalescing `principal.user.userid` and `principal.user.user_display_name` for BYOD coverage. In addition to scoring daily upload/paste counts via the Iglewicz-Hoaglin Modified Z-Score ($M_Z > 3.5$, $\ge 7$ active days, with MeanAD fallback when $\text{MAD} = 0$), Stage 1 projects cumulative payload bytes (`sum(target.file.size)`, directly auditing the `10 KB` daily CEP DLP benchmark) alongside `EVENT_RESULT_WARNED` / `EVENT_RESULT_BLOCKED` and `EVENT_RESULT_BYPASSED` counts to highlight warn-decline-then-paste circumvention (`warn_or_block_events > 0` with `bypass_events = 0`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous spikes in Chrome DLP file uploads and clipboard pastes (including cumulative under-the-cap allowed pastes and warn-decline circumvention) across corporate and BYOD profiles.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT sensitiveDataEvent and contentTransferEvent)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (MAD_MODIFIED_Z: M_Z > 3.5, active_days >= 7)
// ============================================================================

// Stage 1: Daily observed Chrome DLP upload & clipboard paste volume and byte totals per user profile
stage daily_stats {
    metadata.log_type = "CHROME_MANAGEMENT"
    (
      metadata.product_event_type = "sensitiveDataEvent"
      or metadata.product_event_type = "contentTransferEvent"
    )
    additional.fields["trigger_type"] != "FILE_DOWNLOAD"
    $entity = strings.coalesce(principal.user.userid, principal.user.user_display_name)
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.userid

  match:
    $entity by 1d

  outcome:
    $daily_value = count(metadata.id)
    $daily_bytes = sum(target.file.size)
    $warn_or_block_count = sum(if(security_result.action_details = "EVENT_RESULT_WARNED" or security_result.action_details = "EVENT_RESULT_BLOCKED", 1, 0))
    $bypass_count = sum(if(security_result.action_details = "EVENT_RESULT_BYPASSED", 1, 0))
    $distinct_sample_values = count_distinct(target.url)
    $sample_data = array_distinct(target.url)
}

// Stage 2: Baseline median of daily upload/paste events per user (active days only; false preserves 0 values)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, mean absolute deviation (MAD = 0 fallback), and active day count per user
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

// Root Stage: Iglewicz-Hoaglin Modified Z-Score, CEP DLP Byte/Circumvention Context & 6 Evidence Pillars
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

  // CEP DLP cumulative byte & warn-decline-then-paste triage context
  $total_egress_bytes = max($daily_stats.daily_bytes)
  $warn_or_block_events = max($daily_stats.warn_or_block_count)
  $bypass_events = max($daily_stats.bypass_count)

  // Robust scale with Iglewicz-Hoaglin MAD = 0 fallback (branches precomputed to avoid arithmetic in if())
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 10
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

#### Query 8B: Windowed Slack Sum (Longitudinal CUSUM Prefilter) on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Rebuilt from `longitudinal_cusum_2stage.yl2`. Stateless YARA-L computes the **Windowed Slack Sum** $W = \sum \max(0, Z_t - 0.5)$ across multi-day horizons (`Mode B` / `Mode C`, minimum 2 days; because Page's stateful recursion satisfies $S_t \le W$, any entity with $W < h$ cannot alarm under exact Page's CUSUM in `cusum_helper.py`). Standardizes daily `network.sent_bytes` against `metrics.network_bytes_outbound` using the empirical fleet byte dispersion floor (`44979.0` bytes) and the 7-active-day maturity gate (`$active_days >= 7`, `$windowed_slack_sum >= 4.0`, `$drift_days >= 2`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Screen low-and-slow multi-day outbound byte exfiltration via lossless Windowed Slack Sum prefiltering over 30-day metrics.network_bytes_outbound baselines.
// Statistical Model: Windowed Slack Sum / Longitudinal CUSUM Prefilter (WINDOWED_SLACK_SUM: W = sum(max(0, Z_t - 0.5)) >= 4.0, drift_days >= 2, min_baseline_days = 7)
// ARCHITECTURE: WINDOWED SLACK SUM (LONGITUDINAL CUSUM PREFILTER) PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Outbound Network Bytes & 30-Day Metrics Baseline Extraction
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $entity
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.hostname

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
}

// Stage 2: Per-Day Standardized Slack Excess with Empirical Fleet Byte Floor (44979.0 B) & 7-Day Maturity Gate
stage stage2_daily_slack {
    $entity = $stage1_extract.entity
    $ws = $stage1_extract.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $observed_val = max($stage1_extract.observed_val)
    $historical_avg = max($stage1_extract.historical_avg)
    $historical_stddev = max($stage1_extract.historical_stddev)
    $historical_active_days = max($stage1_extract.historical_active_days)

    $safe_stddev = if($historical_stddev > 44979.0, $historical_stddev, 44979.0)
    $daily_z = ($observed_val - $historical_avg) / $safe_stddev
    $deviation = $daily_z - 0.5
    $daily_excess = if($historical_active_days >= 7 and $deviation > 0.0, $deviation, 0.0)
}

// Root Stage: Multi-Day Windowed Slack Sum Accumulation
$entity = $stage2_daily_slack.entity

match:
  $entity

outcome:
  $observed_val = max($stage2_daily_slack.observed_val)
  $baseline_mean = max($stage2_daily_slack.historical_avg)
  $baseline_stddev = max($stage2_daily_slack.historical_stddev)
  $active_days = max($stage2_daily_slack.historical_active_days)

  $daily_z = max($stage2_daily_slack.daily_z)
  $slack_excess = sum($stage2_daily_slack.daily_excess)
  $windowed_slack_sum = $slack_excess
  $cusum_drift_score = $windowed_slack_sum
  $drift_days = sum(if($stage2_daily_slack.daily_excess > 0.0, 1, 0))

condition:
  $active_days >= 7
  and $windowed_slack_sum >= 4.0
  and $drift_days >= 2

order:
  $windowed_slack_sum desc
```

---

### Scenario 9: Post-Compromise Workspace Hoarding & Cross-Sector Kill-Chain Progression

* **Curated Detection Operational Focus**: Correlates browser security warnings and endpoint alerts with downstream Google Workspace download activity and outbound network transfers.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates every human Workspace user across the **3-Metric Multilevel Workspace Activity Triad** (`part_of_the_whole_triad_multilevel.yl2`: `workspace_auth_attempts_total`, `workspace_total_download_actions`, `workspace_total_change_actions`) using leave-one-out enterprise peer scoring and positive-rectified squared distance (`Query 9A`, $D_{\text{vs fleet}}^2 \ge 12.25$), and fuses multiplicity-adjusted per-rule EDR alert surges (`metrics.alert_event_name_count`) with 30-day outbound byte baselines (`metrics.network_bytes_outbound`) (`Query 9B`, $D^2 \ge 12.25$).

#### Query 9A: 3-Metric Multilevel Part-of-the-Whole Workspace Activity Triad (`secops-risk-metrics-multistage`)
Rebuilt from `part_of_the_whole_triad_multilevel.yl2` (fleet-only configuration). Stage 1 (`all_entities`) extracts daily observations and 30-day personal baselines across the Workspace Activity Triad while excluding machine/system accounts; Stage 2 (`enterprise_stats`) aggregates fleet sums, sample SDs, and degrees-of-freedom factors; Stage 3 (`loo_scores`) computes leave-one-out enterprise Z-scores (`(sum_all - obs) / (N - 1)`) with a continuous `sqrt(max(var, max(loo_avg, 1.0)))` floor so an extreme hoarder never inflates their own cohort variance; Root computes personal Z-scores and positive-rectified $D_{\text{vs fleet}}^2 = \sum \max(0, Z_m)^2 \ge 12.25$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect post-compromise Google Workspace Drive hoarding and account abuse across human users via Leave-One-Out Multilevel Triad scoring.
// Statistical Model: 3-Metric Leave-One-Out Multilevel Triad Z-Scores (Personal + Fleet) & Positive-Rectified Distance (D_vs_fleet^2 >= 12.25)
// ARCHITECTURE: 3-METRIC MULTILEVEL PART-OF-THE-WHOLE TRIAD DAG
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Enterprise Population Telemetry + 30-Day Baselines for the Workspace Activity Triad
stage all_entities {
    metadata.vendor_name = "Google Workspace"
    principal.user.userid = $user
    $user != ""
    not re.regex(principal.user.userid, `(?i)(\$$|^system$|^local service$|^network service$)`)
    // Optional CEP DLP / BYOD Watchlist Data Table filter (apply in Root to preserve full fleet baseline in Stage 2):
    // $user in %cep_dlp_watchlist.userid

  match:
    $user by 1d

  outcome:
    $m1_obs = sum(if((metadata.product_name = "login" or metadata.product_name = "saml" or metadata.product_name = "token"), 1, 0))
    $m1_p_avg = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m1_p_std = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    $m2_obs = sum(if(metadata.product_event_type = "download", 1, 0))
    $m2_p_avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m2_p_std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    $m3_obs = count(metadata.id)
    $m3_p_avg = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m3_p_std = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
}

// Stage 2: Enterprise Whole (Macro sums, sample SDs, and Leave-One-Out degrees-of-freedom factors)
stage enterprise_stats {
    $ws = $all_entities.window_start

  match:
    $ws by 1d

  outcome:
    $m1_fleet_sum = sum($all_entities.m1_obs)
    $m1_fleet_avg = avg($all_entities.m1_obs)
    $m1_fleet_std = stddev($all_entities.m1_obs)

    $m2_fleet_sum = sum($all_entities.m2_obs)
    $m2_fleet_avg = avg($all_entities.m2_obs)
    $m2_fleet_std = stddev($all_entities.m2_obs)

    $m3_fleet_sum = sum($all_entities.m3_obs)
    $m3_fleet_avg = avg($all_entities.m3_obs)
    $m3_fleet_std = stddev($all_entities.m3_obs)

    $fleet_size = count_distinct($all_entities.user)
    $fleet_valid = if($fleet_size > 1, 1.0, 0.0)
    $safe_n2 = if($fleet_size > 1, $fleet_size, 2)
    $fleet_peer_n = $safe_n2 - 1.0
    $fleet_n_over_nm1 = $fleet_size / $fleet_peer_n
    $safe_n3 = if($fleet_size > 2, $fleet_size, 3)
    $fleet_df = $safe_n3 - 2.0
    $fleet_inv_df = 1.0 / $fleet_df
    $m1_fleet_ss = $fleet_peer_n * $m1_fleet_std * $m1_fleet_std
    $m2_fleet_ss = $fleet_peer_n * $m2_fleet_std * $m2_fleet_std
    $m3_fleet_ss = $fleet_peer_n * $m3_fleet_std * $m3_fleet_std
}

// Stage 3: Per-User Leave-One-Out Cross-Sectional Enterprise Z-Scores
stage loo_scores {
    $user = $all_entities.user
    $ws = $all_entities.window_start
    $ws = $enterprise_stats.ws

  match:
    $user, $ws by 1d

  outcome:
    $e1_loo_avg = (max($enterprise_stats.m1_fleet_sum) - max($all_entities.m1_obs)) / max($enterprise_stats.fleet_peer_n)
    $e1_var = (max($enterprise_stats.m1_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m1_obs) - max($enterprise_stats.m1_fleet_avg)) * (max($all_entities.m1_obs) - max($enterprise_stats.m1_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e1_v1 = if($e1_var > $e1_loo_avg, $e1_var, $e1_loo_avg)
    $e1_v2 = if($e1_v1 > 1.0, $e1_v1, 1.0)
    $e1_safe_sd = math.sqrt($e1_v2)
    $z1_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m1_obs) - $e1_loo_avg) / $e1_safe_sd

    $e2_loo_avg = (max($enterprise_stats.m2_fleet_sum) - max($all_entities.m2_obs)) / max($enterprise_stats.fleet_peer_n)
    $e2_var = (max($enterprise_stats.m2_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m2_obs) - max($enterprise_stats.m2_fleet_avg)) * (max($all_entities.m2_obs) - max($enterprise_stats.m2_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e2_v1 = if($e2_var > $e2_loo_avg, $e2_var, $e2_loo_avg)
    $e2_v2 = if($e2_v1 > 1.0, $e2_v1, 1.0)
    $e2_safe_sd = math.sqrt($e2_v2)
    $z2_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m2_obs) - $e2_loo_avg) / $e2_safe_sd

    $e3_loo_avg = (max($enterprise_stats.m3_fleet_sum) - max($all_entities.m3_obs)) / max($enterprise_stats.fleet_peer_n)
    $e3_var = (max($enterprise_stats.m3_fleet_ss) - (max($enterprise_stats.fleet_n_over_nm1) * (max($all_entities.m3_obs) - max($enterprise_stats.m3_fleet_avg)) * (max($all_entities.m3_obs) - max($enterprise_stats.m3_fleet_avg)))) * max($enterprise_stats.fleet_inv_df)
    $e3_v1 = if($e3_var > $e3_loo_avg, $e3_var, $e3_loo_avg)
    $e3_v2 = if($e3_v1 > 1.0, $e3_v1, 1.0)
    $e3_safe_sd = math.sqrt($e3_v2)
    $z3_vs_enterprise = max($enterprise_stats.fleet_valid) * (max($all_entities.m3_obs) - $e3_loo_avg) / $e3_safe_sd
}

// Root Stage: Personal Z-Scores & Positive-Rectified Multilevel Triad Distance
$user = $all_entities.user
$ws = $all_entities.window_start
$user = $loo_scores.user
$ws = $loo_scores.ws

match:
  $user, $ws by 1d

outcome:
  $m1_observed = max($all_entities.m1_obs)
  $m2_observed = max($all_entities.m2_obs)
  $m3_observed = max($all_entities.m3_obs)

  $f1 = math.sqrt(if(max($all_entities.m1_p_avg) > 1.0, max($all_entities.m1_p_avg), 1.0))
  $f2 = math.sqrt(if(max($all_entities.m2_p_avg) > 1.0, max($all_entities.m2_p_avg), 1.0))
  $f3 = math.sqrt(if(max($all_entities.m3_p_avg) > 1.0, max($all_entities.m3_p_avg), 1.0))
  $s1 = if(max($all_entities.m1_p_std) > $f1, max($all_entities.m1_p_std), $f1)
  $s2 = if(max($all_entities.m2_p_std) > $f2, max($all_entities.m2_p_std), $f2)
  $s3 = if(max($all_entities.m3_p_std) > $f3, max($all_entities.m3_p_std), $f3)
  $z1_personal = ($m1_observed - max($all_entities.m1_p_avg)) / $s1
  $z2_personal = ($m2_observed - max($all_entities.m2_p_avg)) / $s2
  $z3_personal = ($m3_observed - max($all_entities.m3_p_avg)) / $s3

  $z1_vs_enterprise = max($loo_scores.z1_vs_enterprise)
  $z2_vs_enterprise = max($loo_scores.z2_vs_enterprise)
  $z3_vs_enterprise = max($loo_scores.z3_vs_enterprise)
  $z1_pos = if($z1_vs_enterprise > 0.0, $z1_vs_enterprise, 0.0)
  $z2_pos = if($z2_vs_enterprise > 0.0, $z2_vs_enterprise, 0.0)
  $z3_pos = if($z3_vs_enterprise > 0.0, $z3_vs_enterprise, 0.0)

  $d_vs_fleet_sq = ($z1_pos * $z1_pos) + ($z2_pos * $z2_pos) + ($z3_pos * $z3_pos)
  $composite_threat_norm_sq = $d_vs_fleet_sq

condition:
  $d_vs_fleet_sq >= 12.25

order:
  $d_vs_fleet_sq desc
```

#### Query 9B: Roll-Up Endpoint Alert + Outbound Network Bytes Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Rebuilt from `rollup_sector_fusion_4stage.yl2` using a shared entity-union spine so single-sector outliers survive when the companion sector has zero events today. Rolls per-rule security alerts (`metrics.alert_event_name_count` over `principal.asset.hostname` + `security_result.rule_name`) up to the host level by subtracting the Gaussian expected-maximum multiplicity offset `math.sqrt(2.0 * math.log($k_eff))` across active alert rules (`$k_eff`, an expected-maximum approximation rather than a Bonferroni correction), and fuses with 30-day `metrics.network_bytes_outbound` standardized using the `44979.0` byte dispersion floor and 7-active-day maturity gate ($D^2 \ge 12.25$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse multiplicity-adjusted endpoint security alert surges with 30-day outbound network byte anomalies on the same host without dropping single-sector outliers.
// Statistical Model: Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D^2 >= 12.25, min_baseline_days = 7)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A rolls alert_event_name_count up from per-(security_result.rule_name) baselines with sqrt(2*ln(K_eff)) expected-maximum offset; it measures peak per-rule anomaly rather than host total alert volume.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2, union spine): one row per host and alert rule_name ---
stage sector_a_detail {
    (
      ((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "")
      or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000)
    )
    principal.asset.hostname = $entity
    $entity != ""
    security_result.rule_name = $security_result_rule_name
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.hostname

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

// --- STAGE 2: Per-rule continuous floor & 7-day maturity standardization (stage-to-stage) ---
stage sector_a_scored {
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
    $d_z_pos = if($d_z_raw > 0.0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

// --- STAGE 3: Sector A roll-up (stage-to-stage): one row per host with K_eff multiplicity offset ---
stage sector_a {
    $entity = $sector_a_scored.entity
    $ws = $sector_a_scored.ws

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_scored.d_obs)
    $a_keys = count_distinct($sector_a_scored.security_result_rule_name)
    $a_active_keys = sum($sector_a_scored.d_active)
    $a_hot_keys = sum($sector_a_scored.d_hot)
    $a_novel_keys = sum($sector_a_scored.d_novel)
    $a_days = max($sector_a_scored.d_days)
    $z_a_max = max($sector_a_scored.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

// --- STAGE 4: Sector B — Outbound Network Bytes (UDM Source 2 of 2, union spine) ---
stage sector_b {
    (
      ((metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS") and security_result.rule_name != "")
      or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000)
    )
    principal.asset.hostname = $entity
    $entity != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.hostname

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
}

// --- ROOT STAGE: Empirical Byte Floor (44979.0 B), 7-Day Maturity Gate & Euclidean Fusion ---
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

  $z_a = max($sector_a.z_a)
  $b_safe_std = if($b_stddev > 44979.0, $b_stddev, 44979.0)
  $z_b_raw = ($b_observed - $b_mean) / $b_safe_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  $composite_threat_norm_sq = ($z_a * $z_a) + ($z_b * $z_b)

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

### Scenario 10: Capstone Multi-Scenario Browser & Endpoint Entity Convergence via Native UDM Loopback (`Option 3` Connective Tissue)

* **Curated Detection Operational Focus**: Individual browser, DLP, Workspace, and endpoint alerts evaluated independently within their respective telemetry domains.
* **How Multi-Stage UEBA Extends Coverage**: Executes in **Wave 3** after Wave 1 and Wave 2 findings have been indexed as `GENERIC_EVENT` records (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
  1. **Per-Scenario Deduplication (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` records for the active `$run_id` across Scenarios 1–9 (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-9]`)`), clamping negative confidence scores at `0.0` before squaring.
  2. **Multi-Scenario $L_2$ Convergence (`stage2_multi_scenario_rollup`)**: Aggregates across distinct scenario tags per `$entity`, requiring `$distinct_scenarios_matched >= 2` (`LOOPBACK_MIN_DISTINCT_HITS`) and `$capstone_threat_norm_sq >= 25.0` (`LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD`, equivalent to composite $L_2 \ge 5.0$).
  3. **Domain-Separated Raw Forensic Bridge (`stage3_raw_forensic_pivot`)**: Joins matched entities against raw browser (`SCAN_FILE` for `CHROME_MANAGEMENT` DLP/download scans), endpoint (`PROCESS_LAUNCH`), network (`NETWORK_CONNECTION`), cloud (`RESOURCE_READ`, `USER_RESOURCE_ACCESS`), and authentication (`USER_LOGIN`) events with explicit per-event-type conditional counters so analysts receive immediate cross-plane attribution.

#### Query 10: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Capstone multi-scenario convergence deduplicating UEBA hunt matches across Scenarios 1 through 9 via UDM Loopback and joining raw browser, endpoint, network, and cloud telemetry.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 25.0) + Domain-Separated Raw Telemetry Bridge
// Skill: secops-statistical-hunter
// ============================================================================

stage stage1_per_scenario_dedup {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_[1-9]`)
    $scenario_tag = security_result.rule_name
    $entity = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.ip[0])
    $entity != ""
    $run_id != ""
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $entity in %cep_dlp_watchlist.entity_id

  match:
    $entity, $scenario_tag

  outcome:
    $scenario_z = max(if(security_result.confidence_score > 0, security_result.confidence_score, 0))
    $scenario_hits = count(metadata.id)
    $run_ids = array_distinct(metadata.product_log_id)
}

stage stage2_multi_scenario_rollup {
    $entity = $stage1_per_scenario_dedup.entity
    $scenario_tag = $stage1_per_scenario_dedup.scenario_tag

  match:
    $entity

  outcome:
    $distinct_scenarios_matched = count_distinct($stage1_per_scenario_dedup.scenario_tag)
    $matched_scenario_tags = array_distinct($stage1_per_scenario_dedup.scenario_tag)
    $correlated_run_ids = array_distinct($stage1_per_scenario_dedup.run_ids)
    $total_loopback_matches = sum($stage1_per_scenario_dedup.scenario_hits)
    $peak_scenario_z = max($stage1_per_scenario_dedup.scenario_z)
    $capstone_threat_norm_sq = sum($stage1_per_scenario_dedup.scenario_z * $stage1_per_scenario_dedup.scenario_z)
}

stage stage3_raw_forensic_pivot {
    (
      metadata.event_type = "SCAN_FILE"
      or metadata.event_type = "PROCESS_LAUNCH"
      or metadata.event_type = "NETWORK_CONNECTION"
      or metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
      or metadata.event_type = "USER_LOGIN"
    )
    $entity = strings.coalesce(principal.user.userid, principal.user.user_display_name, principal.asset.hostname, principal.ip[0])
    $entity != ""

  match:
    $entity

  outcome:
    $raw_event_count = count(metadata.id)
    $chrome_scan_events = sum(if(metadata.event_type = "SCAN_FILE", 1, 0))
    $process_events = sum(if(metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $network_events = sum(if(metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $cloud_access_events = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $login_events = sum(if(metadata.event_type = "USER_LOGIN", 1, 0))
    $sample_urls = array_distinct(target.url)
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
  $capstone_threat_norm_sq = max($stage2_multi_scenario_rollup.capstone_threat_norm_sq)
  $capstone_threat_score = math.sqrt($capstone_threat_norm_sq)

  $raw_event_count = max($stage3_raw_forensic_pivot.raw_event_count)
  $chrome_scan_events = max($stage3_raw_forensic_pivot.chrome_scan_events)
  $process_events = max($stage3_raw_forensic_pivot.process_events)
  $network_events = max($stage3_raw_forensic_pivot.network_events)
  $cloud_access_events = max($stage3_raw_forensic_pivot.cloud_access_events)
  $login_events = max($stage3_raw_forensic_pivot.login_events)
  $sample_urls = array_distinct($stage3_raw_forensic_pivot.sample_urls)
  $sample_processes = array_distinct($stage3_raw_forensic_pivot.sample_processes)
  $sample_resources = array_distinct($stage3_raw_forensic_pivot.sample_resources)
  $total_sent_bytes = max($stage3_raw_forensic_pivot.total_sent_bytes)

  // 6 Core Evidence Pillars compatibility aliases
  $observation_count = $total_loopback_matches
  $baseline_active_samples = $distinct_scenarios_matched
  $z_score = $capstone_threat_score

condition:
  $distinct_scenarios_matched >= 2
  and $capstone_threat_norm_sq >= 25.0
  and $raw_event_count >= 1

order:
  $capstone_threat_score desc
```

---

## 4. Non-Parametric Quantiles (`window.percentile`), Bowley Skewness & Rare-Domain Egress Sieve

Static browser DLP byte caps and Gaussian mean/stddev baselines lose sensitivity when developers or analysts occasionally upload large legitimate files (which inflate the 30-day arithmetic mean and standard deviation) or when an insider hides an archive upload to a personal cloud domain inside heavy routine traffic. Rebuilt from `quantile_iqr_skew_3stage.yl2`:
1. **1-Stage Quantile Envelope & Hubert-Vandervieren Skew-Adjusted Tukey Fence (`QUANTILE_IQR_SKEW`)**: Computes `$q25`, `$q50`, and `$q75` in a single intermediate stage (`quantile_envelope`, saving 1 stage compared to 4-stage MAD), freeing Stage 3 (`stage3_rare_domain`) to inner-join `DERIVED_CONTEXT` rare domain prevalence (`day_count = 10`, `rolling_max <= 3`, `rolling_max > 0`).
2. **Bowley Quartile Skewness (`1.35` Exponent) & Robust Scale-Excess (`$tukey_excess_z >= 1.0`)**: Computes Bowley quartile skewness $S_B = (Q_3 + Q_1 - 2Q_2) / \text{IQR}$, adjusts the upper Tukey fence via $Q_3 + 1.5 \cdot e^{1.35 \cdot \max(0, S_B)} \cdot \text{IQR}$, and standardizes excess above the fence in Gaussian-consistent IQR units (`$robust_scale = $safe_iqr / 1.349`) alongside the 30-day `metrics.network_bytes_outbound` Z-score (`44979.0` byte dispersion floor, `$hist_active_days >= 7`). Run over a 14-day window ending at `D+1 T00:00:00Z` (or `D-2` to `D+1` for Mode A compile verification) with `$in_scoring_window` pinned to the scored UTC day (`"2026-10-29"`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect right-skewed outbound byte surges to rare external domains (DERIVED_CONTEXT rolling_max <= 3) via Hubert-Vandervieren Skewness-Adjusted Tukey Fences.
// Statistical Model: 4-Stage Quantile/Bowley Skewness Tukey Fence (QUANTILE_IQR_SKEW: Bowley 1.35 exponent, tukey_excess_z >= 1.0) + DERIVED_CONTEXT Rare Domain Sieve
// ARCHITECTURE: QUANTILE / BOWLEY SKEWNESS TUKEY FENCE + DERIVED_CONTEXT DOMAIN PREVALENCE
// Skill: secops-risk-metrics-multistage
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""
    not re.regex(target.hostname, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)
    // Optional CEP DLP / BYOD Watchlist Data Table filter (see Section 1.2):
    // $host in %cep_dlp_watchlist.hostname

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29", 1, 0))
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

stage quantile_envelope {
    $host = $stage1_extract.host

  match:
    $host

  outcome:
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

stage stage3_rare_domain {
    $g.graph.metadata.entity_type = "DOMAIN_NAME"
    $g.graph.metadata.source_type = "DERIVED_CONTEXT"
    $g.graph.entity.domain.name = $domain
    $domain != ""
    $g.graph.entity.domain.prevalence.day_count = 10
    $g.graph.entity.domain.prevalence.rolling_max > 0
    $g.graph.entity.domain.prevalence.rolling_max <= 3

  match:
    $domain

  outcome:
    $domain_prevalence = min($g.graph.entity.domain.prevalence.rolling_max)
}

$host = $stage1_extract.host
$host = $quantile_envelope.host
$domain = $stage1_extract.domain
$domain = $stage3_rare_domain.domain
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $observed = sum($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $hist_active_days = max($stage1_extract.historical_active_days)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)
  $min_domain_prevalence = min($stage3_rare_domain.domain_prevalence)

  $safe_stddev = if($hist_stddev > 44979.0, $hist_stddev, 44979.0)
  $raw_personal_z = ($observed - $hist_avg) / $safe_stddev
  $personal_z = if($hist_active_days >= 7, $raw_personal_z, 0.0)

  $iqr = $q75_val - $q25_val
  $q50_floor = ($q50_val * 0.05) + 1.0
  $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $pos_skew = if($bowley_skew > 0.0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * $pos_skew) * $safe_iqr)
  $tukey_excess_z = ($observed - $adj_upper_fence) / ($safe_iqr / 1.349)

condition:
  $in_scoring_window = 1
  and $raw_active_days >= 7
  and $tukey_excess_z >= 1.0

order:
  $tukey_excess_z desc
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
