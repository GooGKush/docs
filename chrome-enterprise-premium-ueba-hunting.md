# Hunting Chrome Enterprise Premium Browser & Extension Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Chrome Enterprise Premium Threats** curated detection pack provides high-confidence, real-time alerting for browser-layer threats, including password reuse, phishing navigation, malicious Chrome extension installations, data loss prevention (DLP) policy violations, and anomalous browser downloads.

This playbook supplements those point-in-time and single-stage browser detections with cyclical **Multi-Stage Behavioral Analytics** (`secops-risk-metrics-multistage` and `secops-statistical-hunter`). By combining **30-day behavioral baselines (`metrics.*`)** with **multi-stage statistical models over raw Chrome Enterprise telemetry**, the UEBA harness extends visibility beyond the inherent constraints of single-event rules—capturing high-entropy credential harvesting redirects, rare or sideloaded extension adoption across the fleet, low-and-slow session/clipboard exfiltration, automated extension C2 beaconing, and multi-user campaign rollouts.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

### Table 1: Scenario Coverage Matrix — Chrome Enterprise Premium Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Credential Reuse, Phishing Redirects & Lateral Auth** | Real-time detection of corporate password reuse on non-corporate domains, phishing warnings, and suspicious login redirects. | Measures URL query-parameter character-class Shannon entropy ($H(X) \ge 3.8$) to surface obfuscated phishing tokens and fuses 30-day authentication failure and login success baselines ($D^2 \ge 12.25$) to detect post-phishing credential replay. | `Query 1A` (Shannon Entropy)<br>`Query 1B` (30d Auth Fusion) |
| **2. Malicious, Sideloaded & Uncategorized Chrome Extensions** | Point-in-time detection of known-malicious extension IDs, sideloaded unpacked extensions, and unauthorized extension installs. | Unifies cold-start first-time host installs (Two-Part Hurdle) with fleetwide Zipfian power-law rarity ($I = \ln(N / df) \ge 3.2$) in a single piecewise query (`Option 1`) to surface rare or newly introduced extensions regardless of static reputation. | `Query 2` (Piecewise Hurdle + Zipfian Fleet Rarity) |
| **3. Session Cookie Harvesting, Clipboard & Screen Capture Abuse** | Detection of sensitive content copy/paste events, screen capture actions, and browser session theft indicators. | Evaluates over-dispersed bursts of browser clipboard, print, and sensitive-data access events via Poisson Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$) and 30-day Workspace/Web activity divergence. | `Query 3A` (Poisson Fano Burst)<br>`Query 3B` (30d Workspace/Web Triad) |
| **4. Browser Extension C2 Beaconing & Newly Observed Domains** | Alerts on browser connections to known C2 indicators and suspicious external endpoints. | Computes inter-arrival jitter Coefficient of Variation ($\text{CV} \le 0.20$) to identify robotic extension callback timers and weights 30-day outbound HTTP volume by event-relative WHOIS domain registration age. | `Query 4A` (Inter-Arrival CV)<br>`Query 4B` (30d HTTP + WHOIS Lifecycle) |
| **5. SafeBrowsing Warning Bypasses & Ephemeral Phishing Infrastructure** | Detects user click-throughs on browser security warnings and navigation to newly registered or shortened URLs. | Applies Empirical Bayes Beta-Binomial regularization to user warning-bypass rates and correlates 30-day failed HTTP navigation spikes with DNS query anomalies. | `Query 5A` (Beta-Binomial Bypass Rate)<br>`Query 5B` (30d HTTP Fail + DNS Fusion) |
| **6. Drive-By Malware Downloads & Anomalous Binary Execution** | Identifies hazardous file downloads and suspicious payload delivery through the browser. | Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` fleet prevalence (`day_max <= 3`) and Markov 2-gram browser-to-shell process transition surprisal. | `Query 6A` (30d Execution + 10d Prevalence)<br>`Query 6B` (Markov 2-Gram Surprisal) |
| **7. Coordinated Multi-User Download Campaigns & Fleet Rollouts** | Tracks high-risk browser download events and shared file hashes across endpoints. | Applies 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z = Z_{\text{entity}} - Z_{\text{fleet}} \ge 3.0\sigma$) to separate targeted payload delivery from benign enterprise software updates. | `Query 7` (Dual-Baseline Fleet Delta-Z) |
| **8. Browser & Extension Data Exfiltration (Archives, Non-Corporate Accounts & Clipboard)** | Monitors sensitive file uploads, clipboard pastes, and personal-account data transfers in the browser. | Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and 4-stage non-parametric 30-day MAD over browser upload events. | `Query 8A` (Piecewise 30d MAD Uploads)<br>`Query 8B` (Producer-Consumer Inversion) |
| **9. Post-Compromise Workspace Hoarding & Cross-Sector Progression** | Correlates browser warnings with downstream Google Workspace download activity. | Replaces static post-warning thresholds with a 3-Metric Multilevel Part-of-the-Whole Workspace Triad (`workspace_total_download_actions`, `workspace_chrome_os_File_download_upload_events`, `http_queries_total`). | `Query 9` (3-Metric Multilevel Workspace Triad) |
| **10. Capstone Multi-Scenario Browser Entity Convergence** | Individual scenario alerts evaluated independently within their respective telemetry domains. | Correlates users and hosts matching $\ge 2$ distinct browser hunting scenarios within the same run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Credential Reuse, Breached Passwords & Phishing Parameter Obfuscation

* **Curated Detection Operational Focus**: Real-time detection of corporate password reuse on non-corporate domains, phishing warnings, and suspicious login redirects.
* **How Multi-Stage UEBA Extends Coverage**: Measures URL query-parameter character-class Shannon entropy ($H(X) \ge 3.8$) to surface obfuscated phishing tokens and fuses 30-day authentication failure and login success baselines ($D^2 \ge 12.25$) to detect post-phishing credential replay.

#### Query 1A: Shannon Character-Class Entropy Hunt on Chrome Navigation & Password-Event URLs (`secops-statistical-hunter`)
Compensates for the `@`/`%40` regex bypass and `is_admin` filter by measuring information-theoretic **Shannon character-class entropy** ($H(X) = -\sum p_i \log_2 p_i$) across lowercase, uppercase, digit, and symbol/delimiter distributions on Chrome navigation and password reuse/breach URLs across *all* users.

```yara
// ============================================================================
// Goal: Detect obfuscated AitM phishing tokens, Base64/Hex-encoded victim lures, and high-entropy credential harvesting URLs across all Chrome users.
// Target Telemetry: UDM_EVENTS (CHROME_MANAGEMENT navigation, passwordReuseEvent, passwordBreachEvent)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)))
// ============================================================================

// Stage 1: Aggregate URL string lengths and character-class distributions per user and target URL
stage url_feature_extraction {
    metadata.product_name = "Chrome Browser Cloud Management"
    (
      metadata.product_event_type = "passwordReuseEvent"
      or metadata.product_event_type = "passwordBreachEvent"
      or metadata.product_event_type = "badNavigationEvent"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_SOCIAL_ENGINEERING"
      or metadata.product_event_type = "UNSAFE_SITE_VISIT_MALWARE"
    )
    principal.user.userid = $user
    $user != ""
    $url = target.url
    $url != ""
    strings.length($url) >= 48

  match:
    $user, $url by 1d

  outcome:
    $execution_count = count(metadata.id)
    $raw_len = max(strings.length($url))

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax for AST compliance)
    $len_no_lower = max(strings.length(re.replace($url, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($url, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($url, `\d`, "")))

    $c_lower = $raw_len - $len_no_lower
    $c_upper = $raw_len - $len_no_upper
    $c_digit = $raw_len - $len_no_digit
    $c_other_raw = $raw_len - ($c_lower + $c_upper + $c_digit)
    $c_other = if($c_other_raw > 0, $c_other_raw, 0)
}

// Stage 2: Enterprise fleet prevalence of each distinct URL across users
stage url_fleet_prevalence {
    $url = $url_feature_extraction.url

  match:
    $url by 1d

  outcome:
    $fleet_users = count_distinct($url_feature_extraction.user)
}

// Root Stage: Compute 4-Class Shannon Entropy Equivalent & 6 Evidence Pillars
$user = $url_feature_extraction.user
$url = $url_feature_extraction.url
$url = $url_fleet_prevalence.url

match:
  $user, $url by 1d

outcome:
  $exec_count = max($url_feature_extraction.execution_count)
  $len = max($url_feature_extraction.raw_len)
  $safe_len = if($len > 0, $len, 1)

  $n_lower = max($url_feature_extraction.c_lower)
  $n_upper = max($url_feature_extraction.c_upper)
  $n_digit = max($url_feature_extraction.c_digit)
  $n_other = max($url_feature_extraction.c_other)

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
  $length_bonus = if($len >= 120, 0.5, 0.0)
  $shannon_entropy_score = ($class_entropy * 2.25) + $length_bonus
  $z_score = $shannon_entropy_score

  // 6 Core Evidence Pillars
  $observation_count = $exec_count
  $baseline_active_samples = $len
  $baseline_mean = $class_entropy
  $baseline_dispersion = $shannon_entropy_score
  $fleet_prevalence = max($url_fleet_prevalence.fleet_users)
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 48
  and $fleet_prevalence <= 3
  and $shannon_entropy_score >= 3.8

order:
  $shannon_entropy_score desc
```

#### Query 1B: 30-Day Multi-Sector Authentication Failure & Login Success Fusion (`secops-risk-metrics-multistage`)
Compensates for the lack of post-reuse / post-breach authentication correlation across all user roles by fusing 30-day behavioral baselines for failed logins (`metrics.auth_attempts_fail`) and successful logins (`metrics.auth_attempts_success`) per user (`target.user.userid`).

```yara
// ============================================================================
// Goal: Detect post-password-reuse and post-breach credential stuffing or account takeover across all users (admin and non-admin).
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D^2 = Z_fail^2 + Z_success^2 >= 12.25)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION
// Skill: secops-risk-metrics-multistage
// ADVISORY: Two metrics of the same auth family (auth_attempts_fail + auth_attempts_success) are paired to capture spray-then-login progression.
// ============================================================================

// --- STAGE 1: Sector A — Authentication Failures (UDM Source 1 of 2) ---
stage sector_a {
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = count(metadata.id)
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
}

// --- STAGE 2: Sector B — Authentication Successes (UDM Source 2 of 2) ---
stage sector_b {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
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

### Scenario 2: Malicious & Uncategorized Chrome Extensions (Sideloading & Rare Fleet Adoption)

* **Curated Detection Operational Focus**: Point-in-time detection of known-malicious extension IDs, sideloaded unpacked extensions, and unauthorized extension installs.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start first-time host installs (Two-Part Hurdle) with fleetwide Zipfian power-law rarity ($I = \ln(N / df) \ge 3.2$) in a single piecewise query (`Option 1`) to surface rare or newly introduced extensions regardless of static reputation.

#### Query 2: Unified Two-Part Host Hurdle & Zipfian Fleet Rarity on Chrome Extensions (`secops-statistical-hunter`)
Because both **Zipfian Fleet Rarity** (fixing the `$ext_count < 3` constraint on sideloaded/rare extensions) and the **Two-Part Zero-Inflated Host Hurdle** (detecting dormant or newly installed `WEBSTORE`/`EXTERNAL` extensions waking up on a workstation) operate on the exact same `Chrome Browser Cloud Management` extension telemetry stream (`$host, $ext_id by 1d`), this **Option 1 Unified Pipeline** evaluates both models inside a single 4-stage DAG (`$unified_threat_score = if($baseline_active_samples <= 2, $hurdle_threat_score, $zipf_rarity_score)`):
- **Regime 1 — Dormant / First-Time Host Activation ($\text{active\_days} \le 2$)**: Applies a $3.0\times$ Bernoulli Hurdle Crossing multiplier to the positive-activity intensity Z-score (`$hurdle_threat_score`).
- **Regime 2 — Persistent Rare Fleet Extension ($\text{active\_days} \ge 3, \text{fleet\_prevalence} \le 3$)**: Scores Inverse Host Frequency (IDF) surprisal combined with log execution intensity (`$zipf_rarity_score`), fixing the `$ext_count < 3` self-suppression constraint when an aggressive extension generates $\ge 3$ events per hour on a single host.

```yara
// ============================================================================
// Goal: Unify dormant/first-time Chrome extension hurdle activation (Two-Part Hurdle) and fleet-rare extension intensity (Zipfian IDF Rarity) in a single 4-stage pipeline, fixing the $ext_count < 3 constraint across both EXTERNAL and WEBSTORE extensions.
// Target Telemetry: UDM_EVENTS (Chrome Browser Cloud Management extension events)
// Statistical Model: Option 1 Piecewise Two-Part Zero-Inflated Hurdle + Zipf-Mandelbrot Inverse Host Frequency (IDF) Surprisal
// ============================================================================

// Stage 1: Daily extension activity counts per (host, extension_id) pair across EXTERNAL and WEBSTORE extensions
stage daily_extension_activity {
    metadata.product_name = "Chrome Browser Cloud Management"
    (
      metadata.product_event_type = "extensionTelemetryEvent"
      or metadata.product_event_type = "browserExtensionInstallEvent"
      or additional.fields["extension_source"] != ""
    )
    additional.fields["extension_action"] != "UNINSTALL"
    principal.asset.hostname = $host
    $host != ""
    $ext_id = target.resource.product_object_id
    $ext_id != ""

  match:
    $host, $ext_id by 1d

  outcome:
    $daily_events = count(metadata.id)
    $distinct_apis = count_distinct(target.resource.name)
    $sample_actions = array_distinct(target.resource.name)
}

// Stage 2: Historical presence (Part 1 Hurdle) and positive-activity baseline (Part 2 Intensity)
stage extension_hurdle_baseline {
    $host = $daily_extension_activity.host
    $ext_id = $daily_extension_activity.ext_id

  match:
    $host, $ext_id

  outcome:
    $active_days = count($daily_extension_activity.window_start)
    $pos_mean = avg($daily_extension_activity.daily_events)
    $pos_stddev = stddev($daily_extension_activity.daily_events)
    $total_events = sum($daily_extension_activity.daily_events)
}

// Stage 3: Enterprise fleet prevalence of the extension ID per window (Zipfian adopter breadth)
stage extension_fleet_context {
    $ext_id = $daily_extension_activity.ext_id
    $ws = $daily_extension_activity.window_start

  match:
    $ext_id, $ws by 1d

  outcome:
    $fleet_hosts = count_distinct($daily_extension_activity.host)
}

// Root Stage: Option 1 Unified Two-Part Hurdle & Zipfian Fleet Rarity Scoring
$host = $daily_extension_activity.host
$ext_id = $daily_extension_activity.ext_id
$host = $extension_hurdle_baseline.host
$ext_id = $extension_hurdle_baseline.ext_id
$ext_id = $extension_fleet_context.ext_id
$ws = $daily_extension_activity.window_start
$ws = $extension_fleet_context.ws

match:
  $host, $ext_id, $ws by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_extension_activity.daily_events)
  $baseline_active_samples = max($extension_hurdle_baseline.active_days)
  $baseline_mean = max($extension_hurdle_baseline.pos_mean)
  $baseline_dispersion = max($extension_hurdle_baseline.pos_stddev)
  $fleet_prevalence = max($extension_fleet_context.fleet_hosts)
  $distinct_binaries = max($daily_extension_activity.distinct_apis)
  $sample_commands = array_distinct($daily_extension_activity.sample_actions)

  // Branch A: Two-Part Hurdle Threat Score (Cold-Start / Dormant Extension Activation <= 2 active days)
  $hurdle_rarity_boost = if($baseline_active_samples <= 2, 3.0, 1.0)
  $safe_sd = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $intensity_z = ($observation_count - $baseline_mean) / $safe_sd
  $pos_intensity_z = if($intensity_z > 0, $intensity_z, 1.5)
  $hurdle_threat_score = $pos_intensity_z * $hurdle_rarity_boost

  // Branch B: Zipfian Fleet Rarity Score (Fixes $ext_count < 3 constraint for low-prevalence extensions)
  $safe_adopters = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $idf_surprisal = math.log(50.0) - math.log($safe_adopters)
  $local_intensity = math.log($observation_count + 1)
  $singleton_boost = if($fleet_prevalence = 1, 1.5, 1.0)
  $zipf_rarity_score = ($idf_surprisal + $local_intensity) * $singleton_boost

  // Option 1 Piecewise Regime Switch
  $unified_threat_score = if($baseline_active_samples <= 2, $hurdle_threat_score, $zipf_rarity_score)

condition:
  $observation_count >= 3
  and $fleet_prevalence <= 3
  and $unified_threat_score >= 3.5

order:
  $unified_threat_score desc
```

---

---

### Scenario 3: Chrome Extension Session Cookie Harvesting & Screen Capture Surveillance

* **Curated Detection Operational Focus**: Detection of sensitive content copy/paste events, screen capture actions, and browser session theft indicators.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates over-dispersed bursts of browser clipboard, print, and sensitive-data access events via Poisson Fano Factor dispersion ($F = \sigma^2/\mu \ge 4.0$) and 30-day Workspace/Web activity divergence.

#### Query 3A: Poisson Fano Factor Burst Clustering on Extension Cookie & Screenshot APIs (`secops-statistical-hunter`)
Removes the `cookie_is_session = "true"` coverage considerations to cover **both session and persistent cookies** alongside tab screenshots, and applies the **Fano Factor** ($F = \sigma^2 / \mu \ge 4.0$) over hourly tumbling buckets to distinguish automated credential/screen harvesting bursts from steady background SSO checks.

```yara
// ============================================================================
// Goal: Detect automated bursts of Chrome extension cookie harvesting (both session and persistent cookies) and tab screen captures via Poisson dispersion.
// Target Telemetry: UDM_EVENTS (extensionTelemetryEvent: COOKIES_GET_ALL_INFO and TABS_API_INFO/CAPTURE_VISIBLE_TAB)
// Statistical Model: Poisson Dispersion via Fano Factor (F = σ² / μ >= 4.0) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly surveillance API call counts per (host, extension_id) pair
stage hourly_surveillance_calls {
    metadata.product_name = "Chrome Browser Cloud Management"
    metadata.product_event_type = "extensionTelemetryEvent"
    (
      target.resource.name = "COOKIES_GET_ALL_INFO"
      or (
        target.resource.name = "TABS_API_INFO"
        and additional.fields["tabs_api_method"] = "CAPTURE_VISIBLE_TAB"
      )
    )
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1h

  outcome:
    $hourly_calls = count(metadata.id)
    $distinct_exts = count_distinct(target.resource.product_object_id)
    $sample_exts = array_distinct(target.resource.product_object_id)
}

// Stage 2: Historical arrival mean (μ), standard deviation (σ), and active hour density per host
stage dispersion_baseline {
    $entity = $hourly_surveillance_calls.entity

  match:
    $entity

  outcome:
    $mean_rate = avg($hourly_surveillance_calls.hourly_calls)
    $stddev_rate = stddev($hourly_surveillance_calls.hourly_calls)
    $total_calls = sum($hourly_surveillance_calls.hourly_calls)
    $active_hours = count($hourly_surveillance_calls.window_start)
    $max_distinct_exts = max($hourly_surveillance_calls.distinct_exts)
}

// Stage 3: Enterprise-wide host breadth per hourly window
stage fleet_breadth {
    $ws = $hourly_surveillance_calls.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($hourly_surveillance_calls.entity)
}

// Root Stage: Compute Fano Factor (F = σ² / μ) and emit 6 Core Evidence Pillars
$entity = $hourly_surveillance_calls.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_surveillance_calls.window_start
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
  $distinct_binaries = max($dispersion_baseline.max_distinct_exts)
  $sample_commands = array_distinct($hourly_surveillance_calls.sample_exts)

  // Aggregate Fano Factor (F = σ² / μ)
  $raw_mean = max($dispersion_baseline.mean_rate)
  $safe_mean = if($raw_mean > 0, $raw_mean, 1.0)
  $raw_stddev = max($dispersion_baseline.stddev_rate)
  $variance = $raw_stddev * $raw_stddev
  $fano_factor = $variance / $safe_mean

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 15
  and $baseline_mean >= 1.0
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

#### Query 3B: Empirical Bayes Gamma-Poisson Credibility Shrinkage on Extension Surveillance (`secops-statistical-hunter`)
Uses Method-of-Moments Gamma prior estimation ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$) so that noisy, erratic SSO extensions are shrunk toward their prior mean while a sudden spike in cookie or screenshot API calls on a normally predictable endpoint triggers a high posterior belief shift ($\text{anomaly\_score} \ge 3.0$).

```yara
// ============================================================================
// Goal: Suppress noisy enterprise SSO/productivity extension false positives while detecting true surges in cookie harvesting or tab screenshots via Bayesian shrinkage.
// Target Telemetry: UDM_EVENTS (extensionTelemetryEvent: COOKIES_GET_ALL_INFO and TABS_API_INFO)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting
// ============================================================================

// Stage 1: Hourly surveillance API volume per host
stage host_hourly_activity {
    metadata.product_name = "Chrome Browser Cloud Management"
    metadata.product_event_type = "extensionTelemetryEvent"
    (
      target.resource.name = "COOKIES_GET_ALL_INFO"
      or target.resource.name = "TABS_API_INFO"
    )
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_exts = count_distinct(target.resource.product_object_id)
}

// Stage 2: Historical Parameter Estimation (Method of Moments Gamma Prior)
stage host_prior_stats {
    $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
    $active_hours = count($host_hourly_activity.window_start)
}

// Stage 3: Organizational Peer Prevalence Baseline per window
stage fleet_context {
    $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($host_hourly_activity.host)
}

// Root Stage: Bayesian Conjugate Updating & Credibility Scoring
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

match:
  $host, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_exts)

  // Method-of-Moments Gamma prior (alpha_0 = mu^2 / sigma^2, beta_0 = mu / sigma^2)
  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $beta_prior = max($host_prior_stats.hist_mean) / $safe_var
  $alpha_prior = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $posterior_arrival_rate = ($alpha_prior + max($host_hourly_activity.hourly_count)) / ($beta_prior + 1.0)
  $safe_hist_mean = if(max($host_prior_stats.hist_mean) > 0, max($host_prior_stats.hist_mean), 1.0)
  $anomaly_score = $posterior_arrival_rate / $safe_hist_mean
  $z_score = $anomaly_score

condition:
  $baseline_active_samples >= 4
  and $observation_count >= 10
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
```

---

---

### Scenario 4: Chrome Extension Command-and-Control (C2) Beaconing & Newly Observed Domains

* **Curated Detection Operational Focus**: Alerts on browser connections to known C2 indicators and suspicious external endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Computes inter-arrival jitter Coefficient of Variation ($\text{CV} \le 0.20$) to identify robotic extension callback timers and weights 30-day outbound HTTP volume by event-relative WHOIS domain registration age.

#### Query 4A: Inter-Arrival Jitter Coefficient of Variation ($\text{CV} \le 0.20$) on Extension Remote Callbacks (`secops-statistical-hunter`)
Detects automated background service-worker C2 beaconing (`setInterval` / `chrome.alarms`) from Chrome extensions to low-prevalence external hosts ($\le 3$ endpoints in the fleet) regardless of TLD or domain age.

```yara
// ============================================================================
// Goal: Detect periodic Chrome extension C2 beaconing (with sleep jitter) to low-prevalence external hosts regardless of TLD or domain age.
// Target Telemetry: UDM_EVENTS (extensionTelemetryEvent: REMOTE_HOST_CONTACTED_INFO)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ <= 0.20) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly callback intervals per (host, remote_url) pair for extension network contacts
stage ext_host_intervals {
    metadata.product_name = "Chrome Browser Cloud Management"
    metadata.product_event_type = "extensionTelemetryEvent"
    target.resource.name = "REMOTE_HOST_CONTACTED_INFO"
    additional.fields["contacted_by"] = "EXTENSION"
    principal.asset.hostname = $src_host
    $src_host != ""
    target.url = $dst_url
    $dst_url != ""
    $ts = metadata.event_timestamp.seconds

  match:
    $src_host, $dst_url by 1h

  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = (max($ts) - min($ts)) / (count(metadata.id) + 1.0)
    $distinct_exts = count_distinct(target.resource.product_object_id)
}

// Stage 2: Aggregate historical inter-arrival timing stats across active hours
stage timing_stats {
    $src_host = $ext_host_intervals.src_host
    $dst_url = $ext_host_intervals.dst_url

  match:
    $src_host, $dst_url

  outcome:
    $mean_gap = avg($ext_host_intervals.avg_gap)
    $stddev_gap = stddev($ext_host_intervals.avg_gap)
    $total_conns = sum($ext_host_intervals.conn_count)
    $active_hours = count($ext_host_intervals.window_start)
    $max_exts = max($ext_host_intervals.distinct_exts)
}

// Stage 3: Enterprise-wide host prevalence of the contacted remote URL
stage dst_prevalence {
    $dst_url = $ext_host_intervals.dst_url

  match:
    $dst_url

  outcome:
    $src_breadth = count_distinct($ext_host_intervals.src_host)
}

// Root Stage: Compute Coefficient of Variation (CV = σ / μ) and emit 6 Core Evidence Pillars
$src_host = $timing_stats.src_host
$dst_url = $timing_stats.dst_url
$dst_url = $dst_prevalence.dst_url

match:
  $src_host, $dst_url

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.max_exts)

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

#### Query 4B: Hybrid 30-Day HTTP Volume Baseline + 10-Day Entity Context Graph Domain Prevalence (`secops-risk-metrics-multistage`)
Replaces the brittle 12-hour `first_seen_time` cliff with `DERIVED_CONTEXT` **10-day rolling organizational prevalence** (`rolling_max <= 3`) fused with the endpoint's 30-day `metrics.http_queries_total` baseline. Even if an attacker ages a domain for weeks, as long as it is only contacted by $\le 3$ hosts in the organization and drives an HTTP surge on the endpoint, this pipeline catches it.

```yara
// ============================================================================
// Goal: Detect endpoints communicating with rare external domains (10-day rolling_max <= 3 hosts) alongside an HTTP query surge, defeating the 12h/24h first_seen_time cliff.
// Statistical Model: Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + DERIVED_CONTEXT 10-Day Prevalence Multiplier
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT DOMAIN PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint HTTP Activity + 30-Day Behavioral Baseline per (host, target_domain)
stage http_metric_anomalies {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $http_count = count(metadata.id)
    $b_avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z_score = ($http_count - $b_avg) / if($b_std > 0, $b_std, 1.0)

  condition:
    $http_count >= 10 and $b_days >= 5
}

// Root Stage: Enrich with DERIVED_CONTEXT 10-Day Domain Prevalence (rolling_max <= 3)
$host = $http_metric_anomalies.host
$domain = $http_metric_anomalies.domain

$g.graph.metadata.entity_type = "DOMAIN_NAME"
$g.graph.metadata.source_type = "DERIVED_CONTEXT"
$g.graph.entity.domain.name = $domain
$g.graph.entity.domain.prevalence.day_count = 10
$g.graph.entity.domain.prevalence.rolling_max <= 3
$g.graph.entity.domain.prevalence.rolling_max > 0

match:
  $host, $domain

outcome:
  $observed_http = max($http_metric_anomalies.http_count)
  $baseline_mean = max($http_metric_anomalies.b_avg)
  $baseline_stddev = max($http_metric_anomalies.b_std)
  $z_score = max($http_metric_anomalies.z_score)
  $org_prevalence_10d = max($g.graph.entity.domain.prevalence.rolling_max)
  $domain_first_seen = max($g.graph.entity.domain.first_seen_time.seconds)

  // Rarity multiplier: singleton domain in the org gets 2.0x boost; <= 3 hosts gets 1.5x
  $rarity_multiplier = if($org_prevalence_10d <= 1, 2.0, 1.5)
  $pos_z = if($z_score > 0, $z_score, 0.5)
  $fused_threat_score = $pos_z * $rarity_multiplier

condition:
  $fused_threat_score >= 3.0

order:
  $fused_threat_score desc
```

---

---

### Scenario 5: SafeBrowsing Warning Bypasses, Shortened URLs & Newly Created Domains

* **Curated Detection Operational Focus**: Detects user click-throughs on browser security warnings and navigation to newly registered or shortened URLs.
* **How Multi-Stage UEBA Extends Coverage**: Applies Empirical Bayes Beta-Binomial regularization to user warning-bypass rates and correlates 30-day failed HTTP navigation spikes with DNS query anomalies.

#### Query 5A: Hybrid 30-Day Host HTTP Baseline + Event-Relative WHOIS Domain Lifecycle (`secops-risk-metrics-multistage`)
Fixes the `timestamp.current_seconds()` constraint by computing domain age relative to `max(metadata.event_timestamp.seconds)`, incorporates **expired/hijacked domain detection** (`expiration_time < event_ts`), and weights the host's 30-day `metrics.http_queries_total` Z-score by the WHOIS lifecycle risk multiplier.

```yara
// ============================================================================
// Goal: Detect anomalous host HTTP activity targeting newly registered (<= 30d at event time) or expired/hijacked WHOIS domains.
// Statistical Model: Hybrid 30-Day Behavioral Z-Score (metrics.http_queries_total) + GLOBAL_CONTEXT WHOIS Lifecycle Multiplier
// ARCHITECTURE: 2-STAGE HYBRID METRIC + GLOBAL_CONTEXT WHOIS DOMAIN LIFECYCLE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint HTTP Activity + 30-Day Baseline with event timestamp tracking
stage http_activity_anomalies {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $http_count = count(metadata.id)
    $latest_event_ts = max(metadata.event_timestamp.seconds)
    $b_avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $b_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z_score = ($http_count - $b_avg) / if($b_std > 0, $b_std, 1.0)

  condition:
    $http_count >= 5 and $b_days >= 5
}

// Root Stage: Join with GLOBAL_CONTEXT WHOIS Creation & Expiration Timestamps
$host = $http_activity_anomalies.host
$domain = $http_activity_anomalies.domain

$whois.graph.metadata.entity_type = "DOMAIN_NAME"
$whois.graph.metadata.vendor_name = "WHOIS"
$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
$whois.graph.entity.domain.name = $domain
$whois.graph.entity.domain.creation_time.seconds > 0

match:
  $host, $domain

outcome:
  $observed_http = max($http_activity_anomalies.http_count)
  $event_ts = max($http_activity_anomalies.latest_event_ts)
  $z_score = max($http_activity_anomalies.z_score)
  $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)
  $expiration_ts = max($whois.graph.entity.domain.expiration_time.seconds)

  // Event-relative domain age in seconds (fixes timestamp.current_seconds() retrohunt constraint)
  $domain_age_seconds = $event_ts - $creation_ts
  $domain_age_days = $domain_age_seconds / 86400

  // Lifecycle Risk Multiplier: 2.0x if newly registered (<= 30 days) or expired before event
  $is_newly_registered = if($domain_age_seconds >= 0 and $domain_age_seconds <= 2592000, 1, 0)
  $is_expired = if($expiration_ts > 0 and $expiration_ts < $event_ts, 1, 0)
  $lifecycle_multiplier = if($is_newly_registered = 1 or $is_expired = 1, 2.0, 1.0)

  $pos_z = if($z_score > 0, $z_score, 0.5)
  $fused_threat_score = $pos_z * $lifecycle_multiplier

condition:
  ($is_newly_registered = 1 or $is_expired = 1)
  and $fused_threat_score >= 3.0

order:
  $fused_threat_score desc
```

#### Query 5B: Same-Host Multi-Sector HTTP Failure & DNS Resolution Fusion (`secops-risk-metrics-multistage`)
Separates benign clicks on shortened URLs or SafeBrowsing warnings from active exploit/redirect chains by fusing 30-day anomalies in failed HTTP responses (`metrics.http_queries_fail`) and DNS query volume (`metrics.dns_queries_total`) on the same endpoint.

```yara
// ============================================================================
// Goal: Correlate browser redirect/exploit chains by fusing 30-day HTTP failure surges with DNS resolution surges on the same host.
// Statistical Model: 3-Stage Dual-Sector Euclidean Risk Fusion (D^2 = Z_http_fail^2 + Z_dns_total^2 >= 12.25)
// ARCHITECTURE: 3-STAGE SAME-ENTITY MULTI-SECTOR TELEMETRY FUSION
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Sector A — Failed HTTP Queries (UDM Source 1 of 2) ---
stage sector_a {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    network.http.response_code >= 400
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $a_obs = count(metadata.id)
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

### Scenario 6: Drive-By & File-Hosting Malware Downloads

* **Curated Detection Operational Focus**: Identifies hazardous file downloads and suspicious payload delivery through the browser.
* **How Multi-Stage UEBA Extends Coverage**: Combines 30-day host file execution baselines (`metrics.file_executions_total`) with 10-day `DERIVED_CONTEXT` fleet prevalence (`day_max <= 3`) and Markov 2-gram browser-to-shell process transition surprisal.

#### Query 6A: Hybrid 30-Day Endpoint Process Execution Baseline + Entity Context Graph Binary Prevalence (`secops-risk-metrics-multistage`)
Bridges browser download telemetry with endpoint execution by scoring per-(host, SHA256) process launches (`metrics.file_executions_total`) against a 30-day behavioral baseline and filtering via `DERIVED_CONTEXT` `FILE` prevalence (`rolling_max <= 3` hosts across the organization over 10 days).

```yara
// ============================================================================
// Goal: Detect execution of rare, newly downloaded binaries (10-day org prevalence <= 3 hosts) with anomalous per-host execution frequency.
// Statistical Model: Hybrid 30-Day Composite Metric Z-Score (metrics.file_executions_total) + DERIVED_CONTEXT 10-Day File Prevalence
// ARCHITECTURE: 2-STAGE HYBRID METRIC + DERIVED_CONTEXT FILE PREVALENCE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Endpoint Process Execution + 30-Day Composite Baseline per (host, event_type, sha256)
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

#### Query 6B: Markov 2-Gram Parent-to-Child Transition Surprisal for Browser-Spawned Processes (`secops-statistical-hunter`)
Detects drive-by exploits, trojanized installers, and ClickFix / FakeUpdates social-engineering chains where Chrome (or a binary launched from `Downloads` / `Temp`) spawns an unusual child interpreter (`powershell.exe`, `cmd.exe`, `mshta.exe`, `cscript.exe`, `sh`, `osascript`, `python3`) via **Markov 2-Gram conditional probability** $P(\text{Child} \mid \text{Parent})$ and **Information Surprisal** $I = -\ln P(\text{Child} \mid \text{Parent})$.

```yara
// ============================================================================
// Goal: Detect rare parent-to-child process execution transitions spawned by Chrome or user download directories via Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln(P(Child | Parent)))
// ============================================================================

// Stage 1: Parent Process Launch Baseline Frequency per host
stage parent_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.asset.hostname = $host
    $host != ""
    $parent = principal.process.file.full_path
    $parent != ""
    re.regex($parent, `(?i)(chrome|msedge|brave|firefox|Downloads|AppData\\Local\\Temp|/tmp/)`)

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
    re.regex($parent, `(?i)(chrome|msedge|brave|firefox|Downloads|AppData\\Local\\Temp|/tmp/)`)

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

---

---

### Scenario 7: Multi-User / Multi-Hash Download Campaigns & Coordinated Rollouts

* **Curated Detection Operational Focus**: Tracks high-risk browser download events and shared file hashes across endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Applies 3-stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z = Z_{\text{entity}} - Z_{\text{fleet}} \ge 3.0\sigma$) to separate targeted payload delivery from benign enterprise software updates.

#### Query 7A: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) on Chrome File Downloads (`secops-statistical-hunter`)
Eliminates both hash-polymorphism evasion and developer-rollout false positives by computing **Dual-Baseline Delta-Z** ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$) over Chrome download and content-transfer events per host. When the entire engineering fleet downloads a new tool simultaneously, $Z_{\text{fleet}}$ rises alongside $Z_{\text{personal}}$ and $\Delta Z \approx 0$; when a targeted host experiences a multi-file download surge while the rest of the fleet sits at baseline, $\Delta Z \ge 3.0\sigma$ isolates the targeted victim even if every file hash is unique.

```yara
// ============================================================================
// Goal: Isolate targeted host Chrome download surges while suppressing fleet-wide software rollouts via Dual-Baseline Delta-Z.
// Target Telemetry: UDM_EVENTS (Chrome Browser Cloud Management download/transfer events)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift))
// ============================================================================

// Stage 1: Individual Host Chrome Download Volume in daily windows
stage host_hourly_extract {
    metadata.product_name = "Chrome Browser Cloud Management"
    (
      metadata.product_event_type = "dangerousDownloadEvent"
      or metadata.product_event_type = "malwareTransferEvent"
      or metadata.product_event_type = "contentTransferEvent"
      or metadata.product_event_type = "unscannedFileEvent"
    )
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(about.file.sha256)
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

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active Chrome hosts in the same window
stage fleet_concurrent_baseline {
    $host = $host_hourly_extract.host
    $ws = $host_hourly_extract.window_start

  match:
    $ws by 1d

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
  $host, $ws by 1d

outcome:
  // 6 Standardized Evidence Pillars
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
  $z_score = $delta_z

condition:
  $baseline_active_samples >= 3
  and $fleet_prevalence >= 3
  and $observation_count >= 5
  and $delta_z >= 3.0

order:
  $delta_z desc
```

#### Query 7B: Leave-One-Out Discrete Poisson Rarity on User Dangerous & Unscanned Downloads (`secops-statistical-hunter`)
Defeats slow multi-hour download pacing (`>1h` between downloads) on endpoints with near-zero historical dangerous-download rates ($\lambda \le 0.5\text{/day}$) using **Leave-One-Out Discrete Poisson Deviance** ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$) over a 30-day window.

```yara
// ============================================================================
// Goal: Detect multi-hour paced dangerous or unscanned Chrome downloads on users/hosts with near-zero historical baseline rates.
// Target Telemetry: UDM_EVENTS (Chrome Browser Cloud Management dangerousDownloadEvent, malwareTransferEvent, unscannedFileEvent)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (Poisson Z^2 = (k - λ)^2 / λ >= 9.0)
// ============================================================================

// Stage 1: Daily dangerous/unscanned download counts per user and event type
stage daily_download_counts {
    metadata.product_name = "Chrome Browser Cloud Management"
    (
      metadata.product_event_type = "dangerousDownloadEvent"
      or metadata.product_event_type = "malwareTransferEvent"
      or metadata.product_event_type = "unscannedFileEvent"
    )
    principal.user.userid = $entity
    $entity != ""
    $evt_type = metadata.product_event_type
    $evt_type != ""

  match:
    $entity, $evt_type by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_files = count_distinct(about.file.full_path)
}

// Stage 2: Historical accumulation across active days per user and event type
stage baseline_accumulation {
    $entity = $daily_download_counts.entity
    $evt_type = $daily_download_counts.evt_type

  match:
    $entity, $evt_type

  outcome:
    $total_hist_runs = sum($daily_download_counts.daily_count)
    $active_days = count($daily_download_counts.window_start)
}

// Root Stage: Calculate Leave-One-Out Discrete Poisson Score and emit 6 Evidence Pillars
$entity = $daily_download_counts.entity
$evt_type = $daily_download_counts.evt_type
$entity = $baseline_accumulation.entity
$evt_type = $baseline_accumulation.evt_type

match:
  $entity, $evt_type by 1d

outcome:
  // Leave-one-out prior runs & Jeffreys-smoothed daily arrival rate over 29 prior calendar days
  $today_k = max($daily_download_counts.daily_count)
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
  $distinct_binaries = max($daily_download_counts.distinct_files)

  // Aggregate Poisson Squared Score (Z^2 = (k - λ)^2 / λ)
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 2
  and $baseline_mean > 0.0
  and $baseline_mean <= 0.5
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 9.0

order:
  $poisson_z_sq desc
```

---

---

### Scenario 8: Browser & Extension Data Exfiltration (Archives, Non-Corporate Accounts & Clipboard Pastes)

* **Curated Detection Operational Focus**: Monitors sensitive file uploads, clipboard pastes, and personal-account data transfers in the browser.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start and 30-day outbound byte baselines (`Option 1`) with Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) and 4-stage non-parametric 30-day MAD over browser upload events.

#### Query 8A: 4-Stage Non-Parametric MAD / Modified Z-Score ($M_Z > 3.5$) on Chrome Uploads & Clipboard Pastes (`secops-statistical-hunter`)
Removes all static file-extension, `target.url != /google/`, and `content_type != "text/plain"` exclusions, scoring each user's daily Chrome upload and clipboard paste activity (`sensitiveDataEvent` and `contentTransferEvent` with `WEB_CONTENT_UPLOAD`, `FILE_UPLOAD`, `CLIPBOARD_PASTE`, or `PAGE_PRINT`) against their own non-parametric **Median Absolute Deviation (MAD)** baseline ($M_Z > 3.5$).

```yara
// ============================================================================
// Goal: Detect anomalous spikes in Chrome file uploads and text/clipboard pastes (including text/plain and Google/non-Google destinations) using robust MAD scaling.
// Target Telemetry: UDM_EVENTS (Chrome Browser Cloud Management sensitiveDataEvent and contentTransferEvent)
// Statistical Model: 4-Stage Non-Parametric Median Absolute Deviation / Iglewicz-Hoaglin Modified Z-Score (M_Z > 3.5)
// ============================================================================

// Stage 1: Daily observed Chrome upload & clipboard paste volume per user
stage daily_stats {
    metadata.product_name = "Chrome Browser Cloud Management"
    (
      metadata.product_event_type = "sensitiveDataEvent"
      or metadata.product_event_type = "contentTransferEvent"
    )
    additional.fields["trigger_type"] != "FILE_DOWNLOAD"
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $daily_value = count(metadata.id)
    $distinct_sample_values = count_distinct(target.url)
    $sample_data = array_distinct(target.url)
}

// Stage 2: Baseline median of daily upload/paste events per user (active days only)
stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity

  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

// Stage 3: MAD, mean absolute deviation (MAD=0 fallback), and active day count per user
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

// Root Stage: Modified Z-Score per user-day and the 6 Core Evidence Pillars
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
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 5
  and $observation_count >= 10
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

#### Query 8B: 2-Stage Longitudinal CUSUM Behavioral Drift on Outbound Network Bytes (`secops-risk-metrics-multistage`)
Catches stealthy, low-and-slow background extension exfiltration (`fetch()` / `WebSocket` drips that stay below single-day $3\sigma$ thresholds and never use `chrome-extension://` URLs) by tracking the **Cumulative Sum (CUSUM)** of positive daily standardized deviations ($S_t^+ = \sum \max(0, Z_t - 0.5)$) against the endpoint's 30-day `metrics.network_bytes_outbound` baseline across multiple days.

```yara
// ============================================================================
// Goal: Detect low-and-slow background Chrome extension data exfiltration across multiple days via Longitudinal CUSUM drift on outbound bytes.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (k = 0.5 sigma slack, drift_days >= 2)
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Deviation Tracker for Outbound Network Bytes
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
  $z_score = $cusum_drift_score

condition:
  $active_days >= 5
  and $cusum_drift_score >= 3.0
  and $drift_days >= 2

order:
  $cusum_drift_score desc
```

---

---

### Scenario 9: Post-Compromise Workspace Hoarding & Cross-Sector Kill-Chain Progression

* **Curated Detection Operational Focus**: Correlates browser warnings with downstream Google Workspace download activity.
* **How Multi-Stage UEBA Extends Coverage**: Replaces static post-warning thresholds with a 3-Metric Multilevel Part-of-the-Whole Workspace Triad (`workspace_total_download_actions`, `workspace_chrome_os_File_download_upload_events`, `http_queries_total`).

#### Query 9A: 3-Metric Multilevel Part-of-the-Whole Workspace Activity Triad (`secops-risk-metrics-multistage`)
Fixes the dormant-user single-stage baseline constraints constraint using zero-safe denominators (`if($m2_p_std > 0, $m2_p_std, 1.0)`) and removes the brittle dependency on a prior SafeBrowsing alert `$d`. Simultaneously scores every user across the **Workspace Activity Triad** (`workspace_auth_attempts_total`, `workspace_total_download_actions`, and `workspace_total_change_actions`) against both their personal 30-day baseline and the enterprise fleet ($D_{\text{vs\_fleet}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Detect post-compromise Google Workspace Drive hoarding and account abuse across all users (including dormant 0-baseline users) via a 3-Metric Multilevel Triad.
// Statistical Model: Multilevel Triad Z-Scores (Personal + Fleet) & Composite Distance (D_vs_fleet^2 >= 12.25)
// ARCHITECTURE: 3-METRIC MULTILEVEL PART-OF-THE-WHOLE TRIAD DAG
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Enterprise Population Telemetry + 30-Day Baselines for the Workspace Activity Triad
stage all_entities {
    metadata.vendor_name = "Google Workspace"
    principal.user.userid = $user
    $user != ""

  match:
    $user by 1d

  outcome:
    // Metric 1: Workspace Auth Attempts Total (login, saml, token)
    $m1_obs = sum(if((metadata.product_name = "login" or metadata.product_name = "saml" or metadata.product_name = "token"), 1, 0))
    $m1_p_avg = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m1_p_std = max(metrics.workspace_auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // Metric 2: Workspace Total Download Actions (fixes the single-stage baseline constraints cold-start baseline constraint)
    $m2_obs = sum(if(metadata.product_event_type = "download", 1, 0))
    $m2_p_avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m2_p_std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // Metric 3: Workspace Total Change Actions
    $m3_obs = count(metadata.id)
    $m3_p_avg = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $m3_p_std = max(metrics.workspace_total_change_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))

    // In-Stage Personal Historical Z-Scores with zero-safe denominators (dormant-user safe)
    $z1_personal = ($m1_obs - $m1_p_avg) / if($m1_p_std > 0, $m1_p_std, 1.0)
    $z2_personal = ($m2_obs - $m2_p_avg) / if($m2_p_std > 0, $m2_p_std, 1.0)
    $z3_personal = ($m3_obs - $m3_p_avg) / if($m3_p_std > 0, $m3_p_std, 1.0)
}

// Stage 2: Enterprise Whole (Macro baseline across all active Workspace users)
stage enterprise_stats {
    $ws = $all_entities.window_start

  match:
    $ws by 1d

  outcome:
    $m1_fleet_avg = avg($all_entities.m1_obs)
    $m1_fleet_std = stddev($all_entities.m1_obs)

    $m2_fleet_avg = avg($all_entities.m2_obs)
    $m2_fleet_std = stddev($all_entities.m2_obs)

    $m3_fleet_avg = avg($all_entities.m3_obs)
    $m3_fleet_std = stddev($all_entities.m3_obs)

    $m1_fleet_div = if($m1_fleet_std > 0, $m1_fleet_std, 1.0)
    $m2_fleet_div = if($m2_fleet_std > 0, $m2_fleet_std, 1.0)
    $m3_fleet_div = if($m3_fleet_std > 0, $m3_fleet_std, 1.0)

    $fleet_size = count_distinct($all_entities.user)
}

// Root Stage: Multilevel Triad Scoring & Composite Distance
$user = $all_entities.user
$ws = $all_entities.window_start
$ws = $enterprise_stats.ws

match:
  $user, $ws by 1d

outcome:
  $m1_observed = max($all_entities.m1_obs)
  $m2_observed = max($all_entities.m2_obs)
  $m3_observed = max($all_entities.m3_obs)

  // 1. Personal Historical Z-Scores from Stage 1
  $z1_personal = max($all_entities.z1_personal)
  $z2_personal = max($all_entities.z2_personal)
  $z3_personal = max($all_entities.z3_personal)

  // 2. Enterprise Cross-Sectional Z-Scores ("Part of the Fleet")
  $z1_vs_enterprise = ($m1_observed - max($enterprise_stats.m1_fleet_avg)) / max($enterprise_stats.m1_fleet_div)
  $z2_vs_enterprise = ($m2_observed - max($enterprise_stats.m2_fleet_avg)) / max($enterprise_stats.m2_fleet_div)
  $z3_vs_enterprise = ($m3_observed - max($enterprise_stats.m3_fleet_avg)) / max($enterprise_stats.m3_fleet_div)

  // 3. Composite Threat Norm Across the Triad vs the Fleet
  $d_vs_fleet_sq = ($z1_vs_enterprise * $z1_vs_enterprise) + ($z2_vs_enterprise * $z2_vs_enterprise) + ($z3_vs_enterprise * $z3_vs_enterprise)
  $composite_threat_norm_sq = $d_vs_fleet_sq

condition:
  $d_vs_fleet_sq >= 12.25

order:
  $d_vs_fleet_sq desc
```

#### Query 9B: 4-Stage Roll-Up Endpoint Alert + Outbound Network Bytes Kill-Chain Fusion (`secops-risk-metrics-multistage`)
Correlates endpoint/browser security alerts (`metrics.alert_event_name_count` rolled up across `security_result.rule_name`) with 30-day outbound network exfiltration surges (`metrics.network_bytes_outbound`) on the same endpoint ($D^2 = Z_{\text{alert}}^2 + Z_{\text{bytes}}^2 \ge 12.25$).

```yara
// ============================================================================
// Goal: Fuse endpoint/browser security alert anomalies with outbound network byte surges on the same host to detect full kill-chain progression.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.alert_event_name_count + metrics.network_bytes_outbound, D^2 >= 12.25)
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

### Scenario 10: Capstone Multi-Scenario Browser & Endpoint Entity Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Individual scenario alerts evaluated independently within their respective telemetry domains.
* **How Multi-Stage UEBA Extends Coverage**: Correlates users and hosts matching $\ge 2$ distinct browser hunting scenarios within the same run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

#### Capstone Query: Multi-Scenario Chrome Endpoint & User Convergence via UDM Loopback (`secops-risk-metrics-multistage` + `PlaybookRunner`)

```yara
// ============================================================================
// Goal: Correlate Chrome Enterprise endpoints and users matching >= 2 distinct behavioral queries across Scenarios 1-9 via PlaybookRunner's native UDM loopback (PLAYBOOK_BEHAVIORAL_HUNT_MATCH).
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
    $rule_name != "chrome-enterprise-premium-ueba-hunting:capstone_cross_query_convergence"

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

### 3.1 Shannon Character-Class Entropy ($H(X)$ — Query 1A)
* **What it measures**: How mixed and unpredictable the characters inside a URL are across lowercase letters, uppercase letters, numbers, and symbols.
* **How multi-stage UEBA extends coverage**: Static rules look for literal `@` or `%40` email strings in phishing URLs. Attackers bypass this by Base64- or Hex-encoding the victim's email address in the URL.
* **How the math works**: Human-readable URLs (`/login/account/profile`) consist almost entirely of lowercase letters and slashes, yielding low entropy. Base64-encoded session tokens and encrypted AitM parameters mix uppercase, lowercase, digits, and delimiters evenly, driving $H(X) = -\sum p_i \log_2 p_i$ above `3.8` bits/character.

### 3.2 Zipfian Power-Law Rarity & Inverse Document Frequency (IDF — Query 2A)
* **What it measures**: How rare a Chrome extension is across the entire fleet (`adopter_hosts`) combined with how aggressively it executes on a single workstation (`local_intensity`).
* **How multi-stage UEBA extends coverage**: curated detection rules accidentally counts *events* instead of *hosts* (`$ext_count < 3`), suppressing any sideloaded extension that emits 3 or more telemetry events per hour.
* **How the math works**: By computing $\ln(N_{\text{total\_hosts}} / N_{\text{adopter\_hosts}}) + \ln(\text{exec\_count} + 1)$ across two stages, an extension installed on only 1 or 2 workstations that generates hundreds of API events rises to the very top of the hunt queue instead of suppressing itself.

### 3.3 Two-Part Zero-Inflated Hurdle Model (Query 2B)
* **What it measures**: First, whether an extension is rarely active on a host (Part 1: Bernoulli hurdle crossing, $\le 2$ active days); second, how large today's burst is compared to its active days (Part 2: positive-activity Z-score).
* **How multi-stage UEBA extends coverage**: Legitimate extensions installed from the Chrome Web Store that are later compromised via a malicious update have `extension_source = "WEBSTORE"` and bypass sideloading rules.
* **How the math works**: Separating *presence* from *magnitude* prevents zero-inflation distortion and amplifies dormant or newly installed extensions that suddenly wake up and execute a high-volume burst.

### 3.4 Poisson Dispersion & Fano Factor ($F = \sigma^2 / \mu$ — Query 3A)
* **What it measures**: How "clumpy" or bursty an extension's API calls (`COOKIES_GET_ALL_INFO`, `CAPTURE_VISIBLE_TAB`) are across hourly windows.
* **How multi-stage UEBA extends coverage**: Alerting on `$event_count = 1` triggers on every routine SSO check or single user screenshot.
* **How the math works**: Steady background processes follow a Poisson process where variance equals the mean ($F = \sigma^2 / \mu \approx 1.0$). When an infostealer extension harvests all browser cookies or captures rapid-fire tab screenshots during a user's banking/cloud session, the variance explodes relative to the 24-hour mean ($F \ge 4.0$).

### 3.5 Empirical Bayes Gamma-Poisson Credibility Shrinkage (Query 3B)
* **What it measures**: The ratio of a host's posterior arrival rate to its historical mean, weighted by how stable that host's history is.
* **How multi-stage UEBA extends coverage**: Noisy developer laptops with dozens of extensions generate erratic telemetry spikes that fool standard Z-scores.
* **How the math works**: Method-of-Moments estimates a Gamma prior ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$). Erratic hosts have high variance ($\sigma^2 \gg \mu$), shrinking their credibility weight, whereas a sudden spike on a rock-solid, predictable workstation produces an immediate posterior anomaly shift ($\ge 3.0\times$).

### 3.6 Coefficient of Variation for C2 Beaconing Jitter ($\text{CV} = \sigma / \mu$ — Query 4A)
* **What it measures**: The regularity of time gaps between an extension's outbound `REMOTE_HOST_CONTACTED_INFO` network callbacks.
* **How multi-stage UEBA extends coverage**: Static TLD lists miss `.com`/`.io` C2 domains, and the 12-hour `first_seen_time` cliff misses extensions that sleep for a day before beaconing.
* **How the math works**: Human web browsing produces erratic time gaps ($\text{CV} > 0.50$). Automated extension service-worker timers (`chrome.alarms` / `setInterval` with 15% random jitter) produce tightly clustered inter-arrival intervals where $\sigma / \mu \le 0.20$.

### 3.7 Hybrid 30-Day UEBA Metrics + Entity Context Graph Prevalence & WHOIS Lifecycle (Queries 4B, 5A, 6A)
* **What it measures**: Combines a 30-day pre-computed behavioral Z-score (`metrics.http_queries_total`, `metrics.file_executions_total`) with `DERIVED_CONTEXT` 10-day rolling organizational prevalence (`rolling_max <= 3`) or `GLOBAL_CONTEXT` WHOIS registration/expiration lifecycle.
* **How multi-stage UEBA extends coverage**: Hardcoded 12-hour and 24-hour `first_seen_time` cutoffs fail the moment an adversary ages a domain beyond 24 hours, and `timestamp.current_seconds()` breaks historical retrohunts.
* **How the math works**: Even if a domain was first seen 9 days ago, if $\le 3$ hosts in the entire enterprise have ever communicated with it (`rolling_max <= 3`) and the host exhibits a 30-day HTTP or process-execution anomaly, the rarity multiplier boosts the Z-score above the detection threshold.

### 3.8 Markov 2-Gram Parent-to-Child Surprisal ($I = -\ln P(\text{Child} \mid \text{Parent})$ — Query 6B)
* **What it measures**: How unexpected it is for Chrome (or a binary in `Downloads`/`Temp`) to spawn a specific child process on that endpoint.
* **How multi-stage UEBA extends coverage**: Download rules only see the browser event, not whether the user actually ran the downloaded file or pasted a ClickFix command.
* **How the math works**: Routine browser helper launches have $P(\text{Child} \mid \text{Parent}) \approx 1.0 \implies I \approx 0$. When `chrome.exe` or a downloaded installer spawns `powershell.exe`, `cmd.exe`, or `mshta.exe` for the first time, $P(\text{Child} \mid \text{Parent})$ is tiny and self-information surprisal $I = -\ln(P)$ spikes above `3.0`.

### 3.9 Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$ — Query 7A)
* **What it measures**: How much a single endpoint's download activity surged above its own history *after subtracting any simultaneous fleet-wide surge*.
* **How multi-stage UEBA extends coverage**: Cross-host hash matching (`$host_count > 1`) is defeated by per-victim polymorphic hashes and false-alerts on legitimate company-wide developer tool rollouts.
* **How the math works**: During a company-wide rollout, both $Z_{\text{personal}}$ and $Z_{\text{fleet}}$ rise together, so $\Delta Z \approx 0$. During a targeted polymorphic malware campaign affecting 1–3 victims, the fleet mean stays flat ($Z_{\text{fleet}} \approx 0$) while the targeted host's $\Delta Z$ exceeds `3.0`.

### 3.10 Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda$ — Query 7B)
* **What it measures**: The improbability of observing $k \ge 2$ dangerous or unscanned downloads in a day when the user's prior 29-day arrival rate $\lambda$ is near zero ($\le 0.5\text{/day}$).
* **How multi-stage UEBA extends coverage**: `c_chrome_multiple_suspicious_downloads_on_same_host` requires $>1$ download within a `1h` window; spacing downloads 90 minutes apart evades it.
* **How the math works**: By aggregating over a full day and computing leave-one-out $\lambda = (\text{prior\_runs} + 0.5) / 29.0$, even 2 or 3 paced downloads across an 8-hour workday yield $Z_{\text{Poisson}}^2 \ge 9.0$.

### 3.11 Non-Parametric Median Absolute Deviation (MAD / Modified Z-Score $M_Z$ — Query 8A)
* **What it measures**: How many robust standard deviations a user's daily Chrome uploads and clipboard pastes (`text/plain` included) sit above their historical median.
* **How multi-stage UEBA extends coverage**: Static exfiltration rules exclude `text/plain` clipboard pastes, ignore `target.url = /google/`, and only check 9 archive extensions.
* **How the math works**: Unlike mean and standard deviation—which are corrupted by a single massive upload day—the median and MAD have a 50% breakdown point. When MAD is zero (a user who uploads exactly the same small number of items every day), the Iglewicz-Hoaglin MeanAD fallback ($1.253314 \times \text{MeanAD}$) ensures a sudden clipboard/upload exfiltration burst is still scored accurately.

### 3.12 Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 8B)
* **What it measures**: The multi-day accumulation of small positive outbound network byte excesses ($Z_t - 0.5\sigma$) above a host's 30-day baseline.
* **How multi-stage UEBA extends coverage**: Malicious Chrome extensions that trickle stolen data out via background `fetch()` calls keep each day's volume at $1.2\sigma\text{–}1.8\sigma$, staying underneath single-day $3\sigma$ thresholds.
* **How the math works**: Subtracting the $0.5\sigma$ slack constant zeros out normal daily noise, while a steady $1.5\sigma$ daily exfiltration drip adds $+1.0$ to $S_t^+$ every day, crossing `cusum_drift_score >= 3.0` within 3 days.

### 3.13 Multi-Sector Euclidean Risk Fusion & Multilevel Triads ($D^2 = \sum Z_i^2$ — Queries 1B, 5B, 9A, 9B)
* **What it measures**: The combined multi-dimensional anomaly distance across two or three independent behavioral telemetry streams (e.g., Auth Failures + Auth Successes; HTTP Failures + DNS Queries; Workspace Auth + Downloads + Changes; Endpoint Alerts + Outbound Bytes).
* **How multi-stage UEBA extends coverage**: curated detection rules requires single-stage baseline constraints, which evaluates to **false** for any dormant user with 0 prior downloads ($\mu=0, \sigma=0$), and requires a prior SafeBrowsing alert.
* **How the math works**: Replacing single-stage baseline constraints with zero-safe variance floors (`if($std > 0, $std, 1.0)`) ensures dormant users with $\mu=0, \sigma=0$ who suddenly download 50 files achieve $Z = 50.0$ instead of being dropped. Combining rectified Z-scores across sectors via $D^2 = Z_A^2 + Z_B^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius) catches coordinated kill-chain activity even when each individual sector sits at a moderate $2.5\sigma$.
