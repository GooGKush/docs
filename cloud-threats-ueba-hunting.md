# Hunting Multi-Cloud, Kubernetes, Serverless & Identity Threats with Multi-Stage Behavioral Analytics in Google SecOps

*Authored by Greg Kushmerek — Google Security Operations (Chronicle SIEM & SOAR)*

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Cloud Threats** curated detection suite provides foundational coverage across AWS, Google Cloud (GCP), Microsoft Azure / Entra ID, and Kubernetes environments—monitoring high-risk IAM modifications, credential issuance, cloud storage exposure, serverless execution, and container control-plane tampering.

While point-in-time signatures and single-stage metric rules provide rapid alerting for known attack patterns and high-volume spikes, cloud control-plane activity naturally spans both ephemeral workload identities (cold-start service accounts and short-lived roles) and variable-cadence automation pipelines. This playbook extends coverage beyond the built-in constraints of single-stage cloud rules using **Option 1 Inline Piecewise Unification** (combining Two-Part Hurdle cold-start scoring with 30-day Z-score and non-parametric Median Absolute Deviation baselines in a single query) and **Option 3 UDM Loopback Capstone Convergence**.

### Complementary Detection Layers (3-Wave `A -> UDM -> B` & Capstone Architecture)
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical 3-Wave Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through a **3-Wave Execution Pipeline** orchestrated by `PlaybookRunner` in `agentic-ueba`:
  1. **Wave 1 — Consolidated Single-Shot Queries & Parallel Pairs (`Option 1` Piecewise Cold-Start + 30d Baselines)**: Executes all `by 1d` `metrics.*` baselines, inline Piecewise Cold-Start/Mature unified queries (`active_days <= 4` Hurdle vs. `active_days >= 5` 30-day Z-Score/MAD), and tightly pre-filtered statistical hunter queries concurrently. Every match is ingested into Chronicle UDM as a `GENERIC_EVENT` (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`) stamped with the cycle's unique `run_id` (`metadata.product_log_id`) and hierarchical rule tag (`:q[0-9]+_query_Xa`).
  2. **Wave 2 — Serial `A -> UDM -> B` Candidate-Gated Queries (`Option 3` Stage B Loopback)**: After `PlaybookRunner` flushes Wave 1 findings and verifies indexing via `verify_udm_run_indexed()`, Wave 2 `Query XB` queries read `Query XA`'s candidate entities in Stage 1 (`re.regex(security_result.rule_name, `:q[0-9]+_query_Xa`)`) to bound sub-day (`by 1h`) raw cadence, dispersion, and shrinkage calculations without risking 1M-row enterprise scan caps.
  3. **Wave 3 — Unified 3-Stage Capstone Convergence & Raw Telemetry Forensic Bridge (`Query 10`)**: Unions all upstream scenario tags (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-9]`)`), deduplicates per scenario in Stage 1, computes cross-scenario Euclidean L2 convergence (`$distinct_scenarios_matched >= 2` and `$capstone_threat_norm_sq >= 18.0`) in Stage 2, and pivots winning entities directly into raw endpoint, network, and cloud telemetry in Stage 3.

### Table 1: Scenario Coverage Matrix — Cloud Threats & Complementary UEBA Analytics

| Scenario & Threat Domain | Curated Detection Operational Focus | How Multi-Stage UEBA Extends Visibility | UEBA Models & Query IDs |
| :--- | :--- | :--- | :--- |
| **1. Cloud IAM Privilege Escalation, Service Account Impersonation & Role Chaining** | Point-in-time detection of privileged role attachments, service account key creation, and cross-account role assumptions across AWS, GCP, and Azure. | Measures Markov 2-gram API service-to-method transition surprisal ($I = -\ln P(\text{Method}\mid\text{Service}) \ge 3.5$) to catch rare privilege-escalation chains and fuses 30-day Cloud Resource Write and Authentication baselines ($D^2 \ge 12.25$). | `Query 1A` (Markov 2-Gram API Surprisal)<br>`Query 1B` (30d Cloud Write + Auth Fusion) |
| **2. Cloud Enumeration, Automated Recon & Permission Discovery** | Detects known cloud enumeration utilities, bursty `AccessDenied` errors, and reconnaissance API calls. | Applies Empirical Bayes Gamma-Poisson credibility shrinkage to normalize permission-denial bursts against fleet priors and fuses 30-day Cloud Read Failure and HTTP API volume baselines. | `Query 2A` (Empirical Bayes Shrinkage)<br>`Query 2B` (30d Read Fail + HTTP Fusion) |
| **3. Cloud Secrets Manager, Key Vault & Credential Harvesting** | Single-stage threshold and baseline checks for excessive secret reads or vault enumeration. | Unifies cold-start identities (`active_days <= 4` via Two-Part Hurdle) and mature identities (`active_days >= 5` via 4-stage non-parametric 30-day MAD) in a single piecewise query (`Option 1`), overcoming variance masking from scheduled CI/CD jobs. | `Query 3` (Piecewise Hurdle + 4-Stage 30d MAD) |
| **4. Cloud Storage, Snapshot & Workspace Data Exfiltration** | Monitors public bucket ACL changes, cross-account snapshot sharing, and large-volume object downloads. | Evaluates 3-Metric Multilevel Part-of-the-Whole Workspace/Cloud download triads and Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) coupled with 30-day outbound byte surges. | `Query 4A` (30d Multilevel Triad)<br>`Query 4B` (Producer-Consumer Inversion) |
| **5. Cloud Defense Evasion, Audit Log Tampering & Network Weakening** | Alerts on audit log disabling, firewall rule opening, and KMS key deletion across cloud providers. | Combines a Two-Part Zero-Inflated Hurdle model over destructive control-plane operations with 4-stage 30-day Cloud Resource Deletion baselines (`metrics.resource_deletion_total`). | `Query 5A` (Two-Part Control-Plane Hurdle)<br>`Query 5B` (30d Resource Deletion Baseline) |
| **6. Serverless (Cloud Run / Functions / Lambda), Compute VM & Cryptomining** | Tracks serverless function/job creation, IAM policy changes on functions, and known cryptomining indicators. | Unifies cold-start serverless identity activation with 30-day resource creation baselines (`Option 1`) and detects automated C2/stratum callback cadence via inter-arrival jitter ($\text{CV} \le 0.20$). | `Query 6A` (Piecewise Hurdle + 30d Creation)<br>`Query 6B` (Serverless C2 Jitter CV) |
| **7. Kubernetes (GKE / EKS / AKS) RBAC Abuse & Workload Masquerading** | Detects privileged pod creation, `kubectl exec` sessions, and cluster-admin role bindings. | Computes Zipfian power-law fleet rarity across Kubernetes API verb/resource tuples and Markov 2-gram container runtime parent-to-child process transition surprisal. | `Query 7A` (Kubernetes Zipfian Rarity)<br>`Query 7B` (Container Markov Surprisal) |
| **8. Cloud Identity Plane: MFA Fatigue, Token Anomalies & Account Takeover** | Flags logins from anomalous geographies, MFA push bombing, and unfamiliar device contexts. | Calculates geodesic haversine velocity ($\ge 900\text{ km/h}$) across consecutive cloud logins and circular 24-hour von Mises off-hours authentication divergence. | `Query 8A` (Geodesic Impossible Travel)<br>`Query 8B` (Circadian von Mises Clock) |
| **9. Cloud DNS Tunneling, C2 Beaconing & Infant Cloud Asset Egress** | Monitors outbound connections from cloud instances to known C2 domains or newly observed endpoints. | Combines multi-class character Shannon entropy on DNS queries with 30-day outbound network byte and DNS baselines. | `Query 9A` (DNS Shannon Entropy)<br>`Query 9B` (30d Cloud Asset Egress + DNS) |
| **10. Capstone Multi-Scenario Cloud Entity Convergence** | Individual cloud alerts evaluated within isolated control-plane or workload domains. | Correlates cloud identities matching $\ge 2$ distinct scenarios in the current playbook run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` validated via `run_id`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$). | `Capstone Query` (UDM Loopback $L_2$ Convergence) |

---

## 2. Scenario-by-Scenario Breakdown & Verified Multi-Stage Queries

### Scenario 1: Cloud IAM Privilege Escalation, Service Account Impersonation & Role Chaining

* **Curated Detection Operational Focus**: Point-in-time detection of privileged role attachments, service account key creation, and cross-account role assumptions across AWS, GCP, and Azure.
* **How Multi-Stage UEBA Extends Coverage**: Measures Markov 2-gram API service-to-method transition surprisal ($I = -\ln P(\text{Method}\mid\text{Service}) \ge 3.5$) to catch rare privilege-escalation chains and fuses 30-day Cloud Resource Write and Authentication baselines ($D^2 \ge 12.25$).

#### Query 1A: Markov 2-Gram Cloud Service-to-Method Transition Surprisal on IAM & Token Minting (`secops-statistical-hunter`)
Consolidates IAM privilege escalation and token impersonation across GCP, AWS, and Azure by modeling conditional transition probabilities $P(\text{Method} \mid \text{Service})$ and **Information Surprisal** $I = -\ln P(\text{Method} \mid \text{Service}) \ge 3.0$ per cloud principal over daily windows, independent of `gcloud` User-Agent strings or `10m` cliffs.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rare cloud IAM policy mutations, service account impersonation, and token/credential minting transitions per user via Markov 2-Gram Surprisal.
// Target Telemetry: UDM_EVENTS (USER_RESOURCE_UPDATE_PERMISSIONS, USER_RESOURCE_UPDATE_CONTENT, RESOURCE_PERMISSIONS_CHANGE, RESOURCE_WRITTEN)
// Statistical Model: Markov 2-Gram Transition Probability & Information Surprisal (I = -ln(P(Child | Parent)))
// ============================================================================

// Stage 1: Cloud Service (Parent State) Baseline Frequency per principal user
stage parent_baseline {
    (
      metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
      or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
      or metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"
      or metadata.event_type = "RESOURCE_WRITTEN"
    )
    principal.user.userid = $host
    $host != ""
    $parent = metadata.product_name
    $parent != ""

  match:
    $host, $parent by 1d

  outcome:
    $parent_total_launches = count(metadata.id)
}

// Stage 2: Specific IAM / Token API Method (Child State) Transition Frequency per (user, service, method)
stage child_transition {
    (
      metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
      or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
      or metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"
      or metadata.event_type = "RESOURCE_WRITTEN"
    )
    principal.user.userid = $host
    $host != ""
    $parent = metadata.product_name
    $child = metadata.product_event_type
    $parent != ""
    $child != ""
    re.regex($child, `(?i)(SetIamPolicy|GenerateAccessToken|GenerateIdToken|SignJwt|SignBlob|CreateServiceAccountKey|AssumeRole|UpdateAssumeRolePolicy|PutUserPolicy|PutRolePolicy|AttachRolePolicy|CreateAccessKey|AddServicePrincipalCredentials|AddMemberToRole)`)

  match:
    $host, $parent, $child by 1d

  outcome:
    $transition_count = count(metadata.id)
    $sample_command = array_distinct(target.resource.name)
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

  // 2. Markov Transition Probability: P(Child | Parent) = Count(Service -> Method) / Count(Service)
  $transition_prob = $safe_trans / $safe_parent

  // 3. Information Surprisal: I = -ln(P) = ln(Parent) - ln(Transition)
  $log_parent = math.log($safe_parent)
  $log_trans = math.log($safe_trans)
  $surprisal_score = $log_parent - $log_trans

  // 4. Rare Sequence Multiplier (Amplifies singleton/doubleton IAM/token transitions)
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

#### Query 1B: 4-Stage Roll-Up Cloud Resource Write + Authentication Success Fusion (`secops-risk-metrics-multistage`)
Rolls up 30-day composite `metrics.resource_written_success` (capturing `RESOURCE_WRITTEN` and `USER_RESOURCE_UPDATE_CONTENT` across all cloud products/vendors) and fuses it with 30-day `metrics.auth_attempts_success` ($D^2 = Z_{\text{write}}^2 + Z_{\text{auth}}^2 \ge 12.25$) to detect principals combining anomalous control-plane writes with anomalous authentication/role-assumption volume.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fuse 30-day cloud resource/IAM write anomalies (metrics.resource_written_success) with authentication surges (metrics.auth_attempts_success) per principal.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (D^2 = Z_write^2 + Z_auth^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A (resource_written_success) is a composite-only roll-up sector; Z_a is the largest per-(product, vendor) Z for the user.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2): one row per user and (product_name, vendor_name) ---
stage sector_a_detail {
    (metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT")
    security_result.action = "ALLOW"
    principal.user.userid = $entity
    $entity != ""
    metadata.product_name = $metadata_product_name
    $metadata_product_name != ""
    metadata.vendor_name = $metadata_vendor_name
    $metadata_vendor_name != ""

  match:
    $entity, $metadata_product_name, $metadata_vendor_name by 1d

  outcome:
    $d_obs = count(metadata.id)
    $d_avg = max(metrics.resource_written_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_std = max(metrics.resource_written_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_days = max(metrics.resource_written_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_z_raw = ($d_obs - $d_avg) / if($d_std > 0, $d_std, 1.0)
    $d_z = if($d_days >= 5 and $d_z_raw > 0, $d_z_raw, 0.0)
    $d_hot = if($d_days >= 5 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_days = 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per user ---
stage sector_a {
    $entity = $sector_a_detail.entity
    $ws = $sector_a_detail.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.metadata_product_name)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a = max($sector_a_detail.d_z)
}

// --- STAGE 3: Sector B — Authentication Successes (UDM Source 2 of 2) ---
stage sector_b {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
    $b_avg = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $b_std = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
    $b_days = max(metrics.auth_attempts_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid
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

### Scenario 2: Cloud Hacktools, Automated Recon & Permission Brute-Forcing

* **Curated Detection Operational Focus**: Detects known cloud enumeration utilities, bursty `AccessDenied` errors, and reconnaissance API calls.
* **How Multi-Stage UEBA Extends Coverage**: Applies Empirical Bayes Gamma-Poisson credibility shrinkage to normalize permission-denial bursts against fleet priors and fuses 30-day Cloud Read Failure and HTTP API volume baselines.

#### Query 2A: 4-Stage Roll-Up Cloud Resource Read Failure + HTTP API Volume Fusion (`secops-risk-metrics-multistage`)
Directly replaces curated detection rules by rolling up 30-day `metrics.resource_read_fail` across all cloud products/vendors and fusing it with 30-day `metrics.http_queries_total` per user ($D^2 \ge 12.25$), without the single-stage single-stage baseline constraints filter.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect cloud permission enumeration and brute-force discovery by fusing 30-day resource_read_fail surges with HTTP API volume per user.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.resource_read_fail + metrics.http_queries_total, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A (resource_read_fail) is a composite-only roll-up sector; Z_a is the largest per-(product, vendor) Z for the user.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2): one row per user and (product_name, vendor_name) ---
stage sector_a_detail {
    (metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS")
    not security_result.action = "ALLOW"
    principal.user.userid = $entity
    $entity != ""
    metadata.product_name = $metadata_product_name
    $metadata_product_name != ""
    metadata.vendor_name = $metadata_vendor_name
    $metadata_vendor_name != ""

  match:
    $entity, $metadata_product_name, $metadata_vendor_name by 1d

  outcome:
    $d_obs = count(metadata.id)
    $d_avg = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_std = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_days = max(metrics.resource_read_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_z_raw = ($d_obs - $d_avg) / if($d_std > 0, $d_std, 1.0)
    $d_z = if($d_days >= 5 and $d_z_raw > 0, $d_z_raw, 0.0)
    $d_hot = if($d_days >= 5 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_days = 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per user ---
stage sector_a {
    $entity = $sector_a_detail.entity
    $ws = $sector_a_detail.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.metadata_product_name)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a = max($sector_a_detail.d_z)
}

// --- STAGE 3: Sector B — Total HTTP/API Queries (UDM Source 2 of 2) ---
stage sector_b {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = count(metadata.id)
    $b_avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $b_std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
    $b_days = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid
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

#### Query 2B: 4-Stage UDM-Gated Empirical Bayes Gamma-Poisson Shrinkage on Cloud Discovery & Permission Bursts (`secops-statistical-hunter`)
Evaluates hourly cloud `RESOURCE_READ` and `USER_RESOURCE_ACCESS` discovery bursts via **Poisson-Gamma Bayesian Conjugate Updating** strictly on candidate cloud identities surfaced by `Query 2A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED EMPIRICAL BAYES GAMMA-POISSON SHRINKAGE PIPELINE
// Goal: Detect custom-User-Agent cloud reconnaissance and permission brute-forcing on candidate identities from Query 2A (strictly gated by Query 2A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson-Gamma Bayesian Conjugate Updating
// ============================================================================

stage stage1_upstream_2a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_2a`)
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_2a_z = max(security_result.confidence_score)
}

stage host_hourly_activity {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
    )
    $host = strings.coalesce(principal.user.userid, principal.asset.hostname, principal.hostname, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_exts = count_distinct(metadata.product_event_type)
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

$host = $stage1_upstream_2a_candidates.host
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start

match:
  $host, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_2a_candidates.upstream_2a_z)
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

### Scenario 3: Cloud Secrets Manager, Key Vault & Credential Harvesting

* **Curated Detection Operational Focus**: Single-stage threshold and baseline checks for excessive secret reads or vault enumeration.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start identities (`active_days <= 4` via Two-Part Hurdle) and mature identities (`active_days >= 5` via 4-stage non-parametric 30-day MAD) in a single piecewise query (`Option 1`), overcoming variance masking from scheduled CI/CD jobs.

#### Query 3: Unified Cold-Start Hurdle & 30-Day Robust MAD on Multi-Cloud Secret & Resource Reads (`secops-risk-metrics-multistage` + `secops-statistical-hunter`)
Rather than splitting secret and resource harvesting into two disconnected queries (one for cold-start identities with $< 5$ active days and another for mature identities with $\ge 5$ active days), this unified 4-stage pipeline evaluates **both statistical regimes inside a single DAG** via an in-query piecewise switch (`$unified_threat_score = if($raw_active_days <= 4, $hurdle_threat_score, $modified_z)`):
- **Regime 1 — Cold-Start & Dormant Identities ($\text{raw active days} \le 4$)**: Directly fixes the single-stage baseline constraints coverage considerations in curated detection rules by applying a $3.0\times$ Bernoulli Hurdle Crossing multiplier weighted by log read volume and distinct secret/resource breadth (`$distinct_secrets`).
- **Regime 2 — Mature Active Identities ($\text{raw active days} \ge 5$)**: Replaces the single-stage single-stage baseline constraints and single-stage baseline constraints gates with a 4-stage Iglewicz-Hoaglin **Modified Z-Score ($M_Z$)** over 30-day Median Absolute Deviation (MAD), cross-checked against 30-day `metrics.resource_read_success`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Unify cold-start secret/resource harvesting (<= 4 active days via Two-Part Hurdle) and mature baseline anomalies (>= 5 active days via 30-Day MAD + metrics.resource_read_success) in a single 4-stage pipeline.
// Statistical Model: Option 1 Piecewise Two-Part Hurdle + 4-Stage Iglewicz-Hoaglin Modified Z-Score (MAD) & Classical 30d metrics.resource_read_success
// ARCHITECTURE: 4-STAGE ALL-REGIME PIECEWISE HURDLE & ROBUST MODIFIED Z-SCORE (TRUE MEDIAN ABSOLUTE DEVIATION)
// Skill: secops-risk-metrics-multistage + secops-statistical-hunter
// ============================================================================

// Stage 1: Telemetry Extraction, Secret/Resource Breadth & Pre-Computed 30-Day Baseline Lookup per (user, product, vendor)
stage stage1_extract {
    (metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS")
    security_result.action = "ALLOW"
    principal.user.userid = $entity
    metadata.product_name = $product
    metadata.vendor_name = $vendor
    $entity != ""
    $product != ""
    $vendor != ""

  match:
    $entity, $product, $vendor by 1d

  outcome:
    $observed_val = count(metadata.id)
    $observed_events = count(metadata.id)
    $distinct_secrets = count_distinct(target.resource.name)

    $historical_avg = max(metrics.resource_read_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $historical_stddev = max(metrics.resource_read_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $historical_active_days = max(metrics.resource_read_success(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
}

// Stage 2: Median of daily cloud resource/secret reads and active-day count per (user, product, vendor)
stage mad_center {
    $entity = $stage1_extract.entity
    $product = $stage1_extract.product
    $vendor = $stage1_extract.vendor

  match:
    $entity, $product, $vendor

  outcome:
    $median_val = window.median($stage1_extract.observed_val, false)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

// Stage 3: MAD and Mean Absolute Deviation (MAD=0 fallback)
stage mad_spread {
    $entity = $stage1_extract.entity
    $product = $stage1_extract.product
    $vendor = $stage1_extract.vendor
    $entity = $mad_center.entity
    $product = $mad_center.product
    $vendor = $mad_center.vendor

  match:
    $entity, $product, $vendor

  outcome:
    $mad = window.median(math.abs($stage1_extract.observed_val - $mad_center.median_val), false)
    $mean_abs_dev = avg(math.abs($stage1_extract.observed_val - $mad_center.median_val))
    $median_val = max($mad_center.median_val)
    $raw_active_days = max($mad_center.raw_active_days)
}

// Root Stage: Piecewise All-Regime Scoring (Cold-Start Hurdle for <= 4 days; Robust 30d MAD for >= 5 days)
$entity = $stage1_extract.entity
$product = $stage1_extract.product
$vendor = $stage1_extract.vendor
$entity = $mad_spread.entity
$product = $mad_spread.product
$vendor = $mad_spread.vendor
$ws = $stage1_extract.window_start

match:
  $entity, $product, $vendor, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $distinct_secrets = max($stage1_extract.distinct_secrets)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $median_val = max($mad_spread.median_val)
  $mad = max($mad_spread.mad)
  $mean_abs_dev = max($mad_spread.mean_abs_dev)
  $raw_active_days = max($mad_spread.raw_active_days)

  // 2. Mature Regime (>= 5 active days): Robust scale with Iglewicz-Hoaglin MAD=0 fallback and flat-history floor
  $scale_from_mad = $mad / 0.6745
  $scale_from_meanad = $mean_abs_dev * 1.253314
  $robust_scale = if($mad > 0, $scale_from_mad, $scale_from_meanad)
  $median_floor = $median_val * 0.05 + 1.0
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, $median_floor)
  $modified_z = ($observed - $median_val) / $safe_robust_scale

  // 3. Cold-Start / Dormant Regime (<= 4 active days): Two-Part Hurdle Rarity Boost + Secret Breadth
  $safe_secrets = if($distinct_secrets > 0, $distinct_secrets, 1)
  $hurdle_threat_score = math.log($observed + 1.0) * $safe_secrets

  // 4. Option 1 Piecewise Regime Switch: Seamless coverage across cold-start and mature identities
  $unified_threat_score = if($raw_active_days <= 4, $hurdle_threat_score, $modified_z)

condition:
  $observed >= 3
  and (
    ($raw_active_days <= 4 and $distinct_secrets >= 2 and $unified_threat_score >= 3.5)
    or ($raw_active_days >= 5 and $observed >= 10 and $unified_threat_score >= 3.5)
  )

order:
  $unified_threat_score desc
```

---

---

### Scenario 4: Cloud Storage, Snapshot & Workspace/M365 Data Exfiltration

* **Curated Detection Operational Focus**: Monitors public bucket ACL changes, cross-account snapshot sharing, and large-volume object downloads.
* **How Multi-Stage UEBA Extends Coverage**: Evaluates 3-Metric Multilevel Part-of-the-Whole Workspace/Cloud download triads and Producer-Consumer Byte Ratio inversion ($\rho \ge 0.80$) coupled with 30-day outbound byte surges.

#### Query 4A: 3-Stage Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z \ge 3.0\sigma$) on Cloud Storage & Snapshot Operations (`secops-statistical-hunter`)
Catches both targeted snapshot/ACL sharing (including sharing with specific external account IDs) and bulk object reads (`GetObject`, `storage.objects.get`, `ModifySnapshotAttribute`, `ModifyDBSnapshotAttribute`) by computing **Dual-Baseline Fleet-Normalized Delta-Z** ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}}) \ge 3.0\sigma$), automatically suppressing scheduled fleet-wide backup waves.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Isolate targeted cloud storage, bucket ACL, and snapshot sharing/exfiltration surges while suppressing scheduled fleet-wide backup waves via Dual-Baseline Delta-Z.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ, USER_RESOURCE_ACCESS, USER_RESOURCE_UPDATE_PERMISSIONS on Cloud Storage/S3/Snapshots)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - max(0, Z_Fleet_Shift))
// ============================================================================

// Stage 1: Individual Principal Cloud Storage & Snapshot Volume in daily windows
stage host_hourly_extract {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
      or metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
    )
    re.regex(metadata.product_event_type, `(?i)(storage\.objects\.get|storage\.objects\.list|storage\.buckets\.setIamPolicy|GetObject|CopyObject|PutBucketPolicy|PutBucketAcl|ModifySnapshotAttribute|ModifyDBSnapshotAttribute|ModifyImageAttribute|BlobGet)`)
    principal.user.userid = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.resource.name)
}

// Stage 2: Individual Principal Personal Historical Baseline (Temporal Baseline)
stage host_personal_baseline {
    $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active principals in the same window
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
  and $fleet_prevalence >= 2
  and $observation_count >= 5
  and $delta_z >= 3.0

order:
  $delta_z desc
```

#### Query 4B: 2-Stage Longitudinal CUSUM Behavioral Drift on Outbound Cloud Network Bytes (`secops-risk-metrics-multistage`)
Catches low-and-slow multi-day cloud storage/database exfiltration (`rclone --bwlimit`, throttled S3/GCS syncs, or multi-day Drive/SharePoint exports that stay below single-day $6\sigma$ thresholds) by tracking cumulative positive drift ($S_t^+ = \sum \max(0, Z_t - 0.5) \ge 3.0$ across $\ge 2$ days) on 30-day `metrics.network_bytes_outbound`.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect multi-day low-and-slow cloud storage or database exfiltration via Longitudinal CUSUM drift on 30-day outbound network bytes.
// Statistical Model: 2-Stage Longitudinal CUSUM Behavioral Drift (k = 0.5 sigma slack, drift_days >= 2)
// ARCHITECTURE: 2-STAGE LONGITUDINAL CUSUM BEHAVIORAL DRIFT PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Daily Standardized Deviation Tracker for Outbound Network Bytes per host/workload
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

### Scenario 5: Cloud Defense Evasion, Audit Log Tampering & Network Weakening

* **Curated Detection Operational Focus**: Alerts on audit log disabling, firewall rule opening, and KMS key deletion across cloud providers.
* **How Multi-Stage UEBA Extends Coverage**: Combines a Two-Part Zero-Inflated Hurdle model over destructive control-plane operations with 4-stage 30-day Cloud Resource Deletion baselines (`metrics.resource_deletion_total`).

#### Query 5A: 2-Stage Dual-Branch Cloud Repository Scope & 4-Family CRUD Outlier Pipeline (`secops-risk-metrics-multistage`)
Evaluates every cloud service account or IAM role across all four 30-day CRUD metric families (`metrics.resource_read_total`, `metrics.resource_written_total`, `metrics.resource_deletion_total`, `metrics.resource_creation_total`) plus **Caller Origin IP** (`principal.ip`) to isolate service accounts modifying or deleting cloud resources out of their historical scope or from a novel IP.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect cloud service accounts and IAM roles modifying, deleting, or accessing cloud resources out of their 30-day behavioral scope or from an anomalous caller IP.
// Statistical Model: 2-Stage Dual-Branch 4-Family Cloud CRUD & Caller Origin IP Isolation
// ARCHITECTURE: 2-STAGE DUAL-BRANCH CLOUD REPOSITORY SCOPE & ORIGIN OUTLIER PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// --- STAGE 1: Dynamic Cloud Repository Extraction & Pre-Computed 4-Family CRUD Baseline Lookups ---
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

    $sa != ""
    $sa = /gserviceaccount\.com|arn:aws:iam::|arn:aws:sts::|ServicePrincipal/ nocase
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
    // 1b. Destination Resource Write, Deletion & Creation Baselines
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

#### Query 5B: 4-Stage UDM-Gated Poisson Fano Factor Burst Clustering on Cloud Storage & Database Deletions (`secops-statistical-hunter`)
Evaluates hourly cloud resource and object deletion burstiness ($F = \sigma^2 / \mu \ge 4.0$) strictly on candidate cloud identities surfaced by `Query 5A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED POISSON FANO FACTOR BURST DISPERSION PIPELINE
// Goal: Detect rapid cloud storage/database mass deletion & ransomware wiping bursts on candidate identities from Query 5A (strictly gated by Query 5A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Poisson Index of Dispersion (Fano Factor F = sigma^2 / mu >= 4.0)
// ============================================================================

stage stage1_upstream_5a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_5a`)
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""
    $run_id != ""

  match:
    $host

  outcome:
    $upstream_5a_z = max(security_result.confidence_score)
}

stage hourly_bursts {
    (
      metadata.event_type = "RESOURCE_DELETION"
      or metadata.event_type = "USER_RESOURCE_DELETION"
      or metadata.event_type = "RESOURCE_WRITTEN"
    )
    $host = strings.coalesce(principal.asset.hostname, principal.hostname, principal.user.userid, principal.ip[0])
    $host != ""

  match:
    $host by 1h

  outcome:
    $event_count = count(metadata.id)
    $distinct_targets = count_distinct(target.resource.name)
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

$host = $stage1_upstream_5a_candidates.host
$host = $host_dispersion.host

match:
  $host

outcome:
  $upstream_z = max($stage1_upstream_5a_candidates.upstream_5a_z)
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
  and $peak_burst >= 5
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

---

---

### Scenario 6: Serverless (Cloud Run / Functions / Lambda), Compute VM & Cryptomining

* **Curated Detection Operational Focus**: Tracks serverless function/job creation, IAM policy changes on functions, and known cryptomining indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start serverless identity activation with 30-day resource creation baselines (`Option 1`) and detects automated C2/stratum callback cadence via inter-arrival jitter ($\text{CV} \le 0.20$).

#### Query 6A: Leave-One-Out Discrete Poisson Rarity on Serverless & Compute Resource Creation (`secops-statistical-hunter`)
Directly implements the UEBA analytic requested in `` and replaces curated detection rules by computing **Leave-One-Out Discrete Poisson Arrival Rarity** ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$) over daily `RESOURCE_CREATION` / `USER_RESOURCE_CREATION` events (`CreateServiceAccountKey`, `Jobs.CreateJob`, `Services.CreateService`, `CreateFunction`, `RunInstances`, `compute.instances.insert`). When a serverless identity with 0 prior creations ($\lambda = 0.5/29 \approx 0.0172$) creates even **1** service account key or job ($k = 1$), $Z_{\text{Poisson}}^2 = (1 - 0.0172)^2 / 0.0172 = 56.0 \ge 9.0$, catching the single-key creation that `$event_count > 1` missed!

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Fulfill and replace curated detection rules by detecting rare Serverless (Cloud Run/Functions/Lambda) and VM resource/key creations (including k >= 1 on zero-prior identities) via Leave-One-Out Poisson Rarity.
// Target Telemetry: UDM_EVENTS (RESOURCE_CREATION and USER_RESOURCE_CREATION)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (Poisson Z^2 = (k - λ)^2 / λ >= 9.0)
// ============================================================================

// Stage 1: Daily resource/key creation counts per principal and API method
stage daily_download_counts {
    (
      metadata.event_type = "RESOURCE_CREATION"
      or metadata.event_type = "USER_RESOURCE_CREATION"
    )
    principal.user.userid = $entity
    $entity != ""
    $evt_type = metadata.product_event_type
    $evt_type != ""

  match:
    $entity, $evt_type by 1d

  outcome:
    $daily_count = count(metadata.id)
    $distinct_files = count_distinct(target.resource.name)
}

// Stage 2: Historical accumulation across active days per principal and API method
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
  and $observation_count >= 1
  and $baseline_mean > 0.0
  and $baseline_mean <= 0.5
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 9.0

order:
  $poisson_z_sq desc
```

#### Query 6B: 4-Stage Roll-Up Cloud Resource Creation + Outbound Network Bytes Fusion (`secops-risk-metrics-multistage`)
Replaces curated detection rules by rolling up 30-day `metrics.resource_creation_total` across cloud products/vendors and fusing it with 30-day `metrics.network_bytes_outbound` per user ($D^2 \ge 12.25$), catching cryptomining spin-ups and rogue serverless deployments that generate immediate network traffic.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Replace curated detection rules by fusing 30-day cloud resource creation surges with outbound network byte anomalies.
// Statistical Model: 4-Stage Roll-Up Sector Fusion (metrics.resource_creation_total + metrics.network_bytes_outbound, D^2 >= 12.25)
// ARCHITECTURE: 4-STAGE ROLL-UP SECTOR FUSION (COMPOSITE-ONLY METRIC + ENTITY-KEYED METRIC)
// Skill: secops-risk-metrics-multistage
// ADVISORY: Sector A (resource_creation_total) is a composite-only roll-up sector; Z_a is the largest per-(product, vendor) Z for the user.
// ============================================================================

// --- STAGE 1: Sector A detail (UDM Source 1 of 2): one row per user and (product_name, vendor_name) ---
stage sector_a_detail {
    (metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION")
    principal.user.userid = $entity
    $entity != ""
    metadata.product_name = $metadata_product_name
    $metadata_product_name != ""
    metadata.vendor_name = $metadata_vendor_name
    $metadata_vendor_name != ""

  match:
    $entity, $metadata_product_name, $metadata_vendor_name by 1d

  outcome:
    $d_obs = count(metadata.id)
    $d_avg = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_std = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_days = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid,
        metadata.product_name: metadata.product_name,
        metadata.vendor_name: metadata.vendor_name
    ))
    $d_z_raw = ($d_obs - $d_avg) / if($d_std > 0, $d_std, 1.0)
    $d_z = if($d_days >= 5 and $d_z_raw > 0, $d_z_raw, 0.0)
    $d_hot = if($d_days >= 5 and $d_z_raw >= 3.0, 1, 0)
    $d_novel = if($d_days = 0, 1, 0)
}

// --- STAGE 2: Sector A roll-up (stage-to-stage): one row per user ---
stage sector_a {
    $entity = $sector_a_detail.entity
    $ws = $sector_a_detail.window_start

  match:
    $entity, $ws by 1d

  outcome:
    $a_obs = sum($sector_a_detail.d_obs)
    $a_keys = count_distinct($sector_a_detail.metadata_product_name)
    $a_hot_keys = sum($sector_a_detail.d_hot)
    $a_novel_keys = sum($sector_a_detail.d_novel)
    $a_days = max($sector_a_detail.d_days)
    $z_a = max($sector_a_detail.d_z)
}

// --- STAGE 3: Sector B — Outbound Network Bytes (UDM Source 2 of 2) ---
stage sector_b {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $b_obs = sum(network.sent_bytes)
    $b_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $b_std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
    $b_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.user.userid: principal.user.userid
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

### Scenario 7: Kubernetes (GKE / EKS / AKS) RBAC Abuse & Workload Masquerading

* **Curated Detection Operational Focus**: Detects privileged pod creation, `kubectl exec` sessions, and cluster-admin role bindings.
* **How Multi-Stage UEBA Extends Coverage**: Computes Zipfian power-law fleet rarity across Kubernetes API verb/resource tuples and Markov 2-gram container runtime parent-to-child process transition surprisal.

#### Query 7A: Zipfian Power-Law Fleet Rarity & Inverse Principal Frequency on Kubernetes Workload & RBAC Creations (`secops-statistical-hunter`)
Removes the `kube-system` and `/\/gke\-/` prefix coverage considerations by ranking all Kubernetes pod, workload, ClusterRoleBinding, RoleBinding, and token creation targets across **all namespaces** using **Zipfian Power-Law Rarity & Inverse Principal Frequency** ($\text{zipf rarity score} \ge 4.0$, $\le 2$ principals).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect rogue Kubernetes pod deployments, RBAC bindings, and masquerading workloads across all namespaces (GKE, EKS, AKS) via Zipfian Fleet Rarity.
// Target Telemetry: UDM_EVENTS (Kubernetes pod, workload, RBAC, and serviceaccount token creation events)
// Statistical Model: Zipf-Mandelbrot Heavy-Tail Frequency Distribution & Inverse Document Frequency (IDF) Surprisal
// ============================================================================

// Stage 1: Per-principal daily Kubernetes workload & RBAC creation volume across all namespaces
stage host_extension_freq {
    re.regex(metadata.product_event_type, `(?i)(io\.k8s\.core\.v1\.pods\.create|io\.k8s\.apps\.v1\.daemonsets\.create|io\.k8s\.apps\.v1\.deployments\.create|io\.k8s\.rbac\.authorization\.k8s\.io\.v1\.clusterrolebindings\.create|io\.k8s\.rbac\.authorization\.k8s\.io\.v1\.rolebindings\.create|io\.k8s\.core\.v1\.serviceaccounts\.token\.create|io\.k8s\.certificates\.v1\.certificatesigningrequests\.create)`)
    principal.user.userid = $host
    $host != ""
    $ext_id = target.resource.name
    $ext_id != ""

  match:
    $host, $ext_id by 1d

  outcome:
    $exec_count = count(metadata.id)
    $sample_actions = array_distinct(metadata.product_event_type)
}

// Stage 2: Cluster-wide principal adoption breadth per K8s target resource (IDF denominator)
stage extension_fleet_breadth {
    $ext_id = $host_extension_freq.ext_id

  match:
    $ext_id by 1d

  outcome:
    $adopter_hosts = count_distinct($host_extension_freq.host)
    $fleet_total_execs = sum($host_extension_freq.exec_count)
}

// Stage 3: Total active Kubernetes principals in the window (Population size N)
stage fleet_total_hosts {
    $ws = $host_extension_freq.window_start

  match:
    $ws by 1d

  outcome:
    $total_hosts = count_distinct($host_extension_freq.host)
}

// Root Stage: Zipfian Rarity Surprisal & Intensity Scoring
$host = $host_extension_freq.host
$ext_id = $host_extension_freq.ext_id
$ext_id = $extension_fleet_breadth.ext_id
$ws = $host_extension_freq.window_start
$ws = $fleet_total_hosts.ws

match:
  $host, $ext_id by 1d

outcome:
  $host_execs = max($host_extension_freq.exec_count)
  $adopters = max($extension_fleet_breadth.adopter_hosts)
  $fleet_execs = max($extension_fleet_breadth.fleet_total_execs)
  $n_hosts = max($fleet_total_hosts.total_hosts)
  $sample_commands = array_distinct($host_extension_freq.sample_actions)

  // 1. Safe denominators
  $safe_adopters = if($adopters > 0, $adopters, 1)
  $safe_n_hosts = if($n_hosts > 0, $n_hosts, 1)

  // 2. Inverse Principal Frequency (IDF): ln(Total_Principals / Adopter_Principals)
  $idf_surprisal = math.log($safe_n_hosts) - math.log($safe_adopters)

  // 3. Zipfian Rarity Score: rewards high local activity on a cluster-rare K8s resource/binding
  $local_intensity = math.log($host_execs + 1)
  $singleton_boost = if($adopters = 1, 1.5, 1.0)
  $zipf_rarity_score = ($idf_surprisal + $local_intensity) * $singleton_boost

  // 6 Core Evidence Pillars
  $observation_count = $host_execs
  $baseline_active_samples = $n_hosts
  $baseline_mean = $safe_adopters / $safe_n_hosts
  $baseline_dispersion = $idf_surprisal
  $fleet_prevalence = $adopters
  $distinct_binaries = 1

condition:
  $fleet_prevalence <= 2
  and $baseline_active_samples >= 3
  and $zipf_rarity_score >= 4.0

order:
  $zipf_rarity_score desc
```

#### Query 7B: 4-Stage Roll-Up Cloud/Container Alert + Outbound Network Bytes Fusion (`secops-risk-metrics-multistage`)
Consolidates the 55 native cloud provider detector sub-packs (`cdir-scc-*`, `aws-guardduty-*`, `azure-defender-for-cloud-*`) and Kubernetes runtime alerts by rolling up 30-day `metrics.alert_event_name_count` per host/node (`principal.asset.hostname` + `security_result.rule_name`) and fusing it with 30-day `metrics.network_bytes_outbound` ($D^2 \ge 12.25$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Consolidate native cloud/container alerts (GCP SCC, AWS GuardDuty, Azure Defender, EDR) with 30-day outbound network byte surges on the same node/host.
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

### Scenario 8: Cloud Identity Plane: MFA Fatigue, Token Anomalies & Account Takeover

* **Curated Detection Operational Focus**: Flags logins from anomalous geographies, MFA push bombing, and unfamiliar device contexts.
* **How Multi-Stage UEBA Extends Coverage**: Calculates geodesic haversine velocity ($\ge 900\text{ km/h}$) across consecutive cloud logins and circular 24-hour von Mises off-hours authentication divergence.

#### Query 8A: 3-Metric Multilevel Part-of-the-Whole Cloud Identity & Workspace Triad (`secops-risk-metrics-multistage`)
Upgrades curated detection rules by simultaneously scoring every user across the **Workspace Identity & Activity Triad** (`metrics.workspace_auth_attempts_total`, `metrics.workspace_total_download_actions`, and `metrics.workspace_total_change_actions`) against both their personal 30-day baseline (with zero-safe denominators) and the concurrent enterprise fleet ($D_{\text{vs fleet}}^2 \ge 12.25$).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect post-compromise cloud identity and Google Workspace account takeover across Auth, Download, and Admin/Change sectors via a 3-Metric Multilevel Triad.
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

    // Metric 2: Workspace Total Download Actions
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

    // In-Stage Personal Historical Z-Scores with zero-safe denominators
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

#### Query 8B: 4-Stage UDM-Gated Beta-Binomial Empirical Bayes Cloud Auth Failure Rate (`secops-statistical-hunter`)
Evaluates hourly cloud `USER_LOGIN` failure-rate spikes via **Beta-Binomial Empirical Bayes Shrinkage** strictly on candidate identities surfaced by `Query 8A` via UDM Loopback (`re.regex(security_result.rule_name, `:q[0-9]+_query_8a`)`).

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 4-STAGE UDM-GATED BETA-BINOMIAL EMPIRICAL BAYES AUTH FAILURE RATE PIPELINE
// Goal: Detect distributed password spraying and MFA fatigue against candidate cloud identities from Query 8A (strictly gated by Query 8A UDM Loopback candidates).
// Statistical Model: UDM Loopback Stage 1 Candidate Gate + Beta-Binomial Empirical Bayes Shrinkage
// ============================================================================

stage stage1_upstream_8a_candidates {
    metadata.event_type = "GENERIC_EVENT"
    metadata.vendor_name = "Google SecOps"
    metadata.product_name = "SecOps Risk Metrics Hunter"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    metadata.product_log_id = $run_id
    re.regex(security_result.rule_name, `:q[0-9]+_query_8a`)
    $user = strings.coalesce(principal.user.userid, target.user.userid, principal.asset.hostname)
    $user != ""
    $run_id != ""

  match:
    $user

  outcome:
    $upstream_8a_z = max(security_result.confidence_score)
}

stage hourly_auth_stats {
    metadata.event_type = "USER_LOGIN"
    $user = strings.coalesce(target.user.userid, principal.user.userid)
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_attempts = count(metadata.id)
    $failed_attempts = sum(if(security_result.action = "BLOCK", 1, 0))
    $distinct_src_ips = count_distinct(principal.ip)
}

stage user_prior_stats {
    $user = $hourly_auth_stats.user

  match:
    $user

  outcome:
    $hist_mean_total = avg($hourly_auth_stats.total_attempts)
    $hist_mean_fail = avg($hourly_auth_stats.failed_attempts)
    $hist_stddev_fail = stddev($hourly_auth_stats.failed_attempts)
    $active_windows = count($hourly_auth_stats.window_start)
}

$user = $stage1_upstream_8a_candidates.user
$user = $hourly_auth_stats.user
$user = $user_prior_stats.user
$ws = $hourly_auth_stats.window_start

match:
  $user, $ws by 1h

outcome:
  $upstream_z = max($stage1_upstream_8a_candidates.upstream_8a_z)
  $n_trials = max($hourly_auth_stats.total_attempts)
  $k_failures = max($hourly_auth_stats.failed_attempts)
  $prior_mean_n = max($user_prior_stats.hist_mean_total)
  $prior_mean_k = max($user_prior_stats.hist_mean_fail)

  $alpha_0 = $prior_mean_k + 1.0
  $raw_beta = $prior_mean_n - $prior_mean_k
  $beta_0 = if($raw_beta > 0, $raw_beta, 1.0) + 5.0

  $posterior_fail_rate = ($alpha_0 + $k_failures) / ($alpha_0 + $beta_0 + $n_trials)
  $prior_fail_rate = $alpha_0 / ($alpha_0 + $beta_0)
  $safe_prior_rate = if($prior_fail_rate > 0, $prior_fail_rate, 0.05)

  $beta_binomial_score = ($posterior_fail_rate / $safe_prior_rate) * math.log($k_failures + 1.0)
  $z_score = $beta_binomial_score

  $observation_count = $k_failures
  $baseline_active_samples = max($user_prior_stats.active_windows)
  $baseline_mean = $prior_mean_k
  $baseline_dispersion = max($user_prior_stats.hist_stddev_fail)
  $fleet_prevalence = 1
  $distinct_binaries = max($hourly_auth_stats.distinct_src_ips)

condition:
  $baseline_active_samples >= 2
  and $k_failures >= 5
  and $posterior_fail_rate >= 0.35
  and $beta_binomial_score >= 3.5

order:
  $beta_binomial_score desc
```

---

---

### Scenario 9: Cloud DNS Tunneling, C2 Beaconing & Infant Cloud Asset Egress

* **Curated Detection Operational Focus**: Monitors outbound connections from cloud instances to known C2 domains or newly observed endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Combines multi-class character Shannon entropy on DNS queries with 30-day outbound network byte and DNS baselines.

#### Query 9A: Record-Agnostic Cloud DNS Subdomain Character-Class Shannon Entropy (`secops-statistical-hunter`)
Removes the `CNAME`/`SRV` restriction and `>= 50 in 5m` rate cliff by measuring **4-Class Character Distribution Shannon Entropy** ($H(X) \ge 3.8$) across all DNS record types (`A`, `AAAA`, `TXT`, `CNAME`, `SRV`, `NULL`) on long DNS query names (`strings.length >= 48`) contacted by $\le 3$ hosts in the fleet.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Detect record-agnostic DNS tunneling and Base32/Base64/Hex-encoded subdomain exfiltration across all DNS record types (TXT, AAAA, A, CNAME, SRV, NULL).
// Target Telemetry: UDM_EVENTS (NETWORK_DNS across Cloud DNS, Route53, Azure DNS, VPC DNS)
// Statistical Model: Multi-Class Character Distribution Shannon Entropy (H(X) = -sum(p_i * log2(p_i)))
// ============================================================================

// Stage 1: Aggregate DNS query string lengths and character-class distributions per host and FQDN
stage url_feature_extraction {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.hostname = $user
    $user != ""
    $url = network.dns.questions.name
    $url != ""
    strings.length($url) >= 48

  match:
    $user, $url by 1d

  outcome:
    $execution_count = count(metadata.id)
    $raw_len = max(strings.length($url))
    $safe_len = if($raw_len > 0, $raw_len, 1)

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax)
    $len_no_lower = max(strings.length(re.replace($url, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($url, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($url, `\d`, "")))

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

// Stage 2: Enterprise fleet prevalence of each distinct DNS query name across hosts
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
  $p_lower = max($url_feature_extraction.p_lower)
  $p_upper = max($url_feature_extraction.p_upper)
  $p_digit = max($url_feature_extraction.p_digit)
  $p_other = max($url_feature_extraction.p_other)

  $h_lower = (0.0 - $p_lower) * (math.log($p_lower) / 0.693147)
  $h_upper = (0.0 - $p_upper) * (math.log($p_upper) / 0.693147)
  $h_digit = (0.0 - $p_digit) * (math.log($p_digit) / 0.693147)
  $h_other = (0.0 - $p_other) * (math.log($p_other) / 0.693147)

  $class_entropy = $h_lower + $h_upper + $h_digit + $h_other
  $length_bonus = if($len >= 80, 0.5, 0.0)
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

#### Query 9B: 2-Stage Hybrid 30-Day Outbound Network Bytes + `DERIVED_CONTEXT` Infant Cloud Asset Age (`secops-risk-metrics-multistage`)
Detects newly spun-up or ephemeral attacker-provisioned cloud VMs/containers (`asset_age_days <= 7.0` in `DERIVED_CONTEXT`) that immediately exhibit anomalous outbound network byte volume (`metrics.network_bytes_outbound`), boosting infant asset threat scores by $2.5\times$.

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// Goal: Isolate infant cloud VMs and container nodes (first seen <= 7 days ago in DERIVED_CONTEXT) exhibiting immediate anomalous outbound network egress.
// Statistical Model: Hybrid 30-Day Host Network Egress Z-Score (metrics.network_bytes_outbound) + DERIVED_CONTEXT Infant Asset Multiplier (2.5x)
// ARCHITECTURE: 2-STAGE DUAL-PLANE DERIVED CONTEXT ASSET AGE PIPELINE
// Skill: secops-risk-metrics-multistage
// ============================================================================

// Stage 1: Macro 30-Day Host Network Egress Baseline (metrics.network_bytes_outbound)
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

// Stage 3 (Root Stage): Fuses Host Anomaly Z-Score with Infant Cloud Asset Age Coloring
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

  // Infant Asset Multiplier: 2.5x threat score boost for cloud instances first seen <= 7 days ago
  $is_infant_asset = if($first_seen > 0 and $asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)
  $threat_multiplier = if($is_infant_asset = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $threat_multiplier

condition:
  $z_score >= 2.0
  and $asset_age_days <= 7.0
  and $threat_score >= 3.5

order:
  $threat_score desc
```

---

---

### Scenario 10: Capstone Multi-Scenario Entity Convergence via Native UDM Loopback (Option 3 Connective Tissue)

* **Curated Detection Operational Focus**: Individual cloud alerts evaluated within isolated control-plane or workload domains.
* **How Multi-Stage UEBA Extends Coverage**: Correlates cloud identities matching $\ge 2$ distinct scenarios in the current playbook run (`Option 3` UDM Loopback `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` validated via `run_id`) using an $L_2$ Euclidean risk norm ($\sum Z_i^2 \ge 25.0$).

### Scenario 10: Unified 3-Stage Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`Option 3` Cross-Query Connective Tissue)

Individual behavioral queries in Scenarios 1–9 frequently fire inside ambiguous overlap regimes when evaluated in isolation. Furthermore, 30-day `metrics.*` stages aggregate away raw forensic artifacts such as full process paths or specific cloud/web resource names.

**Scenario 10 (`Query 10`)** executes in **Wave 3** after all **Wave 1** (upstream `by 1d` and pre-filtered queries) and **Wave 2** (inline UDM-gated `Query XB` Stage B queries) have exported their findings into Chronicle's unified `GENERIC_EVENT` UDM stream (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`):
1. **Regex Union Token Matching Across All 9 Scenarios (`stage1_per_scenario_dedup`)**: Matches `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` events for the active `$run_id` using a single hierarchical regex union (`re.regex(security_result.rule_name, `:q[0-9]+_query_[1-9]`)`) and deduplicates by `$entity, $scenario_tag`.
2. **Multi-Scenario Euclidean L2 Rollup (`stage2_multi_scenario_rollup`)**: Aggregates across Stage 1 by `$entity`, counting distinct scenario tags (`$distinct_scenarios_matched >= 2`) and summing their squared Z-scores (`$capstone_threat_norm_sq >= 18.0`).
3. **Raw Telemetry Forensic Pivot (`stage3_raw_forensic_pivot` & Root Join)**: Simultaneously aggregates raw telemetry (`PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `RESOURCE_READ`, `USER_RESOURCE_ACCESS`, `USER_LOGIN`) by `$entity` and joins it with Stage 2 in Root to deliver both the cross-scenario Euclidean L2 convergence score and concrete raw forensic artifacts in a single query.

#### Query 10: 3-Stage Unified Capstone Multi-Scenario Convergence & Raw Telemetry Forensic Bridge (`secops-statistical-hunter`)

```yara
// ============================================================================
// Copyright 2026 Google LLC. All Rights Reserved.
// Author: Greg Kushmerek
// ARCHITECTURE: 3-STAGE UNIFIED CAPSTONE CONVERGENCE & RAW FORENSIC BRIDGE
// Goal: Deduplicate and roll up normalized UEBA hunt matches across all 9 Cloud Threats scenarios (1 through 9B) via UDM Loopback regex token union while simultaneously joining raw telemetry for forensic attribution.
// Statistical Model: Cross-Scenario Euclidean L2 Threat Norm Convergence (distinct_scenarios_matched >= 2, capstone_threat_norm_sq >= 18.0) + Cross-Plane Raw Telemetry Bridge
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
