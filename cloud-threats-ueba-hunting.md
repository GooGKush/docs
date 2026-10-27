# Hunting Multi-Cloud, Kubernetes, Serverless & Identity Threats with Multi-Stage Behavioral Analytics in Google SecOps

## 1. Architectural Overview: How Multi-Stage UEBA Complements Curated Detections

The **Cloud Threats** curated detection suite provides foundational coverage across AWS, Google Cloud (GCP), Microsoft Azure / Entra ID, and Kubernetes environments—monitoring high-risk IAM modifications, credential issuance, cloud storage exposure, serverless execution, and container control-plane tampering.

While point-in-time signatures and single-stage metric rules provide rapid alerting for known attack patterns and high-volume spikes, cloud control-plane activity naturally spans both ephemeral workload identities (cold-start service accounts and short-lived roles) and variable-cadence automation pipelines. This playbook extends coverage beyond the built-in constraints of single-stage cloud rules using **Option 1 Inline Piecewise Unification** (combining Two-Part Hurdle cold-start scoring with 30-day Z-score and non-parametric Median Absolute Deviation baselines in a single query) and **Option 3 UDM Loopback Capstone Convergence**.

### Complementary Detection Layers
* **Curated Detections (Real-Time Deterministic & Single-Stage Layer)**: Provide immediate, low-latency alerting on high-confidence indicators, explicit attack syntax, and single-stage threshold breaches.
* **Multi-Stage UEBA & Statistical Hunting Harness (Cyclical Behavioral Layer)**: Extends coverage beyond the built-in window and observation constraints of single-stage rules through two architectural patterns executed by `PlaybookRunner` in `agentic-ueba`:
  1. **Option 1 — In-DAG Piecewise Cold-Start & Mature Baseline Unification**: Evaluates both newly active or dormant entities (`active_days <= 4` via a **Two-Part Zero-Inflated Hurdle** branch) and established entities (`active_days >= 5` via a **30-Day Parametric Z-Score** or **4-Stage Non-Parametric Median Absolute Deviation (MAD)** branch) inside a single unified YARA-L 2.0 query.
  2. **Option 3 — UDM Loopback Connective Tissue & Run-Scoped Capstone Convergence**: Every upstream query match is ingested back into Chronicle as a structured `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` UDM event stamped with the execution cycle's unique `run_id` (`metadata.product_log_id`). Before the **Capstone Query** executes, `PlaybookRunner` validates via a read-after-write UDM search barrier (`verify_udm_run_indexed()`) that all upstream events are indexed, and then correlates entities exhibiting multi-scenario convergence ($\sum Z_i^2 \ge 25.0$).

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

#### Query 2A: Empirical Bayes Gamma-Poisson Credibility Shrinkage on Cloud Discovery & Permission-Denial Bursts (`secops-statistical-hunter`)
Replaces static User-Agent strings, the `>= 95` ScoutSuite cliff, and the single-stage single-stage baseline constraints gate by applying **Poisson-Gamma Bayesian Conjugate Updating** to hourly cloud `RESOURCE_READ` / `USER_RESOURCE_ACCESS` discovery and permission-probe calls per cloud principal.

```yara
// ============================================================================
// Goal: Detect custom-User-Agent cloud reconnaissance and permission brute-forcing (Pacu, ScoutSuite, Cloudfox, gcpwn) via Bayesian Gamma-Poisson shrinkage.
// Target Telemetry: UDM_EVENTS (RESOURCE_READ and USER_RESOURCE_ACCESS across GCP, AWS, Azure)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting
// ============================================================================

// Stage 1: Hourly cloud discovery & resource access volume per cloud principal
stage host_hourly_activity {
    (
      metadata.event_type = "RESOURCE_READ"
      or metadata.event_type = "USER_RESOURCE_ACCESS"
    )
    principal.user.userid = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count(metadata.id)
    $distinct_exts = count_distinct(metadata.product_event_type)
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
  and $observation_count >= 15
  and $distinct_binaries >= 5
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
```

#### Query 2B: 4-Stage Roll-Up Cloud Resource Read Failure + HTTP API Volume Fusion (`secops-risk-metrics-multistage`)
Directly replaces curated detection rules by rolling up 30-day `metrics.resource_read_fail` across all cloud products/vendors and fusing it with 30-day `metrics.http_queries_total` per user ($D^2 \ge 12.25$), without the single-stage single-stage baseline constraints filter.

```yara
// ============================================================================
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

---

---

### Scenario 3: Cloud Secrets Manager, Key Vault & Credential Harvesting

* **Curated Detection Operational Focus**: Single-stage threshold and baseline checks for excessive secret reads or vault enumeration.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start identities (`active_days <= 4` via Two-Part Hurdle) and mature identities (`active_days >= 5` via 4-stage non-parametric 30-day MAD) in a single piecewise query (`Option 1`), overcoming variance masking from scheduled CI/CD jobs.

#### Query 3: Unified Cold-Start Hurdle & 30-Day Robust MAD on Multi-Cloud Secret & Resource Reads (`secops-risk-metrics-multistage` + `secops-statistical-hunter`)
Rather than splitting secret and resource harvesting into two disconnected queries (one for cold-start identities with $< 5$ active days and another for mature identities with $\ge 5$ active days), this unified 4-stage pipeline evaluates **both statistical regimes inside a single DAG** via an in-query piecewise switch (`$unified_threat_score = if($raw_active_days <= 4, $hurdle_threat_score, $modified_z)`):
- **Regime 1 — Cold-Start & Dormant Identities ($\text{raw\_active\_days} \le 4$)**: Directly fixes the single-stage baseline constraints coverage considerations in curated detection rules by applying a $3.0\times$ Bernoulli Hurdle Crossing multiplier weighted by log read volume and distinct secret/resource breadth (`$distinct_secrets`).
- **Regime 2 — Mature Active Identities ($\text{raw\_active\_days} \ge 5$)**: Replaces the single-stage single-stage baseline constraints and single-stage baseline constraints gates with a 4-stage Iglewicz-Hoaglin **Modified Z-Score ($M_Z$)** over 30-day Median Absolute Deviation (MAD), cross-checked against 30-day `metrics.resource_read_success`.

```yara
// ============================================================================
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

  // 1. Classical 30d metrics Z (cross-check)
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  // 2. Mature Regime (>= 5 active days): Robust scale with Iglewicz-Hoaglin MAD=0 fallback and flat-history floor
  $scale_from_mad = $mad / 0.6745
  $scale_from_meanad = $mean_abs_dev * 1.253314
  $robust_scale = if($mad > 0, $scale_from_mad, $scale_from_meanad)
  $median_floor = $median_val * 0.05 + 1.0
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, $median_floor)
  $modified_z = ($observed - $median_val) / $safe_robust_scale
  $z_gap = $modified_z - $personal_z

  // 3. Cold-Start / Dormant Regime (<= 4 active days): Two-Part Hurdle Rarity Boost + Secret Breadth
  $hurdle_rarity_boost = if($raw_active_days <= 4, 3.0, 1.0)
  $safe_secrets = if($distinct_secrets > 0, $distinct_secrets, 1)
  $hurdle_threat_score = math.log($observed + 1) * $safe_secrets * $hurdle_rarity_boost / 3.0

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

#### Query 5A: Poisson Fano Factor Burst Clustering on Cloud Resource, Log & Firewall Deletions (`secops-statistical-hunter`)
Replaces deprecated curated detection rules and separates erratic sabotage/evasion bursts (`DeleteFlowLogs`, `StopLogging`, `DeleteTrail`, `firewalls.delete`, `DestroySecretVersion`, `DisableServiceAccountKey`, `DisableService`) from steady IaC maintenance using the **Fano Factor** ($F = \sigma^2 / \mu \ge 4.0$) over hourly buckets.

```yara
// ============================================================================
// Goal: Detect erratic bursts of cloud defense evasion, log tampering, firewall deletion, and mass key/secret destruction via Poisson dispersion (Fano Factor >= 4.0).
// Target Telemetry: UDM_EVENTS (RESOURCE_DELETION and USER_RESOURCE_DELETION across GCP, AWS, Azure)
// Statistical Model: Poisson Dispersion via Fano Factor (F = σ² / μ >= 4.0) & Fleet Prevalence Filter
// ============================================================================

// Stage 1: Hourly cloud resource/log/firewall deletion counts per principal user
stage hourly_surveillance_calls {
    (
      metadata.event_type = "RESOURCE_DELETION"
      or metadata.event_type = "USER_RESOURCE_DELETION"
    )
    principal.user.userid = $entity
    $entity != ""

  match:
    $entity by 1h

  outcome:
    $hourly_calls = count(metadata.id)
    $distinct_exts = count_distinct(metadata.product_event_type)
    $sample_exts = array_distinct(metadata.product_event_type)
}

// Stage 2: Historical arrival mean (μ), standard deviation (σ), and active hour density per principal
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

// Stage 3: Enterprise-wide principal breadth per hourly window
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
  and $observation_count >= 10
  and $baseline_mean >= 1.0
  and $fano_factor >= 4.0

order:
  $fano_factor desc
```

#### Query 5B: 2-Stage Dual-Branch Cloud Repository Scope & 4-Family CRUD Outlier Pipeline (`secops-risk-metrics-multistage`)
Evaluates every cloud service account or IAM role across all four 30-day CRUD metric families (`metrics.resource_read_total`, `metrics.resource_written_total`, `metrics.resource_deletion_total`, `metrics.resource_creation_total`) plus **Caller Origin IP** (`principal.ip`) to isolate service accounts modifying or deleting cloud resources out of their historical scope or from a novel IP.

```yara
// ============================================================================
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

---

---

### Scenario 6: Serverless (Cloud Run / Functions / Lambda), Compute VM & Cryptomining

* **Curated Detection Operational Focus**: Tracks serverless function/job creation, IAM policy changes on functions, and known cryptomining indicators.
* **How Multi-Stage UEBA Extends Coverage**: Unifies cold-start serverless identity activation with 30-day resource creation baselines (`Option 1`) and detects automated C2/stratum callback cadence via inter-arrival jitter ($\text{CV} \le 0.20$).

#### Query 6A: Leave-One-Out Discrete Poisson Rarity on Serverless & Compute Resource Creation (`secops-statistical-hunter`)
Directly implements the UEBA analytic requested in `` and replaces curated detection rules by computing **Leave-One-Out Discrete Poisson Arrival Rarity** ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda \ge 9.0$) over daily `RESOURCE_CREATION` / `USER_RESOURCE_CREATION` events (`CreateServiceAccountKey`, `Jobs.CreateJob`, `Services.CreateService`, `CreateFunction`, `RunInstances`, `compute.instances.insert`). When a serverless identity with 0 prior creations ($\lambda = 0.5/29 \approx 0.0172$) creates even **1** service account key or job ($k = 1$), $Z_{\text{Poisson}}^2 = (1 - 0.0172)^2 / 0.0172 = 56.0 \ge 9.0$, catching the single-key creation that `$event_count > 1` missed!

```yara
// ============================================================================
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
Removes the `kube-system` and `/\/gke\-/` prefix coverage considerations by ranking all Kubernetes pod, workload, ClusterRoleBinding, RoleBinding, and token creation targets across **all namespaces** using **Zipfian Power-Law Rarity & Inverse Principal Frequency** ($\text{zipf\_rarity\_score} \ge 4.0$, $\le 2$ principals).

```yara
// ============================================================================
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

#### Query 8A: 4-Stage Beta-Binomial Empirical Bayes Authentication Failure Rate Regularization (`secops-statistical-hunter`)
Eliminates the shared-`CorrelationId` constraint, `$e1.ip != $e2.ip` contradiction, and `>= 20 in 2m` cliff by modeling hourly authentication trials across Entra ID, Office 365, Okta, and Google Workspace with **Beta-Binomial Conjugate Updating** ($\hat{p}_{\text{EB}} = (\text{fails} + 1.0) / (\text{trials} + 10.0) \ge 0.50$).

```yara
// ============================================================================
// Goal: Detect MFA fatigue push bombing, password spraying, and credential stuffing across Entra ID, Okta, O365, and Workspace via Beta-Binomial Regularization.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Beta-Binomial Bayesian Updating & Small-Sample Shrinkage
// ============================================================================

// Stage 1: Aggregate authentication trials and failures per target user in tumbling hourly windows
stage entity_hourly_trials {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count(metadata.id)
    $failed_trials = sum(if(security_result.action = "BLOCK", 1, 0))
    $distinct_sources = count_distinct(principal.ip)
}

// Stage 2: Historical Parameter Estimation across all active baseline windows
stage entity_historical_rates {
    $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

// Stage 3: Fleet Context across active users in the window
stage fleet_stats {
    $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = count_distinct($entity_hourly_trials.user)
}

// Root Stage: Beta-Binomial Conjugate Updating & Shrinkage
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($entity_hourly_trials.failed_trials)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $baseline_mean = max($entity_historical_rates.total_historical_fails)
  $baseline_dispersion = max($entity_historical_rates.total_historical_events)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Regularized Posterior Failure Probability (alpha_0 = 1.0, beta_0 = 9.0)
  $regularized_failure_prob = (max($entity_hourly_trials.failed_trials) + 1.0) / (max($entity_hourly_trials.total_trials) + 10.0)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1.0)
  $unregularized_raw_rate = max($entity_hourly_trials.failed_trials) / $safe_trials

condition:
  $baseline_active_samples >= 3
  and $observation_count >= 6
  and $regularized_failure_prob >= 0.50

order:
  $regularized_failure_prob desc
```

#### Query 8B: 3-Metric Multilevel Part-of-the-Whole Cloud Identity & Workspace Triad (`secops-risk-metrics-multistage`)
Upgrades curated detection rules by simultaneously scoring every user across the **Workspace Identity & Activity Triad** (`metrics.workspace_auth_attempts_total`, `metrics.workspace_total_download_actions`, and `metrics.workspace_total_change_actions`) against both their personal 30-day baseline (with zero-safe denominators) and the concurrent enterprise fleet ($D_{\text{vs\_fleet}}^2 \ge 12.25$).

```yara
// ============================================================================
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

---

---

### Scenario 9: Cloud DNS Tunneling, C2 Beaconing & Infant Cloud Asset Egress

* **Curated Detection Operational Focus**: Monitors outbound connections from cloud instances to known C2 domains or newly observed endpoints.
* **How Multi-Stage UEBA Extends Coverage**: Combines multi-class character Shannon entropy on DNS queries with 30-day outbound network byte and DNS baselines.

#### Query 9A: Record-Agnostic Cloud DNS Subdomain Character-Class Shannon Entropy (`secops-statistical-hunter`)
Removes the `CNAME`/`SRV` restriction and `>= 50 in 5m` rate cliff by measuring **4-Class Character Distribution Shannon Entropy** ($H(X) \ge 3.8$) across all DNS record types (`A`, `AAAA`, `TXT`, `CNAME`, `SRV`, `NULL`) on long DNS query names (`strings.length >= 48`) contacted by $\le 3$ hosts in the fleet.

```yara
// ============================================================================
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

    // Character-class counts via regex replacement length deltas (bracket-free RE2 syntax)
    $len_no_lower = max(strings.length(re.replace($url, `a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z`, "")))
    $len_no_upper = max(strings.length(re.replace($url, `A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z`, "")))
    $len_no_digit = max(strings.length(re.replace($url, `\d`, "")))

    $c_lower = $raw_len - $len_no_lower
    $c_upper = $raw_len - $len_no_upper
    $c_digit = $raw_len - $len_no_digit
    $c_other_raw = $raw_len - ($c_lower + $c_upper + $c_digit)
    $c_other = if($c_other_raw > 0, $c_other_raw, 0)
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
  $safe_len = if($len > 0, $len, 1)

  $n_lower = max($url_feature_extraction.c_lower)
  $n_upper = max($url_feature_extraction.c_upper)
  $n_digit = max($url_feature_extraction.c_digit)
  $n_other = max($url_feature_extraction.c_other)

  // Empirical probability per character class
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

#### Capstone Query: Multi-Scenario Cloud Entity Convergence via UDM Loopback (`secops-risk-metrics-multistage` + `PlaybookRunner`)

```yara
// ============================================================================
// Goal: Correlate cloud identities matching >= 2 distinct behavioral queries across Scenarios 1-9 via PlaybookRunner's native UDM loopback (PLAYBOOK_BEHAVIORAL_HUNT_MATCH).
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
    principal.user.userid = $entity
    security_result.rule_name = $rule_name
    $entity != ""
    $rule_name != ""
    $run_id != ""
    $rule_name != "cloud-threats-ueba-hunting:capstone_cross_query_convergence"

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

### 3.1 Markov 2-Gram Cloud Service-to-Method Surprisal ($I = -\ln P(\text{Method}\mid\text{Service})$ — Query 1A)
* **What it measures**: How unexpected it is for a cloud user or service account to call a sensitive IAM/token API (`SetIamPolicy`, `GenerateAccessToken`, `SignJwt`, `AssumeRole`) relative to their normal usage of that cloud service.
* **How multi-stage UEBA extends coverage**: curated detection rules hardcodes `user_agent = /gcloud.iam.service-accounts.add-iam-policy-binding/` and a `10m` window; custom SDK calls or 11-minute delays bypass it.
* **How the math works**: Routine API calls have $P(\text{Method}\mid\text{Service}) \approx 1 \implies I \approx 0$. A rare token-minting or policy-binding call produces a tiny conditional probability and spikes $I = \ln(\text{Service}) - \ln(\text{Transition})$ above `3.0`.

### 3.2 4-Stage Roll-Up Multi-Sector Euclidean Risk Fusion ($D^2 = Z_A^2 + Z_B^2$ — Queries 1B, 2B, 6B, 7B)
* **What it measures**: Joint anomaly distance across a composite cloud metric (`metrics.resource_written_success`, `metrics.resource_read_fail`, `metrics.resource_creation_total`, `metrics.alert_event_name_count`) rolled up to the entity level and fused with an independent behavioral sector (`metrics.auth_attempts_success`, `metrics.http_queries_total`, `metrics.network_bytes_outbound`).
* **How multi-stage UEBA extends coverage**: Single-sector rules either drown in benign CI/CD noise or use single-stage single-stage baseline constraints gates.
* **How the math works**: Stage 1 computes per-(product, vendor) Z-scores; Stage 2 rolls up the peak Z-score per user; Stage 3 computes the second sector's Z-score; Root Stage requires $Z_A^2 + Z_B^2 \ge 12.25$ ($\sqrt{12.25} = 3.5\sigma$ joint radius).

### 3.3 Empirical Bayes Gamma-Poisson Credibility Shrinkage (Query 2A)
* **What it measures**: The posterior hourly rate of cloud discovery/read calls relative to the principal's historical mean, shrunk by historical variance.
* **How multi-stage UEBA extends coverage**: curated detection rules requires `>= 95` distinct APIs in `1h` and `offsec_user_agent` checks static User-Agent strings.
* **How the math works**: Method-of-Moments estimates a Gamma prior ($\alpha_0 = \mu^2/\sigma^2, \beta_0 = \mu/\sigma^2$), suppressing noisy monitoring accounts while elevating targeted recon bursts ($\ge 15$ calls across $\ge 5$ distinct APIs) on normally quiet principals.

### 3.4 Two-Part Zero-Inflated Hurdle Model (Query 3A)
* **What it measures**: Part 1 measures whether a principal rarely touches Secret Manager / Key Vault ($\le 2$ active days); Part 2 measures the positive-day read intensity Z-score.
* **How multi-stage UEBA extends coverage**: curated detection rules requires single-stage baseline constraints, blinding it to any compromised user or role accessing Secrets Manager for the first time (`obs == 0`).
* **How the math works**: Crossing the zero-hurdle ($\le 2$ active days) applies a $3.0\times$ rarity multiplier to the intensity score, immediately catching first-time secret harvesters.

### 3.5 4-Stage Robust Modified Z-Score / 30-Day MAD ($M_Z$ — Query 3B)
* **What it measures**: How many Median Absolute Deviations (MAD) today's cloud resource read volume sits above the 30-day median, alongside the classical 30-day `metrics.resource_read_success` Z-score.
* **How multi-stage UEBA extends coverage**: curated detection rules requires single-stage baseline constraints and `10 * historical_max`, where a single historical deployment spike inflates `stddev` and `max` and masks future attacks.
* **How the math works**: The median and MAD have a 50% breakdown point, remaining uncorrupted by prior spikes ($M_Z \ge 3.5$).

### 3.6 Dual-Baseline Fleet-Normalized Delta-Z ($\Delta Z = Z_{\text{personal}} - \max(0, Z_{\text{fleet}})$ — Query 4A)
* **What it measures**: A principal's storage/snapshot read and ACL mutation surge above personal history after subtracting any concurrent fleet-wide backup wave.
* **How multi-stage UEBA extends coverage**: curated detection rules only checks `group = "all"` or `userId = "*"`, missing targeted external Account ID sharing.
* **How the math works**: Fleet-wide backups raise $Z_{\text{fleet}}$ so $\Delta Z \approx 0$; targeted snapshot/bucket exfiltration by a single compromised principal yields $\Delta Z \ge 3.0\sigma$.

### 3.7 Longitudinal CUSUM Behavioral Drift ($S_t^+$ — Query 4B)
* **What it measures**: Multi-day accumulation of positive daily network egress excesses ($\sum \max(0, Z_t - 0.5\sigma)$) over `metrics.network_bytes_outbound`.
* **How multi-stage UEBA extends coverage**: Throttled `rclone` transfers stay beneath single-day $6\sigma$ thresholds and outside `2h` composite rule windows.
* **How the math works**: Accumulating daily excesses above $0.5\sigma$ across $\ge 2$ drift days catches low-and-slow cloud exfiltration once $S_t^+ \ge 3.0$.

### 3.8 Poisson Dispersion & Fano Factor ($F = \sigma^2 / \mu$ — Query 5A)
* **What it measures**: Hourly burstiness of cloud `RESOURCE_DELETION` calls (log, firewall, secret, and SA key deletions).
* **How multi-stage UEBA extends coverage**: Atomic rules (curated detection rules) fire on every single Terraform teardown, while curated detection rules is deprecated.
* **How the math works**: Concentrated sabotage bursts drive variance far above the mean ($F = \sigma^2/\mu \ge 4.0$).

### 3.9 Dual-Branch 4-Family Cloud CRUD Scope & Caller Origin IP Isolation (Query 5B)
* **What it measures**: Per-(service account, product, target resource) Z-scores across Read, Write, Delete, and Create metrics plus Caller Origin IP (`principal.ip`).
* **How multi-stage UEBA extends coverage**: Broad account-level rules suffer from the "Elephant & Mouse" problem where high-volume reads on one bucket mask unauthorized deletions or writes on another resource.
* **How the math works**: Local-baseline isolation scores each `(sa, product, resource)` tuple and `(sa, product, ip)` origin independently ($\text{composite\_risk} \ge 3.5$).

### 3.10 Leave-One-Out Discrete Poisson Rarity ($Z_{\text{Poisson}}^2 = (k - \lambda)^2 / \lambda$ — Query 6A)
* **What it measures**: The Poisson improbability of a serverless or compute principal creating $k \ge 1$ resources/keys when its leave-one-out 29-day rate $\lambda$ is near zero ($\le 0.5/\text{day}$).
* **How multi-stage UEBA extends coverage**: All 6 curated detection rules rules have `enhancement:` and use `$event_count > 1`, missing single-key creation ($k = 1$).
* **How the math works**: With Jeffreys smoothing $\lambda = (\text{prior\_runs} + 0.5)/29.0$, even $k = 1$ on a zero-prior Cloud Run service account yields $Z_{\text{Poisson}}^2 = 56.0 \ge 9.0$.

### 3.11 Zipfian Power-Law Fleet Rarity & Inverse Principal Frequency (IDF — Query 7A)
* **What it measures**: Cluster-wide rarity of a Kubernetes workload or RBAC binding target ($\le 2$ principals) combined with local creation frequency across *all* namespaces.
* **How multi-stage UEBA extends coverage**: curated detection rules only checks `kube-system` and curated detection rules only checks `/\/gke\-/` prefixes.
* **How the math works**: $\ln(N_{\text{total}} / N_{\text{adopters}}) + \ln(\text{count} + 1)$ elevates singleton/doubleton K8s pods and RBAC bindings in any namespace.

### 3.12 Beta-Binomial Empirical Bayes Failure Rate Regularization (Query 8A)
* **What it measures**: Posterior authentication failure probability $\hat{p}_{\text{EB}} = (\text{fails} + 1)/(\text{trials} + 10)$ per user per hour.
* **How multi-stage UEBA extends coverage**: curated detection rules requires shared `$correlationId` and `$e1.ip != $e2.ip`; curated detection rules requires `>= 20` denials in `2m`.
* **How the math works**: Conjugate Beta(1,9) shrinkage suppresses 1-of-1 typos while catching sustained MFA push bombing ($\ge 6$ failures, $\hat{p}_{\text{EB}} \ge 0.50$).

### 3.13 3-Metric Multilevel Part-of-the-Whole Triad ($D_{\text{vs\_fleet}}^2$ — Query 8B)
* **What it measures**: Simultaneous personal and cross-sectional fleet Z-scores across Workspace Auth, Downloads, and Admin/Change actions.
* **How multi-stage UEBA extends coverage**: Dormant users with 0 prior downloads have $\mu=0, \sigma=0$ and fail single-stage baseline constraints.
* **How the math works**: Zero-safe denominators (`if($std > 0, $std, 1.0)`) and fleet-wide standardization ($D_{\text{vs\_fleet}}^2 \ge 12.25$) catch dormant-account takeovers immediately.

### 3.14 Record-Agnostic DNS Shannon Entropy & Hybrid Infant Asset Egress (Queries 9A, 9B)
* **What it measures**: Query 9A measures 4-class character Shannon entropy ($H(X) \ge 3.8$) across all DNS record types; Query 9B fuses 30-day `metrics.network_bytes_outbound` with `DERIVED_CONTEXT` asset `first_seen_time` ($\le 7\text{d}$).
* **How multi-stage UEBA extends coverage**: curated detection rules ignores `TXT`/`AAAA` tunneling and `<50` queries/5m; static egress rules lack asset age context.
* **How the math works**: High-entropy Base32/Base64 DNS payloads score $\ge 3.8$ regardless of record type or rate, while infant cloud VMs ($\le 7\text{d}$ old) receive a $2.5\times$ egress risk multiplier.
