# Overnight evaluation: data for the paper (§8 `[MODELS]`, §9 `[RESULTS]`)

**Answer:** Yes, there's real data for the paper this morning. It supports a **working draft with clearly labeled preliminary results**: one test tenant and 15 labeled items. It isn't a benchmark. The formal evaluation (live campaign, replayed public captures, more tenants) stays as follow-up.

**Ready-to-publish working draft:** [inspectable-by-default.md](inspectable-by-default.md). It's your draft with `[MODELS]` and `[RESULTS]` filled in, a recall-vs-volume table, and the editor's note changed to working-draft status. The original draft is untouched.

## What ran (2026-10-30, 02:30–02:56Z)
- **Campaign.** I injected the labeled synthetic campaign into gus-sdl under your identity: 4,636 events, back-dated over event days Oct 20–29. All 15 items were confirmed indexed at their exact counts.
  - Every event carries `metadata.product_log_id = EVAL-…`, the description "SYNTHETIC EVAL … not a real attack", and `additional.eval_injection`.
  - Generator, ground truth and logs are in `scratch/ueba_eval/backdated/`.
- **Why back-dating works.** The harness scores a day from raw events and takes only the 30-day baseline from `metrics.*`. Back-dated events are therefore scored, and the baselines stay frozen at their pre-campaign values (disclosed below). This was checked against the skill text (`SKILL.md:33`, `timeline-modes-guide.md`) and in the results.
- **Detectors.** Two runners, each blind to the ground truth, used the skills' own templates on `ueba-remediation` at default thresholds. No query failed.
  - 30-day plane: 44 queries.
  - Short-window plane: 19 queries.
  - Each run log records the query verbatim, the window, the baseline and the threshold. That's the inspectability evidence: `results/macro_runs.md`, `results/micro_runs.md`.
- **Scoring.** `results/attribution.py` is strict: a detection counts only on the item's own event days.

## Results

**Per item** (strict; "designed" = the detector the scenario was built for):

| Item | Technique | Detected by | Rules |
|---|---|---|---|
| S1, S3 | One-day login surge, +4σ / +6σ | auth Z 4.8 / 6.9; cohort ΔZ 4.2 / 6.3 | – |
| S2 | One-day surge, +2.5σ (built to fall under Z 3) | auth Z 3.2: real activity pushed it just over | – |
| S4 | Noise-floor probe (+20 logins, σ = 0 account) | **Quiet** with the √μ floor (Z 2.5). The old σ = 1 fallback gives Z 20.0 | – |
| D1 | Drift +1σ/day, 10 days | CUSUM on drift day 7 or 8, depending on anchor | – |
| D2 | Drift +0.5σ/day, 10 days | CUSUM on day 10 (Oct 23 anchor only) | – |
| D3 | Drift +2σ/day, 5 days | CUSUM on day 2; single-day Z on one day (3.2) | – |
| R | Rollout: +3σ on 14 of 23 cohort users | Per-user Z flags 13 of 14; **cohort ΔZ flags 0** | – |
| RT | Targeted +6σ on the rollout day | Cohort ΔZ 3.5; per-user Z 6.8 | – |
| SP | Password spray, 2 × 40 users from one IP | Poisson burst (Fano) 23.6 | – |
| N1 | Never-seen binary in a public folder | Zipf rarity 5.0; Markov | ✔ |
| N2 | w3wp.exe → cmd / PowerShell | Markov transition 3.9 (w3wp → PowerShell) and 3.5 (w3wp → cmd) | ✔ |
| X (held out) | 6 × 0.9 GB outbound | Outbound concentration 4.6 (the 17:30 and 17:45 buckets) | – |
| DNS (held out) | 60 random 40-character TXT labels | **Missed**: +1.4σ against only 11 benign names of similar length | – |
| O (held out) | 8 logins between 03:10 and 03:45Z | Hour-of-day 5.0 (03:00Z bucket: 15 logins vs μ 4.3) | – |
| ON-1 (held out) | vssadmin first seen on a host (tenant onset) | Markov: cmd.exe → vssadmin.exe, 10.0. Zipf's hit on that host was unrelated installer temp files | – |
| ON-2 | One-off scythe scheduler (tenant onset) | **Not detected.** The short-window models didn't run on its days. The process-Z hit on that host-day was a CompatTelRunner.exe burst (940 launches vs 7/day), not the scheduler | – |

- **Recall:** 13 of 15 (12 of 13 injected techniques plus one of two onsets). **Held-out: 3 of 4.**
- **Matches checked:** a hit was counted only after I confirmed the flagged evidence was the injected activity: the binary, parent/child pair, hour bucket or time bucket. That check removed two coincidental matches that land on the same host and day: ON-2 above, and Zipf on ON-1.
- **Drift caveat:** the CUSUM results come from re-anchored runs. With the Oct 20 anchor, the three drift users had 3–4 days of history, so the ≥7-day gate withheld scoring. I added Oct 23 and Oct 25 anchors after seeing that; they're logged as post-hoc runs.
- **Drift counterfactual:** rerunning CUSUM on the real-only counts (injected events removed) gives **no alarm for any drift user** at either anchor. The alarms come from the injected drift, not from organic growth.

**Recall at several alert volumes.** Alerts are de-duplicated per (entity, day). Alerts/day covers Oct 28–29, the days every detector ran. Recall covers all days.

| Configuration | Threshold | Alerts/day | On attack items | On labeled benign (rollout, probe) | Unlabeled | Recall | Held-out |
|---|---|---|---|---|---|---|---|
| A. 30-day core (auth Z, cohort ΔZ, CUSUM) | 3 | 10.0 | 5 | 13 | 2 | 7/15 | 0/4 |
|  | 4 | 1.5 | 3 | 0 | 0 | 3/15 | 0/4 |
| B. A + targeted short-window (spray, outbound, DNS entropy) | 3 | 14.0 | 7 | 13 | 8 | 9/15 | 1/4 |
|  | 4 | 4.0 | 5 | 0 | 3 | 5/15 | 1/4 |
| C. B + rarity and profile (Zipf, Markov, hour-of-day) | 3 | 64.5 | 15 | 18 | 96 | 13/15 | 3/4 |
|  | 4 | 45.0 | 11 | 18 | 61 | 11/15 | 3/4 |
|  | 5 | 25.5 | 8 | 15 | 28 | 8/15 | 1/4 |
|  | 6 | 16.5 | 6 | 15 | 12 | 6/15 | 1/4 |

The table counts alerts by (entity, day), so a few coincidental same-host matches may sit in "On attack items". The per-item table above was checked against evidence.

**Unlabeled alerts outside the scenarios, 30-day plane, over 10 days:**
- auth Z: 2 unlabeled in 10 days (charles.hardy, Oct 26–27).
- process Z: 4 unlabeled, including a Windows telemetry burst on the PT-1 host.
- CUSUM: 4, 4 and 1 unlabeled alarms for the three anchors, mostly machine accounts with sustained higher volume.

The short-window rarity and profile models carry the alert cost: hour-of-day 33/day, Zipf 21/day, Markov 18.5/day. For scale, the tenant's existing rules average **212 alerts/day** (Oct 20–27).

**The other §9 items:**
- **Overlap with rules.** Rules caught 2 of 13 injected techniques, N1 and N2, and the harness caught both too. The harness alone caught 10 more injected techniques plus one onset. DNS was caught by neither. Rules also fire daily on the persistent simulated attacks.
- **Behavior through change (rollout).** Per-user Z raised 13 alerts on the rollout day. Cohort-normalized ΔZ raised none of them and kept the targeted user. Cost: ΔZ also dropped S2 (+2.5σ) below threshold.
- **Persistent simulated attacks (PT-1..5).** The 30-day plane flagged the persistent activity on **0 of 10 days**. Its one hit on a PT host was an unrelated telemetry burst. Rarity models flagged all five on both days they ran, for example mimikatz.exe on activedir. That's rule-like behavior, as §5 predicts.
- **Design comparison, Z vs MAD.** On Oct 29, MAD raised 26 alerts; 22 of them sit at its saturation value on constant-volume accounts (e.g. 75 → 77 logins), including the noise-floor probe. Z with the √μ floor raised 3, all injected.
- **Noise floor.** On Oct 29, accounts at Z ≥ 2 numbered 11 with the √μ floor versus 27 with the old σ = 1 fallback. At Z ≥ 3 it's 3 versus 4; the extra one is the probe.
- **Evasion budget,** computed from live baselines for 350 accounts:
  - median 131 extra logins/day fit under the single-day threshold, 84% of the account's normal daily volume;
  - p10: 7 logins; p90: 8,466.

## Caveats to state in the paper
1. **Scale.** One demo tenant with simulated background, 15 labeled items, synthetic events. The numbers are illustrative, not benchmarks.
2. **Frozen baselines.** Events were back-dated, so `metrics.*` baselines didn't absorb the campaign. A live attacker's drift would partly inflate the baseline, which makes the drift results somewhat optimistic.
3. **Short-window baselines include campaign days.** Zipf, Markov and hour-of-day use 7-day raw windows, so repeated campaign activity lowers its own score.
4. **Hour-of-day counts by the hour,** so it also flags volume surges. Its hits on S1–S3, D1 and D3 are incidental; O is its designed hit.
5. **The 30-day network template keys on host names,** but the injected transfer (X) carried only an IP. The short-window model caught it. This is a campaign-design flaw, not a detector result.
6. **Young account population.** 72% (Oct 20) and 67% (Oct 25) of active login accounts had fewer than 7 baseline days, so the 30-day plane couldn't score them. That's a coverage limit to report.
7. **The CUSUM anchors were chosen after the first run** (reason above).
8. **Side effect.** The injected events raised real SIEM alerts and SOAR cases for N1 and N2 (critical; created 02:30Z). Close them as test activity; I didn't touch cases.

## Paste-ready text for §9 "How the example performs"
> We evaluated the example on one test tenant: a Google SecOps demo tenant with simulated background activity and about 380 active login accounts. We injected a labeled synthetic campaign of 4,636 events: 13 attack techniques, a simulated rollout across 14 accounts and a noise-floor probe, spread over ten days. Three techniques and one onset already present in the tenant were held out. All detectors ran at their default thresholds: 30-day detectors over the ten days, short-window detectors over the last two.
> - **Recall.** At least one detector found 13 of 15 labeled items on the day they occurred: 12 of 13 injected techniques and one of two onsets. The other onset fell on days the short-window detectors weren't run. Held-out recall was 3 of 4. The miss was DNS-tunnel-like lookups, which scored +1.4σ because only 11 benign names of similar length were available for comparison.
> - **Alert volume.** Each 30-day detector raised fewer than one unlabeled alert a day (0.2–0.6) outside the scenarios. Adding rarity and hour-of-day models raised recall from 9 to 13 of 15 and the volume to about 65 alerts a day, 48 of them unlabeled. That is the trade-off the curve in Table N lets readers price. For scale, the tenant's existing rules raise about 212 alerts a day.
> - **Overlap with rules.** The rules caught 2 of the 13 injected techniques, both also caught by the harness.
> - **Behavior through change.** During the simulated rollout, per-account scoring flagged 13 of 14 accounts. Cohort-normalized scoring flagged none of them and still flagged the targeted account.
> - **Noise floor.** The noise-floor probe stayed quiet (Z = 2.5). Under the previous σ = 1 fallback it would have scored 20.
> - **Drift.** With at least seven days of baseline, cumulative-sum drift detection alarmed on day 7–8 of a +1σ/day drift, day 2 of a +2σ/day drift and day 10 of a +0.5σ/day drift. On the same accounts without the injected events, it did not alarm.
> - **Persistent attacks.** The 30-day detectors didn't flag the tenant's persistent simulated attacks on any of the ten days. Rarity models flagged them daily, behaving like rules, as §5 predicts.
> - **Evasion budget.** Because the detectors are transparent, the evasion budget can be computed rather than probed. At the single-day threshold, the median account could add 131 logins a day unseen. As a share of each account's normal daily volume, the median budget was 84%.
>
> These are illustrative results from one tenant and a synthetic campaign, not a benchmark.

**For `[MODELS]`,** list the models exercised here, each with its formula in the run logs:
- standard Z-score with a √μ dispersion floor;
- cohort-normalized ΔZ;
- start-anchored cumulative sum (helper-computed);
- median-based robust Z, with the saturation caveat;
- per-binary process Z;
- Poisson burst / Fano dispersion;
- Zipf rarity;
- Markov transition rarity;
- character-entropy scoring (helper-computed);
- hour-of-day profile;
- outbound concentration.

## Files
- `scratch/ueba_eval/backdated/results/attribution.md`: per-item and configuration tables.
- `scratch/ueba_eval/backdated/results/macro_runs.md` and `micro_runs.md`: every query verbatim, with windows and baselines.
- `scratch/ueba_eval/backdated/results/macro_detections.json` and `micro_detections.json`: scorer input.
- `scratch/ueba_eval/backdated/results/rule_alerts.json`: rule alerts on ground-truth entities.
- `scratch/ueba_eval/backdated/results/auth_fleet_baseline_20261029_rows.json`: evasion-budget inputs.
- `scratch/ueba_eval/backdated/results/drift_users_series.json`: the drift counterfactual.

## Also from overnight
- **secops-regress re-run** of the 36 tests that failed the first pass:
  - risk-metrics: 16 of 26 now pass on both engines.
  - stats-hunter: 7 of 10 pass on both.
  - Still failing on the engine that loads the skill (agentapi): REG-P1-07 (periodic exfil, no `metrics.*` stage), REG-P1-16 (`stage auth_risk` token), REG-P1-17 ("Nominal Baseline" phrase) and SH-P1-10 (report sections).
  - Still failing on direct-MCP only, mostly gaps in that engine's thin prompt:
    - the Entity Graph D−2 window (REG-P0-01, -28, -42);
    - REG-P1-14 and -35;
    - an ASCII diagram instead of SVG (REG-P2-15);
    - SH-P1-04, -10 and -12;
    - plus one infrastructure error (REG-P1-41).
  - Not fixed yet.
- **Deferred until after the paper data:** the agentic_ueba update and the runbook regeneration. Nothing was edited in either repo.
- **The live 10-day campaign (Oct 29 → Nov 7) is not running.** No crontab was installed. The back-dated run produced tonight's data, and a live run would land on the same users. If you want a live follow-up, it needs fresh entities. The scripts are ready in `scratch/ueba_eval/live/`.
- **Tenant writes tonight:**
  - the 4,636 labeled campaign events;
  - 3 format-check events on a made-up host (`eval-format-check.invalid`, 192.0.2.250/.251; Oct 30 01:57Z).
- **Metrics job timing (your earlier question).** The job runs on fixed **UTC** schedules, in customer pools, twice a day: 00/12, 02/14, 04/16, 06/18, 08/20 or 10/22Z, depending on the pool. Each run computes the previous UTC day, bucketed by event time. It's still open whether back-dated events get counted; I'll check once gus-sdl's Oct 29 metrics land.
- **Cleanup when you're ready:** the pinned worktrees in `~/projects/.worktrees/campaign/`, the overnight WS0–WS9 worktrees, and the open SOAR cases from N1 and N2.
