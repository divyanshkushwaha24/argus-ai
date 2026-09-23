# Streaming Pipeline Failure — Root Cause & Remediation Report

**Prepared for:** Cherenkov project team
**Scope:** Why real-time detection produces zero alerts while batch mode works, and how to fix it
**Sources:** `root_cause_analysis.md` (live-traced bug report), `analysis_modes.md` (architecture design doc)

---

## 1. Summary

Batch mode works. Streaming mode does not — not because the streaming architecture is wrong, but because two pieces of it were built by different code paths that never agreed on a shared vocabulary for "features." The dashboard staying static is a downstream symptom of four separable bugs, one primary and three infrastructural. All four are fixable without a redesign.

| # | Bug | Severity | Effect |
|---|---|---|---|
| 1 | Detectors expect batch-CSV features; streaming events never get enriched with the equivalent live features | Critical (root cause) | Every detector returns `None` for every event |
| 2 | Suricata launched without `-c`, can't read its config, exits immediately | Critical | `eve.json` never created; event processor waits forever, silently |
| 3 | `db.py` caches its first DB connection forever, never retries Postgres | High | Dashboard permanently stuck reading stale SQLite data |
| 4 | Alert writer has no fallback and no startup health-check | Medium | Real detections silently vanish into a dead-letter queue if Postgres isn't ready at boot |

---

## 2. Bug 1 — Training/Serving Feature Skew (Root Cause)

### 2.1 The core concept

A single network event carries almost no signal on its own — "one SYN to port 443" is unremarkable. What makes something a port scan, a beacon, or exfiltration is a **pattern across many events over time** (200 ports from one source in 2 seconds; a connection every 5 seconds for an hour; a lopsided upload/download ratio). Before any detector can judge a single event, that event has to be converted into evidence about *recent behavior* — that conversion is what "feature extraction" means in this system.

Two independent things make that conversion possible, and it's worth being precise about what each one actually does:

- **Redis (the state layer)** provides the *memory* the system needs to answer "how many distinct ports has this source touched in the last 30 seconds" — a question that cannot be answered from any single event, because the answer depends on everything that happened recently, not on the event currently being looked at. Without a state layer, every event is judged in total isolation, and none of the six threats — which are all multi-event patterns — could ever be detected.
- **Normalization** (`normalize_suricata()` / `normalize_zeek()`) is pure translation: it renames a tool's wire-format field names (`dest_ip`, nested `tls.ja3.hash`) into one common internal vocabulary. It cannot create information that wasn't in the original event. It will never produce a "fan-out count," because that number doesn't exist inside any single event — only Redis-backed aggregation over time can produce it.

### 2.2 What actually goes wrong

The live-traced evidence in `root_cause_analysis.md` shows the pipeline correctly performing steps 1–3 below, and then silently failing to complete step 4:

1. A raw Suricata event arrives (wire-format JSON).
2. `normalize_suricata()` renames its fields into the common schema. No new information is created here — this step is a relabeling, not a computation.
3. `StateStore` genuinely computes the real aggregate features — fan-out counts, source-IP entropy, connection periodicity — and stores them as current Redis state.
4. **The event published downstream (`stream_event`) is built from the normalized event only.** The features computed in step 3 are never merged into it before `r.xadd(...)` publishes it.
5. `detector.evaluate()` receives an event that only ever had wire-format fields, looks for batch-only keys like `source_ip_count_in_file`, doesn't find them, and falls back to `dict.get(key, default)` defaults chosen to represent "nothing unusual."
6. Every threshold check evaluates against that default and comes back false. The detector correctly returns `None` for a "boring" input — the detector's logic is not broken; it has simply never been shown real evidence.

This is why the RCA's live test shows `Processed: 100 DDoS events, Detections triggered: 0` — not because the DDoS logic is wrong, but because it was never given anything but placeholder values to evaluate.

### 2.3 Why this happened: two definitions of the same feature

The deeper issue is that `generate_fresh_dataset.py` (the batch/training path) and `features/` (the streaming/state path) are **two separate, independently-written implementations of the same statistics.** One computes `source_ip_entropy_in_file` as a pandas aggregate over an entire CSV; the other computes an equivalent entropy incrementally in Redis under a different name. Nothing forces these two to agree, because they are not the same code. This is a well-known failure mode in production ML systems, usually called **training/serving skew**: the model is trained on features computed one way and served on features computed a different way, and the mismatch is invisible until the serving path runs for real.

The reframe that resolves this: `source_ip_count_in_file` is not conceptually different from a live fan-out count — it is the *same statistic* with the averaging window set to "the whole file" instead of "the last 30 seconds." Batch features are streaming features with an unusually wide window, not a different kind of feature.

---

## 3. Bug 2 — Suricata Fails to Start

`run_realtime.py` invokes `sudo suricata -i veth1 -l <path> -k none` with no `-c` flag. Suricata falls back to its default system config path (`/etc/suricata/suricata.yaml`), which the invoking user cannot read, and exits immediately with a permissions error. `eve.json` is never created.

Downstream, `event_processor.py`'s `follow()` loop (`while not os.path.exists(path): time.sleep(poll_interval)`) waits indefinitely with no timeout and no error surfaced — a second silent failure stacked on the first, which is why this bug is easy to miss: nothing crashes, nothing logs, the pipeline just never produces anything.

**Fix:** generate a minimal, valid `suricata.yaml` at startup (rule paths, `eve-log` output enabled, interface settings) and always pass it explicitly via `-c`.

---

## 4. Bug 3 — Dashboard Permanently Stuck on Stale Data

`db.py` caches its database connection in a module-level global the first time it's requested, and every subsequent call short-circuits straight to the cached object:

```python
_conn = None
def get_connection():
    global _conn
    if _conn is not None:
        return _conn   # never re-checked
    ...
```

If Postgres was unreachable at the very first call, `_conn` becomes a SQLite connection permanently — even once Postgres comes online, this function will never try it again. The dashboard isn't failing to refresh; it's correctly, faithfully displaying a completely different, frozen database (311 old batch rows) than the one the live pipeline is writing to.

**Fix:** don't treat a fallback connection as permanent. Re-attempt the primary connection on a short interval (or on every call, with lightweight caching), and reset `_conn = None` on any connection error so the next call retries cleanly.

---

## 5. Bug 4 — Real Detections Silently Discarded

The alert writer (`alerting/writer.py`) has no fallback at all — if Postgres isn't reachable at write time, it throws. `ReliableSink` retries three times, then routes the alert into a Redis dead-letter stream (`cherenkov:dlq`) that nothing consumes. This is a pure startup-ordering race: if detection workers start before Postgres is confirmed healthy, genuine detections are generated and then thrown away with no visibility.

**Fix:** health-check Postgres (and Redis) in `run_realtime.py` and block startup of any consumer/worker until both are confirmed reachable, rather than starting optimistically and hoping.

---

## 6. Remediation Plan

### 6.1 Immediate patch (unblocks alerts today)

In `event_processor.py`, capture the return values already produced by the feature functions (`fanout.record_connection_attempt()`, `entropy.record_dns_query()` / `record_destination_hit()`, `periodicity.record_connection()`, `fingerprint.check_ja3()`) and merge them into `stream_event` before `r.xadd(...)`. These functions already compute and return exactly the right numbers — the fix is capturing what's already there, not writing new feature logic.

### 6.2 Root fix (prevents this class of bug recurring)

1. **One feature implementation, two callers.** Rework `generate_fresh_dataset.py` to build its training CSV by replaying historical events through the same `features/` functions the streaming path uses, in timestamp order, rather than maintaining a separate pandas-based aggregation. Batch and streaming should call identical code with different window widths, never separate code.
2. **One feature vocabulary.** Retire the CSV-only key names (`source_ip_count_in_file`, `flow_state`, etc.) in favor of the `features/` module's actual output keys. Update detector `evaluate()` methods to read the new names.
3. **Fail loud, not quiet.** Replace silent `dict.get(key, default)` fallbacks in detector code with an explicit check that logs a warning (or increments a metric) when an expected feature key is missing. A missing feature should be visible within minutes, not discovered weeks later via a live trace.
4. **Health-gate startup.** `run_realtime.py` confirms Postgres and Redis are reachable, and that Suricata has actually produced a growing `eve.json`, before starting any downstream worker. This directly removes Bugs 3 and 4's failure window.
5. **Fix the Suricata invocation.** Generate a minimal `suricata.yaml` and always pass `-c` explicitly.
6. **Regression test using existing tooling.** The project already has labeled synthetic pcaps (`data/synthetic/*.pcap`) and a harness (`ingest/test_all_threats.sh`) built for exactly this kind of validation. Extend it into an end-to-end check: replay `ddos.pcap` through the live pipeline and assert at least one `DDoS` alert lands in Postgres. This turns "zero detections in production" from a live-debugging discovery into a test that fails in CI before it ever reaches a demo.

### 6.3 One documentation correction

`analysis_modes.md` states Redis Streams handle ">10,000 eps" as a given. The project's own constraints require throughput to be measured, not asserted (see `docs/throughput_benchmark.md`). Once the fixes above are in place and alerts are flowing, replace that figure with an actual measured number from a benchmark run.

---

## 7. What to verify after applying the fixes

- [ ] Replay `data/synthetic/portscan.pcap` live; confirm `distinct_ports_to_host` appears on the published stream event (not just in Redis state)
- [ ] Confirm at least one alert per threat type lands in `public.alerts` after a full six-threat replay
- [ ] Kill Postgres mid-run, restart it, confirm the dashboard recovers without a process restart
- [ ] Start `run_realtime.py` with Postgres deliberately delayed; confirm workers wait rather than dropping alerts into `cherenkov:dlq`
- [ ] Confirm Suricata's own log (not just `event_processor.py`) shows a clean startup with the explicit `-c` config
