# Throughput Benchmark

Owner: Network Engineering
Status: methodology defined — numbers pending (target: Week 7-8)

Constraint (d) from the tech-stack doc: "Defined throughput target... tested,
not asserted." This document exists so that when we say a number on stage,
we can show exactly how we measured it.

## Method

1. Replay a known pcap at a fixed rate using `ingest/replay.sh replay
   <pcap> <interface> <rate-pps>`, which wraps `tcpreplay`.
2. Zeek and Suricata listen live on that interface for the duration of the
   replay.
3. Measure, per run:
   - **Sustained flows/sec** the pipeline processes without dropping packets
     (check Suricata's `stats.log` / `capture.kernel_drops` in eve.json, and
     Zeek's own `reporter.log` for dropped-packet warnings).
   - **End-to-end detection latency** — timestamp of the triggering packet
     in the pcap vs. timestamp on the resulting alert row in Postgres.
     Report the median and a high percentile (e.g. p95), not just an
     average — a single slow outlier shouldn't hide behind a mean.
4. Repeat at increasing rates until drops start, to find the actual ceiling
   — not just confirm the system survives one comfortable rate.

## Test hardware (fill in before reporting any number)

| Field | Value |
|---|---|
| CPU | |
| RAM | |
| NIC | |
| OS | |
| Zeek version | |
| Suricata version | |
| Docker / native | |

## Results

| Replay rate (pps) | Sustained flows/sec | Packet drops? | Median latency | p95 latency |
|---|---|---|---|---|
| | | | | |

## Language for the pitch

- ✅ "Sustained 12,000 flows/sec, median 340ms detection latency, measured
  on [hardware] with `tcpreplay`." (fill in real numbers, don't reuse the
  example)
- ❌ "Real-time" with no number behind it.
