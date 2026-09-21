# Architecture — Read-Only Network Boundary

Owner: Argus-AI
Status: draft — refine wording once the physical tap/mirror hardware is chosen

## 1. The core constraint

This system watches network traffic. It never sends any of its own.

Every component downstream of the tap can read what crosses the wire and can
write alerts to storage — but nothing in this pipeline has a socket, route,
or credential that lets it send a single packet back toward the monitored
network. That is not a coding convention enforced by review; it is a
property of the physical and network topology itself, verified below.

## 2. Topology

```
        PRODUCTION NETWORK
               │ real traffic
               ▼
      Mirror / Hardware Data Diode ── ONE WAY ONLY ──►
               │
               ▼
      Zeek + Suricata (passive parsing)
               │
               ▼
      Event processor → Redis sliding-window state
               │
               ▼
        Detectors → Fusion → Postgres → Dashboard
               │
               ▼
      Alerting egress (physically separate NIC / network path)
```

## 3. Why this is a network fact, not a code fact

- The ingest NIC is configured in **promiscuous / listen-only mode**, fed by
  a SPAN port or a hardware data diode. A SPAN port only replicates traffic
  to the monitoring port; a hardware diode is physically one-directional —
  there is no transmit path, even if software tried to use one.
- The ingest interface **has no IP address configured** for routing purposes
  (or, if the capture tooling requires one for setup, that address is not
  reachable from the monitored network — no route exists back to it).
- **Alerting egress is a physically separate network path** from ingest.
  The dashboard, alert writer, and any notification channel go out over a
  different NIC / different network segment than the one receiving mirrored
  traffic. This is the concrete answer to "how do you guarantee this can't
  be used to attack back into the network": there is no interface capable
  of doing so.
- No component past the tap holds a route, ARP entry, or open socket
  pointed at the monitored network's address space.

## 4. What "passive" actually means here (for the pitch)

- ✅ "We see everything crossing the mirrored link; we cannot inject,
  block, or respond on it."
- ✅ "Metadata only — no TLS/QUIC content inspection. JA3/JA3S/JA4, SNI,
  certificate fields, and size/timing statistics, not payload."
- ❌ Do not claim the system "blocks" or "stops" anything. Mitigation is
  explicitly out of scope by design.

## 5. Open items

- [ ] Confirm which hardware is actually used for the demo (SPAN port on a
      lab switch vs. an actual data-diode device) and update the diagram
      with real make/model once chosen.
- [ ] Document the alerting egress path's actual physical NIC/segment once
      the dashboard is deployed somewhere other than localhost.
