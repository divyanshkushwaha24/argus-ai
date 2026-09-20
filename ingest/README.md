# Ingest layer -- handoff notes

Owner: Network Engineering (traffic simulation + Zeek/Suricata capture)
Consumer: Streaming / event_processor.py + feature engineering

## What's here

```
ingest/
  replay.sh              tcpreplay wrapper -- offline pcap analysis or live replay
  generate_synthetic.py  Scapy generator for 6 threats + benign control
  test_all_threats.sh    runs all 7 pcaps through live Zeek+Suricata, saves logs
  zeek_config/local.zeek Zeek policy: which logs are enabled, JSON output format

data/
  synthetic/              the 7 generated pcaps (committed, small)
  sample_logs/<name>/     ALREADY-CAPTURED output, ready to consume now:
    zeek/                 conn.log, dns.log, ssl.log, etc. (one JSON object per line)
    suricata/eve.json     Suricata's combined flow+alert stream (one JSON object per line)
```

`<name>` is one of: `benign`, `ddos`, `beacon`, `dns_tunnel`, `ja3_malware`, `portscan`, `exfil`.

## Quickest path: just start reading the logs

You don't need to install Zeek/Suricata/WSL2 to start writing `event_processor.py`. Pull the repo and point your code straight at `data/sample_logs/<name>/`:

```python
import json

with open("data/sample_logs/portscan/zeek/conn.log") as f:
    for line in f:
        event = json.loads(line)
        # event now has keys like: ts, uid, id.orig_h, id.orig_p,
        # id.resp_h, id.resp_p, proto, duration, orig_bytes,
        # resp_bytes, conn_state, ...

with open("data/sample_logs/ja3_malware/suricata/eve.json") as f:
    for line in f:
        event = json.loads(line)
        # event["event_type"] is one of: flow, alert, tls, dns, http, ...
        # TLS events carry event["tls"]["ja3"]["hash"] when present
```

Every log file is plain **JSON Lines** (one JSON object per line, no wrapping array) -- both Zeek's logs (via the `json-logs` policy) and Suricata's `eve.json` use this format, so the same `for line in f: json.loads(line)` pattern works on all of them.

## Regenerating everything yourself (once your own environment is set up)

If you want fresh data, or need to regenerate after the generator script changes:

```bash
git pull
docker-compose up -d          # Redis + Postgres, if you need them running too

# one-time interface setup (see ingest/test_all_threats.sh header for full prereqs)
sudo ip link add veth-tx type veth peer name veth-rx
sudo ip link set veth-tx up && sudo ip link set veth-rx up
sudo ip link set veth-rx promisc on

python3 ingest/generate_synthetic.py all
sudo bash ingest/test_all_threats.sh
```

This needs Zeek, Suricata, and tcpreplay installed natively (not via Docker -- see the comments in `test_all_threats.sh` for why). If you're only consuming the already-committed `data/sample_logs/`, you can skip all of this.

## What each threat's data represents

| Folder | Ground truth |
|---|---|
| `benign` | Normal short TCP conversations -- negative-class control |
| `ddos` | SYN flood, many spoofed source IPs, one target |
| `beacon` | Periodic low-volume connections to one destination (~5s interval) |
| `dns_tunnel` | High-entropy long subdomain TXT queries |
| `ja3_malware` | TLS sessions with a deliberately narrow, non-browser cipher/extension set |
| `portscan` | One source, ~200 destination ports on one host, tight timing |
| `exfil` | One connection, heavily skewed outbound:inbound byte ratio |

None of this is real malware traffic -- it's synthetic, built to exhibit the *statistical signature* each detector in `models/` is designed to catch, so you have labeled fixtures to develop and unit-test against before the real datasets (CICIDS2017/2018, CTU-13) are wired in.

## Known limitation

The synthetic pcaps are one-sided for most threats (no full realistic response traffic) -- that's intentional and matches how these attacks actually look on the wire, but it means some Zeek connections will show as incomplete (`conn_state: S0`). That's expected, not a bug in the capture.
