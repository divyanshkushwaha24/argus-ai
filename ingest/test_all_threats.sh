#!/usr/bin/env bash
#
# Cherenkov -- ingest/test_all_threats.sh
#
# Runs every synthetic pcap in data/synthetic/ through the live Zeek +
# Suricata pipeline in turn, saving each threat's logs into its own
# folder. This is the automated version of the manual 3-terminal-tab
# workflow -- same underlying steps, just looped over all six threats
# (plus the benign control) instead of one at a time.
#
# Prereqs:
#   - veth-tx / veth-rx already exist:
#       sudo ip link add veth-tx type veth peer name veth-rx
#       sudo ip link set veth-tx up && sudo ip link set veth-rx up
#       sudo ip link set veth-rx promisc on
#   - Zeek, Suricata, tcpreplay installed natively (apt), not via Docker
#   - data/synthetic/*.pcap generated: python3 ingest/generate_synthetic.py all
#
# Usage:
#   sudo bash ingest/test_all_threats.sh
#
# If a run doesn't clean up (Ctrl+C mid-script), recover with:
#   sudo pkill zeek; sudo pkill suricata

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE_RX="veth-rx"
IFACE_TX="veth-tx"
OUTBASE="$REPO/data/sample_logs"
PCAP_DIR="$REPO/data/synthetic"

THREATS=(benign ddos beacon dns_tunnel ja3_malware portscan exfil)

if ! ip link show "$IFACE_RX" >/dev/null 2>&1; then
  echo "Interface $IFACE_RX not found -- create the veth pair first (see header comment)."
  exit 1
fi

mkdir -p "$OUTBASE"

for name in "${THREATS[@]}"; do
  PCAP="$PCAP_DIR/$name.pcap"
  if [[ ! -f "$PCAP" ]]; then
    echo "skip $name -- $PCAP not found (run generate_synthetic.py first)"
    continue
  fi

  OUT="$OUTBASE/$name"
  mkdir -p "$OUT/zeek" "$OUT/suricata"
  echo "=== $name ==="

  ( cd "$OUT/zeek" && zeek -i "$IFACE_RX" local ) &
  ZEEK_PID=$!
  suricata -i "$IFACE_RX" -l "$OUT/suricata" &
  SURICATA_PID=$!

  sleep 2   # let both engines finish startup before traffic hits the wire

  tcpreplay --intf1="$IFACE_TX" --pps=1000 "$PCAP"

  sleep 2   # let both engines flush in-flight state
  kill "$ZEEK_PID" "$SURICATA_PID" 2>/dev/null || true
  wait "$ZEEK_PID" "$SURICATA_PID" 2>/dev/null || true

  echo "    zeek:     $OUT/zeek/"
  echo "    suricata: $OUT/suricata/eve.json"
done

echo ""
echo "Done. Per-threat logs under $OUTBASE/<threat_name>/"
