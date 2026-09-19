#!/usr/bin/env bash
#
# Cherenkov — ingest/replay.sh
#
# Two modes:
#
#   analyze  Run Zeek + Suricata directly against a pcap file. No live
#            interface, no tcpreplay, no host networking — works
#            identically on Windows/Docker Desktop, macOS, or Linux.
#            This is what you use for Weeks 1-2 development.
#
#   replay   Actually tcpreplay the pcap onto a real network interface
#            with Zeek/Suricata sniffing it live. This is the throughput-
#            benchmark mode (constraint (d) in the tech-stack doc) and
#            needs raw-socket access, which means a Linux box — the
#            ingest server the project eventually targets, not a Windows
#            dev laptop. Docker Desktop's networking model doesn't give
#            containers reliable raw access to a host NIC on Windows/macOS.
#
# Usage:
#   ./replay.sh analyze <pcap> [output-dir]
#   ./replay.sh replay  <pcap> <interface> [rate-pps]

set -euo pipefail

MODE="${1:-}"
PCAP="${2:-}"

if [[ -z "$MODE" || -z "$PCAP" ]]; then
  echo "Usage:"
  echo "  $0 analyze <pcap> [output-dir]"
  echo "  $0 replay  <pcap> <interface> [rate-pps]"
  exit 1
fi

if [[ ! -f "$PCAP" ]]; then
  echo "pcap not found: $PCAP"
  exit 1
fi

PCAP_ABS="$(cd "$(dirname "$PCAP")" && pwd)/$(basename "$PCAP")"
PCAP_DIR="$(dirname "$PCAP_ABS")"
PCAP_FILE="$(basename "$PCAP_ABS")"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$MODE" in
  analyze)
    OUTDIR="${3:-$REPO_ROOT/ingest_out/$(basename "$PCAP" .pcap)}"
    ZEEK_OUT="$OUTDIR/zeek"
    SURICATA_OUT="$OUTDIR/suricata"
    mkdir -p "$ZEEK_OUT" "$SURICATA_OUT"

    echo "==> Running Zeek on $PCAP_FILE"
    docker run --rm \
      -v "$PCAP_DIR:/pcap:ro" \
      -v "$REPO_ROOT/ingest/zeek_config/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro" \
      -v "$ZEEK_OUT:/data" \
      -w /data \
      zeek/zeek zeek -C -r "/pcap/$PCAP_FILE" local

    echo "==> Running Suricata on $PCAP_FILE"
    docker run --rm \
      -v "$PCAP_DIR:/pcap:ro" \
      -v "$SURICATA_OUT:/var/log/suricata" \
      jasonish/suricata:latest -r "/pcap/$PCAP_FILE" -k none

    echo "==> Done."
    echo "    Zeek logs:     $ZEEK_OUT"
    echo "    Suricata logs: $SURICATA_OUT/eve.json"
    ;;

  replay)
    IFACE="${3:-}"
    RATE="${4:-10000pps}"
    if [[ -z "$IFACE" ]]; then
      echo "replay mode needs an interface: $0 replay <pcap> <interface> [rate]"
      exit 1
    fi
    echo "==> [Linux only] Replaying $PCAP_FILE onto $IFACE at $RATE"
    echo "    Zeek/Suricata must already be listening on $IFACE before you run this —"
    echo "    this script only sends traffic, it does not start the listeners."
    sudo tcpreplay --intf1="$IFACE" --pps="${RATE%pps}" "$PCAP_ABS"
    ;;

  *)
    echo "Unknown mode: $MODE (expected 'analyze' or 'replay')"
    exit 1
    ;;
esac
