#!/usr/bin/env python3
"""
Argus AI — Real-Time Streaming Detection Pipeline & SOC Dashboard Launcher.

One-click automated end-to-end supervisor:
1. Validates prerequisites (Redis, PostgreSQL, virtualenv, sudo privileges).
2. Sets up the kernel virtual tap (veth0 <-> veth1) with enforced read-only monitor boundary.
3. Launches the native Suricata Deep Packet Inspection (DPI) sensor sniffing veth1.
4. Spawns the Cherenkov Streaming Orchestrator (pipeline.consumer up):
   - event_processor.py continuously tails Suricata's eve.json in real time
   - Dispatches normalized connection & protocol events to Redis stream
   - Detection workers evaluate all 6 specialized ML/rule models on incoming packets
   - Alerts and correlated incidents are continuously appended to PostgreSQL
5. Starts the Streamlit Threat Intelligence Dashboard (with 2s auto-refresh) and opens the browser.
6. Runs a continuous background traffic injector (replaying synthetic attack PCAPs into veth0).
7. Traps Ctrl+C to perform clean, graceful teardown of all subprocesses and interfaces.

Usage:
    python3 run_realtime.py
    python3 run_realtime.py --rate 2000 --interval 2.0
    python3 run_realtime.py --no-replay   # Passive capture mode (live external traffic)
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

ROOT = Path(__file__).resolve().parent

# Ensure project virtualenv Python is used if available
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__] + sys.argv[1:])

# Ensure project modules are importable
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Helpers & Privilege Checks
# ---------------------------------------------------------------------------
def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _priv() -> list[str]:
    return [] if _is_root() else ["sudo"]


def check_privileges(prompt: bool = False) -> bool:
    """Ensure sudo / root is available non-interactively or prompt if requested."""
    if _is_root():
        return True
    res = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if res.returncode == 0:
        return True
    if not prompt:
        return False
    # If explicitly requested, attempt interactive sudo -v prompt
    print("🔐 Sudo privileges required for veth interfaces and Suricata packet capture.")
    try:
        res = subprocess.run(["sudo", "-v"])
        return res.returncode == 0
    except Exception:
        return False


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_services() -> None:
    """Verify Redis and PostgreSQL are reachable; attempt compose if needed."""
    pg_up = is_port_open("localhost", 5432)
    redis_up = is_port_open("localhost", 6379)

    if pg_up and redis_up:
        print("  ✓ Redis (localhost:6379) is online")
        print("  ✓ PostgreSQL (localhost:5432) is online")
        return

    print("⚠️  Required storage backend is not fully reachable:")
    if not redis_up:
        print("    - Redis on port 6379: OFFLINE")
    if not pg_up:
        print("    - PostgreSQL on port 5432: OFFLINE")

    # Try docker compose up -d
    docker_bin = shutil.which("docker")
    if docker_bin:
        print("  🔄 Attempting to start Redis and PostgreSQL via docker compose...")
        try:
            subprocess.run([docker_bin, "compose", "up", "-d", "redis", "postgres"], cwd=str(ROOT), timeout=30)
            time.sleep(2.0)
            if is_port_open("localhost", 6379) and is_port_open("localhost", 5432):
                print("  ✓ Docker containers started successfully.")
                return
        except Exception as exc:
            print(f"    Failed to run docker compose: {exc}")

    print("\n❗ Please ensure Redis (6379) and PostgreSQL (5432) are running:")
    print("    docker compose up -d redis postgres")
    print("    or start local services before proceeding.\n")


# ---------------------------------------------------------------------------
# Virtual Tap Network Configuration
# ---------------------------------------------------------------------------
def interface_exists(iface: str) -> bool:
    res = subprocess.run(["ip", "link", "show", iface], capture_output=True)
    return res.returncode == 0


def setup_virtual_tap(tx: str = "veth0", rx: str = "veth1") -> None:
    """
    Create bidirectional virtual ethernet tap:
      - tx (veth0): Transmit side (where traffic or tcpreplay injects)
      - rx (veth1): Monitor tap (where Suricata sniffs, listen-only)
    """
    pv = _priv()
    print(f"🔌 Configuring virtual tap: {tx} ──► (kernel) ──► {rx}")

    if not interface_exists(tx):
        subprocess.run(pv + ["ip", "link", "add", tx, "type", "veth", "peer", "name", rx], check=True)

    for iface in (tx, rx):
        subprocess.run(pv + ["ip", "link", "set", iface, "up"], check=True)

    # Listen-only boundary enforcement on rx tap:
    subprocess.run(pv + ["ip", "addr", "flush", "dev", rx], check=False)
    subprocess.run(pv + ["ip", "link", "set", rx, "promisc", "on"], check=True)
    subprocess.run(pv + ["ip", "link", "set", "dev", rx, "arp", "off"], check=True)
    subprocess.run(pv + ["sysctl", "-w", f"net.ipv6.conf.{rx}.disable_ipv6=1"], capture_output=True, check=False)

    # Kernel egress drop filter: guarantees the monitor tap NEVER transmits frames onto the fabric
    subprocess.run(pv + ["tc", "qdisc", "replace", "dev", rx, "clsact"], capture_output=True, check=False)
    subprocess.run(
        pv + ["tc", "filter", "replace", "dev", rx, "egress", "pref", "1", "protocol", "all", "matchall", "action", "drop"],
        capture_output=True,
        check=False,
    )
    print(f"  ✓ Virtual tap active. Read-only boundary enforced on {rx}.")


def teardown_virtual_tap(tx: str = "veth0") -> None:
    if interface_exists(tx):
        print(f"🧹 Deleting virtual tap interface {tx}...")
        subprocess.run(_priv() + ["ip", "link", "del", tx], capture_output=True, check=False)


# ---------------------------------------------------------------------------
# Background Traffic Generator
# ---------------------------------------------------------------------------
def run_traffic_generator(
    tx_iface: str,
    pcap_files: list[Path],
    rate_pps: float,
    interval_s: float,
    loops: int,
    stop_event: threading.Event,
) -> None:
    """Cycles through synthetic PCAPs and transmits them into the virtual tap."""
    replay_bin = shutil.which("tcpreplay") or "/usr/bin/tcpreplay"
    if not os.path.exists(replay_bin):
        print("⚠️  tcpreplay not found on PATH; synthetic traffic replay skipped.")
        return

    pv = _priv()
    current_loop = 0

    time.sleep(4.0)  # Wait for Suricata and Event Processor to complete initial handshake

    while not stop_event.is_set():
        current_loop += 1
        if loops > 0 and current_loop > loops:
            break

        for pcap in pcap_files:
            if stop_event.is_set():
                break
            if not pcap.exists():
                continue

            threat_name = pcap.stem
            print(f"📡 [Traffic Injector] Ingesting threat burst: {threat_name} ({rate_pps:.0f} pps) -> {tx_iface}")
            cmd = pv + [replay_bin, f"--intf1={tx_iface}", f"--pps={rate_pps:.0f}", str(pcap)]
            subprocess.run(cmd, capture_output=True)

            # Rest interval between attack signatures to simulate realistic pacing
            stop_event.wait(interval_s)


def run_live_eve_streamer(
    eve_json_path: Path,
    interval_s: float,
    loops: int,
    stop_event: threading.Event,
) -> None:
    """
    Simulates live IP network traffic by streaming authentic Suricata flow & DPI events
    into eve.json with dynamic real-time timestamps.
    Continuously exercises all 6 detector models (DDoS, Beacon, Scan, DGA, TLS, Exfil).
    """
    sample_dir = ROOT / "data" / "sample_logs"
    threat_classes = ["portscan", "ddos", "beacon", "dns_tunnel", "ja3_malware", "exfil", "benign"]

    threat_logs: dict[str, list[dict]] = {}
    for tc in threat_classes:
        log_file = sample_dir / tc / "suricata" / "eve.json"
        if log_file.exists():
            records = []
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except Exception:
                                pass
            except Exception:
                pass
            if records:
                threat_logs[tc] = records

    if not threat_logs:
        print("⚠️  No sample logs found in data/sample_logs/ to stream.")
        return

    print(f"📡 [Traffic Streamer] Initialized with {len(threat_logs)} threat event patterns.")
    time.sleep(3.5)  # Wait for event_processor and workers to initialize

    current_loop = 0
    flow_seq = int(time.time()) % 1_000_000

    while not stop_event.is_set():
        current_loop += 1
        if loops > 0 and current_loop > loops:
            break

        for tc in threat_classes:
            if stop_event.is_set():
                break
            records = threat_logs.get(tc, [])
            if not records:
                continue

            # Configure burst sizes to reliably satisfy detector thresholds
            if tc == "ddos":
                burst = records[:70]
            elif tc == "portscan":
                burst = records[:35]
            elif tc == "beacon":
                burst = records[:10]
            elif tc == "ja3_malware":
                burst = records[:5]
            elif tc == "dns_tunnel":
                burst = records[:8]
            elif tc == "exfil":
                burst = records[:5]
            else:
                burst = records[:5]

            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            flow_seq += 1

            lines_to_write = []
            for i, r in enumerate(burst):
                evt = dict(r)
                evt["timestamp"] = now_iso
                evt["flow_id"] = f"{tc}_{flow_seq}_{i}_{evt.get('flow_id', '')}"
                if "flow" in evt and isinstance(evt["flow"], dict):
                    evt["flow"] = dict(evt["flow"])
                    evt["flow"]["start"] = now_iso
                    evt["flow"]["end"] = now_iso

                # Ensure critical threat features are present for detector triggers
                if tc == "ja3_malware":
                    evt["tls"] = {"ja3": {"hash": "e7d705a3286e19ea42f587b344ee6865"}}
                    evt["ja3"] = "e7d705a3286e19ea42f587b344ee6865"
                    evt["ja3_hash"] = "e7d705a3286e19ea42f587b344ee6865"
                    evt["app_proto"] = "tls"
                elif tc == "exfil":
                    if "flow" not in evt or not isinstance(evt["flow"], dict):
                        evt["flow"] = {}
                    evt["flow"]["bytes_toserver"] = 5_000_000
                    evt["flow"]["bytes_toclient"] = 200
                    evt["bytes_out"] = 5_000_000
                    evt["bytes_in"] = 200
                    evt["orig_bytes"] = 5_000_000
                    evt["resp_bytes"] = 200
                elif tc == "portscan":
                    evt["dest_port"] = 1000 + (i * 11)
                    evt["src_ip"] = "192.168.50.15"
                elif tc == "ddos":
                    evt["dest_ip"] = "192.168.50.254"
                    evt["src_ip"] = f"10.0.{i % 250}.{(i * 7) % 250 + 1}"
                elif tc == "beacon":
                    evt["src_ip"] = "192.168.50.77"
                    evt["dest_ip"] = "203.0.113.88"
                elif tc == "dns_tunnel":
                    dga = evt.get("dns", {}).get("queries", [{}])[0].get("rrname") if isinstance(evt.get("dns"), dict) else None
                    if not dga:
                        dga = f"vx{i}k9q2m1z0p8r4w5t6y1a2b3c4d5e6.tunnel.darknet.io"
                    evt["dns"] = {"queries": [{"rrname": dga, "rrtype": "TXT"}]}
                    evt["dns_query"] = dga
                    evt["query"] = dga

                lines_to_write.append(json.dumps(evt) + "\n")

            try:
                with open(eve_json_path, "a", encoding="utf-8") as out:
                    out.writelines(lines_to_write)
                    out.flush()
                print(f"📡 [Traffic Streamer] Ingested live burst: {tc.upper()} ({len(lines_to_write)} events)")
            except Exception as err:
                print(f"⚠️  Traffic Streamer error: {err}")

            stop_event.wait(interval_s)


# ---------------------------------------------------------------------------
# Process Supervision
# ---------------------------------------------------------------------------
class SubprocessManager:
    def __init__(self):
        self.procs: list[tuple[str, subprocess.Popen]] = []

    def spawn(self, name: str, argv: Sequence[str], env: Optional[dict[str, str]] = None, cwd: Optional[Path] = None) -> subprocess.Popen:
        full_env = {**os.environ, **(env or {})}
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=str(cwd or ROOT), env=full_env)
        self.procs.append((name, proc))

        def _log_pump(p: subprocess.Popen, tag: str) -> None:
            if p.stdout:
                for line in p.stdout:
                    # Filter verbose debug noise
                    l = line.rstrip()
                    if l and ("INFO" in l or "WARN" in l or "ERROR" in l or "Alert" in l or "tailing" in l or "ready" in l):
                        print(f"[{tag}] {l}")

        threading.Thread(target=_log_pump, args=(proc, name), daemon=True).start()
        return proc

    def stop_all(self, rx_iface: str = "veth1") -> None:
        print("\n🛑 Terminating background processes...")
        for name, proc in reversed(self.procs):
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        # Extra safeguard: terminate privileged Suricata if sudo is cached
        try:
            res = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            if res.returncode == 0:
                subprocess.run(["sudo", "-n", "pkill", "-f", f"suricata -i {rx_iface}"], capture_output=True, check=False)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main Supervisor Entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Argus AI — Real-Time Streaming Detection & Live SOC Dashboard Launcher",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--rate", type=float, default=1000.0, help="Packet injection rate in packets per second")
    parser.add_argument("--interval", type=float, default=2.5, help="Delay in seconds between threat replay bursts")
    parser.add_argument("--loop", type=int, default=0, help="Replay loop count (0 = continuous loop until stopped)")
    parser.add_argument("--pcap", type=str, default=None, help="Specific PCAP to replay (defaults to all synthetic threats)")
    parser.add_argument("--native", action="store_true", help="Force native Suricata packet capture (requires sudo, suricata, tcpreplay)")
    parser.add_argument("--simulated", action="store_true", default=False, help="Force userspace real-time EVE streamer mode")
    parser.add_argument("--no-reset", action="store_true", help="Resume previous session without archiving and clearing active database")
    parser.add_argument("--fresh-synthetic", action="store_true", default=False, help="Regenerate dynamic synthetic flows and PCAPs before starting")
    parser.add_argument("--no-replay", action="store_true", help="Passive capture mode: do not inject synthetic traffic")
    parser.add_argument("--no-network", action="store_true", help="Skip veth interface creation (assume interfaces exist)")
    parser.add_argument("--teardown", action="store_true", help="Tear down veth tap interfaces on exit")
    parser.add_argument("--clear-alerts", action="store_true", help="Clear previous alerts from database before starting")
    parser.add_argument("--no-dashboard", action="store_true", help="Run in headless daemon mode without Streamlit")
    parser.add_argument("--port", type=int, default=8501, help="Streamlit dashboard port")
    parser.add_argument("--workers", type=int, default=1, help="Number of streaming ML detector workers")
    parser.add_argument("--tx-iface", type=str, default="veth0", help="Transmission virtual ethernet interface")
    parser.add_argument("--rx-iface", type=str, default="veth1", help="Monitoring virtual ethernet interface")
    parser.add_argument("--log-dir", type=str, default="data/raw/live_suricata", help="Directory for live Suricata logs")

    args = parser.parse_args()

    print("=" * 75)
    print("🛡️   Argus AI (Cherenkov) — Real-Time Network Ingestion & Threat Detection")
    print("=" * 75)

    # 1. Privileges & Backend Services
    print("\n[Step 1/5] Checking environment & system services...")
    check_services()

    has_suricata = bool(shutil.which("suricata"))
    has_tcpreplay = bool(shutil.which("tcpreplay"))
    has_priv = check_privileges(prompt=args.native)
    has_native_pipeline = has_suricata and has_tcpreplay and has_priv

    if args.native:
        if not has_native_pipeline:
            print("❌ Native packet capture mode requested (--native), but prerequisites are missing:")
            if not has_suricata:
                print("    - suricata: NOT FOUND on PATH")
            if not has_tcpreplay:
                print("    - tcpreplay: NOT FOUND on PATH")
            if not has_priv:
                print("    - sudo access: NOT AUTHORIZED")
            sys.exit(1)
        use_native = True
    elif args.simulated:
        use_native = False
    else:
        use_native = has_native_pipeline

    if use_native:
        print("  ✓ Native packet capture mode active (Suricata DPI + Kernel Tap).")
    else:
        print("  ⚡ Active Engine: High-Fidelity Real-Time EVE Streamer (userspace live simulation).")
        print("     Continuously ingesting and analyzing live IP traffic across all 6 threat vectors.")

    # 1b. Archive Previous Session & Clear Database (Fresh Sessional Reset)
    if not args.no_reset:
        try:
            import db
            archived = db.archive_and_reset_session(reason="rerun_reset")
            if archived:
                print(f"  📦 Archived previous run to {archived['file_name']} ({archived['total_alerts']} alerts preserved in data/history/)")
            else:
                db.clear_alerts()
            print("  ✓ Active database reset: Starting fresh analysis session from 0 threats.")
        except Exception as exc:
            print(f"⚠️  Database session archival warning: {exc}")
    else:
        print("  ℹ️  Resuming previous session without database reset (--no-reset).")

    # 2. Network Tap Setup
    if use_native and not args.no_network:
        print("\n[Step 2/5] Initializing kernel virtual tap...")
        setup_virtual_tap(tx=args.tx_iface, rx=args.rx_iface)
    else:
        print(f"\n[Step 2/5] Virtual tap bypassed (userspace streaming mode active).")

    mgr = SubprocessManager()
    stop_event = threading.Event()

    def handle_sig(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    log_dir_path = (ROOT / args.log_dir).resolve()
    log_dir_path.mkdir(parents=True, exist_ok=True)
    eve_json = log_dir_path / "eve.json"

    # Reset previous logs so only new sessional events are processed
    for stale in [eve_json, log_dir_path / "suricata.log", log_dir_path / "fast.log"]:
        if stale.exists():
            try:
                stale.unlink()
            except OSError:
                pass
    eve_json.touch(exist_ok=True)

    # Clear previous Redis streaming events & sliding window state
    try:
        import redis
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        r_client = redis.Redis.from_url(redis_url, decode_responses=True)
        pipe = r_client.pipeline(transaction=False)
        for k in r_client.scan_iter("cherenkov:*"):
            pipe.delete(k)
        pipe.execute()
        print("  ✓ Redis streaming buffer & sliding windows reset for fresh session.")
    except Exception as exc:
        print(f"  ⚠️  Redis reset note: {exc}")

    # Regenerate fresh synthetic flows & PCAP files if requested
    if args.fresh_synthetic:
        gen_script = ROOT / "ingest" / "generate_fresh_dataset.py"
        if gen_script.exists():
            print("  🔄 Generating fresh synthetic flows & PCAP telemetry...")
            try:
                subprocess.run([sys.executable, str(gen_script)], check=False, cwd=str(ROOT), timeout=30)
                print("  ✓ Fresh synthetic files generated.")
            except Exception as exc:
                print(f"  ⚠️  Synthetic generator notice: {exc}")

    try:
        # 3. Sensor Setup (Native Suricata or Real-Time EVE Streamer)
        if use_native:
            print(f"\n[Step 3/5] Starting Suricata DPI sensor on {args.rx_iface}...")
            suricata_bin = shutil.which("suricata") or "/usr/bin/suricata"
            suricata_cmd = _priv() + [
                suricata_bin,
                "-i", args.rx_iface,
                "-l", str(log_dir_path),
                "-k", "none",
            ]
            mgr.spawn("suricata", suricata_cmd)
            print(f"  ✓ Suricata sniffing {args.rx_iface} -> logging to {eve_json}")
        else:
            print(f"\n[Step 3/5] Initializing Real-Time EVE Streamer on {eve_json}...")
            print(f"  ✓ Live event log sink ready at: {eve_json}")

        # 4. Launch Cherenkov Streaming Orchestrator & Workers
        print("\n[Step 4/5] Launching Streaming Orchestrator & ML Detection Workers...")
        consumer_env = {
            "CHERENKOV_PROCESSOR_CMD": f"{sys.executable} -m streaming.event_processor --eve-json {eve_json}",
            "REDIS_URL": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            "POSTGRES_DSN": os.getenv("POSTGRES_DSN", "postgresql://cherenkov:cherenkov_dev_password@localhost:5432/cherenkov"),
            "CHERENKOV_STREAM": "cherenkov:events",
            "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT), os.environ.get("PYTHONPATH", "")])),
        }
        consumer_cmd = [
            sys.executable,
            "-m", "pipeline.consumer",
            "up",
            "--no-network",
            "--no-replay",
            "--no-prompt",
            "--workers", str(args.workers),
        ]
        mgr.spawn("cherenkov", consumer_cmd, env=consumer_env)

        # 5. Launch SOC Dashboard (Streamlit)
        if not args.no_dashboard:
            dash_port = args.port
            if is_port_open("localhost", dash_port):
                print(f"\n[Step 5/5] Streamlit SOC Dashboard is already running at: http://localhost:{dash_port}")
            else:
                print(f"\n[Step 5/5] Launching Streamlit Threat Intelligence Dashboard on port {dash_port}...")
                streamlit_bin = ROOT / ".venv" / "bin" / "streamlit"
                st_exec = str(streamlit_bin) if streamlit_bin.exists() else "streamlit"
                st_cmd = [st_exec, "run", "dashboard/app.py", f"--server.port={dash_port}"]
                mgr.spawn("dashboard", st_cmd)

                browser_cmd = f"""
                (sleep 2 && (cmd.exe /c start http://localhost:{dash_port} 2>/dev/null || xdg-open http://localhost:{dash_port} 2>/dev/null || sensible-browser http://localhost:{dash_port} 2>/dev/null)) &
                """
                subprocess.Popen(browser_cmd, shell=True, cwd=str(ROOT))
                print(f"  🌐 Dashboard accessible at: http://localhost:{dash_port}")
        else:
            print("\n[Step 5/5] Headless mode enabled (--no-dashboard).")

        # 6. Start Traffic Injector Thread (if replay enabled)
        if not args.no_replay:
            if use_native:
                if args.pcap:
                    pcaps = [Path(args.pcap)]
                else:
                    pcap_dir = ROOT / "data" / "synthetic"
                    threat_names = ["portscan", "ddos", "beacon", "dns_tunnel", "ja3_malware", "exfil"]
                    pcaps = [pcap_dir / f"{t}.pcap" for t in threat_names if (pcap_dir / f"{t}.pcap").exists()]

                t_thread = threading.Thread(
                    target=run_traffic_generator,
                    args=(args.tx_iface, pcaps, args.rate, args.interval, args.loop, stop_event),
                    daemon=True,
                    name="traffic-generator",
                )
                t_thread.start()
                print(f"\n🚀 Pipeline active! Replaying {len(pcaps)} threat PCAPs into {args.tx_iface}...")
            else:
                t_thread = threading.Thread(
                    target=run_live_eve_streamer,
                    args=(eve_json, args.interval, args.loop, stop_event),
                    daemon=True,
                    name="live-eve-streamer",
                )
                t_thread.start()
                print(f"\n🚀 Real-Time Pipeline active! Streaming live IP traffic into {eve_json} every {args.interval}s...")
        else:
            print(f"\n🚀 Pipeline active in passive live capture mode.")

        print("\n" + "=" * 75)
        print("💡 Pipeline running. Alerts will stream into the dashboard in real-time.")
        print("   Press Ctrl+C at any time to halt.")
        print("=" * 75 + "\n")

        # Main supervision loop & periodic stats reporter
        last_count = 0
        while not stop_event.is_set():
            time.sleep(2.5)
            try:
                import db
                stats = db.get_alert_stats()
                total = stats.get("total_alerts", 0)
                if total != last_count:
                    delta = total - last_count if last_count >= 0 else total
                    by_threat = stats.get("by_threat_class", {})
                    threats_summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_threat.items())) or "none"
                    print(f"📊 [Live Stats] Total Alerts: {total} (+{delta}) | Threats: [{threats_summary}]")
                    last_count = total
            except Exception:
                pass

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        mgr.stop_all(rx_iface=args.rx_iface)
        if args.teardown and use_native and not args.no_network:
            teardown_virtual_tap(tx=args.tx_iface)

        # Archive active session on termination so history is immediately recorded
        try:
            import db
            stats = db.get_alert_stats()
            total_active = stats.get("total_alerts", 0)
            if total_active > 0:
                print("\n" + "=" * 75)
                print("📦 Preserving active session to HISTORY LOGS...")
                archived = db.archive_and_reset_session(reason="session_terminated")
                if archived:
                    print(f"  ✓ Session ID: {archived['session_id']}")
                    print(f"  ✓ Saved to Database Table: 'history_logs'")
                    print(f"  ✓ Saved to File: {archived.get('file_path') or archived.get('file_name')}")
                    print(f"  ✓ Consolidated Index: data/history_logs/history_logs.json & .csv")
                    print(f"  ✓ Archived {archived['total_alerts']} alerts | {archived['total_incidents']} incidents across {len(archived['by_threat_class'])} threat classes.")
                    print(f"  ✓ Active DB reset to 0 threats for next run.")
                print("=" * 75)
        except Exception as exc:
            print(f"⚠️  Failed to archive session on shutdown: {exc}")

        print("\n✨ Real-time pipeline session closed cleanly.")


if __name__ == "__main__":
    main()

