# Cherenkov — custom Zeek site policy
#
# Mounted into the container at:
#   /usr/local/zeek/share/zeek/site/local.zeek
#
# This intentionally does NOT load Zeek's full default local.zeek bundle
# (file extraction, geoip enrichment, every optional log stream). We only
# enable the log streams the detectors in §4 of the tech-stack doc actually
# consume. Add more @load lines here as new detectors need new signal —
# don't load things "because they might be useful."

@load base/protocols/conn      # conn.log       — every flow: 5-tuple, duration, bytes, state
@load base/protocols/dns       # dns.log        — query/response, used by the DGA/tunneling detector
@load base/protocols/http      # http.log       — request/response metadata, no payload
@load base/protocols/ssl       # ssl.log        — SNI, cert fields, TLS version (JA3 needs a package — see note below)
@load base/protocols/ssh       # ssh.log        — auth attempts, client/server version strings
@load base/frameworks/notice   # notice.log     — Zeek's own built-in anomaly notices
@load base/frameworks/software # software.log   — detected client/server software from banners

# JSON output instead of Zeek's default tab-separated format — this is what
# makes tailing these logs from streaming/event_processor.py straightforward
# (one json.loads() per line instead of a custom TSV parser).
@load policy/tuning/json-logs

# 1 hour is fine for local development. Tighten this once you're running
# the throughput benchmark so log rotation doesn't skew your latency numbers.
redef Log::default_rotation_interval = 1hr;

# TODO: set this to your actual replay/lab subnet once you have one.
# Affects local-vs-remote classification in conn.log and any fan-out /
# scan features that depend on knowing which side is "inside."
redef Site::local_nets += { 10.0.0.0/8, 192.168.0.0/16 };

event zeek_init()
	{
	print "cherenkov local.zeek loaded";
	}

# --- JA3 / JA3S note ---------------------------------------------------
# Unlike Suricata, stock Zeek does NOT compute JA3/JA3S out of the box.
# It needs the community package zeek/salesforce/ja3, installed via zkg
# (Zeek's package manager) and then @load'ed here. This is a real Tier B
# nice-to-have per the tech-stack doc, not a Tier A blocker — Suricata's
# eve.json already gives you JA3/JA3S/JA4 natively (enable it in
# suricata.yaml under app-layer.protocols.tls.ja3-fingerprints). Come back
# to this once the four statistical detectors are stable.
