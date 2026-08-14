# wan_healthcheck

Simple Python pinger that moves keepalived and does graceful RA prefix/route
withdrawal per RFC 4861 — failing a LAN over to a backup router when the WAN
**degrades but stays up**.

The failure this exists for: your WAN keeps its DHCP lease, the link stays up,
the kernel default route sits there looking perfectly healthy — and no traffic
reaches the internet. Link-state checks, route-presence checks and dynamic
routing protocols all see a working uplink, so nothing fails over and clients
just time out.

`wan_healthcheck` probes the WAN for real and, once it has been unusable for
long enough, moves clients to your backup router — both the IPv4 default
gateway and the IPv6 one.

> **It routes nothing itself.** It flips three switches so that keepalived and
> systemd-networkd move traffic. It is only useful if you already run both —
> see [Requirements and setup](#requirements-and-setup).

## Topology

```
              Internet                              Internet
                 |                                     |
          +------+------+                    +---------+---------+
          | primary WAN |                    |    backup WAN     |
          +------+------+                    +---------+---------+
                 | wan0                                | wan0
                 |                                     |
   +-------------+-----------+          +--------------+----------+
   |    router A (primary)   |          |    router B (backup)    |
   |                         |          |                         |
   |  wan_healthcheck :42    |          |  wan_healthcheck :42    |
   |    ARMED                |          |    REPORT-ONLY          |
   |    probe: ping -I wan0  |          |    probe: unbound       |
   |                         |          |                         |
   |  VRRP prio 100  MASTER  |          |  VRRP prio 69   BACKUP  |
   |  RA RouterPreference=hi |          |  RA RouterPreference=lo |
   +------------+------------+          +------------+------------+
                |                                    |
                |  GET /api/v1/status  ------------> |  "is the backup
                |  (peer gate, every tick)           |   actually usable?"
                |                                    |
   =============+====================================+=============
                            LAN segment
                                   |
                          +--------+--------+
                          |   LAN clients   |
                          +-----------------+
                   IPv4 gateway: the VRRP VIP, held by whichever
                                 router is MASTER
                   IPv6 gateway: whichever router's RA wins on
                                 RouterPreference
```

On a sustained WAN failure — and only if the backup reports healthy:

```
  A stops + deprecates its RAs   ->  clients' IPv6 default router ages out
                                     and B's RA wins
  A writes track_file = 1        ->  VRRP 100 - 42 = 58 < 69, so B takes
                                     the IPv4 VIP
```

## How it works

Every 5s (configurable), `ping -c 3` at a set of targets — by default
Cloudflare and Google over both IPv4 and IPv6. `-I <interface>` pins the
probes to the WAN link, so they keep testing *that* uplink even after the
default route has moved, which is what makes recovery detection work.

**The verdict is per address family.** A target fails only if all 3 pings are
lost; a family (v4/v6) is down once the share of its targets failing reaches
`--family-fail-pct` (default 100, i.e. all of them); the round is unhealthy if
*either* family is down.

This is deliberately not a flat majority across all targets. With an even
split across v4 and v6, a family-wide outage — the WAN's IPv6 breaking while
IPv4 keeps working — is exactly half the targets, which sits on a majority
rule's tolerance boundary and would never trip it. At the default of 100%, one
provider having a bad day still cannot trip anything, because the other
provider answers in both families.

**Hysteresis is asymmetric on purpose.** `--fall 6` consecutive bad rounds
(~30s) to fail over, `--rise 60` good ones (~5min) to come back. Failing over
quickly is cheap; flapping is not.

On the degraded transition three things happen, all idempotent and re-asserted
every tick while degraded:

1. **Stop RAs** — write `IPv6SendRA=no` drop-ins under
   `/run/systemd/network/<network-file>.d/` and run `networkctl reload &&
   networkctl reconfigure`. networkd emits its own graceful RFC 4861 shutdown
   advert (router lifetime 0) on the way out, then falls silent.
2. **Deprecate the prefix** — send RAs with per-prefix **preferred lifetime 0**
   for the interface's global /64s. networkd's shutdown advert carries no
   prefix information, so without this clients keep the WAN-derived prefix as
   *preferred* and go on sourcing from an address whose uplink is dead. Sent
   *after* networkd goes quiet, or its next scheduled advert re-advertises the
   prefix at full lifetime and undoes the deprecation within seconds.
3. **Drop VRRP priority** — write `1` to the keepalived `track_file`.

Recovery reverses all of it: drop-ins removed, networkd reloaded so RAs
resume, track file back to `0`, keepalived preempts the VIP back.

### Why deprecating the prefix matters

RFC 6724 rule 5.5 ("prefer the next hop's prefix") is *optional* and
implementations differ — measured, macOS implements it and moves to a ULA by
itself, Linux does not and keeps the WAN-derived global. Rule 3 (avoid
deprecated addresses) is mandatory everywhere, so deprecation is the only
mechanism that moves every client regardless of OS.

## The peer gate

Failing over to a backup with no internet makes an outage worse — it just
moves everyone onto a second dead path. So the backup runs the same daemon in
**report-only** mode (`--dry-run`): it probes, logs, and serves
`/api/v1/status` and `/metrics`, but never touches RAs or VRRP.

The primary polls the backup's status endpoint each tick (`--peer-url`) and
refuses to fail over while it reports unhealthy, exposing that as
`wan_healthcheck_failover_suppressed` plus a "Holding position" log line.

Polled rather than pushed: it reuses an endpoint that already exists, needs no
staleness handling, and an unreachable peer naturally reads as "not a viable
failover target" — the safe answer. A transport blip is tolerated for `--fall`
consecutive polls; the peer's *verdict* is trusted directly, since it is
already hysteresis-smoothed by the peer's own fall/rise.

The backup should probe **unbound** (`--interface ""`). The question is "can
this router reach the internet by any path", not "is one specific link up" —
pinning it to a link reports the backup dead whenever that link is down even
though it has other routes, and that silently disables failover.

`wan_healthcheck failover` bypasses the gate — that is an operator saying "do
it anyway". Leave `--peer-url` unset to disable gating entirely.

## Requirements and setup

**The daemon does not route anything.** It probes a WAN and, on sustained
failure, flips three switches so that *other* software moves traffic:

| it does | so that |
| --- | --- |
| stops networkd's Router Advertisements | IPv6 clients stop using this router |
| sends deprecation RAs | they stop *immediately*, not after the RA lifetime |
| writes an int to a file keepalived watches | keepalived hands the IPv4 VIP over |

It is therefore only useful when all of the following are already true.

### 1. Two routers serving one LAN segment

Both must be able to serve the same clients, and be reachable to each other on
that segment (the peer gate polls over it).

### 2. The backup must be able to reach the internet

This is the requirement people miss. Either:

- the backup has its **own** WAN, or
- the two routers **exchange default routes**, so each can use the other's
  uplink — via a routing protocol, or a static floating route.

If you exchange routes, each router must prefer **its own** uplink over the
peer's, or you get a routing loop. With FRR that falls out for free: a live
kernel default from your own DHCP/RA lease is administrative distance 0 and
beats an eBGP-learned route at distance 20, so the peer's route is only
installed once yours disappears. With static routes, give the peer's default a
worse metric than your own.

The same applies to a metered last-resort link (a cellular modem, say): it
must be *less* preferred than the peer's route, or you burn data while a good
path exists. systemd-networkd's `RouteMetric=` packs two values into one
32-bit field — the top byte is an administrative distance override, the low
three bytes the metric — so `RouteMetric=4194305042` = `(250 << 24) | 1042`
gives distance 250, worse than everything else, while remaining a normal
metric-1042 route.

> The daemon steers **clients**, not the router itself. The primary keeps
> using its own broken uplink for its own traffic, because its kernel default
> route is still there at distance 0.

### 3. keepalived, for the IPv4 gateway

The primary needs a `track_file` block pointing at the daemon's weight file,
attached to every VRRP instance you want to move. **The weight must be large
enough** that `primary_priority - weight < backup_priority`, or nothing
happens when it fires.

```
global_defs {
    router_id primary
}

# The daemon writes 0 (healthy) or 1 (degraded) here.
track_file wan_health {
    file /run/wan_healthcheck/wan_weight
    weight -42
}

vrrp_instance LAN {
    state MASTER
    interface lan0
    virtual_router_id 69
    priority 100          # 100 - 42 = 58, below the backup's 69
    advert_int 5
    track_file {
        wan_health
    }
    virtual_ipaddress {
        10.0.0.1
    }
}
```

Backup: same `virtual_router_id` and VIP, `state BACKUP`, `priority 69`, and
**no** `track_file` — it has nothing to fail over to.

Do not set `init_file` on the track file: it resets the value to 0 on every
keepalived restart, briefly un-failing-over mid-outage. Seed the file with
tmpfiles.d instead. Leave preemption on (the default) so the primary takes the
VIP back when it recovers.

### 4. systemd-networkd, for the IPv6 gateway

**systemd-networkd only** — RA suppression works by dropping a config file
into networkd's drop-in directory. NetworkManager, ifupdown, radvd and bird
are not supported.

Both routers advertise; the preference steers clients:

```ini
# primary: /etc/systemd/network/10-lan0.network
[Match]
Name=lan0

[Network]
IPv6SendRA=yes

[IPv6SendRA]
RouterPreference=high
RouterLifetimeSec=30
```

Backup: identical but `RouterPreference=low`.

Keep `RouterLifetimeSec` short (30s is reasonable). The daemon sends explicit
lifetime-0 RAs so clients re-home in seconds, but the lifetime is your
backstop if the daemon is killed mid-failover.

### 5. polkit, so a non-root daemon can drive networkd

Both actions are required. Granting only `reconfigure` fails at the reload
step in the worst way — the drop-in is on disk so it looks applied, but
networkd never re-read it, so IPv4 fails over and IPv6 does not.

```javascript
// /etc/polkit-1/rules.d/50-wan_healthcheck.rules
polkit.addRule(function (action, subject) {
    if ((action.id == "org.freedesktop.network1.reload" ||
         action.id == "org.freedesktop.network1.reconfigure") &&
        subject.user == "wan_healthcheck") {
        return polkit.Result.YES;
    }
});
```

### 6. A user, and runtime directories it can write

```bash
useradd --system --shell /usr/sbin/nologin --no-create-home wan_healthcheck
```

`/run/systemd/network` is root-owned, so the drop-in directory for **each** RA
interface must be pre-created with the daemon as owner. The directory name is
the interface's `.network` filename plus `.d` — find it with:

```bash
networkctl --json=short status lan0 |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["NetworkFile"])'
```

```
# /etc/tmpfiles.d/wan_healthcheck.conf
d /run/wan_healthcheck 0755 wan_healthcheck wan_healthcheck -
f /run/wan_healthcheck/wan_weight 0644 wan_healthcheck wan_healthcheck - 0
d /run/systemd/network/10-lan0.network.d 0755 wan_healthcheck wan_healthcheck -
```

Everything is on `/run` (tmpfs) on purpose: a reboot wipes the drop-ins and
resets the weight, so the mechanism is **fail-open**. Apply with
`systemd-tmpfiles --create /etc/tmpfiles.d/wan_healthcheck.conf`.

Seeding the weight file matters — if it does not exist when keepalived starts,
keepalived logs `track file ... not found, ignoring` and runs untracked.

### 7. systemd units

Primary — armed, probes pinned to the WAN, gated on the backup:

```ini
# /etc/systemd/system/wan_healthcheck.service
[Unit]
Description=WAN health check
After=network-online.target systemd-networkd.service keepalived.service
Wants=network-online.target

[Service]
User=wan_healthcheck
Group=wan_healthcheck
ExecStart=/usr/local/venvs/wan_healthcheck/bin/wan_healthcheck \
  --interface "wan0" \
  --target-v4 1.1.1.1 --target-v4 8.8.8.8 \
  --target-v6 2606:4700:4700::1111 --target-v6 2001:4860:4860::8888 \
  --interval 5 --fall 6 --rise 60 \
  --ra-interface lan0 \
  --track-file /run/wan_healthcheck/wan_weight \
  --peer-url "http://[fd00:1::3]:42" \
  monitor
# CAP_NET_RAW: raw ICMPv6 socket for the deprecation RAs, and inherited by
#   the ping subprocess for -I binding.
# CAP_NET_BIND_SERVICE: only needed because 42 is a privileged port.
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/wan_healthcheck /run/systemd/network
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Backup — report-only, unbound probes, no peer:

```ini
ExecStart=/usr/local/venvs/wan_healthcheck/bin/wan_healthcheck \
  --dry-run \
  --interface "" \
  --target-v4 1.1.1.1 --target-v4 8.8.8.8 \
  --target-v6 2606:4700:4700::1111 --target-v6 2001:4860:4860::8888 \
  --interval 5 --fall 6 --rise 60 \
  --track-file /run/wan_healthcheck/wan_weight \
  monitor
```

### 8. Choosing probe targets

Use at least two providers across both address families. Targets must be
outside your own network — pinging your ISP's gateway proves nothing about
whether traffic reaches the internet, which is the whole failure mode this
exists for.

### 9. Check it before trusting it

```bash
# Both must exit 0. "Access denied ... interactive authentication" means the
# polkit rule is missing or misspelled.
sudo systemd-run --uid=wan_healthcheck --wait --pipe --quiet networkctl reload
sudo systemd-run --uid=wan_healthcheck --wait --pipe --quiet \
  networkctl reconfigure lan0

wan_healthcheck status          # does it see the peer?

wan_healthcheck failover        # force one and watch
ip -6 route show default        # on a LAN client: should be the backup now
wan_healthcheck fallback
```

`--dry-run` never touches networkd or sends RAs, so a clean dry-run soak does
**not** prove those paths work. Exercise them for real once before relying on
them.

## CLI

Global options go before the subcommand (`wan_healthcheck --dry-run failover`).

```bash
wan_healthcheck                  # default command: failover
wan_healthcheck fallback         # undo a failover
wan_healthcheck status [--json]  # query the running daemon
wan_healthcheck monitor          # the daemon loop (systemd runs this)
```

`failover`/`fallback` prefer the running daemon's REST API — they set or clear
a *forced* state the monitor loop respects, so a one-shot never fights the
daemon's next-tick re-assertion. Only when the API is unreachable (daemon
stopped) do they act on the drop-ins and track file directly.

`--dry-run` works with every command and executes nothing, logging what it
would have done.

## HTTP API and metrics

Served on `[::]:42` by default (`--port`).

- `GET /metrics` — Prometheus exposition
- `GET /api/v1/status` — JSON state document
- `POST /api/v1/failover` / `POST /api/v1/fallback` — set/clear forced state

No authentication. Bind it somewhere only your management network can reach.

| metric | meaning |
| --- | --- |
| `wan_healthcheck_failed_over` | 1 while traffic is on the backup — **the one to alert on** |
| `wan_healthcheck_healthy` | probe verdict |
| `wan_healthcheck_family_healthy{family}` | per address family |
| `wan_healthcheck_family_failing_pct{family}` | failing share, vs `_fail_pct_threshold` |
| `wan_healthcheck_peer_healthy` | is the backup usable (1 when no peer configured) |
| `wan_healthcheck_failover_suppressed` | degraded, but held back because the peer is no better |
| `wan_healthcheck_probe_success{target,family}` | last round, per target |
| `wan_healthcheck_failovers_total` | transitions into failed-over |
| `wan_healthcheck_last_state_change_timestamp_seconds` | from the track file's mtime, so it survives daemon restarts |

The daemon logs every transition and action, plus a heartbeat every
`--heartbeat-s` (default 300, 0 disables) so a log view has a pulse — without
it a healthy daemon is silent for days and looks broken.

## Suggested alerts

- **failed over** — `wan_healthcheck_failed_over > 0` for 5m. You are running
  on the backup.
- **backup unhealthy** — the backup's own `wan_healthcheck_healthy < 1` for
  5m. Nothing is broken for clients yet, but the redundancy is gone and
  failover will refuse to happen until it is fixed. Fix it *before* the
  primary needs it.
- **flapping** — `increase(wan_healthcheck_failovers_total[1h]) > 2`.

If you scrape both routers, label them (`router=a|b`) and scope anything
meaning "we acted" to the armed one — the report-only daemon going degraded is
input to the gate, not an incident, and unscoped aggregates false-fire.

## Install

```bash
python3 -m venv /usr/local/venvs/wan_healthcheck
/usr/local/venvs/wan_healthcheck/bin/pip install \
  git+https://github.com/cooperlees/wan_healthcheck
```

Set `WAN_HEALTHCHECK_MYPYC=1` during install to compile the module with mypyc
(needs a C compiler and Python headers). Optional — it installs as pure Python
otherwise.

## Development

```bash
python3 -m venv /tmp/whc && /tmp/whc/bin/pip install . mypy
/tmp/whc/bin/mypy --strict wan_healthcheck.py
/tmp/whc/bin/python -m unittest discover -s . -p 'test_*.py' -v
```

No test needs root, real sockets, ping, or a live networkd. Re-run
`pip install .` after editing — the venv holds an installed copy.

To reproduce the compiled build:

```bash
rm -rf build *.egg-info .mypy_cache   # a stale cache hides real errors
WAN_HEALTHCHECK_MYPYC=1 pip install .
```

mypyc type checks inside pip's isolated build environment, so the runtime
dependencies are also `[build-system] requires` in `pyproject.toml` — keep the
two lists in sync.

## Known limitations

- The daemon steers **clients**, not the router it runs on. The primary keeps
  using its own broken uplink for its own traffic.
- IPv6 suppression requires systemd-networkd.
- The backup's own RAs are not health-gated by report-only mode; it keeps
  advertising itself (at low preference) even if its own WAN is dead.

## License

MIT — see [LICENSE](LICENSE).
