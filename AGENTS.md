# AGENTS.md

Guidance for working in this repo. `README.md` explains what the daemon does
and how to deploy it; this covers how to change it without breaking it.

## Layout

One module per concern, and the tests mirror it one-for-one:

| module | owns | tests |
| --- | --- | --- |
| `main.py` | click CLI, `run_monitor`, one-shot commands | `tests/test_main.py` |
| `config.py` | `Settings` — every tunable | — |
| `log.py` | glog formatter | `tests/test_log.py` |
| `probe.py` | pinging, per-family verdict | `tests/test_probe.py` |
| `state.py` | `HealthState`, hysteresis, peer gate | `tests/test_state.py` |
| `metrics.py` | Prometheus registry | `tests/test_metrics.py` |
| `networkd.py` | drop-ins, `networkctl` | `tests/test_networkd.py` |
| `keepalived.py` | the track file | `tests/test_keepalived.py` |
| `ra.py` | RA building/sending, `/proc/net/if_inet6` | `tests/test_ra.py` |
| `actions.py` | the three switches a failover flips | `tests/test_actions.py` |
| `monitor.py` | the tick loop | `tests/test_monitor.py` |
| `server.py` | aiohttp app + the client used to poll a peer | `tests/test_server.py` |

`server.py` imports `Monitor` only under `TYPE_CHECKING` — `monitor.py` imports
`api_request` from it, so a runtime import would be circular.

Shared test fixtures live in `tests/helpers.py` (`make_settings`,
`IF_INET6_FIXTURE`).

**Patch where a symbol is looked up, not where it is defined.** `actions.py`
does `from .ra import send_ra_packet`, so a test must patch
`actions.send_ra_packet`; patching `ra.send_ra_packet` leaves the reference
`actions` already holds untouched and the test silently tests nothing.

## Checks

```bash
python3 -m venv /tmp/whc && /tmp/whc/bin/pip install -e '.[dev]'
/tmp/whc/bin/black wan_healthcheck/ tests/
/tmp/whc/bin/mypy --strict wan_healthcheck/
/tmp/whc/bin/pytest
```

All three run in CI and all must pass. `mypy --strict` is the real guard —
it has repeatedly caught call sites that batch edits missed.

The tests are plain `unittest`, so `python -m unittest discover -s tests -t .`
works too; pytest is just a nicer runner. `pytest-xdist` is a dev dependency
but **not** used in CI: measured at this suite size, `-n auto` takes 5.1s
against 1.8s serial, because worker startup dominates 83 fast tests. Revisit
if the suite grows.

No test needs root, real sockets, `ping`, or a live networkd.

## Design decisions that are intentional — do not "fix" them

- **Detection is per address family; the response is all-or-nothing.** Either
  family failing moves *both* stacks. Chosen for symmetry over a split-stack
  LAN, where IPv4 goes out one router and IPv6 the other with different NAT
  state and asymmetric return paths.
- **Per-family detection exists so single-family faults are noticed at all.**
  A flat majority across the targets cannot see them — with an even v4/v6
  split, a whole family failing is exactly half, which is within tolerance.
- **Hysteresis is asymmetric** (`fall` ~30s, `rise` ~5min). Failing over fast
  is cheap; flapping is not.
- **SIGTERM does not undo an active failover.** Stopping the daemon mid-outage
  must not silently restore a broken router. Use `wan_healthcheck fallback`.
- **Do not go back to firewalling the RAs.** An nftables OUTPUT drop returns
  `EPERM` to networkd, and `sd-radv` responds by stopping its RA timer
  *permanently* — silently, nothing logged, never resuming when the block
  lifts. That made IPv6 fail over but never fail back while IPv4 recovered
  normally: invisible without a packet capture.
- **`apply_networkd` needs both `network1.reload` and `.reconfigure` in
  polkit.** Granting only reconfigure fails at the reload step in the nastiest
  way — the drop-in is on disk so it looks applied, but networkd never re-read
  it, so IPv4 fails over and IPv6 does not.
- **`ensure_failover` rolls drop-ins back if `apply_networkd` raises**, or the
  next tick sees nothing missing, assumes the work is done, and leaves files
  networkd never read.
- **Deprecation RAs are sent *after* networkd goes quiet**, never before — an
  advert still in flight re-advertises the prefix at full lifetime and undoes
  the deprecation within seconds. `RouterLifetimeSec=0` is not a usable
  alternative for the same reason, and networkd cannot deprecate a DHCPv6-PD
  prefix itself (`[IPv6Prefix] PreferredLifetimeSec=0` is ignored for
  delegated prefixes — tested).
- **`write_track_file` compares stripped, not byte-exact.** systemd-tmpfiles
  seeds the file as a bare `0` with no trailing newline; an exact comparison
  rewrites it on the first armed tick and bumps the mtime `state_since()`
  reads, faking a transition.
- **`state_since` comes from the track file's mtime**, not an in-process
  timestamp, so it survives daemon restarts and resets at boot with the tmpfs.
- **The peer gate defaults open.** No `--peer-url` means no gating, so a
  single-router setup behaves as if it did not exist.
- **`--interface` defaults to empty (unbound).** A backup router relies on
  that to answer "do I have internet at all". Deployments should pass it
  explicitly either way so the unit is the source of truth, not this default.

## Gotchas

- **`--dry-run` never executes the networkd or RA paths** — it returns before
  touching a drop-in. A clean dry-run soak proves nothing about them. Exercise
  them for real once before relying on them.
- **Count RAs on the wire; do not trust the logs.** A successful `sendto` and
  a written drop-in both look fine while IPv6 has silently not failed over.
- **A stale `.mypy_cache` hides mypyc build failures.** mypyc type checks
  inside pip's isolated build env where only `[build-system] requires` exists,
  so that list must stay in sync with `project.dependencies`. Always
  `rm -rf build *.egg-info .mypy_cache` before reproducing a compiled build.
- Version is **CalVer** in `pyproject.toml`. Consumers installing from a
  branch may pin by commit rather than version, so a bump is not required for
  a change to ship — but bump it for anything worth calling a release.
