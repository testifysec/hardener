---
name: manifest-author
description: Generate a hardener workload manifest for an application artifact (RPM, tarball, vendor binary). Use when the user asks to "write a manifest", "onboard an app to hardener", "confine <application>", or hands you an artifact to generate SELinux policy for.
---

# Authoring hardener workload manifests

A workload manifest tells hardener how to install, start, exercise, and stop
one application. **Manifest quality is policy quality**: behavior the exercise
never drives never reaches the policy, and the application will be denied that
behavior in production. Your job is to make the exercise representative, not
minimal.

## Process

1. **Inspect the artifact before writing anything.**
   - RPM: `rpm -qpl pkg.rpm` (file list), `rpm -qp --scripts pkg.rpm`
     (scriptlets you may need to replicate), look for unit files and default
     configs.
   - Tarball/binary: list contents; find the daemon binary, sample configs,
     any bundled unit file.
   - Read the vendor's install docs for: config location, state directory,
     log destination, listening ports, the user it expects to run as.
2. **Decide the filesystem layout.** Prefer the vendor's own paths. For bare
   binaries use `/opt/<app>/bin/<app>` with state in `/var/lib/<app>`, config
   in `/etc/<app>`, logs in `/var/log/<app>` — hardener derives SELinux types
   from these claims.
3. **Write the exercise as scenarios, not a ping.** Cover, at minimum:
   startup to readiness, one real unit of work per protocol the app speaks
   (a publish AND a subscribe; a write AND a read), anything that touches
   persistence, and — if cheap — a reload (`systemctl reload`/SIGHUP).
   Every behavior you skip is a denial waiting in production.
4. **Choose the party class** (see below) and add `declared:`/`baseline:`
   accordingly.
5. **Run hardener and read the report**, especially the coverage cross-check:
   `predicted but NOT observed` findings are your exercise's gaps — extend
   the exercise until the gaps are behaviors you consciously exclude.

## Hard-won rules (each of these cost us a corpus failure)

- **`set -e` + command substitution kills retry loops.** Any command whose
  failure you tolerate inside the exercise must end in `|| true`:
  `code=$(curl -s -o /dev/null -w '%{http_code}' URL || true)`.
- **Readiness is a bounded poll**, never a fixed sleep:
  ```bash
  ok=0
  for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:PORT/health >/dev/null 2>&1; then ok=1; break; fi
    sleep 0.5
  done
  [ "$ok" = "1" ]
  ```
- **Verify the response, not the transport.** Assert on status codes or body
  content you have actually observed (`/ping` may return a bare `.`, not "OK").
- **List the real entrypoint binaries** under `executables:`. hardener
  resolves symlinks and derives ExecStart itself, but helper binaries the
  daemon executes (scanners, tuners) belong in the list.
- **First run of stateful vendor software often needs a setup step** (seed
  passwords, license acceptance, database init) — do it in `setup:` so the
  observation rounds exercise steady-state, not first-boot.
- **Make setup idempotent** (`useradd ... || true`, guard unit generation
  with `[ -f ... ]`) — manifests get re-run.

## Manifest schema

```yaml
name: appname                 # becomes the SELinux domain: appname_t
license: open-source (MIT)    # informational, lands in the report/attestation
source: https://...           # where the artifact comes from
party: third                  # third (default) | second | first
install: |                    # bash; sudo available
  sudo dnf -y install /tmp/app.rpm
unit: appname.service         # systemd unit hardener starts/stops
unit_file: |                  # optional; written to /etc/systemd/system/
  [Unit]
  ...
setup: |                      # optional; users, dirs, config, first-run init
  sudo useradd -r -s /sbin/nologin app 2>/dev/null || true
executables:
  - /opt/app/bin/appd
paths:
  - { path: "/etc/app(/.*)?",     kind: conf }
  - { path: "/var/lib/app(/.*)?", kind: var_lib }
  - { path: "/var/log/app(/.*)?", kind: log }
ports:
  - { proto: tcp, port: 8443 }
exercise: |                   # bash; unit is running when this starts
  ...readiness poll, then real workload scenarios...
declared:                     # party: second only — the supplier's claim
  capabilities: [setgid, setuid]
  ports: [{ proto: tcp, port: 8443 }]
baseline: baselines/app.yaml  # party: first only — the committed lockfile
```

`kind` values: `conf`, `var_lib`, `log`, `runtime` (/run), `content`
(read-mostly application trees like /opt/app), `tmp`, `cache`.

## Party classes

- **third** (default): COTS/OSS artifact, no counterparty. Observation is
  discovery; privileged rules route to the review gate.
- **second**: contractor/supplier deliverable. Put the supplier's privilege
  declaration in `declared:`. Observed-but-undeclared behavior FAILS the run
  — that is the point; do not pad the declaration to make it pass.
- **first**: your own code. Set `party: first`; the first run with
  `--update-baseline` creates the privilege lockfile; subsequent drift fails
  CI until a human reviews and re-runs with `--update-baseline`.

## What NOT to do

- Do not write an exercise that only checks the process started — a policy
  derived from that confines nothing the app actually does.
- Do not add `capabilities:` or extra `paths:` to silence findings you have
  not understood; the review gate exists for a reason.
- Do not reuse another app's manifest with the names changed; the exercise
  must reflect THIS application's protocols and lifecycle.
