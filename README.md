# hardener — automated SELinux policy compiler for legacy artifacts

Give it a legacy artifact (RPM, tarball, vendor binary). It determines the
minimum privileges the application actually needs, generates a proper SELinux
confinement policy with file labels, packages it as an installable RPM, and
**proves** the application still works with SELinux Enforcing — including
negative checks that the confinement is real.

```
artifact → analyze → synthesize policy → observe (permissive domain)
        → refine (relabel vs. allow — the audit2allow discrimination)
        → enforce → verify (positive + negative) → <app>-selinux.rpm
```

## Quickstart

```bash
# 1. A verifier VM: any RHEL-family guest with SELinux Enforcing.
limactl start template://almalinux-9 --name selinux-verifier
limactl shell selinux-verifier -- sudo dnf install -y \
  selinux-policy-devel policycoreutils-python-utils setools-console \
  audit checkpolicy rpm-build make && \
limactl shell selinux-verifier -- sudo systemctl enable --now auditd

# 2. Build and run against a manifest
go build -o bin/hardener ./cmd/hardener
./bin/hardener run --vm selinux-verifier --out reports targets/mosquitto.yaml

# 3. Read reports/mosquitto.md and reports/mosquitto.verdict.json
```

Any `vm.Runner` backend works; the Lima runner is what ships. The verifier
must match your deployment baseline — the verdict is scoped to it.

## Manifests are meant to be written by AI agents

The workload manifest is the one input that requires judgment, and it is the
input that bounds policy quality. This repo ships a skill —
[`skills/manifest-author/SKILL.md`](skills/manifest-author/SKILL.md) — that
teaches an AI agent (Claude Code or compatible) to inspect an artifact,
choose the filesystem layout, write a scenario-based exercise with the
retry/readiness idioms that actually work under `set -e`, pick the party
class, and iterate against the coverage cross-check in the report. Point your
agent at an artifact and the skill; review the manifest it produces the same
way you would review a test plan.

## Why this isn't just audit2allow

- **Mislabel vs. missing permission.** A denial whose target path falls under
  the module's own file-context claims but carries a generic label is a
  labeling problem — fixed with `restorecon`, never with an allow rule.
  `audit2allow` would happily emit `allow app_t var_lib_t:file write`, which
  grants access to *every* generically-labeled state file on the system.
- **Dangerous-rule review gate.** Privileged capabilities (`sys_admin`,
  `setuid`, `dac_override`, …) and sensitive targets (`shadow_t`,
  `selinux_config_t`, …) are never auto-applied silently; they are flagged in
  the report for human security review (`--accept-flagged` applies them for
  unattended runs but keeps the flag in the report).
- **Anti-cheat verification.** Passing requires all of:
  1. the systemd service starts and the workload exercise succeeds under
     **Enforcing**;
  2. the main process actually runs in the generated domain (`ps -o label=`)
     — a failed domain transition would otherwise leave the app unconfined
     and trivially "pass";
  3. zero residual AVC denials in the exercise window;
  4. static least-privilege assertions via `sesearch` (no `shadow_t` access,
     no `etc_t` write, no `sys_admin`/`sys_module`, domain not permissive).

## Failure classes the corpus surfaced

Every one of these was found by running real vendor artifacts, and each is now
detected and reported by name instead of appearing as a mystery failure:

| Class | Symptom without detection | What hardener reports |
|---|---|---|
| Symlinked entrypoint | Service runs unconfined; policy looks fine | Resolves `ExecStart` through symlinks before labeling (`nats-server` → `/usr/bin/nats-server`) |
| Mislabeled entrypoint | Service never starts; **zero denials** in the app domain | init_t denied execute on our content type ⇒ names the file and the fix (`emby`) |
| `NoNewPrivileges=yes` | Process silently stays in `init_t`, fails on its own files | Bounded-transition incompatibility, with remediation (`splunk-uf`) |
| Base-policy collision | `semodule` rejects the module: "Problems processing filecon rules" | Names the path and the base type already claiming it (`webmin`: `/var/webmin` is `var_log_t`) |
| Broken app/unit/test | Five wasted rounds, reported as a policy failure | Bails after round 1: permissive blocks nothing, so it is not a policy problem |
| Broad shared type | audit2allow-style over-permission ships silently | Flags `var_log_t`, `var_lib_t`, `tmp_t`, … as granting access to other apps' files |

The `emby` case is the one worth dwelling on: labeling the entrypoint as
content means the service can never start, so the confined domain generates
**no denials at all**. A tool that only watches its own domain reports that as
a clean run. That is why denials against our types from *any* source domain
are collected, and why a passing verdict requires proof of the domain
transition rather than absence of denials.

## Coverage: how we know the exercise tested enough

Dynamic observation under-approximates (it proves only what the exercise
drove); static analysis over-approximates (linking `setuid()` isn't calling
it). hardener uses both and reports the *difference*:

- `internal/elfscan` reads each entrypoint's dynamic symbol imports
  (`readelf --dyn-syms`) and predicts policy-relevant features:
  `bind/listen` → port-bind, `setuid/initgroups` → privilege-drop
  capabilities, `connect` → outbound network, `execve/system` → exec-other.
  On mosquitto this predicts the exact `setuid/setgid` capability pair the
  dynamic loop later observes — before ever running the binary.
- After verification, predictions with no corresponding grant in the final
  policy are reported as **coverage gaps**: behavior the binary is capable of
  that the exercise never drove. That is the honest answer to "did we test
  enough", per artifact, in the report.
- Statically linked binaries (most Go daemons) have no dynamic imports; the
  report says so explicitly instead of feigning confidence. The follow-up for
  that case is syscall-site disassembly (scan for `svc #0` sites and recover
  the syscall number register), and for full rigor, block-coverage
  measurement of the exercise itself under QEMU/Frida.
- Nondeterministic late paths are real: webmin's dashboard probed getty and
  hostname only under Enforcing, never in five permissive rounds. The
  enforce-phase now feeds residual denials back through refinement (bounded,
  progress-gated) instead of pretending one clean permissive run is proof.

## Supply-chain party classes

The pipeline applies a different contract per software origin (the
first/second/third-party taxonomy from supply-chain security guidance), set
via `party:` in the manifest. One comparison engine (`internal/conformance`)
serves all three; what differs is where the claimed privilege set comes from
and what a mismatch means.

| Party | Claim source | Mismatch means | Verdict |
|---|---|---|---|
| `third` (default) | none — the manifest is *your* claim | n/a; observation is discovery | current behavior; `declared:` compared advisorily if present |
| `second` | `declared:` block — the supplier's privilege declaration, deliverable with the artifact | supplier noncompliance or compromise | undeclared behavior **fails the run** |
| `first` | committed baseline file (`baselines/<name>.yaml`) — a privilege lockfile for your own code | drift from reviewed privilege envelope | drift **fails the run** until a human accepts it with `--update-baseline` |

The comparison is bidirectional: observed-but-undeclared behavior is the
violation/drift signal (capabilities and port binds rank high severity,
foreign type access medium); declared-but-unobserved behavior is reported as
a coverage gap or over-declaration, never fatal. For second-party software
this turns delivery acceptance into a checkable contract: the supplier's
declaration rides with the artifact, and the factory proves the software
stays inside it. For first-party software it gives CI snapshot-test
semantics for privilege: a developer whose change makes the app bind a new
port sees the build fail until the new privilege is reviewed and the
baseline updated.

## The verdict as an attestation

Every run emits `<target>.verdict.json` next to the report: an **unsigned
in-toto v1 Statement** whose subjects are the built policy RPM and the
`.te`/`.fc` (by sha256) and whose predicate
(`https://testifysec.com/attestations/hardener-verdict/v0.1`) is the
machine-readable verdict — pass/fail, every verification gate, the flagged
rules with dispositions, the conformance outcome per party class, coverage
gaps, and the exact verifier baseline (distro, kernel, policy package) the
claim is scoped to. A deploy gate needs nothing else to decide.

Signing and upload are **built in and strictly optional** — both off by
default:

```bash
# sign each verdict into a DSSE envelope (<target>.verdict.dsse.json)
hardener run --sign-key ed25519.pem --vm selinux-verifier targets/app.yaml

# ...and store it in an Archivista instance (yours or the hosted platform)
hardener run --sign-key ed25519.pem --archivista-url https://archivista.example \
  --vm selinux-verifier targets/app.yaml
```

The in-binary signer is deliberately minimal: ed25519 PKCS#8 keys, DSSE, no
key generation, no keyless flows. For keyless Fulcio signing, RFC 3161
timestamps, execution provenance (environment/material/product attestors),
and platform storage, wrap the run with CI/Lock instead — the two compose:

```bash
cilock run --step confine --workload manual -o envelope.json -- \
  hardener run --vm selinux-verifier --out reports targets/app.yaml
``` Note the semantics the fail
case demonstrates: a second-party artifact can pass *enforcement*
verification (the RPM builds) while the attestation records `"verdict":
"fail"` on the supplier contract — the artifact exists, and the deploy gate
refuses it.

## Layout

- `cmd/hardener` — CLI (`hardener run --vm <lima-instance> targets/*.yaml`)
- `internal/avc` — AVC denial parser (byte-offset capture of audit.log;
  `ausearch` time filtering proved unreliable)
- `internal/policy` — path classifier, `.te`/`.fc` generators, refine engine
- `internal/pipeline` — orchestration, static checks, RPM spec generation
- `internal/target` — per-app YAML manifest (install/setup/unit/exercise)
- `targets/` — the corpus manifests
- `reports/` — generated per-target reports (policy, checks, review flags)

## Verifier environment

A Lima VM (`limactl start template://almalinux-9 --name selinux-verifier`),
AlmaLinux 9 aarch64 with SELinux **Enforcing** (targeted policy), provisioned
with: `selinux-policy-devel policycoreutils-python-utils setools-console
audit checkpolicy rpm-build make epel-release` and auditd active. The
pipeline hard-fails if the verifier cannot observe (not Enforcing, auditd
down).

## Running

```bash
go build -o bin/hardener ./cmd/hardener
./bin/hardener run --vm selinux-verifier --out reports --accept-flagged targets/mosquitto.yaml
go test ./internal/...   # pure-logic unit tests, no VM needed
```

## Corpus

Mixed licensing, all freely downloadable, all Linux aarch64:

| Target | License class | Input form |
|---|---|---|
| mosquitto | open source (EPL-2.0) | EPEL RPM |
| caddy | open source (Apache-2.0) | tarball binary |
| gitea | open source (MIT) | vendor binary |
| minio | open source (AGPL-3.0) | vendor binary |
| nats-server | open source (Apache-2.0) | GitHub RPM |
| node_exporter | open source (Apache-2.0) | tarball binary |
| navidrome | open source (GPL-3.0) | tarball binary |
| victoria-metrics | open source (Apache-2.0) | tarball binary |
| webmin | open source (BSD-3) | noarch RPM (perl, 25-year-old codebase) |
| vault | source-available (BSL 1.1, not OSI) | vendor zip |
| plex | proprietary closed-source | vendor RPM |
| emby | proprietary closed-source core | vendor RPM |
| splunk-uf | proprietary closed-source | vendor RPM |

MongoDB was evaluated and dropped: the distro policy already defines
`mongod_t`, so it is outside the product's target class (already confined).

## Releases

Signed binaries ship from **dist.testifysec.com** (authenticated SFTP + web
portal; contact TestifySec for access). Every release is built by a
cilock-attested pipeline and arrives with everything needed to verify it
offline. All files are prefixed with the release name `<rel>` (e.g.
`hardener-0.1.0-linux-amd64`): the binary `<rel>`, its `<rel>.sha256`, an
in-toto/DSSE bundle `<rel>.intoto.tgz`, a signed verify policy
`<rel>.policy.json.signed` pinning the exact build workflow and tag, the
Fulcio/TSA roots `<rel>.fulcio-root.pem` / `<rel>.tsa-root.pem`, and the
`cilock` verifier `<rel>.cilock-linux-amd64` with its signed checksum
`<rel>.cilock-linux-amd64.sha256(.dsse)`.

**Step 1 — authenticate the verifier before running it.** Everything on the
dist host — the verifier, its checksum, the signature, AND the `*.fulcio-root.pem`
/ `*.tsa-root.pem` files — comes from the same place, so none of it is a trust
anchor: a compromised host could swap all of them and forge a chain that
validates against its own substituted roots. The anchor must come from an
**independent channel**. Authenticate the verifier out-of-band with a DSSE
verifier you already trust (an independently-obtained `cilock`, or `cosign`),
anchoring on **that tool's built-in roots, or the TestifySec Fulcio/TSA roots
obtained directly from TestifySec over an authenticated connection** — never the
host-shipped `*.pem`, and never the downloaded `cilock` checking itself. Run the
verifier only once both pass:

```bash
# (a) integrity — the pulled verifier matches its signed checksum
sha256sum -c <rel>.cilock-linux-amd64.sha256
# (b) provenance — verify <rel>.cilock-linux-amd64.sha256.dsse was signed by THIS
#     release identity, anchoring on roots from the INDEPENDENT channel above
#     (NOT the host-shipped *.pem, which are convenience copies to cross-check):
#       issuer   https://token.actions.githubusercontent.com
#       identity https://github.com/testifysec/judge/.github/workflows/release-hardener.yml@refs/tags/hardener-v*
# Reject the release if either check fails, or if the host-shipped roots do not
# match the independently-obtained ones.
```

**Step 2 — verify the artifact with the now-trusted verifier.** The shipped
`cilock` has the Fulcio/TSA roots and the pinned policy-signer identity compiled
in, so no `--policy-*` trust flags are needed and a policy signed by any other
identity is rejected:

```bash
mkdir attestations && tar -xzf <rel>.intoto.tgz -C attestations
chmod +x <rel>.cilock-linux-amd64
./<rel>.cilock-linux-amd64 verify <rel> \
  --policy <rel>.policy.json.signed \
  --attestations attestations/clone.attestation.json,attestations/build.attestation.json
```

Verification asserts the binary you hold was produced by the pinned release
workflow on the pinned tag pattern, keyless-signed via Fulcio with an RFC
3161 timestamp — no shared key material. Or skip all of it and build from
source; that is the point of the license.

## License

Apache-2.0. The corpus manifests download third-party software from vendor
sources at run time; each application remains under its own license.
