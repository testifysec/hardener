package pipeline

import (
	"fmt"
	"strings"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/vm"
)

// buildRPM packages the compiled .pp as <app>-selinux RPM inside the VM and
// returns the built RPM path (inside the VM). The .fc it ships is the one
// installPolicy wrote, which already omits base-policy collisions.
func buildRPM(r vm.Runner, p *profile.Profile, revision, te, fc string) (string, error) {
	app := policy.SafeName(p.Name)
	spec := GenerateSpec(p, revision)
	// Fail closed on a spec/FC mismatch. %post relabels every p.Paths root and
	// VERIFIES it receives the app type, but a path with no mapping in the shipped
	// .fc can never get that type — restorecon's verify fails and the RPM does not
	// install. The live pipeline trims base-policy-collided paths from p.Paths IN
	// PLACE before it derives BOTH the .fc and this spec, so they agree; this guard
	// makes that invariant explicit and refuses to package an RPM that would fail to
	// install if a caller ever shipped a collision-trimmed .fc with an untrimmed
	// profile (review finding — round 66). Executables are never trimmed: an
	// entrypoint collision is fatal earlier, so only data/config paths can diverge.
	for _, pa := range p.Paths {
		if !strings.Contains(fc, pa.Path+"\t") {
			return "", fmt.Errorf("internal: the RPM spec would relabel %q but the shipped file-contexts have no mapping for it — %%post's label verification would fail and the RPM would not install; refusing to package inconsistent policy", pa.Path)
		}
	}
	if err := r.WriteFile(fmt.Sprintf("/tmp/hardener/%s/%s-selinux.spec", app, app), spec); err != nil {
		return "", err
	}
	// Compile the PACKAGED .pp FRESH from the VERIFIED policy text (res.FinalTE/
	// res.FinalFC, passed by the caller — in-memory Go strings the guest cannot
	// touch) into a dedicated pkg dir, instead of copying the staged
	// /tmp/hardener/<app>/<app>.pp. A root-privileged exercise could have
	// overwritten that staged file AFTER enforcement, so copying it would package
	// unverified policy bytes while the loaded module stayed clean (review
	// finding). No exercise runs during packaging, and SELinux module compilation
	// is deterministic, so bytes written+compiled here are exactly what was
	// enforced. FAIL CLOSED if the write fails.
	pkg := fmt.Sprintf("/tmp/hardener/%s/pkg", app)
	if err := r.WriteFile(pkg+"/"+app+".te", te); err != nil {
		return "", err
	}
	if err := r.WriteFile(pkg+"/"+app+".fc", fc); err != nil {
		return "", err
	}
	// REMOVE any pre-existing build output before compiling, and force the rebuild.
	// `make <app>.pp` is timestamp-driven: a privileged exercise could pre-create
	// /tmp/hardener/<app>/pkg/<app>.pp (and the intermediate tmp/ artifacts) with a
	// FUTURE mtime, so make would consider the target up to date and skip
	// compilation — packaging attacker-supplied policy bytes while the RPM and the
	// verdict attest the verified .te/.fc we just wrote (review finding — round 68).
	// Deleting the outputs makes the rebuild unconditional regardless of clock skew.
	script := fmt.Sprintf(`set -e
mkdir -p ~/rpmbuild/{SOURCES,SPECS}
cd /tmp/hardener/%[1]s/pkg
sudo rm -rf tmp %[1]s.pp %[1]s.mod %[1]s.mod.fc
sudo make -f /usr/share/selinux/devel/Makefile %[1]s.pp
test -f %[1]s.pp
cp /tmp/hardener/%[1]s/pkg/%[1]s.pp ~/rpmbuild/SOURCES/
cp /tmp/hardener/%[1]s/pkg/%[1]s.fc ~/rpmbuild/SOURCES/
cp /tmp/hardener/%[1]s/%[1]s-selinux.spec ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/%[1]s-selinux.spec
`, app)
	out, err := r.Run(script)
	if err != nil {
		return "", err
	}
	// Parse rpmbuild's "Wrote: <path>" — the EXACT artifact just built. A wildcard
	// `ls %[1]s-selinux-*.rpm` returned the lexicographically-last match, which
	// could be a CACHED older RPM (a lower/empty revision), so the verifier could
	// hash and publish STALE policy bytes (review finding).
	rpmPath := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if p, ok := strings.CutPrefix(line, "Wrote:"); ok {
			if p = strings.TrimSpace(p); strings.HasSuffix(p, ".rpm") {
				rpmPath = p
			}
		}
	}
	if rpmPath == "" {
		return "", fmt.Errorf("could not determine the built RPM path from rpmbuild output:\n%s", out)
	}
	return rpmPath, nil
}

// GenerateSpec renders the RPM spec for the policy package. revision is a
// monotonically increasing build stamp (e.g. a UTC timestamp) that becomes part
// of the Release: two policy builds with different content must not share a
// NEVRA, or an `rpm -U` could keep the old confinement while a new verdict
// describes different bytes (review finding).
func GenerateSpec(p *profile.Profile, revision string) string {
	app := policy.SafeName(p.Name)
	execType := policy.TypeForKind(p.Name, policy.KindExec)
	if revision == "" {
		revision = "0"
	}
	// pruneUnder builds the find(1) prune expression that skips any OTHER declared
	// sub-root beneath root — those legitimately carry their own app type.
	pruneUnder := func(root string) string {
		prune := ""
		for _, pa2 := range p.Paths {
			other := fcRoot(pa2.Path)
			if other == "" || other == root {
				continue
			}
			if strings.HasPrefix(strings.TrimRight(other, "/")+"/", strings.TrimRight(root, "/")+"/") {
				prune += fmt.Sprintf("-path %s -prune -o ", vm.ShellQuote(other))
			}
		}
		return prune
	}

	// READ-ONLY PREFLIGHT — emitted into BOTH %pre and %post. Everything here only
	// INSPECTS state, so it can run before rpm commits anything: a failure in %pre
	// aborts the transaction cleanly, whereas the same failure in %post rolls back
	// the module but leaves the package recorded as installed, making a retry of the
	// same NEVRA a no-op and stranding the host without the intended confinement
	// (review finding — round 73). It is re-run in %post as a recheck, because state
	// can change between the two scriptlets.
	var preflight strings.Builder
	// Validate EVERY entrypoint's hard-link count BEFORE any restorecon. The root
	// relabels run `restorecon -RF` over whole trees, which can include an
	// entrypoint; checking per-entrypoint only at relabel time meant a shared inode
	// under a declared root was already relabeled before the check fired, and
	// rollback could not restore the label its other links expect (review finding).
	// A non-1 or unstattable count aborts before anything moves.
	for _, exe := range p.Executables {
		fmt.Fprintf(&preflight,
			"_e=%[1]s\n"+
				"if [ -e \"$_e\" ]; then _lc=$(stat -c '%%h' -- \"$_e\" 2>/dev/null); case \"$_lc\" in 1) : ;; *) printf 'ERROR: entrypoint %%s has hard-link count %%s (want exactly 1); refusing to relabel a shared inode\\n' \"$_e\" \"$_lc\" >&2; exit 1 ;; esac; fi\n",
			vm.ShellQuote(exe))
	}
	// PASS 2 — relabel the declared file-context roots and VERIFY the resulting
	// type. FAIL CLOSED when a root that EXISTS cannot be relabeled OR ends up with
	// a type other than the one its kind maps to: suppressing the error with `|| :`
	// let a data/config tree keep a broader base label while install "succeeded",
	// and a higher-priority file_contexts.local rule can apply a broader type while
	// restorecon still returns success (review finding). A root that does not exist
	// yet (a data dir the app creates on first run) is skipped, not an error.
	for _, pa := range p.Paths {
		root := fcRoot(pa.Path)
		if root == "" {
			continue
		}
		fmt.Fprintf(&preflight,
			"_r=%[1]s\n"+
				// The local file-context OVERLAP check runs REGARDLESS of existence: a
				// rule UNDER our root would mislabel files the app creates on first run,
				// so gating it on [ -e ] let a not-yet-created data dir install with a
				// latent broader label on its future contents (review finding). Capture
				// the listing and FAIL CLOSED on enumeration error — piping it straight
				// into awk|grep masked a semanage failure (review finding).
				"_lfc=\"$(semanage fcontext -C -l 2>/dev/null)\" || { printf 'ERROR: could not enumerate local file-contexts for %%s; refusing\\n' \"$_r\" >&2; exit 1; }; "+
				// Overlap is THREE-way, mirroring the verifier: reject a local rule whose
				// literal root EQUALS ours, is an ANCESTOR of ours (/var/lib(/.*)? over
				// /var/lib/widget), or a DESCENDANT (a rule under our root). The earlier
				// `grep "^$_r/"` caught only descendants, missing exact and ancestor rules
				// that also override our labeling (review finding). To compare a REGEX
				// local entry against our literal root, reduce it to its LITERAL STEM —
				// truncate at the first regex metacharacter — so ANY regex form collapses
				// to its fixed prefix: stripping only the exact `(/.*)?` suffix let an
				// ancestor like `/var/lib(/.+)?` (or `/var/lib/.*`, `/var/lib[0-9]`)
				// bypass the check and silently override our labels on a not-yet-created
				// root (review finding — round 67). Over-detection here is deliberate and
				// fails closed. Compare with slash-normalized index() in both directions.
				"_ov=$(printf '%%s\\n' \"$_lfc\" | awk -v r=\"$_r\" '$1 ~ /^\\// { p=$1; m=match(p, /[].^$*+?(){}|[\\\\]/); if (m>0) p=substr(p,1,m-1); while (length(p)>1 && substr(p,length(p),1)==\"/\") p=substr(p,1,length(p)-1); if (p==\"\") next; rp=r\"/\"; pp=p\"/\"; if (p==r || index(rp,pp)==1 || index(pp,rp)==1) { print p; exit } }'); "+
				"if [ -n \"$_ov\" ]; then printf 'ERROR: a local file-context rule (%%s) overlaps declared root %%s — it could override the app labeling; refusing\\n' \"$_ov\" \"$_r\" >&2; exit 1; fi\n"+
				// HARD-LINKED DESCENDANTS. `restorecon -RF` relabels by INODE, so a
				// multi-link regular file under a declared root silently retypes every
				// alias — including aliases OUTSIDE the root. With a writable app type
				// that hands the confined service access to an unrelated file (review
				// finding — round 73). Entrypoints were already checked this way; the
				// same standard now applies to everything a recursive relabel touches.
				// Directories are excluded (their link count is always >1 from
				// subdirectories); declared sub-roots are pruned as elsewhere. Fails
				// closed on a find error, and stops at the first offender.
				"if [ -e \"$_r\" ]; then _hl=$(find \"$_r\" %[2]s! -type d -links +1 -print -quit 2>/dev/null) || { printf 'ERROR: could not check for hard-linked files under %%s; refusing\\n' \"$_r\" >&2; exit 1; }; "+
				"if [ -n \"$_hl\" ]; then printf 'ERROR: %%s under declared root %%s is a hard link (link count > 1); relabeling it would retype every alias, including paths outside the root — refusing\\n' \"$_hl\" \"$_r\" >&2; exit 1; fi; fi\n",
			vm.ShellQuote(root), pruneUnder(root))
	}

	// MUTATION — relabel the declared roots and entrypoints, and VERIFY the
	// resulting types. Runs only in %post, after the read-only preflight above has
	// passed twice (once pre-commit, once here).
	var relabel strings.Builder
	for _, pa := range p.Paths {
		root := fcRoot(pa.Path)
		if root == "" {
			continue
		}
		wantType := policy.TypeForKind(p.Name, policy.KindFromString(pa.Kind))
		prune := pruneUnder(root)
		fmt.Fprintf(&relabel,
			"_r=%[1]s\n"+
				"if [ -e \"$_r\" ]; then restorecon -RF -- \"$_r\" || { printf 'ERROR: could not relabel declared root %%s; refusing to leave it under a broader label\\n' \"$_r\" >&2; exit 1; }; "+
				"_rl=$(stat -c '%%C' -- \"$_r\" 2>/dev/null); case \"$_rl\" in *:%[2]s:*) : ;; *) printf 'ERROR: declared root %%s is labeled %%s, not %[2]s — a higher-priority file-context rule is overriding it\\n' \"$_r\" \"$_rl\" >&2; exit 1 ;; esac; "+
				// Verify DESCENDANTS, not just the root: a more-specific BASE-policy rule
				// beneath a broad declared root retains a different label while the root
				// verifies correctly (review finding — the local-fcontext grep above only
				// catches LOCAL customizations, not base file_contexts). Prune legitimately
				// overlapping declared sub-roots, stop at the FIRST mismatch (-quit), and
				// FAIL CLOSED on a find error — mirrors the verifier-side check exactly.
				"_bad=$(find \"$_r\" %[3]s! -context '*:%[2]s:*' -print -quit 2>/dev/null) || { printf 'ERROR: could not verify descendant labels under %%s; refusing\\n' \"$_r\" >&2; exit 1; }; "+
				"if [ -n \"$_bad\" ]; then printf 'ERROR: descendant %%s under declared root %%s is not labeled %[2]s — a more-specific file-context rule is overriding it\\n' \"$_bad\" \"$_r\" >&2; exit 1; fi; fi\n",
			vm.ShellQuote(root), wantType, prune)
	}
	// PASS 3 — relabel + VERIFY each entrypoint. The label is load-bearing:
	// without _exec_t the domain transition never fires and the service runs
	// unconfined. restorecon also "succeeds" when a higher-priority local
	// file-context rule applies a different type, so verify the resulting type is
	// actually <app>_exec_t (review finding). Paths are single-quoted so a
	// manifest path can never inject shell into the customer's %post; "$_e" is a
	// variable expansion (never re-evaluated) and printf '%%s' prints it literally.
	for _, exe := range p.Executables {
		fmt.Fprintf(&relabel,
			"_e=%[1]s\n"+
				"restorecon -F -- \"$_e\" || { printf 'ERROR: cannot label entrypoint %%s; the service would run unconfined\\n' \"$_e\" >&2; exit 1; }\n"+
				"_lbl=$(stat -c '%%C' -- \"$_e\" 2>/dev/null); case \"$_lbl\" in *:%[2]s:*) : ;; *) printf 'ERROR: entrypoint %%s is labeled %%s, not %[2]s — a higher-priority file-context rule is overriding it; the service would run unconfined\\n' \"$_e\" \"$_lbl\" >&2; exit 1 ;; esac\n",
			vm.ShellQuote(exe), execType)
	}
	appPortType := policy.PortType(p.Name)
	// desired: a leading+trailing-spaced set of proto:port, EMPTY when the
	// profile declares no ports (so an upgrade to zero ports prunes everything).
	desired := " "
	for _, port := range p.Ports {
		desired += fmt.Sprintf("%s:%d ", port.Proto, port.Port)
	}
	// reconcile runs BEFORE `semodule -i` (a mapping under <app>_port_t that the
	// NEW module no longer defines would fail the load), and is emitted ALWAYS —
	// including for an empty desired set — so a dropped port is removed rather
	// than kept as undeclared bind privilege (review finding). Each removed
	// mapping is recorded in _pruned so rollback can restore it.
	// Capture the port listing and FAIL CLOSED if enumeration fails. Inlining
	// `$(semanage port -l | awk ...)` fails open: if `semanage port -l` errors,
	// the substitution is empty, the loop skips, and stale <app>_port_t mappings
	// (undeclared bind privilege) survive the upgrade (review finding). semanage
	// always lists many rows, so empty output is itself an enumeration failure.
	// Reconciliation may only delete a mapping we can PROVE was ours. Pruning every
	// <app>_port_t row assumed the previous package owned the type — but a PORTLESS
	// profile never declares <app>_port_t at all, so a foreign module can
	// legitimately own it. On upgrade the fresh-install ownership check is skipped,
	// so unconditional pruning silently deleted that foreign module's mappings, and
	// a successful upgrade sets _ok=1 so rollback never restored them (review
	// finding — round 76). Each build therefore ships its declared proto:port set as
	// <app>.ports; %pre stashes it to .oldports on upgrade (same mechanism as
	// .roots), and a row is pruned only when it appears there. A row we cannot prove
	// was ours is LEFT ALONE with a warning — never deleted. (If it genuinely
	// conflicts, semodule -i fails loudly, which is far better than destroying
	// unrelated policy.)
	reconcile := fmt.Sprintf(
		"_portlist=\"$(semanage port -l 2>/dev/null)\" || { echo \"ERROR: 'semanage port -l' failed during %[1]s port reconciliation; refusing to risk leaving an undeclared bind privilege\" >&2; exit 1; }\n"+
			"if [ -z \"$_portlist\" ]; then echo \"ERROR: 'semanage port -l' returned no output during %[1]s reconciliation; refusing to proceed\" >&2; exit 1; fi\n"+
			"_oldports=\" \"\n"+
			"if [ -f %%{_datadir}/selinux/hardener/%[3]s.oldports ]; then _oldports=\" $(tr '\\n' ' ' < %%{_datadir}/selinux/hardener/%[3]s.oldports) \"; fi\n"+
			"for _row in $(printf '%%s\\n' \"$_portlist\" | awk '$1==\"%[1]s\"{for(i=3;i<=NF;i++){gsub(\",\",\"\",$i); print $2\":\"$i}}'); do "+
			"case \"%[2]s\" in *\" $_row \"*) continue ;; esac; "+
			"case \"$_oldports\" in *\" $_row \"*) : ;; "+
			"*) echo \"warning: port mapping $_row under %[1]s was not declared by the previous %[3]s package; leaving it alone rather than deleting a mapping that may belong to another module\" >&2; continue ;; esac; "+
			"_pp=${_row%%%%:*}; _pn=${_row##*:}; "+
			"if semanage port -d -p \"$_pp\" \"$_pn\" 2>/dev/null; then _pruned=\"$_pruned $_row\"; "+
			"else echo \"ERROR: could not prune stale port $_row from %[1]s — refusing to leave an undeclared bind privilege\" >&2; exit 1; fi; done\n",
		appPortType, desired, app)
	// portsContent is this build's declared proto:port set, shipped as <app>.ports
	// so the NEXT upgrade can tell our mappings from a foreign module's.
	var portsContent strings.Builder
	for _, port := range p.Ports {
		fmt.Fprintf(&portsContent, "%s:%d\n", port.Proto, port.Port)
	}

	var ports strings.Builder
	var portsDel strings.Builder
	// %postun deletes our port mappings BEFORE `semodule -r`. Capture and VALIDATE
	// the listing ONCE up front: piping an unvalidated `semanage port -l` into
	// awk|grep is fail-OPEN — an enumeration failure reads as "mapping absent", the
	// deletion is skipped, and semodule -r then fails on the still-referenced type
	// while RPM removal "succeeds", leaving the module and a stale bind privilege
	// installed (review finding). semanage always lists many rows, so empty is a
	// failure; fail the uninstall if cleanup cannot be confirmed.
	if len(p.Ports) > 0 {
		fmt.Fprintf(&portsDel, "_pl=\"$(semanage port -l 2>/dev/null)\"\n")
		fmt.Fprintf(&portsDel, "if [ -z \"$_pl\" ]; then echo \"ERROR: cannot enumerate SELinux ports during %[1]s uninstall; refusing to leave a stale bind privilege — clean up manually\" >&2; exit 1; fi\n", appPortType)
	}
	for _, port := range p.Ports {
		// Add + verify, RECORDING only the ports we actually added (_added), so
		// rollback removes exactly this transaction's additions and never a
		// pre-existing mapping owned by another service. Fail CLOSED if the port
		// cannot land under our type. proto/port validated at load.
		fmt.Fprintf(&ports,
			"if semanage port -a -t %[1]s -p %[2]s %[3]d 2>/dev/null; then _added=\"$_added %[2]s:%[3]d\"; "+
				"elif ! semanage port -l | awk -v t=%[1]s -v p=%[2]s '$1==t && $2==p' | grep -qw %[3]d; then "+
				"echo \"ERROR: port %[3]d/%[2]s could not be assigned to %[1]s (already claimed by another SELinux type?); refusing to leave %[1]s bound to an unintended port type\" >&2; exit 1; fi\n",
			appPortType, port.Proto, port.Port)
		// Full removal for %postun, observable (round-18 finding).
		// `semanage port -d` rejects -t; delete by proto/port only, but ONLY after
		// confirming the mapping still belongs to OUR type — so uninstall never
		// removes a proto/port another service later claimed (review finding).
		fmt.Fprintf(&portsDel, "if printf '%%s\\n' \"$_pl\" | awk -v t=%[1]s -v p=%[2]s '$1==t && $2==p' | grep -qw %[3]d; then semanage port -d -p %[2]s %[3]d 2>/dev/null || { echo \"ERROR: could not remove port %[3]d/%[2]s mapping for %[1]s during uninstall — refusing to leave a stale bind privilege\" >&2; exit 1; }; fi\n",
			appPortType, port.Proto, port.Port)
	}
	// After the module is removed on uninstall, the app's files still carry the
	// now-UNDEFINED app types (<app>_exec_t, etc.) — leaving them labeled makes
	// the files inaccessible. Restore base labels via restorecon (the fc is gone
	// by then, so restorecon assigns the distro type). Messages name only the
	// app (SafeName), never a raw path, so uninstall cannot inject shell.
	var restore strings.Builder
	for _, root := range RelabelRoots(p) {
		fmt.Fprintf(&restore, "restorecon -RF -- %s 2>/dev/null || echo 'warning: could not restore some %s file labels after removal' >&2\n",
			vm.ShellQuote(root), app)
	}
	for _, exe := range p.Executables {
		fmt.Fprintf(&restore, "restorecon -F -- %s 2>/dev/null || echo 'warning: could not restore a %s entrypoint label after removal' >&2\n",
			vm.ShellQuote(exe), app)
	}
	// restoreStrict is the %postun variant. There, reducing a restorecon failure to
	// a warning let the erase SUCCEED while existing files kept now-undefined app
	// types — dangling labels that can make those files inaccessible, with the
	// module already gone and no obvious way back (review finding — round 75). A
	// path that no longer EXISTS is skipped (nothing to relabel); a path that exists
	// and cannot be relabeled fails the uninstall loudly. Best-effort remains
	// correct in the %post ROLLBACK paths above, which are already handling a
	// failure and must finish their remaining steps.
	var restoreStrict strings.Builder
	for _, root := range RelabelRoots(p) {
		fmt.Fprintf(&restoreStrict,
			"if [ -e %[1]s ]; then restorecon -RF -- %[1]s || { echo \"ERROR: could not restore base file labels under a %[2]s path after module removal; those files keep an undefined SELinux type and may be inaccessible — run: sudo restorecon -RF <path>\" >&2; exit 1; }; fi\n",
			vm.ShellQuote(root), app)
	}
	for _, exe := range p.Executables {
		fmt.Fprintf(&restoreStrict,
			"if [ -e %[1]s ]; then restorecon -F -- %[1]s || { echo \"ERROR: could not restore the base label on a %[2]s entrypoint after module removal; it keeps an undefined SELinux type and may be unexecutable — run: sudo restorecon -F <path>\" >&2; exit 1; }; fi\n",
			vm.ShellQuote(exe), app)
	}
	// rootsContent is the list of file-context roots this build labels, shipped
	// as <app>.roots so an upgrade can detect roots REMOVED from the profile and
	// restore their base labels (review finding).
	var rootsContent strings.Builder
	for _, root := range RelabelRoots(p) {
		rootsContent.WriteString(root)
		rootsContent.WriteString("\n")
	}
	return fmt.Sprintf(`Name:           %[1]s-selinux
Version:        1.0.0
Release:        1.%[5]s%%{?dist}
Summary:        SELinux confinement policy for %[1]s (generated by hardener)
License:        Apache-2.0
BuildArch:      noarch
Source0:        %[1]s.pp
Source1:        %[1]s.fc
Requires:       policycoreutils
Requires(post): policycoreutils policycoreutils-python-utils
Requires(postun): policycoreutils policycoreutils-python-utils

%%description
Machine-generated least-privilege SELinux policy module confining %[1]s.
Produced by the hardener pipeline from static analysis plus observed runtime
behavior, validated against the workload with SELinux Enforcing.

%%install
install -D -m 0644 %%{SOURCE0} %%{buildroot}%%{_datadir}/selinux/packages/%[1]s.pp
install -D -m 0644 %%{SOURCE1} %%{buildroot}%%{_datadir}/selinux/hardener/%[1]s.fc
mkdir -p %%{buildroot}%%{_datadir}/selinux/hardener
cat > %%{buildroot}%%{_datadir}/selinux/hardener/%[1]s.roots <<'HARDENER_ROOTS'
%[9]sHARDENER_ROOTS
cat > %%{buildroot}%%{_datadir}/selinux/hardener/%[1]s.ports <<'HARDENER_PORTS'
%[12]sHARDENER_PORTS

%%pre
# ABORTABLE PREFLIGHT (fresh install). These checks also run in %%post, but a
# %%post failure cannot undo the transaction: rpm has already committed the payload
# and the new NEVRA by then, so the install "fails" with files on disk and a DB
# entry that makes a retry of the same NEVRA a no-op. %%pre runs BEFORE the commit,
# so a non-zero exit here aborts the transaction cleanly and leaves nothing behind
# (review finding — round 69). Only read-only, abortable VALIDATION belongs here;
# activation stays in %%post (the remaining post-commit window is the recorded
# activation-design decision, not something a scriptlet can close).
if [ "$1" = 1 ]; then
    # A module with our name must not already exist on a FIRST install — it would
    # be foreign, and loading ours would shadow it (and a rollback would remove
    # it). Fail closed if the module list cannot be read.
    _preml="$(semodule -l 2>/dev/null)" || { echo "ERROR: 'semodule -l' failed; cannot confirm the %[1]s module is absent — refusing to risk shadowing a foreign module" >&2; exit 1; }
    if printf '%%s\n' "$_preml" | grep -qE "^%[1]s([[:space:]]|$)"; then
        echo "ERROR: a SELinux module named %[1]s already exists, but this is a fresh install; refusing to shadow a foreign module. Remove it first or build with a distinct name." >&2
        exit 1
    fi
    # A differently-named foreign module can already own our PORT type; the port
    # reconciliation in %%post would delete ITS mappings before semodule -i fails.
    _prept="$(semanage port -l 2>/dev/null)" || { echo "ERROR: 'semanage port -l' failed; cannot confirm %[7]s is unclaimed — refusing" >&2; exit 1; }
    if printf '%%s\n' "$_prept" | awk -v t=%[7]s '$1==t{f=1} END{exit !f}'; then
        echo "ERROR: SELinux port type %[7]s already has mappings but this is a fresh install; a foreign module owns it — refusing to disturb it. Build with a distinct name." >&2
        exit 1
    fi
fi
# On upgrade, stash the OLD roots list BEFORE the new payload overwrites it, so
# %%post can restore base labels on roots the new profile no longer claims
# (review finding). The stash lives in the package-owned, root-only directory
# /usr/share/selinux/hardener — NOT /tmp: a predictable /tmp path let a local
# user pre-plant a symlink and redirect the root-run cp/restorecon to an
# arbitrary file (review finding). rm any stale copy first so we never follow
# one left by a previously-failed upgrade.
if [ "$1" -ge 2 ] && [ -f %%{_datadir}/selinux/hardener/%[1]s.roots ]; then
    rm -f %%{_datadir}/selinux/hardener/%[1]s.oldroots
    # Fail closed: if the roots inventory exists but cannot be stashed, %%post
    # cannot reconcile removed roots, so an upgrade would silently retain stale
    # labels. Refuse the upgrade rather than proceed without the inventory
    # (review finding). (A pre-roots old version has no .roots file — the guard
    # above skips this and there is nothing to reconcile.)
    if ! cp %%{_datadir}/selinux/hardener/%[1]s.roots %%{_datadir}/selinux/hardener/%[1]s.oldroots; then
        echo "ERROR: could not stash the current file-context roots for upgrade reconciliation; refusing a non-atomic upgrade" >&2
        exit 1
    fi
fi
# Same for the declared PORT set: reconciliation may only delete a mapping the
# PREVIOUS package declared, so stash its inventory before the new payload
# overwrites it. A pre-.ports old version has no file — reconciliation then prunes
# nothing rather than risk deleting a foreign module's mappings (review finding).
if [ "$1" -ge 2 ] && [ -f %%{_datadir}/selinux/hardener/%[1]s.ports ]; then
    rm -f %%{_datadir}/selinux/hardener/%[1]s.oldports
    if ! cp %%{_datadir}/selinux/hardener/%[1]s.ports %%{_datadir}/selinux/hardener/%[1]s.oldports; then
        echo "ERROR: could not stash the current declared ports for upgrade reconciliation; refusing a non-atomic upgrade" >&2
        exit 1
    fi
fi
# Upgrade: snapshot the CURRENTLY-INSTALLED module here, in %%pre, so a snapshot
# failure aborts the transaction BEFORE rpm commits the new payload and NEVRA.
# Taking it in %%post meant a failed mktemp/semodule -E left the OLD policy active
# while the new .pp/.fc/.roots were already recorded as installed — and retrying
# the same NEVRA is a no-op (review finding — round 71). The old package is still
# installed at %%pre time, so semodule -E extracts exactly the module we may need
# to restore. Scriptlet variables do not survive into %%post, so the snapshot lives
# in the package-owned, root-only directory (never /tmp: a predictable temp path is
# a symlink-redirect target for a local user).
if [ "$1" -ge 2 ]; then
    rm -rf %%{_datadir}/selinux/hardener/%[1]s.snap
    mkdir -p %%{_datadir}/selinux/hardener/%[1]s.snap
    if ! ( cd %%{_datadir}/selinux/hardener/%[1]s.snap && semodule -E %[1]s ) 2>/dev/null; then
        rm -rf %%{_datadir}/selinux/hardener/%[1]s.snap
        echo "ERROR: could not snapshot the current %[1]s module for rollback; refusing a non-atomic upgrade" >&2
        exit 1
    fi
fi
# READ-ONLY filesystem/policy validation (hard-linked entrypoints and descendants,
# conflicting local file-contexts). Identical text runs again in %%post as a
# recheck; running it HERE means a failure aborts the transaction before rpm
# commits the payload and NEVRA, instead of "failing" an install that rpm still
# records as done — which makes retrying the same NEVRA a no-op and can leave the
# host without the intended confinement (review finding — round 73). Nothing below
# mutates state, so it is safe to run pre-commit.
%[10]s

%%post
# Fail closed WITH transactional rollback. Loading the module then failing
# entrypoint/port validation must not leave a partial, unverified policy active
# (review finding). Fresh install ($1 == 1): undo everything (restore the empty
# pre-install state). Upgrade ($1 >= 2): restore the PREVIOUS module and its
# labels rather than either keeping the rejected new module or leaving the
# service with none — a snapshot taken before replacement makes that possible.
_op=$1
_ok=0
_added=""
_pruned=""
# Snapshot the currently-installed module before replacing it (upgrade only).
# If the snapshot cannot be taken we ABORT before mutating anything — proceeding
# would make a later failure non-atomic (we could not restore the prior module),
# leaving an unverified, inconsistent policy active (review finding). This runs
# before the trap and any change, so aborting here leaves the prior state intact.
_snap=""
if [ "$_op" = 1 ]; then
    # Fresh install: a module with our name must NOT already exist. RPM reports a
    # first install, so any pre-existing module is FOREIGN — installed manually,
    # by the base policy, or by another package. Loading ours would silently
    # shadow it, and a rollback would remove it (semodule -r), destroying
    # unrelated policy. Refuse before mutating anything (review finding).
    # Capture the module list and FAIL CLOSED if enumeration fails. Piping
    # semodule -l straight into grep masks a semodule failure as "module absent"
    # (the pipeline status is grep's), so a broken query would let us overwrite a
    # foreign module (review finding). The name is followed by ANY whitespace or
    # end-of-line: older semodule prints "name\tversion" (tab), newer prints the
    # bare name. Matching a literal space only would miss the tab-delimited form
    # and let us shadow a foreign same-name module (review finding).
    _modlist="$(semodule -l 2>/dev/null)" || { echo "ERROR: 'semodule -l' failed on fresh install; cannot confirm the %[1]s module is absent — refusing to risk shadowing a foreign module" >&2; exit 1; }
    if printf '%%s\n' "$_modlist" | grep -qE "^%[1]s([[:space:]]|$)"; then
        echo "ERROR: a SELinux module named %[1]s already exists, but this is a fresh install; refusing to shadow a foreign module. Remove it first or build with a distinct name." >&2
        exit 1
    fi
    # A DIFFERENTLY-NAMED foreign module can already own our PORT type (%[7]s)
    # even when no same-name module exists — the module-name check above misses
    # it, unlike the verifier's all-generated-types conflict check. On a fresh
    # install we have never created %[7]s, so any existing mapping under it is
    # foreign; the reconciliation below would DELETE that mapping (mistaking it
    # for our own stale one) BEFORE semodule -i fails on the duplicate type,
    # corrupting unrelated policy. Refuse first. semanage (not seinfo) keeps this
    # portable to a minimal host that lacks setools (review finding).
    _pt="$(semanage port -l 2>/dev/null)" || { echo "ERROR: 'semanage port -l' failed on fresh install; cannot confirm %[7]s is unclaimed — refusing" >&2; exit 1; }
    if printf '%%s\n' "$_pt" | awk -v t=%[7]s '$1==t{f=1} END{exit !f}'; then
        echo "ERROR: SELinux port type %[7]s already has mappings but this is a fresh install; a foreign module owns it — refusing to disturb it. Build with a distinct name." >&2
        exit 1
    fi
else
    # Upgrade: the pre-upgrade module snapshot was taken in %%pre, BEFORE rpm
    # committed the new payload/NEVRA, so a snapshot failure aborted the whole
    # transaction cleanly instead of stranding us here with new files on disk and
    # old policy active (review finding). Verify it arrived and is non-empty —
    # rollback restores from it, so an absent or empty snapshot means we cannot
    # roll back and must refuse before mutating anything.
    _snap=%%{_datadir}/selinux/hardener/%[1]s.snap
    if [ ! -d "$_snap" ] || [ -z "$(ls -A "$_snap" 2>/dev/null)" ]; then
        echo "ERROR: the pre-upgrade %[1]s module snapshot is missing or empty; cannot guarantee rollback — refusing a non-atomic upgrade" >&2
        exit 1
    fi
fi
_rollback() {
    [ "$_ok" = 1 ] && return 0
    # Remove ONLY the port mappings THIS transaction added (while our type still
    # exists), never a pre-existing mapping owned by another service.
    for _row in $_added; do _rp=${_row%%%%:*}; _rn=${_row##*:}; semanage port -d -p "$_rp" "$_rn" 2>/dev/null || :; done
    if [ "$_op" = 1 ]; then
        # Fresh install: remove the REJECTED module, then restore base file labels.
        # VERIFY removal — suppressing the error let a partially-loaded rejected
        # module stay active, confining the app under UNVERIFIED policy (review
        # finding). CAPTURE the module list first: piping semodule -l straight into
        # grep is fail-OPEN — if the enumeration fails, grep finds no match and we
        # would treat an UNVERIFIABLE rejected module as removed (review finding).
        # semodule -l always lists many base modules, so empty output is a failure.
        # Testing emptiness ALONE is still fail-open: a semodule that fails partway
        # can exit nonzero having already printed some modules, and that partial list
        # will not contain ours — which reads as "removed" (review finding — round
        # 74). Capture the EXIT STATUS as well and treat any nonzero as unverifiable.
        semodule -r %[1]s 2>/dev/null || :
        _mlrc=0
        _ml="$(semodule -l 2>/dev/null)" || _mlrc=$?
        if [ "$_mlrc" != 0 ] || [ -z "$_ml" ]; then
            echo "CRITICAL: cannot verify removal of the rejected %[1]s policy module (semodule -l failed); it may still be loaded and confining the app under UNVERIFIED policy. Remove it manually: sudo semodule -r %[1]s" >&2
        elif printf '%%s\n' "$_ml" | grep -qE "^%[1]s([[:space:]]|$)"; then
            echo "CRITICAL: the rejected %[1]s policy module is still loaded after rollback; the application may be confined by UNVERIFIED policy. Remove it manually: sudo semodule -r %[1]s" >&2
        fi
%[6]s
    elif [ -n "$_snap" ]; then
        # Upgrade failure: reinstall the PREVIOUS module and re-apply its labels so
        # the prior working policy is back in place (review finding). VERIFY it
        # reloaded — suppressing the error left the app with the rejected new module
        # or NO module, i.e. running under unverified/absent policy while RPM only
        # reported failure (review finding).
        # A NAME check is insufficient here: the REJECTED new module shares our
        # name, so a semodule-l name grep passes even if restoration failed,
        # leaving the rejected policy active (review finding). Require the restore
        # command to SUCCEED, then verify the loaded module's CONTENT equals the
        # pre-upgrade snapshot by re-extracting it and diffing against $_snap.
        _restored=0
        if ( cd "$_snap" && { semodule -i %[1]s.cil || semodule -i %[1]s.pp; } ) 2>/dev/null; then
            _vfy="$(mktemp -d 2>/dev/null || true)"
            if [ -n "$_vfy" ] && ( cd "$_vfy" && semodule -E %[1]s ) 2>/dev/null && diff -rq "$_snap" "$_vfy" >/dev/null 2>&1; then
                _restored=1
            fi
            [ -n "$_vfy" ] && rm -rf "$_vfy" 2>/dev/null || :
        fi
        if [ "$_restored" != 1 ]; then
            echo "CRITICAL: restoration of the previous %[1]s policy module failed or its content did not match the pre-upgrade snapshot; the application has NO verified policy active. Restore it from the prior package immediately." >&2
        fi
%[6]s
        # Re-apply the PREVIOUS module's labels on ALL of its roots — including
        # any removed root already reset to base before the failure — so the
        # reinstated old module and the on-disk labels are consistent (review
        # finding). Restoring only the new profile's roots (the base-label restore
        # above) would leave already-restored removed roots mislabeled under the
        # old module.
        if [ -f %%{_datadir}/selinux/hardener/%[1]s.oldroots ]; then
            while IFS= read -r _oldroot; do
                [ -n "$_oldroot" ] || continue
                restorecon -RF -- "$_oldroot" 2>/dev/null || :
            done < %%{_datadir}/selinux/hardener/%[1]s.oldroots
        fi
    fi
    # RESTORE the port mappings THIS transaction pruned — in EVERY rollback path.
    # Reconciliation runs on fresh installs too (it prunes stale <app>_port_t
    # mappings a foreign/orphaned policy left behind), so a fresh-install failure
    # that only removed the module would otherwise permanently drop those
    # pre-existing mappings (review finding).
    for _row in $_pruned; do _rp=${_row%%%%:*}; _rn=${_row##*:}; semanage port -a -t %[7]s -p "$_rp" "$_rn" 2>/dev/null || :; done
    # (On upgrade $_snap is always set — we abort above if the snapshot fails.)
}
trap _rollback EXIT
# Reconcile ports BEFORE loading the new module (a mapping to a type the new
# module may not define would fail the load).
%[8]sif ! semodule -i %%{_datadir}/selinux/packages/%[1]s.pp; then
    echo "ERROR: semodule failed to load the %[1]s policy module; the application is NOT confined" >&2
    exit 1
fi
# RECHECK the read-only validation immediately before mutating labels. It already
# ran in %%pre (pre-commit, where a failure aborts cleanly), but state can change
# between scriptlets — so verify again here, right before the first restorecon.
%[10]s%[2]s%[3]s
# Reconcile REMOVED file-context roots BEFORE declaring success: any root the
# previous install labeled that the new profile no longer claims is restored to
# its base label — else the files keep a now-undeclared app type or a dangling
# one. A restore FAILURE fails the whole transaction so the trap rolls back;
# previously this ran AFTER _ok=1 and only warned, so an upgrade could "succeed"
# with obsolete labels and privileges still present (review finding). Consulted
# only on upgrade, from the root-only stash. The redirect (not a pipe) keeps the
# loop in this shell so a failed restore aborts the scriptlet and triggers rollback.
if [ "$_op" != 1 ] && [ -f %%{_datadir}/selinux/hardener/%[1]s.oldroots ]; then
    _newroots="$(cat %%{_datadir}/selinux/hardener/%[1]s.roots 2>/dev/null)"
    while IFS= read -r _oldroot; do
        [ -n "$_oldroot" ] || continue
        printf '%%s\n' "$_newroots" | grep -qxF "$_oldroot" && continue
        restorecon -RF -- "$_oldroot" || { echo "ERROR: could not restore removed root $_oldroot; rolling back the upgrade" >&2; exit 1; }
    done < %%{_datadir}/selinux/hardener/%[1]s.oldroots
fi
_ok=1
rm -f %%{_datadir}/selinux/hardener/%[1]s.oldroots
rm -f %%{_datadir}/selinux/hardener/%[1]s.oldports
# The %%pre snapshot has served its purpose once the upgrade succeeded. Removed
# only on SUCCESS: the rollback path restores from it, and leaving it after a
# failure keeps manual recovery possible.
rm -rf %%{_datadir}/selinux/hardener/%[1]s.snap

%%postun
if [ $1 -eq 0 ]; then
%[4]s    semodule -r %[1]s 2>/dev/null || :
    # VERIFY removal (idempotent: a re-uninstall of an already-absent module is
    # fine). Capture the list and fail closed if it cannot be read or our module
    # is still present — otherwise RPM removal "succeeds" while the module stays
    # installed (review finding). Emptiness alone is not enough: a semodule that
    # fails partway can exit nonzero having already printed some modules, and that
    # partial list will not contain ours — which reads as "removed" and lets the
    # uninstall restore base labels while the module is still loaded (review finding
    # — round 74). Capture the EXIT STATUS too and fail on any nonzero.
    _mlurc=0
    _mlu="$(semodule -l 2>/dev/null)" || _mlurc=$?
    if [ "$_mlurc" != 0 ] || [ -z "$_mlu" ]; then echo "ERROR: cannot verify %[1]s module removal during uninstall (semodule -l failed or returned nothing)" >&2; exit 1; fi
    if printf '%%s\n' "$_mlu" | grep -qE "^%[1]s([[:space:]]|$)"; then echo "ERROR: the %[1]s policy module is still installed after uninstall; remove it manually: sudo semodule -r %[1]s" >&2; exit 1; fi
    # Restore base file labels now that the app types are undefined, or the
    # files would be left with a dangling label and become inaccessible. Fails
    # CLOSED on an existing path that cannot be relabeled (absent paths skipped).
%[11]s
fi

%%files
%%{_datadir}/selinux/packages/%[1]s.pp
%%{_datadir}/selinux/hardener/%[1]s.fc
%%{_datadir}/selinux/hardener/%[1]s.roots
%%{_datadir}/selinux/hardener/%[1]s.ports
`, app, relabel.String(), ports.String(), portsDel.String(), revision, restore.String(), appPortType, reconcile, rootsContent.String(), preflight.String(), restoreStrict.String(), portsContent.String())
}
