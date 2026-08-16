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
	script := fmt.Sprintf(`set -e
mkdir -p ~/rpmbuild/{SOURCES,SPECS}
cd /tmp/hardener/%[1]s/pkg
sudo make -f /usr/share/selinux/devel/Makefile %[1]s.pp
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
	var relabel strings.Builder
	// PASS 1 — validate EVERY entrypoint's hard-link count BEFORE any restorecon.
	// The root relabels below run `restorecon -RF` over whole trees, which can
	// include an entrypoint; doing the per-entrypoint link check only in pass 3
	// meant a shared inode under a declared root was already relabeled before the
	// check fired, and rollback could not restore the label its other links expect
	// (review finding). A non-1 or unstattable count aborts before anything moves.
	for _, exe := range p.Executables {
		fmt.Fprintf(&relabel,
			"_e=%[1]s\n"+
				"_lc=$(stat -c '%%h' -- \"$_e\" 2>/dev/null); case \"$_lc\" in 1) : ;; *) printf 'ERROR: entrypoint %%s has hard-link count %%s (want exactly 1); refusing to relabel a shared inode\\n' \"$_e\" \"$_lc\" >&2; exit 1 ;; esac\n",
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
		wantType := policy.TypeForKind(p.Name, policy.KindFromString(pa.Kind))
		// Prune any OTHER declared sub-root under THIS root from the descendant
		// scan — those legitimately carry their own app type (mirror the
		// verifier-side installPolicy check).
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
		fmt.Fprintf(&relabel,
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
				// that also override our labeling (review finding). awk strips a trailing
				// (/.*)? with pure string ops (no fragile nested regex) and compares with
				// slash-normalized index() in both directions.
				"_ov=$(printf '%%s\\n' \"$_lfc\" | awk -v r=\"$_r\" '$1 ~ /^\\// { p=$1; if (length(p)>=6 && substr(p,length(p)-5)==\"(/.*)?\") p=substr(p,1,length(p)-6); while (length(p)>1 && substr(p,length(p),1)==\"/\") p=substr(p,1,length(p)-1); if (p==\"\") next; rp=r\"/\"; pp=p\"/\"; if (p==r || index(rp,pp)==1 || index(pp,rp)==1) { print p; exit } }'); "+
				"if [ -n \"$_ov\" ]; then printf 'ERROR: a local file-context rule (%%s) overlaps declared root %%s — it could override the app labeling; refusing\\n' \"$_ov\" \"$_r\" >&2; exit 1; fi\n"+
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
	reconcile := fmt.Sprintf(
		"_portlist=\"$(semanage port -l 2>/dev/null)\" || { echo \"ERROR: 'semanage port -l' failed during %[1]s port reconciliation; refusing to risk leaving an undeclared bind privilege\" >&2; exit 1; }\n"+
			"if [ -z \"$_portlist\" ]; then echo \"ERROR: 'semanage port -l' returned no output during %[1]s reconciliation; refusing to proceed\" >&2; exit 1; fi\n"+
			"for _row in $(printf '%%s\\n' \"$_portlist\" | awk '$1==\"%[1]s\"{for(i=3;i<=NF;i++){gsub(\",\",\"\",$i); print $2\":\"$i}}'); do "+
			"case \"%[2]s\" in *\" $_row \"*) : ;; "+
			"*) _pp=${_row%%%%:*}; _pn=${_row##*:}; "+
			"if semanage port -d -p \"$_pp\" \"$_pn\" 2>/dev/null; then _pruned=\"$_pruned $_row\"; "+
			"else echo \"ERROR: could not prune stale port $_row from %[1]s — refusing to leave an undeclared bind privilege\" >&2; exit 1; fi ;; esac; done\n",
		appPortType, desired)

	var ports strings.Builder
	var portsDel strings.Builder
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
		fmt.Fprintf(&portsDel, "if semanage port -l 2>/dev/null | awk -v t=%[1]s -v p=%[2]s '$1==t && $2==p' | grep -qw %[3]d; then semanage port -d -p %[2]s %[3]d 2>/dev/null || echo \"warning: could not remove port %[3]d/%[2]s mapping for %[1]s\" >&2; fi\n",
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

%%pre
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
    # Upgrade: snapshot the currently-installed module before replacing it. If the
    # snapshot cannot be taken we ABORT before mutating anything — proceeding would
    # make a later failure non-atomic (we could not restore the prior module),
    # leaving an unverified, inconsistent policy active (review finding). This runs
    # before the trap and any change, so aborting here leaves the prior state intact.
    _snap="$(mktemp -d 2>/dev/null || true)"
    if [ -z "$_snap" ] || ! ( cd "$_snap" && semodule -E %[1]s ) 2>/dev/null; then
        echo "ERROR: could not snapshot the current %[1]s module for rollback; refusing a non-atomic upgrade" >&2
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
        semodule -r %[1]s 2>/dev/null || :
        _ml="$(semodule -l 2>/dev/null)"
        if [ -z "$_ml" ]; then
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
%[2]s%[3]s
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

%%postun
if [ $1 -eq 0 ]; then
%[4]s    semodule -r %[1]s 2>/dev/null || echo "warning: could not remove the %[1]s policy module" >&2
    # Restore base file labels now that the app types are undefined, or the
    # files would be left with a dangling label and become inaccessible.
%[6]s
fi

%%files
%%{_datadir}/selinux/packages/%[1]s.pp
%%{_datadir}/selinux/hardener/%[1]s.fc
%%{_datadir}/selinux/hardener/%[1]s.roots
`, app, relabel.String(), ports.String(), portsDel.String(), revision, restore.String(), appPortType, reconcile, rootsContent.String())
}
