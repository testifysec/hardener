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
func buildRPM(r vm.Runner, p *profile.Profile, revision string) (string, error) {
	app := policy.SafeName(p.Name)
	spec := GenerateSpec(p, revision)
	if err := r.WriteFile(fmt.Sprintf("/tmp/hardener/%s/%s-selinux.spec", app, app), spec); err != nil {
		return "", err
	}
	script := fmt.Sprintf(`set -e
mkdir -p ~/rpmbuild/{SOURCES,SPECS}
cp /tmp/hardener/%[1]s/%[1]s.pp ~/rpmbuild/SOURCES/
cp /tmp/hardener/%[1]s/%[1]s.fc ~/rpmbuild/SOURCES/
cp /tmp/hardener/%[1]s/%[1]s-selinux.spec ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/%[1]s-selinux.spec
ls ~/rpmbuild/RPMS/noarch/%[1]s-selinux-*.rpm
`, app)
	out, err := r.Run(script)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return lines[len(lines)-1], nil
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
	for _, root := range RelabelRoots(p) {
		fmt.Fprintf(&relabel, "restorecon -RF -- %s 2>/dev/null || :\n", vm.ShellQuote(root))
	}
	// The entrypoint label is load-bearing: without _exec_t the domain
	// transition never fires and the service runs unconfined. Relabel it, FAIL
	// if restorecon errors, and then VERIFY the resulting type is actually
	// <app>_exec_t — restorecon also "succeeds" when a higher-priority local
	// file-context rule applies a different type, which would silently leave the
	// service unconfined (review finding). Paths are single-quoted so a manifest
	// path can never inject shell into the customer's %post.
	for _, exe := range p.Executables {
		// Bind the path to a shell variable ONCE from its single-quoted literal,
		// then reference "$_e" everywhere — including the error messages. The
		// round-16 fix quoted the restorecon argument but still interpolated the
		// raw path into double-quoted echo diagnostics, where $(...) in a
		// manifest path would execute as root on relabel failure (review
		// finding). Variable expansion does not re-evaluate the value, and
		// printf '%%s' prints it literally.
		fmt.Fprintf(&relabel,
			"_e=%[1]s\n"+
				// Refuse to relabel a HARD-LINKED entrypoint: restorecon changes the
				// inode's label, so a shared inode (link count > 1, e.g. hard-linked to
				// /usr/bin/bash) would relabel every other link into <app>_exec_t on the
				// CUSTOMER host too — the verifier-side check alone is not enough (review
				// finding). Privileged stat at %post; any non-1 or unstattable count fails.
				"_lc=$(stat -c '%%h' -- \"$_e\" 2>/dev/null); case \"$_lc\" in 1) : ;; *) printf 'ERROR: entrypoint %%s has hard-link count %%s (want exactly 1); refusing to relabel a shared inode\\n' \"$_e\" \"$_lc\" >&2; exit 1 ;; esac\n"+
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
			"if semanage port -d -t %[1]s -p \"$_pp\" \"$_pn\" 2>/dev/null; then _pruned=\"$_pruned $_row\"; "+
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
		fmt.Fprintf(&portsDel, "semanage port -d -t %[1]s -p %[2]s %[3]d 2>/dev/null || echo \"warning: could not remove port %[3]d/%[2]s mapping for %[1]s\" >&2\n",
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
    if semodule -l 2>/dev/null | grep -qE "^%[1]s( |$)"; then
        echo "ERROR: a SELinux module named %[1]s already exists, but this is a fresh install; refusing to shadow a foreign module. Remove it first or build with a distinct name." >&2
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
    for _row in $_added; do _rp=${_row%%%%:*}; _rn=${_row##*:}; semanage port -d -t %[7]s -p "$_rp" "$_rn" 2>/dev/null || :; done
    if [ "$_op" = 1 ]; then
        # Fresh install: remove the module, then restore base file labels.
        semodule -r %[1]s 2>/dev/null || :
%[6]s
    elif [ -n "$_snap" ]; then
        # Upgrade failure: reinstall the previous module, re-apply its labels, and
        # RESTORE the port mappings this transaction pruned — the prior working
        # policy is fully back in place (review finding).
        ( cd "$_snap" && { semodule -i %[1]s.cil || semodule -i %[1]s.pp; } ) 2>/dev/null || :
%[6]s
        # Re-apply the PREVIOUS module's labels on ALL of its roots — including
        # any removed root already reset to base before the failure — so the
        # reinstated old module and the on-disk labels are consistent (review
        # finding). Restoring only the new profile's roots (%[6]s above) would
        # leave already-restored removed roots mislabeled under the old module.
        if [ -f %%{_datadir}/selinux/hardener/%[1]s.oldroots ]; then
            while IFS= read -r _oldroot; do
                [ -n "$_oldroot" ] || continue
                restorecon -RF -- "$_oldroot" 2>/dev/null || :
            done < %%{_datadir}/selinux/hardener/%[1]s.oldroots
        fi
        for _row in $_pruned; do _rp=${_row%%%%:*}; _rn=${_row##*:}; semanage port -a -t %[7]s -p "$_rp" "$_rn" 2>/dev/null || :; done
    fi
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
