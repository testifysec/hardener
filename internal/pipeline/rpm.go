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
				"restorecon -F -- \"$_e\" || { printf 'ERROR: cannot label entrypoint %%s; the service would run unconfined\\n' \"$_e\" >&2; exit 1; }\n"+
				"_lbl=$(stat -c '%%C' -- \"$_e\" 2>/dev/null); case \"$_lbl\" in *:%[2]s:*) : ;; *) printf 'ERROR: entrypoint %%s is labeled %%s, not %[2]s — a higher-priority file-context rule is overriding it; the service would run unconfined\\n' \"$_e\" \"$_lbl\" >&2; exit 1 ;; esac\n",
			vm.ShellQuote(exe), execType)
	}
	appPortType := policy.PortType(p.Name)
	var ports strings.Builder
	var portsDel strings.Builder
	if len(p.Ports) > 0 {
		// (#6) Reconcile: prune any mapping under OUR port type that is NOT in
		// the current profile. An upgrade that dropped a port would otherwise
		// leave the stale mapping — undeclared bind privilege, or a dangling
		// reference when the type disappears. Only ever touches <app>_port_t.
		var desired strings.Builder
		for _, port := range p.Ports {
			fmt.Fprintf(&desired, " %s:%d", port.Proto, port.Port)
		}
		fmt.Fprintf(&ports,
			"_desired=\"%[2]s \"\n"+
				"for _row in $(semanage port -l | awk '$1==\"%[1]s\"{for(i=3;i<=NF;i++){gsub(\",\",\"\",$i); print $2\":\"$i}}'); do "+
				"case \"$_desired\" in *\" $_row \"*) : ;; "+
				"*) _pp=${_row%%%%:*}; _pn=${_row##*:}; semanage port -d -t %[1]s -p \"$_pp\" \"$_pn\" 2>/dev/null || { echo \"ERROR: could not prune stale port $_row from %[1]s — refusing to leave an undeclared bind privilege\" >&2; exit 1; } ;; esac; done\n",
			appPortType, desired.String())
	}
	for _, port := range p.Ports {
		// (#5) Add + verify, and RECORD only the ports we actually added
		// (_added). Rollback then removes exactly this transaction's additions
		// and never a pre-existing mapping owned by another service (-t is not an
		// ownership guard). Still fail CLOSED if the port cannot land under our
		// type. proto/port are validated at manifest load — safe to interpolate.
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
# Snapshot the currently-installed module before replacing it (upgrade only).
# Best-effort: if extraction is unavailable, _snap stays empty and we keep the
# loaded module rather than leaving the service unconfined.
_snap=""
if [ "$_op" != 1 ]; then
    _snap="$(mktemp -d 2>/dev/null || true)"
    if [ -n "$_snap" ] && ( cd "$_snap" && semodule -E %[1]s ) 2>/dev/null; then :; else _snap=""; fi
fi
_rollback() {
    [ "$_ok" = 1 ] && return 0
    # Remove ONLY the port mappings THIS transaction added (tracked in _added),
    # never a pre-existing mapping owned by another service (review finding).
    for _row in $_added; do _rp=${_row%%%%:*}; _rn=${_row##*:}; semanage port -d -t %[7]s -p "$_rp" "$_rn" 2>/dev/null || :; done
    if [ "$_op" = 1 ]; then
        # Fresh install: remove the module, then restore base file labels.
        semodule -r %[1]s 2>/dev/null || :
%[6]s
    elif [ -n "$_snap" ]; then
        # Upgrade failure: reinstall the previous module and re-apply its labels,
        # so the prior working policy is back in place (review finding).
        ( cd "$_snap" && { semodule -i %[1]s.cil || semodule -i %[1]s.pp; } ) 2>/dev/null || :
%[6]s
    fi
    # (Upgrade with no snapshot: keep the loaded module — never leave none.)
}
trap _rollback EXIT
if ! semodule -i %%{_datadir}/selinux/packages/%[1]s.pp; then
    echo "ERROR: semodule failed to load the %[1]s policy module; the application is NOT confined" >&2
    exit 1
fi
%[2]s%[3]s_ok=1

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
`, app, relabel.String(), ports.String(), portsDel.String(), revision, restore.String(), appPortType)
}
