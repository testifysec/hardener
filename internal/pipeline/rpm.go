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
	var ports strings.Builder
	var portsDel strings.Builder
	for _, port := range p.Ports {
		// Fail CLOSED on the port label: `-a` succeeds on first install and
		// fails on re-install (already defined) OR on a conflict (the port is
		// claimed by ANOTHER type). Distinguish them by verifying the port is
		// actually listed under our type — otherwise `|| :` silently left the
		// service binding an unintended port type (review finding). proto/port
		// are validated at manifest load, so they are safe to interpolate.
		fmt.Fprintf(&ports,
			"if ! { semanage port -a -t %[1]s -p %[2]s %[3]d 2>/dev/null || semanage port -l | awk -v t=%[1]s -v p=%[2]s '$1==t && $2==p' | grep -qw %[3]d; }; then echo \"ERROR: port %[3]d/%[2]s could not be assigned to %[1]s (already claimed by another SELinux type?); refusing to leave %[1]s bound to an unintended port type\" >&2; exit 1; fi\n",
			policy.PortType(p.Name), port.Proto, port.Port)
		// Removal is best-effort but OBSERVABLE — a swallowed `|| :` hid a
		// half-removed policy on uninstall (review finding).
		fmt.Fprintf(&portsDel, "semanage port -d -t %[1]s -p %[2]s %[3]d 2>/dev/null || echo \"warning: could not remove port %[3]d/%[2]s mapping for %[1]s\" >&2\n",
			policy.PortType(p.Name), port.Proto, port.Port)
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
# Fail closed WITH rollback: loading the module then failing entrypoint/port
# validation must not leave the module and partial port mappings installed after
# a reported install failure (review finding). The rollback runs ONLY on a FRESH
# install ($1 == 1), where "undo everything" correctly restores the pre-install
# state (nothing). On an UPGRADE ($1 >= 2) it does NOT remove the module or the
# ports: semodule -i already replaced the prior module, and tearing it down would
# leave the service with NO policy — worse than the flagged issue. The failure is
# still reported via the non-zero exit (review finding).
_op=$1
_ok=0
_rollback() {
    [ "$_ok" = 1 ] && return 0
    [ "$_op" = 1 ] || return 0
%[4]s    semodule -r %[1]s 2>/dev/null || :
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
`, app, relabel.String(), ports.String(), portsDel.String(), revision, restore.String())
}
