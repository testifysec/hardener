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
	// Fail closed on a spec/FC mismatch. A path the profile declares but the shipped
	// .fc has no mapping for will simply never receive the app type — the package
	// installs and reports success while that tree stays under whatever the base
	// policy says, so the confinement silently differs from the profile the verdict
	// describes. The live pipeline trims base-policy-collided paths from p.Paths IN
	// PLACE before deriving BOTH the .fc and this spec, so they agree; this guard
	// makes that invariant explicit (review finding — round 66). Executables are
	// never trimmed: an entrypoint collision is fatal earlier, so only data/config
	// paths can diverge.
	for _, pa := range p.Paths {
		if !strings.Contains(fc, pa.Path+"\t") {
			return "", fmt.Errorf("internal: the profile declares %q but the shipped file-contexts have no mapping for it — that tree would never receive the app type; refusing to package inconsistent policy", pa.Path)
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
//
// STRUCTURE: this is a THIN VERIFIED WRAPPER around the distro's own SELinux RPM
// macros, not a replacement for them. Everything the distro already solves is
// delegated:
//
//	%selinux_requires          — the Requires/Requires(post) set, including the
//	                             RHEL-version-conditional policycoreutils-python
//	                             vs -python-utils split.
//	%selinux_relabel_pre/_post — snapshot file_contexts, then `fixfiles -C <old>
//	                             restore`, which relabels exactly the objects whose
//	                             context the policy change affects, filesystem-wide.
//	                             This subsumes a hand-rolled per-root restorecon AND
//	                             the removed-root reconciliation an earlier version
//	                             did with a shipped .roots inventory.
//	%selinux_modules_install   — installs at PRIORITY 200. Third-party modules
//	%selinux_modules_uninstall   SHADOW the distro's priority-100 modules instead of
//	                             replacing them, and `-X 200 -r` removes only ours.
//	                             That is why this package no longer refuses to
//	                             install when a module of the same name exists:
//	                             priority separation already prevents the collision
//	                             the refusal was guarding against.
//
// What the macros deliberately do NOT do is verify anything — every operative line
// is `|| :` or `&> /dev/null`, because they cannot distinguish "SELinux disabled on
// this host" from "the load actually failed". So a failed `semodule -i` leaves the
// transaction SUCCESSFUL and the application silently unconfined. That gap is the
// reason this wrapper exists, and it is all this wrapper does:
//
//   - after the module install, confirm the module is really in the store;
//   - after the relabel, confirm each entrypoint actually carries <app>_exec_t,
//     because without that label the domain transition never fires and the service
//     runs unconfined while every command still reports success.
//
// Both checks are skipped when SELinux is disabled (nothing to verify) and both
// REPORT rather than abort: the payload is already committed by %post/%posttrans,
// so failing there cannot roll the transaction back — it can only tell the
// operator. Deeper validation (hard links, file-context overlaps, foreign type
// ownership, base-policy rules under declared roots) belongs on the verifier, where
// it already runs and where a failure costs a re-run instead of stranding a host.
func GenerateSpec(p *profile.Profile, revision string) string {
	app := policy.SafeName(p.Name)
	execType := policy.TypeForKind(p.Name, policy.KindExec)
	appPortType := policy.PortType(p.Name)
	if revision == "" {
		revision = "0"
	}

	// desired: the space-delimited proto:port set this build declares. EMPTY when
	// the profile declares no ports, so an upgrade that drops every port still
	// prunes the stale mappings.
	desired := " "
	for _, port := range p.Ports {
		desired += fmt.Sprintf("%s:%d ", port.Proto, port.Port)
	}

	// Port mappings are the one piece of functional install-time work the macros do
	// not cover. Assign after the module is loaded (the type must exist first).
	var ports strings.Builder
	for _, port := range p.Ports {
		fmt.Fprintf(&ports,
			"    semanage port -a -t %[1]s -p %[2]s %[3]d 2>/dev/null || semanage port -m -t %[1]s -p %[2]s %[3]d 2>/dev/null || echo \"WARNING: could not assign port %[3]d/%[2]s to %[1]s; the service may fail to bind\" >&2\n",
			appPortType, port.Proto, port.Port)
	}
	// Prune any mapping under OUR port type that this build no longer declares —
	// otherwise an upgrade that changes ports leaves the domain able to bind a port
	// it no longer asks for. The type is defined by our own module, and the verifier
	// refuses to build when any generated type already exists, so a mapping under it
	// is ours by construction; no ownership inventory is needed.
	var prune strings.Builder
	{
		fmt.Fprintf(&prune,
			"    for _row in $(semanage port -l 2>/dev/null | awk '$1==\"%[1]s\"{for(i=3;i<=NF;i++){gsub(\",\",\"\",$i); print $2\":\"$i}}'); do\n"+
				"        case \"%[2]s\" in *\" $_row \"*) continue ;; esac\n"+
				"        semanage port -d -p \"${_row%%%%:*}\" \"${_row##*:}\" 2>/dev/null || echo \"WARNING: could not prune undeclared port $_row from %[1]s\" >&2\n"+
				"    done\n",
			appPortType, desired)
	}
	var portsDel strings.Builder
	for _, port := range p.Ports {
		fmt.Fprintf(&portsDel,
			"    semanage port -d -p %[1]s %[2]d 2>/dev/null || :\n",
			port.Proto, port.Port)
	}

	// Restore base labels on ERASE. %selinux_relabel_post lives in %posttrans, which
	// is an install-time scriptlet — it does NOT run when the package is erased. So
	// removing the module leaves every file it labeled carrying a now-undefined type,
	// which the kernel reports as unlabeled_t; the application can become
	// inaccessible or unexecutable. Verified by actually installing and erasing the
	// generated RPM: without this, /opt/widget/bin/widgetd ends up unlabeled_t.
	//
	// This runs AFTER the module is removed, so the app's file-context entries are
	// gone and restorecon assigns the distro's base type. Best-effort per path and
	// NEVER aborting: by %postun the payload and module are already gone, so failing
	// cannot roll anything back — it would only abandon the paths not yet restored.
	var restoreBase strings.Builder
	for _, root := range RelabelRoots(p) {
		fmt.Fprintf(&restoreBase,
			"    [ -e %[1]s ] && restorecon -RF -- %[1]s 2>/dev/null || :\n",
			vm.ShellQuote(root))
	}

	// Entrypoint label verification, run in %posttrans AFTER the relabel. This is
	// the check that separates "confined" from "silently unconfined".
	var verifyExec strings.Builder
	for _, exe := range p.Executables {
		fmt.Fprintf(&verifyExec,
			"    _e=%[1]s\n"+
				"    if [ -e \"$_e\" ]; then\n"+
				"        _lbl=$(stat -c '%%C' -- \"$_e\" 2>/dev/null || echo unknown)\n"+
				// "$_e" is a plain variable expansion — never re-evaluated — so a
				// manifest path cannot inject shell into the customer's scriptlet.
				"        case \"$_lbl\" in *:%[2]s:*) : ;; *) echo \"CRITICAL: entrypoint $_e is labeled $_lbl, not %[2]s — the domain transition will not fire and this service will run UNCONFINED. Run: restorecon -F -- $_e\" >&2; _bad=1 ;; esac\n"+
				"    fi\n",
			vm.ShellQuote(exe), execType)
	}

	return fmt.Sprintf(`Name:           %[1]s-selinux
Version:        1.0.0
Release:        1.%[2]s%%{?dist}
Summary:        SELinux confinement policy for %[1]s (generated by hardener)
License:        Apache-2.0
BuildArch:      noarch
Source0:        %[1]s.pp
Source1:        %[1]s.fc
%%{?selinux_requires}
# The macros only emit Requires(post); this package also runs semanage in %%postun
# to remove its port mappings, so declare that ordering explicitly.
Requires(postun): policycoreutils policycoreutils-python-utils

%%description
SELinux policy module for %[1]s, generated and verified by hardener: the policy was
synthesized from observed behavior, refined to least privilege, and re-verified
under enforcement with zero residual denials before this package was built.

%%prep
%%build

%%install
install -D -m 0644 %%{SOURCE0} %%{buildroot}%%{_datadir}/selinux/packages/%[1]s.pp
install -D -m 0644 %%{SOURCE1} %%{buildroot}%%{_datadir}/selinux/hardener/%[1]s.fc

%%pre
%%selinux_relabel_pre -s targeted

%%post
%%selinux_modules_install -s targeted %%{_datadir}/selinux/packages/%[1]s.pp
if selinuxenabled 2>/dev/null; then
    # The macro above swallows every error. Confirm the module is actually in the
    # store — otherwise this package reports success while %[1]s runs unconfined.
    if ! semodule -l 2>/dev/null | grep -qE "^%[1]s([[:space:]]|$)"; then
        echo "CRITICAL: the %[1]s SELinux policy module is not installed after %%post; %[1]s will run UNCONFINED. Install it manually: semodule -X 200 -i %%{_datadir}/selinux/packages/%[1]s.pp" >&2
    fi
%[3]s%[4]sfi

%%postun
if [ $1 -eq 0 ]; then
    if selinuxenabled 2>/dev/null; then
%[5]s    fi
fi
%%selinux_modules_uninstall -s targeted %[1]s
if [ $1 -eq 0 ] && selinuxenabled 2>/dev/null; then
    # The module (and its file-contexts) are gone now, so restorecon assigns the
    # distro base type. Without this the app's files keep a type the kernel no
    # longer knows and show up as unlabeled_t.
%[8]sfi

%%posttrans
%%selinux_relabel_post -s targeted
if selinuxenabled 2>/dev/null; then
    _bad=0
%[6]s    if [ "$_bad" = 1 ]; then
        echo "CRITICAL: one or more %[1]s entrypoints did not receive %[7]s. The policy is installed but will not confine the service until those labels are corrected." >&2
    fi
fi

%%files
%%{_datadir}/selinux/packages/%[1]s.pp
%%{_datadir}/selinux/hardener/%[1]s.fc
`, app, revision, prune.String(), ports.String(), portsDel.String(), verifyExec.String(), execType, restoreBase.String())
}
