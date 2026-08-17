package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func specFor(t *testing.T, ports []profile.Port) string {
	t.Helper()
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
		Ports:       ports,
	}
	return GenerateSpec(p, "20260101000000")
}

func section(t *testing.T, spec, name string) string {
	t.Helper()
	start := strings.Index(spec, "\n%"+name+"\n")
	if start < 0 {
		t.Fatalf("spec has no %%%s section", name)
	}
	rest := spec[start+len(name)+2:]
	for _, next := range []string{"\n%pre\n", "\n%post\n", "\n%postun\n", "\n%posttrans\n", "\n%files\n"} {
		if i := strings.Index(rest, next); i >= 0 {
			rest = rest[:i]
		}
	}
	return rest
}

// The spec delegates all standard plumbing to the distro's own SELinux RPM macros.
// Hand-rolling any of it means reimplementing (worse) what selinux-policy-devel
// already ships: priority-200 module install, the file_contexts snapshot +
// `fixfiles -C` relabel, and the version-conditional Requires set.
func TestSpecUsesDistroSELinuxMacros(t *testing.T) {
	spec := specFor(t, []profile.Port{{Proto: "tcp", Port: 8443}})
	for _, want := range []string{
		"%{?selinux_requires}",
		"%selinux_relabel_pre -s targeted",
		"%selinux_modules_install -s targeted %{_datadir}/selinux/packages/widget.pp",
		"%selinux_modules_uninstall -s targeted widget",
		"%selinux_relabel_post -s targeted",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec must delegate to the distro macro %q", want)
		}
	}
	// %postun also runs semanage (port cleanup), which %selinux_requires does not
	// cover — it only emits Requires(post).
	if !strings.Contains(spec, "Requires(postun): policycoreutils policycoreutils-python-utils") {
		t.Error("spec must declare Requires(postun) for the semanage it runs there")
	}
}

// The reinvention that the macros replace must be gone. Each of these was a
// hand-rolled mechanism that the distro already provides, and each was a source of
// review findings in its own right.
func TestSpecDoesNotReimplementMacroPlumbing(t *testing.T) {
	spec := specFor(t, []profile.Port{{Proto: "tcp", Port: 8443}})
	for frag, why := range map[string]string{
		"semodule -E":                         "module snapshot/rollback — %selinux_modules_install handles install; rpm cannot roll back %post anyway",
		"widget.roots":                        "removed-root reconciliation — %selinux_relabel_post's fixfiles -C covers it",
		"widget.oldroots":                     "ditto",
		"widget.oldports":                     "port ownership inventory — the type is ours by construction",
		"refusing to shadow a foreign module": "priority 200 shadows rather than replaces, so the collision cannot occur",
	} {
		if strings.Contains(spec, frag) {
			t.Errorf("spec still hand-rolls %q (%s)", frag, why)
		}
	}
}

// What the wrapper adds: the verification the macros deliberately skip. Every
// operative line in the distro macros ends in `|| :`, so a failed module load or a
// missing entrypoint label leaves the transaction SUCCESSFUL and the service
// silently unconfined.
func TestSpecVerifiesWhatTheMacrosSkip(t *testing.T) {
	spec := specFor(t, nil)
	post := section(t, spec, "post")
	posttrans := section(t, spec, "posttrans")

	if !strings.Contains(post, `semodule -l 2>/dev/null | grep -qE "^widget([[:space:]]|$)"`) {
		t.Error("the post scriptlet must confirm the module actually reached the store")
	}
	if !strings.Contains(post, "will run UNCONFINED") {
		t.Error("a failed module install must say plainly that the service is unconfined")
	}
	// Entrypoint labels can only be checked AFTER the relabel, which the macro does
	// in %posttrans — checking in %post would race it.
	if !strings.Contains(posttrans, "widget_exec_t") {
		t.Error("the posttrans scriptlet must verify the entrypoint label")
	}
	relabelAt := strings.Index(posttrans, "%selinux_relabel_post")
	verifyAt := strings.Index(posttrans, "widget_exec_t")
	if relabelAt < 0 || verifyAt < 0 || relabelAt > verifyAt {
		t.Errorf("entrypoint verification must follow the relabel (relabel=%d verify=%d)", relabelAt, verifyAt)
	}
	// Both checks must be inert when SELinux is off — otherwise every install on a
	// non-SELinux host screams.
	for _, sec := range []string{post, posttrans} {
		if !strings.Contains(sec, "selinuxenabled") {
			t.Error("verification must be guarded by selinuxenabled")
		}
	}
}

// Ports are the one functional install-time job the macros do not cover.
func TestSpecManagesPorts(t *testing.T) {
	spec := specFor(t, []profile.Port{{Proto: "tcp", Port: 8443}})
	post := section(t, spec, "post")
	postun := section(t, spec, "postun")

	if !strings.Contains(post, "semanage port -a -t widget_port_t -p tcp 8443") {
		t.Error("the post scriptlet must assign the declared port")
	}
	if strings.Count(postun, "semanage port -d -p tcp 8443") != 1 {
		t.Error("the postun scriptlet must delete each declared port exactly once")
	}
	// Port deletion must precede module removal: the mappings reference our type.
	delAt := strings.Index(postun, "semanage port -d")
	remAt := strings.Index(postun, "%selinux_modules_uninstall")
	if delAt < 0 || remAt < 0 || delAt > remAt {
		t.Errorf("ports must be deleted before the module is removed (del=%d rem=%d)", delAt, remAt)
	}
	// A mapping this build no longer declares must be pruned, so an upgrade that
	// drops a port does not leave a stale bind privilege. The prune runs even for a
	// portless profile (upgrade-to-zero-ports).
	for _, s := range []string{spec, specFor(t, nil)} {
		if !strings.Contains(s, `awk '$1=="widget_port_t"`) {
			t.Error("the stale-port prune must run even when no ports are declared")
		}
	}
}

// SECURITY INVARIANT (carried forward): a manifest path reaches the customer's
// root-run scriptlet, so it must never be re-evaluated as shell. Paths are
// single-quoted at generation time and only ever expanded as "$_e".
func TestSpecDoesNotExecuteManifestPaths(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")
	// No command substitution or backticks wrapping a path.
	for _, bad := range []string{"$(/opt/widget", "`/opt/widget", "eval "} {
		if strings.Contains(spec, bad) {
			t.Errorf("spec must never evaluate a manifest path as a command (found %q)", bad)
		}
	}
	// The entrypoint is single-quoted where it is assigned.
	if !strings.Contains(spec, `_e='/opt/widget/bin/widgetd'`) {
		t.Error("entrypoint paths must be single-quoted into the scriptlet")
	}
}

// Basic packaging identity: the Release must carry the build revision so two
// policy builds with different content can never share a NEVRA.
func TestSpecPackagingIdentity(t *testing.T) {
	spec := specFor(t, nil)
	for _, want := range []string{
		"Name:           widget-selinux",
		"Release:        1.20260101000000%{?dist}",
		"%{_datadir}/selinux/packages/widget.pp",
		"%{_datadir}/selinux/hardener/widget.fc",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec missing %q", want)
		}
	}
}
