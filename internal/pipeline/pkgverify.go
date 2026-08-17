package pipeline

import (
	"fmt"
	"strings"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/vm"
)

// PackageCheck is one property proven about the BUILT RPM by actually installing
// it. Distinct from StaticCheck, which asserts things about the loaded policy.
type PackageCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// verifyPackage installs the built RPM on the verifier, proves it delivers the
// confinement the verdict claims, then erases it and proves it cleans up.
//
// This exercises a DIFFERENT layer than the enforcement loop. Enforcement proves
// the POLICY confines the workload. This proves the PACKAGE actually applies that
// policy on a host — the scriptlets, the labeling, the port mappings, and the
// teardown. Those are the parts that fail on the customer's machine rather than
// here, and until now nothing tested them: the scriptlets were only ever checked
// by asserting on their TEXT, never by running them. The first real install
// immediately exposed a bug no amount of text assertion could (files left
// unlabeled_t after erase, because %selinux_relabel_post is an install-time
// scriptlet that never runs on erase).
//
// ORDER MATTERS. installPolicy loaded our module with a bare `semodule -i`, which
// lands at priority 400; the RPM installs at priority 200 and would be SHADOWED by
// that copy, so every check below would pass for the wrong reason. Remove the
// staged module first so the RPM is genuinely the thing under test.
func verifyPackage(r vm.Runner, p *profile.Profile, rpmPath string) ([]PackageCheck, error) {
	app := policy.SafeName(p.Name)
	execType := policy.TypeForKind(p.Name, policy.KindExec)
	portType := policy.PortType(p.Name)
	var checks []PackageCheck
	add := func(name string, passed bool, detail string) {
		checks = append(checks, PackageCheck{Name: name, Passed: passed, Detail: detail})
	}

	// Drop the staged (priority 400) module so the RPM's priority-200 copy is what
	// actually takes effect. Fail hard if it will not go: otherwise the install
	// checks below measure the staged module, not the package.
	if _, err := r.Run(fmt.Sprintf("sudo semodule -r %s 2>/dev/null; true", app)); err != nil {
		return checks, fmt.Errorf("could not unload the staged %s module before package verification: %w", app, err)
	}
	if mods, err := r.Run("sudo semodule -l 2>/dev/null"); err == nil && moduleListed(mods, app) {
		return checks, fmt.Errorf("the staged %s module is still loaded after removal — package verification would measure it instead of the RPM", app)
	}

	// ---- INSTALL ----
	if out, err := r.Run(fmt.Sprintf("sudo rpm -i %s 2>&1", vm.ShellQuote(rpmPath))); err != nil {
		add("rpm install", false, strings.TrimSpace(out))
		return checks, fmt.Errorf("the built RPM does not install: %v\n%s", err, out)
	}
	add("rpm install", true, "")

	// The module must be in the store at the third-party priority. %selinux_modules_install
	// swallows failures, so "rpm -i exited 0" says nothing on its own.
	full, err := r.Run("sudo semodule --list-modules=full 2>/dev/null")
	atPriority := false
	for _, line := range strings.Split(full, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "200" && f[1] == app {
			atPriority = true
			break
		}
	}
	add("module installed at priority 200", err == nil && atPriority, firstLine(full))

	// Entrypoint labels are the load-bearing ones: without <app>_exec_t the domain
	// transition never fires and the service runs unconfined while every command
	// still reports success.
	for _, exe := range p.Executables {
		lbl, lerr := r.Run(fmt.Sprintf("stat -c '%%C' -- %s 2>/dev/null", vm.ShellQuote(exe)))
		ok := lerr == nil && strings.Contains(lbl, ":"+execType+":")
		add("entrypoint labeled "+execType+": "+exe, ok, strings.TrimSpace(lbl))
	}
	// Declared roots must carry their kind's type — this is what fixfiles -C applied.
	for _, pa := range p.Paths {
		root := fcRoot(pa.Path)
		if root == "" {
			continue
		}
		want := policy.TypeForKind(p.Name, policy.KindFromString(pa.Kind))
		lbl, lerr := r.Run(fmt.Sprintf("if [ -e %[1]s ]; then stat -c '%%C' -- %[1]s 2>/dev/null; else echo ABSENT; fi", vm.ShellQuote(root)))
		trimmed := strings.TrimSpace(lbl)
		// A root the app creates on first run may not exist yet; that is not a fault.
		ok := lerr == nil && (trimmed == "ABSENT" || strings.Contains(lbl, ":"+want+":"))
		add("declared root labeled "+want+": "+root, ok, trimmed)
	}
	// Declared ports must be mapped to our port type.
	if len(p.Ports) > 0 {
		portList, perr := r.Run("sudo semanage port -l 2>/dev/null")
		for _, port := range p.Ports {
			ok := perr == nil && portMapped(portList, portType, port.Proto, port.Port)
			add(fmt.Sprintf("port %d/%s mapped to %s", port.Port, port.Proto, portType), ok, "")
		}
	}

	// ---- ERASE ----
	if out, err := r.Run(fmt.Sprintf("sudo rpm -e %s-selinux 2>&1", app)); err != nil {
		add("rpm erase", false, strings.TrimSpace(out))
		return checks, fmt.Errorf("the built RPM does not uninstall cleanly: %v\n%s", err, out)
	}
	add("rpm erase", true, "")

	after, aerr := r.Run("sudo semodule -l 2>/dev/null")
	add("module removed after erase", aerr == nil && after != "" && !moduleListed(after, app), "")

	if len(p.Ports) > 0 {
		portList, perr := r.Run("sudo semanage port -l 2>/dev/null")
		stale := ""
		for _, port := range p.Ports {
			if perr == nil && portMapped(portList, portType, port.Proto, port.Port) {
				stale = fmt.Sprintf("%d/%s still mapped", port.Port, port.Proto)
			}
		}
		add("port mappings removed after erase", perr == nil && stale == "", stale)
	}

	// The bug a text-only test could never find: %selinux_relabel_post lives in
	// %posttrans, which does not run on erase, so without an explicit restore the
	// app's files keep a now-undefined type and the kernel reports unlabeled_t —
	// potentially leaving the binary unexecutable.
	for _, exe := range p.Executables {
		// `ls -Zd` rather than the `stat -c '%C'` used before the erase: the two
		// queries must be distinguishable, since the SAME path legitimately reports
		// a different label at each point and a shared command string could not
		// express that.
		lbl, lerr := r.Run(fmt.Sprintf("if [ -e %[1]s ]; then ls -Zd -- %[1]s 2>/dev/null; else echo ABSENT; fi", vm.ShellQuote(exe)))
		trimmed := strings.TrimSpace(lbl)
		ok := lerr == nil && !strings.Contains(lbl, ":unlabeled_t:") && !strings.Contains(lbl, ":"+execType+":")
		add("entrypoint label restored after erase: "+exe, ok || trimmed == "ABSENT", trimmed)
	}

	return checks, nil
}

// moduleListed reports whether `semodule -l` output contains the module as its own
// entry. Older semodule prints "name\tversion", newer prints the bare name.
func moduleListed(out, app string) bool {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == app {
			return true
		}
	}
	return false
}

// portMapped reports whether `semanage port -l` maps proto/port to typ. Rows look
// like "widget_port_t   tcp   18443, 18444".
func portMapped(out, typ, proto string, port int) bool {
	want := fmt.Sprintf("%d", port)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != typ || f[1] != proto {
			continue
		}
		for _, p := range f[2:] {
			if strings.TrimSuffix(p, ",") == want {
				return true
			}
		}
	}
	return false
}
