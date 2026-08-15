// Package pipeline drives one artifact through analyze → synthesize →
// observe (permissive) → refine → enforce → verify → package.
package pipeline

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/elfscan"
	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/target"
	"github.com/testifysec/hardener/internal/vm"
)

// Options tunes a pipeline run.
type Options struct {
	MaxRounds     int  // permissive observe/refine rounds (default 5)
	AcceptFlagged bool // apply flagged rules (still reported for review)
	Log           func(format string, args ...any)
}

// Result is the full record of one target's run.
type Result struct {
	Target         *target.Target
	Domain         string
	Rounds         []RoundResult
	FinalTE        string
	FinalFC        string
	Flags          []policy.Flag
	Relabels       []policy.Relabel
	Collisions     []policy.Collision
	Predictions    []elfscan.Prediction // static import analysis of entrypoints
	UngrantedPreds []elfscan.Prediction // predicted by imports but not granted by the final policy
	StaticImports  bool                 // false when all entrypoints are statically linked
	EnforceOK      bool
	DomainOK       bool // process really runs in the new domain
	ExerciseOK     bool
	ResidualAVCs   []avc.Denial
	StaticChecks   []StaticCheck
	// FinalProfile and FinalRules are the verified behavior record: the
	// (possibly adjusted) profile plus every refined allow rule. Conformance
	// checking consumes these.
	FinalProfile *profile.Profile
	FinalRules   []policy.AllowRule
	// VerifierEnv describes the baseline the claim is scoped to (distro,
	// kernel, mode, policy package) and RPMSHA256 fingerprints the deliverable.
	VerifierEnv map[string]string
	RPMSHA256   string
	// FlagsAccepted records whether --accept-flagged consciously applied the
	// review-flagged rules; a verdict with unaccepted flags must fail.
	FlagsAccepted bool
	// EntrypointDigests maps each resolved entrypoint path to its sha256 as
	// installed in the verifier — the exact bytes exercised, bound into the
	// verdict attestation.
	EntrypointDigests map[string]string
	// Conformance is filled by the caller per party class; rendered in the report.
	Party             string
	ConformanceUndecl []string
	ConformanceUnexer []string
	ConformanceFatal  string
	// AcceptedExceptions are failed static checks whose grants correspond to
	// review-flagged rules that were consciously accepted (--accept-flagged).
	AcceptedExceptions []StaticCheck
	RPMPath            string
	FailureReason      string
}

// IsFailure is the single source of truth for whether a run failed: a hard
// stage error, a failed enforcement gate, a fatal conformance verdict, or
// review-flagged rules that were never accepted. The CLI exit status, the
// report headline, and the attestation verdict all derive from this.
func (res *Result) IsFailure() bool {
	return res.FailureReason != "" || !res.EnforceOK || res.ConformanceFatal != "" ||
		(len(res.Flags) > 0 && !res.FlagsAccepted)
}

// RoundResult records one permissive observation round.
type RoundResult struct {
	Denials    int
	NewRules   int
	Relabels   int
	ExerciseOK bool
}

// StaticCheck is one sesearch-based least-privilege assertion.
type StaticCheck struct {
	Name   string
	Query  string
	Passed bool
	Detail string
}

// Run executes the full pipeline for one target.
func Run(r vm.Runner, t *target.Target, opts Options) *Result {
	if opts.MaxRounds == 0 {
		opts.MaxRounds = 5
	}
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	p := t.Profile()
	dom := policy.DomainType(p.Name)
	res := &Result{Target: t, Domain: dom, FlagsAccepted: opts.AcceptFlagged}
	// Manifest-declared capabilities get the same danger gate as observed
	// ones — declared privilege must not bypass review.
	if declared := policy.FlagDeclaredCapabilities(p.Name, p.Capabilities); len(declared) > 0 {
		res.Flags = append(res.Flags, declared...)
		if !opts.AcceptFlagged {
			return failEarly(res, opts, "declared-capabilities",
				fmt.Errorf("manifest declares privileged capabilities requiring review: %s (re-run with --accept-flagged after review)", declared[0].Reason))
		}
	}

	fail := func(stage string, err error) *Result {
		res.FailureReason = fmt.Sprintf("%s: %v", stage, err)
		opts.Log("FAIL %s: %v", stage, err)
		return res
	}

	// 0. The verifier must be able to observe: enforcing mode + live auditd.
	// Match whole lines — "inactive" contains "active".
	if out, err := r.Run("getenforce; systemctl is-active auditd"); err != nil ||
		!hasLine(out, "Enforcing") || !hasLine(out, "active") {
		return fail("precheck", fmt.Errorf("verifier not observing (need Enforcing + auditd): %s %v", out, err))
	}
	// Record the baseline the verdict will be scoped to.
	res.VerifierEnv = map[string]string{}
	if out, err := r.Run("cat /etc/redhat-release; uname -r; getenforce; rpm -q selinux-policy 2>/dev/null"); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		keys := []string{"distro", "kernel", "selinuxMode", "policyPackage"}
		for i, k := range keys {
			if i < len(lines) {
				res.VerifierEnv[k] = strings.TrimSpace(lines[i])
			}
		}
	}

	// 1. Install the application.
	opts.Log("[%s] installing", t.Name)
	if _, err := r.Run("set -e\n" + t.Install); err != nil {
		return fail("install", err)
	}
	if t.UnitFile != "" {
		if err := r.WriteFile("/etc/systemd/system/"+t.Unit, t.UnitFile); err != nil {
			return fail("unit-file", err)
		}
	}
	if t.Setup != "" {
		if _, err := r.Run("set -e\n" + t.Setup); err != nil {
			return fail("setup", err)
		}
	}
	if _, err := r.Run("sudo systemctl daemon-reload"); err != nil {
		return fail("daemon-reload", err)
	}

	// The unit's ExecStart is the binary systemd must be able to execute for
	// the domain transition. A manifest that names a different binary yields a
	// service that cannot start, so trust the unit over the manifest.
	if execStart, err := r.Run(fmt.Sprintf(
		"systemctl show -p ExecStart --value %s | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1", t.Unit)); err == nil {
		if bin := strings.TrimSpace(execStart); bin != "" && !slices.Contains(p.Executables, bin) {
			if isAppOwnedExecutable(p, bin) {
				opts.Log("[%s] unit ExecStart is %s — adding as entrypoint", t.Name, bin)
				p.Executables = append([]string{bin}, p.Executables...)
			} else {
				opts.Log("[%s] unit ExecStart %s is not positively app-owned — not labeling it; declare the real entrypoint in the manifest if the transition fails", t.Name, bin)
			}
		}
	}

	// Resolve executable symlinks: exec-domain transition is decided by the
	// label of the resolved inode, so a symlinked entrypoint (common in vendor
	// packages) must have its real target labeled, not the link.
	seen := map[string]bool{}
	var resolved []string
	for _, exe := range p.Executables {
		out, err := r.Run(fmt.Sprintf("readlink -f %q", exe))
		real := strings.TrimSpace(out)
		if err != nil || real == "" {
			real = exe
		}
		if real != exe {
			opts.Log("[%s] executable %s is a symlink → %s (labeling target)", t.Name, exe, real)
			// A symlink can resolve to a shared runtime (/opt/app/launcher ->
			// /bin/sh). Labeling that target as _exec_t would route every use
			// of the shell into this domain — re-validate the resolved inode
			// and drop it if it is not itself app-owned (review finding).
			if !isAppOwnedExecutable(p, real) {
				opts.Log("[%s] resolved target %s is not app-owned — refusing to label a shared binary; declare the real entrypoint", t.Name, real)
				continue
			}
		}
		if !seen[real] {
			seen[real] = true
			resolved = append(resolved, real)
		}
	}
	p.Executables = resolved
	// Fingerprint the resolved entrypoints as installed — bound into the verdict.
	res.EntrypointDigests = map[string]string{}
	for _, exe := range p.Executables {
		if out, err := r.Run(fmt.Sprintf("sha256sum %q 2>/dev/null", exe)); err == nil {
			if fs := strings.Fields(out); len(fs) > 0 && len(fs[0]) == 64 {
				res.EntrypointDigests[exe] = fs[0]
			}
		}
	}

	// A unit with NoNewPrivileges=yes restricts SELinux to bounded transitions,
	// which a generated domain can never satisfy: the service keeps running as
	// init_t and fails on its own files. Refinement cannot fix this, so say so
	// up front instead of after five useless rounds.
	if nnp, err := r.Run(fmt.Sprintf("systemctl show -p NoNewPrivileges --value %s", t.Unit)); err == nil &&
		strings.TrimSpace(nnp) == "yes" {
		return fail("unit-incompatible", fmt.Errorf(
			"%s sets NoNewPrivileges=yes: SELinux permits only bounded transitions, so the process stays in init_t and never enters %s. "+
				"Remediation: drop NoNewPrivileges (systemd drop-in), or declare typebounds for the domain", t.Unit, dom))
	}

	// Static import scan of the entrypoints: what the code CAN do, before we
	// watch what it DOES do. The diff against the final policy becomes the
	// coverage-gap report.
	allSyms := map[string]bool{}
	for _, exe := range p.Executables {
		out, err := r.Run(fmt.Sprintf("readelf --dyn-syms -W %q 2>/dev/null; true", exe))
		if err != nil {
			continue
		}
		for sym := range elfscan.ParseDynSyms(out) {
			allSyms[sym] = true
		}
	}
	res.StaticImports = len(allSyms) > 0
	res.Predictions = elfscan.Predict(allSyms)
	if !res.StaticImports {
		opts.Log("[%s] entrypoints are statically linked — import prediction unavailable", t.Name)
	}

	// 2. Detect path claims the base policy already owns. Re-declaring one
	// makes semodule reject the entire module, and it means the app's files
	// keep a label we did not choose — the operator has to know.
	baseFC, err := r.Run("sudo cat /etc/selinux/targeted/contexts/files/file_contexts")
	if err != nil {
		return fail("read base file_contexts", err)
	}
	res.Collisions = policy.FindCollisions(p, baseFC)
	for _, c := range res.Collisions {
		opts.Log("[%s] base-policy collision: %s", t.Name, c.Render())
	}
	// A collided path is not ours to claim: drop it from the profile so
	// (a) the .fc omits it, and (b) refinement stops expecting our label there
	// and instead proposes access to the base type — which, being a shared
	// type, lands in the human-review flags where it belongs.
	if len(res.Collisions) > 0 {
		collided := map[string]bool{}
		for _, c := range res.Collisions {
			collided[c.Path] = true
		}
		var kept []profile.PathAccess
		for _, pa := range p.Paths {
			if !collided[pa.Path] {
				kept = append(kept, pa)
			}
		}
		p.Paths = kept
	}

	// 3. Synthesize and install initial policy, then observe/refine loop.
	var extraRules []policy.AllowRule
	prevRelabels := ""
	for round := 1; round <= opts.MaxRounds; round++ {
		te := policy.GenerateTE(p) + policy.RenderRefinedSection(p, extraRules)
		fc := policy.GenerateFC(p)
		if err := installPolicy(r, p, te, fc); err != nil {
			return fail(fmt.Sprintf("policy-install round %d", round), err)
		}
		res.FinalTE, res.FinalFC = te, fc

		opts.Log("[%s] observe round %d (permissive domain)", t.Name, round)
		if _, err := r.Run(fmt.Sprintf(
			"sudo semanage permissive -l 2>/dev/null | grep -qw %s || sudo semanage permissive -a %s", dom, dom)); err != nil {
			return fail("permissive", err)
		}
		denials, exOK, _, err := exercise(r, t, dom)
		if err != nil {
			return fail(fmt.Sprintf("exercise round %d", round), err)
		}

		ref := policy.Refine(p, denials)
		if len(ref.Entrypoints) > 0 {
			var names []string
			for _, e := range ref.Entrypoints {
				names = append(names, fmt.Sprintf("%s (labeled %s, %s denied execute)", e.Name, e.ObservedType, e.SourceType))
			}
			return fail("entrypoint", fmt.Errorf(
				"mislabeled entrypoint blocks the domain transition: %s — add it to the manifest's executables",
				strings.Join(names, "; ")))
		}
		res.Flags = append(res.Flags, ref.Flags...)
		res.Relabels = append(res.Relabels, ref.Relabels...)
		rules := ref.AllowRules
		if opts.AcceptFlagged {
			for _, f := range ref.Flags {
				rules = append(rules, f.Rule)
			}
		}
		newRules := mergeNewRules(&extraRules, rules)
		for _, rl := range ref.Relabels {
			if _, err := r.Run(fmt.Sprintf("sudo restorecon -F %q", rl.Path)); err != nil {
				opts.Log("[%s] restorecon %s failed: %v", t.Name, rl.Path, err)
			}
		}
		res.Rounds = append(res.Rounds, RoundResult{
			Denials: len(denials), NewRules: newRules, Relabels: len(ref.Relabels), ExerciseOK: exOK,
		})
		opts.Log("[%s] round %d: %d denials, %d new rules, %d relabels, exercise ok=%v",
			t.Name, round, len(denials), newRules, len(ref.Relabels), exOK)

		// The domain is permissive here: SELinux blocked nothing. An exercise
		// that still fails without producing a single denial is a broken app,
		// unit, or test script — not a policy problem. Repeating the round
		// cannot change the outcome, and reporting it as a policy failure is a
		// lie, so stop and say what actually happened.
		if !exOK && len(denials) == 0 {
			return fail("exercise", fmt.Errorf(
				"workload failed in permissive domain with zero denials — app/unit/exercise is broken, not the policy (check: systemctl status %s)", t.Unit))
		}
		// The same relabel recurring round after round means restorecon is not
		// producing the label we expect — usually our file-context claim never
		// made it into the module. Looping cannot fix that.
		relabelKey := relabelSignature(ref.Relabels)
		if relabelKey != "" && relabelKey == prevRelabels {
			return fail("relabel-loop", fmt.Errorf(
				"restorecon is not achieving the expected label for %s — the file-context claim is missing from the module (check base-policy collisions)", relabelKey))
		}
		prevRelabels = relabelKey

		if newRules == 0 && len(ref.Relabels) == 0 && exOK {
			break
		}
	}

	// The verifier itself must still be trustworthy after running the
	// artifact's privileged install/setup/exercise scripts: a malicious
	// package could have run setenforce 0 or stopped auditd, making every
	// later observation a false pass.
	recheck := func(when string) error {
		out, err := r.Run("getenforce; systemctl is-active auditd")
		if err != nil || !hasLine(out, "Enforcing") || !hasLine(out, "active") {
			return fmt.Errorf("verifier integrity lost %s (need Enforcing + auditd): %s %v", when, strings.TrimSpace(out), err)
		}
		return nil
	}
	if err := recheck("before enforcement verification"); err != nil {
		return fail("verifier-integrity", err)
	}

	// 4. Enforce and verify. Nondeterministic code paths (dashboards, cron
	// ticks, lazy caches) can surface only now, so residual denials feed one
	// more refinement round — bounded, and only while it makes progress.
	opts.Log("[%s] switching domain to enforcing and re-verifying", t.Name)
	if _, err := r.Run(fmt.Sprintf("sudo semanage permissive -d %s", dom)); err != nil {
		return fail("un-permissive", err)
	}
	for attempt := 1; ; attempt++ {
		denials, exOK, label, err := exercise(r, t, dom)
		if err != nil {
			return fail("enforce-exercise", err)
		}
		res.ExerciseOK = exOK
		res.ResidualAVCs = denials
		res.DomainOK = strings.Contains(label, ":"+dom+":")
		res.EnforceOK = exOK && len(denials) == 0 && res.DomainOK
		if res.EnforceOK || attempt >= 3 || !res.DomainOK {
			break
		}
		ref := policy.Refine(p, denials)
		rules := ref.AllowRules
		if opts.AcceptFlagged {
			for _, f := range ref.Flags {
				rules = append(rules, f.Rule)
			}
		}
		res.Flags = append(res.Flags, ref.Flags...)
		// Late paths can need a relabel rather than a rule; apply and record
		// those, and count them as progress so a relabel-only round does not
		// falsely abort the advertised late-path recovery (review finding).
		newRules := mergeNewRules(&extraRules, rules)
		res.Relabels = append(res.Relabels, ref.Relabels...)
		for _, rl := range ref.Relabels {
			_, _ = r.Run(fmt.Sprintf("sudo restorecon -F %q", rl.Path))
		}
		if newRules == 0 && len(ref.Relabels) == 0 {
			break // genuinely nothing new — neither a rule nor a relabel
		}
		opts.Log("[%s] enforcing attempt %d had %d residual denials — refining and retrying", t.Name, attempt, len(denials))
		te := policy.GenerateTE(p) + policy.RenderRefinedSection(p, extraRules)
		fc := policy.GenerateFC(p)
		if err := installPolicy(r, p, te, fc); err != nil {
			return fail("policy-install (enforce refinement)", err)
		}
		res.FinalTE, res.FinalFC = te, fc
	}

	if err := recheck("after enforcement verification"); err != nil {
		return fail("verifier-integrity", err)
	}

	// 5. Static least-privilege assertions (the negative tests). A failing
	// check whose offending rule is one we flagged and consciously accepted is
	// an acknowledged exception, not a silent hole — report it as such.
	res.StaticChecks = staticChecks(r, dom)
	if opts.AcceptFlagged {
		accepted := map[string]bool{}
		for _, f := range res.Flags {
			accepted[f.Rule.Render()] = true
		}
		var remaining []StaticCheck
		for _, c := range res.StaticChecks {
			if !c.Passed && c.Detail != "" && coveredByAccepted(c.Detail, accepted) {
				res.AcceptedExceptions = append(res.AcceptedExceptions, c)
				continue
			}
			remaining = append(remaining, c)
		}
		res.StaticChecks = remaining
	}
	res.UngrantedPreds = elfscan.UngrantedPredictions(res.Predictions, res.FinalTE)

	res.FinalProfile = p
	res.FinalRules = extraRules

	// An unaccepted static-check failure fails the run. The report shows it
	// either way, but evidence must fail closed: a verdict that says pass
	// while sesearch proved forbidden access would let a verdict-only deploy
	// gate fail open (PR-review finding).
	for _, c := range res.StaticChecks {
		if !c.Passed {
			return fail("static-check", fmt.Errorf("%s: %s", c.Name, firstLine(c.Detail)))
		}
	}

	// 6. Package as RPM. Packaging failures also fail closed: a passing run
	// with no subject artifact is an attestation about nothing.
	if res.EnforceOK {
		rpm, err := buildRPM(r, p)
		if err != nil {
			return fail("rpmbuild", err)
		}
		res.RPMPath = rpm
		out, err := r.Run(fmt.Sprintf("sha256sum %q", rpm))
		fields := strings.Fields(out)
		if err != nil || len(fields) == 0 {
			return fail("rpm-digest", fmt.Errorf("sha256sum %s: %v", rpm, err))
		}
		res.RPMSHA256 = fields[0]
	}
	return res
}

// coveredByAccepted reports whether every line of a failing check's output is
// one of the consciously accepted flagged rules.
func coveredByAccepted(detail string, accepted map[string]bool) bool {
	for _, line := range strings.Split(detail, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !accepted[line] {
			return false
		}
	}
	return true
}

// relabelSignature is a stable key for the set of paths needing relabel.
func relabelSignature(rs []policy.Relabel) string {
	if len(rs) == 0 {
		return ""
	}
	paths := make([]string, 0, len(rs))
	for _, r := range rs {
		paths = append(paths, r.Path+"→"+r.ExpectedType)
	}
	sort.Strings(paths)
	return strings.Join(paths, ",")
}

var sharedInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true,
	"env": true, "perl": true, "python": true, "ruby": true, "node": true,
	"java": true, "php": true, "sh.distrib": true,
}

// isAppOwnedExecutable positively establishes that a path is the application's
// own entrypoint before it may receive the app exec type. Labeling a shared
// runtime as the exec type would, via init_daemon_domain, route unrelated
// system services into this application's domain — so a blacklist is unsafe;
// only a positive tie to the application qualifies (review finding).
func isAppOwnedExecutable(p *profile.Profile, path string) bool {
	base := filepath.Base(path)
	name := strings.ToLower(base)
	// bare interpreter (possibly versioned: python3.11, ruby3.3) — never.
	trimmed := strings.TrimRight(name, "0123456789.")
	if sharedInterpreters[trimmed] {
		return false
	}
	// Positive ties, strongest first:
	// 1. already a declared executable.
	if slices.Contains(p.Executables, path) {
		return true
	}
	// 2. under a filesystem tree the profile itself claims.
	for _, pa := range p.Paths {
		if root := fcRoot(pa.Path); root != "" && strings.HasPrefix(path, strings.TrimRight(root, "/")+"/") {
			return true
		}
	}
	// 3. the app name appears as a path component or in the basename. This is
	//    the required POSITIVE tie — there is NO "not in a system bin dir ⇒
	//    app-owned" fallback, which let shared runtimes like
	//    /usr/libexec/platform-python and /lib64/ld-linux-*.so.* through
	//    (review finding). Every entrypoint must earn the label.
	appName := strings.ToLower(policy.SafeName(p.Name))
	normName := strings.ReplaceAll(name, "-", "_")
	if strings.Contains(normName, appName) || strings.Contains(appName, normName) {
		return true
	}
	for _, seg := range strings.Split(strings.ToLower(filepath.Dir(path)), "/") {
		seg = strings.ReplaceAll(seg, "-", "_")
		if seg != "" && strings.Contains(seg, appName) {
			return true
		}
	}
	return false
}

// failEarly mirrors Run's fail closure for use before it is defined.
func failEarly(res *Result, opts Options, stage string, err error) *Result {
	res.FailureReason = fmt.Sprintf("%s: %v", stage, err)
	opts.Log("FAIL %s: %v", stage, err)
	return res
}

// sizeShrank reports whether the post size is smaller than the pre offset.
func sizeShrank(pre, post string) bool {
	a, err1 := strconv.Atoi(strings.TrimSpace(pre))
	b, err2 := strconv.Atoi(strings.TrimSpace(post))
	if err1 != nil || err2 != nil {
		return false
	}
	return b < a
}

// hasLine reports whether any whole line of out equals want.
func hasLine(out, want string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// installPolicy compiles and loads the module, then relabels claimed paths.
func installPolicy(r vm.Runner, p *profile.Profile, te, fc string) error {
	app := policy.SafeName(p.Name)
	dir := "/tmp/hardener/" + app
	if err := r.WriteFile(dir+"/"+app+".te", te); err != nil {
		return err
	}
	if err := r.WriteFile(dir+"/"+app+".fc", fc); err != nil {
		return err
	}
	reconcileStalePorts(r, p)
	script := fmt.Sprintf(`set -e
cd %q
sudo make -f /usr/share/selinux/devel/Makefile %s.pp
sudo semodule -i %s.pp
`, dir, app, app)
	if _, err := r.Run(script); err != nil {
		return err
	}
	for _, root := range RelabelRoots(p) {
		if _, err := r.Run(fmt.Sprintf("sudo restorecon -RF %q 2>/dev/null || true", root)); err != nil {
			return err
		}
	}
	for _, port := range p.Ports {
		_, _ = r.Run(fmt.Sprintf("sudo semanage port -a -t %s -p %s %d 2>/dev/null || true", policy.PortType(p.Name), port.Proto, port.Port))
	}
	return nil
}

// reconcileStalePorts deletes local port mappings of the app's port type that
// the current profile no longer declares. A stale mapping referencing a type
// the new module does not define makes semanage_base_merge fail with
// "Invalid argument" on every later policy operation, so this must run BEFORE
// semodule -i.
func reconcileStalePorts(r vm.Runner, p *profile.Profile) {
	pt := policy.PortType(p.Name)
	current := map[string]bool{}
	for _, port := range p.Ports {
		current[fmt.Sprintf("%s/%d", port.Proto, port.Port)] = true
	}
	// semanage port -l prints "type  proto  8080, 8443, 9000-9010" — every
	// token after the protocol is a port or range, comma-separated. Reading
	// only field 3 leaves stale mappings behind (review finding).
	existing, _ := r.Run(fmt.Sprintf("sudo semanage port -l 2>/dev/null | awk '$1==\"%s\" {proto=$2; for(i=3;i<=NF;i++){gsub(\",\",\"\",$i); print proto\"/\"$i}}'", pt))
	for _, m := range strings.Fields(existing) {
		if current[m] {
			continue
		}
		parts := strings.SplitN(m, "/", 2)
		if len(parts) == 2 && parts[1] != "" {
			_, _ = r.Run(fmt.Sprintf("sudo semanage port -d -t %s -p %s %s 2>/dev/null || true", pt, parts[0], parts[1]))
		}
	}
}

// exercise restarts the unit, runs the scenario script, stops the unit, and
// returns the domain's AVC denials observed during the window. Denials are
// captured by byte offset into audit.log — ausearch time filtering proved
// unreliable (returned "no matches" with matching records present).
func exercise(r vm.Runner, t *target.Target, dom string) ([]avc.Denial, bool, string, error) {
	pre, err := r.Run("sudo stat -c '%s %i' /var/log/audit/audit.log")
	if err != nil {
		return nil, false, "", fmt.Errorf("audit log offset: %w", err)
	}
	preFields := strings.Fields(strings.TrimSpace(pre))
	if len(preFields) != 2 {
		return nil, false, "", fmt.Errorf("audit log stat: unexpected %q", pre)
	}
	offset, startInode := preFields[0], preFields[1]
	if _, err := r.Run("sudo systemctl reset-failed " + t.Unit + " 2>/dev/null; true"); err != nil {
		return nil, false, "", err
	}
	_, startErr := r.Run(fmt.Sprintf("sudo systemctl restart %s", t.Unit))
	exOK := startErr == nil
	var label string
	if exOK {
		label, _ = r.Run(fmt.Sprintf(
			`pid=$(systemctl show -p MainPID --value %s); if [ "$pid" -gt 0 ] 2>/dev/null; then ps -o label= -p "$pid"; else echo NO_PID; fi`, t.Unit))
		_, exErr := r.Run("set -e\n" + t.Exercise)
		exOK = exErr == nil
	}
	_, _ = r.Run(fmt.Sprintf("sudo systemctl stop %s 2>/dev/null; true", t.Unit))
	// Fail closed on log rotation/truncation: a new inode or a shrunk file
	// means our byte offset is stale and a plain tail would silently miss AVC
	// records, reporting a false zero-denial pass (review finding).
	post, err := r.Run("sudo stat -c '%s %i' /var/log/audit/audit.log")
	if err != nil {
		return nil, exOK, label, fmt.Errorf("audit log re-stat: %w", err)
	}
	postFields := strings.Fields(strings.TrimSpace(post))
	if len(postFields) != 2 || postFields[1] != startInode {
		return nil, exOK, label, fmt.Errorf("audit log rotated during exercise (inode %s→%v) — re-run", startInode, postFields)
	}
	if sizeShrank(offset, postFields[0]) {
		return nil, exOK, label, fmt.Errorf("audit log truncated during exercise (%s→%s bytes) — re-run", offset, postFields[0])
	}
	out, err := r.Run(fmt.Sprintf(`sudo tail -c +%s /var/log/audit/audit.log 2>/dev/null | grep -E '^type=(AVC|SELINUX_ERR|PATH)'; true`, "$(("+offset+"+1))"))
	if err != nil {
		return nil, exOK, label, err
	}
	for _, te := range avc.ParseTransitionErrors(out) {
		if te.NewType == dom {
			return nil, exOK, label, fmt.Errorf(
				"kernel refused the domain transition into %s (%s from %s) — the unit almost certainly sets NoNewPrivileges=yes",
				te.NewType, te.Op, te.OldType)
		}
	}
	all := avc.ParseLogWithPaths(out)
	var mine []avc.Denial
	prefix := strings.TrimSuffix(dom, "_t") + "_"
	for _, d := range all {
		// Our domain's own denials, plus anything denied against one of our
		// types — a failed exec of our entrypoint is reported against init_t,
		// and dropping it makes a service that can never start look clean.
		if d.SourceType == dom || strings.HasPrefix(d.TargetType, prefix) {
			mine = append(mine, d)
		}
	}
	return mine, exOK, label, nil
}

// mergeNewRules merges freshly observed rules into the accumulated set,
// returning how many were genuinely new (rule identity = target+class+perm).
func mergeNewRules(acc *[]policy.AllowRule, fresh []policy.AllowRule) int {
	have := map[string]bool{}
	for _, r := range *acc {
		for _, p := range r.Perms {
			have[r.Target+"/"+r.Class+"/"+p] = true
		}
	}
	added := 0
	for _, r := range fresh {
		var newPerms []string
		for _, p := range r.Perms {
			if !have[r.Target+"/"+r.Class+"/"+p] {
				newPerms = append(newPerms, p)
				have[r.Target+"/"+r.Class+"/"+p] = true
			}
		}
		if len(newPerms) > 0 {
			*acc = append(*acc, policy.AllowRule{Source: r.Source, Target: r.Target, Class: r.Class, Perms: newPerms})
			added++
		}
	}
	*acc = normalizeRules(*acc)
	return added
}

// normalizeRules re-merges accumulated rules by (target, class).
func normalizeRules(rules []policy.AllowRule) []policy.AllowRule {
	type key struct{ t, c string }
	idx := map[key]int{}
	var out []policy.AllowRule
	for _, r := range rules {
		k := key{r.Target, r.Class}
		if i, ok := idx[k]; ok {
			out[i].Perms = unionSorted(out[i].Perms, r.Perms)
			continue
		}
		idx[k] = len(out)
		out = append(out, r)
	}
	return out
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		seen[x] = true
	}
	out := make([]string, 0, len(seen))
	for x := range seen {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// RelabelRoots derives concrete filesystem roots to restorecon from the
// profile's file-context regexes and executables.
func RelabelRoots(p *profile.Profile) []string {
	var roots []string
	for _, pa := range p.Paths {
		roots = append(roots, fcRoot(pa.Path))
	}
	for _, exe := range p.Executables {
		roots = append(roots, exe)
	}
	return roots
}

// fcRoot strips the trailing regex portion of a file-contexts pattern.
func fcRoot(pattern string) string {
	for _, suffix := range []string{"(/.*)?", "/.*", "(.*)?", ".*"} {
		pattern = strings.TrimSuffix(pattern, suffix)
	}
	return pattern
}

// staticChecks runs sesearch least-privilege assertions against the loaded policy.
// The queries assert EMPTY output, so broken tooling would make every check
// pass. Two guards close that hole: the tools must exist, and a canary query
// that is non-empty on any targeted policy must return rows.
func staticChecks(r vm.Runner, dom string) []StaticCheck {
	if out, err := r.Run("command -v sesearch semanage >/dev/null && echo TOOLS_OK; true"); err != nil || !strings.Contains(out, "TOOLS_OK") {
		return []StaticCheck{{Name: "static-check tooling present", Passed: false, Detail: "sesearch/semanage unavailable in verifier"}}
	}
	if out, err := r.Run("sesearch -A -s init_t -c file -p execute 2>/dev/null | head -1; true"); err != nil || strings.TrimSpace(out) == "" {
		return []StaticCheck{{Name: "static-check canary", Passed: false, Detail: "canary sesearch query returned nothing — policy query tooling is broken"}}
	}
	checks := []struct {
		name  string
		query string
	}{
		{"no shadow_t read/write", fmt.Sprintf("sesearch -A -s %s -t shadow_t -c file -p read,write,open,append 2>/dev/null", dom)},
		{"no etc_t write", fmt.Sprintf("sesearch -A -s %s -t etc_t -c file -p write,append,create,unlink 2>/dev/null", dom)},
		{"no sys_admin capability", fmt.Sprintf("sesearch -A -s %s -c capability -p sys_admin 2>/dev/null", dom)},
		{"no sys_module capability", fmt.Sprintf("sesearch -A -s %s -c capability -p sys_module 2>/dev/null", dom)},
		{"no kernel module load", fmt.Sprintf("sesearch -A -s %s -c system -p module_load 2>/dev/null", dom)},
		{"not permissive", fmt.Sprintf("sudo semanage permissive -l 2>/dev/null | grep -w %s", dom)},
		{"no selinux mgmt", fmt.Sprintf("sesearch -A -s %s -t selinux_config_t -p write 2>/dev/null", dom)},
	}
	var out []StaticCheck
	for _, c := range checks {
		res, _ := r.Run(c.query + "; true")
		trimmed := strings.TrimSpace(res)
		out = append(out, StaticCheck{Name: c.name, Query: c.query, Passed: trimmed == "", Detail: trimmed})
	}
	return out
}
