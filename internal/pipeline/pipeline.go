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
	// Revision is a monotonically increasing build stamp baked into the policy
	// RPM's Release, so two builds with different content never share a NEVRA
	// (the CLI sets it to a UTC timestamp). Empty falls back to "0".
	Revision string
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
	if opts.MaxRounds < 1 {
		// 0 means "unset" → default; negative would skip synthesis entirely and
		// let enforcement pass against a stale module on a persistent verifier
		// (review finding). Clamp both to the default.
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

	// Refuse to SHADOW an existing SELinux policy. If the domain type already
	// exists before we install anything, a distro (or a leftover) module owns
	// this name — generating a minimal module under the same name would shadow
	// the real one and quietly weaken confinement (review finding: e.g.
	// hardening `sshd`, whose sshd_t the base policy already defines). This is
	// the automated form of the documented "already confined" exclusion; run on
	// a clean verifier. sesearch returns rules only for a type that exists.
	// Detect a pre-existing SELinux type. The previous check piped sesearch to
	// `head`, so the pipeline exit status was head's (always 0) and a sesearch
	// FAILURE looked like "no conflict" — fail open; it also only found types
	// that had a process ALLOW rule, missing a bare type declaration (review
	// finding). Query the type DIRECTLY with seinfo, cross-check with sesearch,
	// and fail closed only when NEITHER tool can run.
	nameConflict := func() (bool, error) {
		out, err := r.Run(fmt.Sprintf("seinfo -t %s 2>/dev/null", dom))
		if err == nil && strings.Contains(out, dom) {
			return true, nil // the type is defined → conflict
		}
		out2, err2 := r.Run(fmt.Sprintf("sesearch -A -s %s -c process 2>/dev/null", dom))
		if err2 == nil && strings.TrimSpace(out2) != "" {
			return true, nil // a process rule for the type exists → conflict
		}
		if err != nil && err2 != nil {
			// Neither seinfo nor sesearch could run — we cannot trust an "absent"
			// answer and must not risk shadowing an existing module.
			return false, fmt.Errorf("cannot query SELinux type %s (seinfo and sesearch both failed) — refusing to risk shadowing an existing policy", dom)
		}
		return false, nil
	}
	if conflict, err := nameConflict(); err != nil {
		return fail("name-conflict-query", err)
	} else if conflict {
		return fail("name-conflict", fmt.Errorf(
			"SELinux type %s already exists on the verifier — %s is already confined by an existing policy (or its name collides with distro policy); hardener will not shadow it. Use a distinct name or a clean verifier", dom, t.Name))
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
	// Re-check for a name conflict AFTER install/setup: the vendor's own
	// packages or setup scripts may have loaded a SELinux module that defines
	// our domain type. The pre-install check could not see it, and proceeding
	// would shadow or replace that module (and rollback would remove it) — refuse
	// instead (review finding).
	if conflict, err := nameConflict(); err != nil {
		return fail("name-conflict-query-post-install", err)
	} else if conflict {
		return fail("name-conflict-post-install", fmt.Errorf(
			"SELinux type %s appeared after installing %s — the artifact ships its own policy for this type; hardener will not shadow or replace it. Use a distinct name or exclude the vendor policy", dom, t.Name))
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
		out, err := r.Run(fmt.Sprintf("readlink -f -- %s", vm.ShellQuote(exe)))
		real := strings.TrimSpace(out)
		if err != nil || real == "" {
			real = exe
		}
		if real != exe {
			opts.Log("[%s] executable %s is a symlink → %s (labeling target)", t.Name, exe, real)
		}
		// Every resolved entrypoint must be positively app-owned before it may
		// receive the app exec type. Labeling a shared runtime as _exec_t routes
		// every use of that binary into this domain via init_daemon_domain. A
		// symlink can resolve to /bin/sh, but a manifest can ALSO name a shared
		// binary (/usr/bin/bash) directly — validation must run for unchanged
		// paths too, not only when readlink rewrote them (review finding: the
		// direct case previously skipped the check and relabeled the shell).
		if !isAppOwnedExecutable(p, real) {
			opts.Log("[%s] entrypoint %s is not positively app-owned — refusing to label a shared binary; declare the real entrypoint in the manifest", t.Name, real)
			continue
		}
		// readlink -f resolves SYMLINKS but not HARD links. An app-owned path can
		// be hard-linked to a shared system binary (/usr/bin/bash); restorecon
		// would then relabel the shared inode as the app exec type, affecting every
		// other link to it (review finding). Require EXACTLY one link and FAIL
		// CLOSED: a root-only binary that unprivileged stat cannot read, or any
		// malformed/failed stat, must refuse the entrypoint rather than assume a
		// single link (review finding: the earlier check failed open on stat error).
		// Privileged stat so a root-owned entrypoint is still countable.
		lc, lerr := r.Run(fmt.Sprintf("sudo stat -c %%h -- %s", vm.ShellQuote(real)))
		n, perr := strconv.Atoi(strings.TrimSpace(lc))
		if lerr != nil || perr != nil || n != 1 {
			opts.Log("[%s] entrypoint %s: hard-link count is %q (want exactly 1) — refusing to label a shared or unstattable inode", t.Name, real, strings.TrimSpace(lc))
			continue
		}
		if !seen[real] {
			seen[real] = true
			resolved = append(resolved, real)
		}
	}
	p.Executables = resolved
	// Fingerprint EVERY resolved entrypoint as installed — bound into the
	// verdict. This must fail closed: an execute-only or root-owned binary that
	// `sha256sum` (unprivileged) cannot read used to be silently skipped, so a
	// binary could run under systemd while the passing verdict bound no digest
	// for it (review finding). Read with sudo and require a valid 64-hex digest
	// for each; a missing one fails the run. Paths are single-quoted (not %q,
	// whose double quotes still expand $()/backticks under passwordless sudo).
	res.EntrypointDigests = map[string]string{}
	for _, exe := range p.Executables {
		out, err := r.Run(fmt.Sprintf("sudo sha256sum -- %s", vm.ShellQuote(exe)))
		if err != nil {
			return fail("entrypoint-digest", fmt.Errorf("hashing entrypoint %s: %w", exe, err))
		}
		fs := strings.Fields(out)
		if len(fs) == 0 || len(fs[0]) != 64 {
			return fail("entrypoint-digest", fmt.Errorf("entrypoint %s produced no valid sha256 (got %q)", exe, strings.TrimSpace(out)))
		}
		res.EntrypointDigests[exe] = fs[0]
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
		out, err := r.Run(fmt.Sprintf("readelf --dyn-syms -W -- %s 2>/dev/null; true", vm.ShellQuote(exe)))
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
	// An ENTRYPOINT collision is fatal. If the base policy already labels the
	// exact executable path, our .fc cannot relabel it to <app>_exec_t (a
	// duplicate spec is dropped or rejected), so the init→domain transition
	// never fires and the service runs unconfined as init_t — while restorecon
	// still exits 0, so nothing downstream notices (review finding). Fail loudly
	// instead of shipping a policy that silently does not confine.
	execSet := map[string]bool{}
	for _, e := range p.Executables {
		execSet[e] = true
	}
	var execCols []string
	for _, c := range res.Collisions {
		if execSet[c.Path] {
			execCols = append(execCols, c.Render())
		}
	}
	if len(execCols) > 0 {
		return fail("entrypoint label collision", fmt.Errorf(
			"the base policy already labels the entrypoint(s) [%s]; %s cannot receive its exec type, so the domain transition into %s never occurs and the service would run unconfined. Remediation: move/rename the entrypoint, or remove the conflicting base file-context",
			strings.Join(execCols, "; "), t.Name, policy.DomainType(p.Name)))
	}
	// A collided PATH (data/config, not an entrypoint) is recoverable: drop it
	// from the profile so (a) the .fc omits it, and (b) refinement stops
	// expecting our label there and instead proposes access to the base type —
	// which, being a shared type, lands in the human-review flags where it
	// belongs. The app keeps working; it is just less confined on that path,
	// and the collision is reported.
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
	//
	// The observe rounds put the domain on the persistent verifier's PERMISSIVE
	// list. The success path removes it before the enforcing check (below), but
	// any early error return in between would otherwise leave the domain
	// permissive for every future run on this box (review finding). Guarantee
	// removal on all paths with a deferred, idempotent cleanup; the success path
	// still calls it explicitly (and surfaces a removal failure) before enforcing.
	permissiveCleared := false
	clearPermissive := func() error {
		if permissiveCleared {
			return nil
		}
		_, err := r.Run(fmt.Sprintf("sudo semanage permissive -d %s", dom))
		if err == nil {
			permissiveCleared = true
		}
		return err
	}
	defer func() { _ = clearPermissive() }()

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
			if _, err := r.Run(fmt.Sprintf("sudo restorecon -F -- %s", vm.ShellQuote(rl.Path))); err != nil {
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

	// Install the FINAL accumulated policy before enforcement. The observe loop
	// installs at the START of each round, so any rules discovered in the LAST
	// round (including when convergence lands exactly on MaxRounds) were merged
	// into extraRules but never installed. Enforcement would then rediscover
	// them as denials, mergeNewRules would report zero new progress, and the
	// enforce loop would give up without ever installing them — failing on rules
	// we already know (review finding).
	finalTE := policy.GenerateTE(p) + policy.RenderRefinedSection(p, extraRules)
	finalFC := policy.GenerateFC(p)
	if err := installPolicy(r, p, finalTE, finalFC); err != nil {
		return fail("final-policy-install", err)
	}
	res.FinalTE, res.FinalFC = finalTE, finalFC

	// The verifier itself must still be trustworthy after running the
	// artifact's privileged install/setup/exercise scripts: a malicious
	// package could have run setenforce 0 or stopped auditd, making every
	// later observation a false pass.
	recheck := func(when string) error {
		out, err := r.Run("getenforce; systemctl is-active auditd")
		if err != nil || !hasLine(out, "Enforcing") || !hasLine(out, "active") {
			return fmt.Errorf("verifier integrity lost %s (need Enforcing + auditd): %s %v", when, strings.TrimSpace(out), err)
		}
		// auditd being ACTIVE is not sufficient — a privileged script can
		// `auditctl -e 0` to disable auditing while the service stays up, so every
		// later observation is a false zero-denial. Require auditing ENABLED (1, or
		// 2=locked) and fail closed if it cannot be confirmed (review finding).
		if en, _, _, ok := auditStatus(r); !ok || en < 1 {
			return fmt.Errorf("verifier integrity lost %s: auditing is not confirmed enabled (auditctl -s enabled=%d, queryable=%v)", when, en, ok)
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
	if err := clearPermissive(); err != nil {
		return fail("un-permissive", err)
	}
	for attempt := 1; ; attempt++ {
		denials, exOK, run, err := exercise(r, t, dom)
		if err != nil {
			return fail("enforce-exercise", err)
		}
		res.ExerciseOK = exOK
		res.ResidualAVCs = denials
		res.DomainOK = strings.Contains(run.Label, ":"+dom+":")
		// Bind the bytes that ACTUALLY ran: DomainOK only proves the MainPID
		// carries our domain label, not that the running binary is one of the
		// entrypoints we hashed. A stale *_exec_t label, an omitted executable,
		// or an ExecStart parse miss could run different bytes while the verdict
		// binds unrelated digests (review finding). When the process is in our
		// domain, its /proc/$pid/exe MUST be a declared entrypoint with the
		// digest we captured.
		if res.DomainOK && exOK {
			if run.ExePath == "" || run.ExeDigest == "" {
				return fail("running-exe-unverified", fmt.Errorf(
					"process runs in %s but its running binary could not be captured (exe=%q sha=%q)", dom, run.ExePath, run.ExeDigest))
			}
			want, ok := res.EntrypointDigests[run.ExePath]
			if !ok {
				return fail("running-exe-unbound", fmt.Errorf(
					"running binary %s is not a declared entrypoint (declared: %v) — the verdict would bind bytes that were not exercised", run.ExePath, sortedKeys(res.EntrypointDigests)))
			}
			if run.ExeDigest != want {
				return fail("running-exe-mismatch", fmt.Errorf(
					"running binary %s has digest %s but the declared entrypoint digest is %s", run.ExePath, run.ExeDigest, want))
			}
		}
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
			_, _ = r.Run(fmt.Sprintf("sudo restorecon -F -- %s", vm.ShellQuote(rl.Path)))
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

	// Re-hash the entrypoints after all executions and fail on any change: a
	// self-updating artifact (or the exercise itself) could have replaced a
	// binary after the initial capture, leaving the verdict bound to bytes
	// that were never actually verified under enforcement (review finding).
	for exe, want := range res.EntrypointDigests {
		out, err := r.Run(fmt.Sprintf("sudo sha256sum -- %s", vm.ShellQuote(exe)))
		fs := strings.Fields(out)
		if err != nil || len(fs) == 0 || fs[0] != want {
			return fail("entrypoint-mutated", fmt.Errorf(
				"entrypoint %s changed digest during verification (%s → %v) — the verdict cannot bind unverified bytes", exe, want, fs))
		}
	}

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
		rpm, err := buildRPM(r, p, opts.Revision)
		if err != nil {
			return fail("rpmbuild", err)
		}
		res.RPMPath = rpm
		out, err := r.Run(fmt.Sprintf("sha256sum -- %s", vm.ShellQuote(rpm)))
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
	// Declaration ALONE is never sufficient. A manifest can list a shared system
	// file well outside the six bin dirs — e.g. /usr/lib/systemd/system/
	// sshd.service — and a blanket "declared and not in a bin dir → owned" rule
	// then relabeled it as the app exec type as root (review finding). Ownership
	// must be positively EARNED by one of the ties below, regardless of whether
	// the path was declared. Positive ties, strongest first:
	// 1. under a filesystem tree the profile itself claims.
	for _, pa := range p.Paths {
		if root := fcRoot(pa.Path); root != "" && strings.HasPrefix(path, strings.TrimRight(root, "/")+"/") {
			return true
		}
	}
	// 3. an EXACT app-specific component tie — the basename or a path
	//    directory component equals the app name, or begins with the app name
	//    followed by a separator (emby-server for app emby). No substring or
	//    reverse-substring match: "plex" must not adopt /usr/bin/x just
	//    because the app name contains "x" (review finding). Every entrypoint
	//    must earn the label with a real name match.
	appName := strings.ToLower(policy.SafeName(p.Name))
	matches := func(seg string) bool {
		seg = norm(seg)
		// Exact, or app name followed by a separator boundary. norm() maps
		// '-' and '.' to '_', so "emby_server" ties to "emby" but "postgres"
		// does NOT tie to "post" and "plexiglass" does NOT tie to "plex"
		// (boundary-aware, review finding). Vendor dirs without a separator
		// (plexmediaserver) rely on the manifest declaring the executable.
		return seg == appName || strings.HasPrefix(seg, appName+"_")
	}
	if matches(name) {
		return true
	}
	for _, seg := range strings.Split(filepath.Dir(path), "/") {
		if seg != "" && matches(seg) {
			return true
		}
	}
	return false
}

// norm lowercases and maps separators to underscores so path components
// compare against the SafeName-normalized app name.
func norm(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
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
cd %s
sudo make -f /usr/share/selinux/devel/Makefile %s.pp
sudo semodule -i %s.pp
`, vm.ShellQuote(dir), app, app)
	if _, err := r.Run(script); err != nil {
		return err
	}
	for _, root := range RelabelRoots(p) {
		if _, err := r.Run(fmt.Sprintf("sudo restorecon -RF -- %s 2>/dev/null || true", vm.ShellQuote(root))); err != nil {
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

// runInfo captures what the MainPID actually was during the exercise window:
// its SELinux label AND the resolved path + digest of the running binary. The
// digest lets the verdict bind the bytes that REALLY ran, not just the
// manifest-derived list (review finding).
type runInfo struct {
	Label     string
	ExePath   string
	ExeDigest string
}

// exercise restarts the unit, runs the scenario script, stops the unit, and
// returns the domain's AVC denials observed during the window. Denials are
// captured by byte offset into audit.log — ausearch time filtering proved
// unreliable (returned "no matches" with matching records present).
func exercise(r vm.Runner, t *target.Target, dom string) ([]avc.Denial, bool, runInfo, error) {
	pre, err := r.Run("sudo stat -c '%s %i' /var/log/audit/audit.log")
	if err != nil {
		return nil, false, runInfo{}, fmt.Errorf("audit log offset: %w", err)
	}
	preFields := strings.Fields(strings.TrimSpace(pre))
	if len(preFields) != 2 {
		return nil, false, runInfo{}, fmt.Errorf("audit log stat: unexpected %q", pre)
	}
	offset, startInode := preFields[0], preFields[1]
	// Snapshot audit status. (1) auditing must be ENABLED — a privileged script
	// can `auditctl -e 0` while auditd the SERVICE stays active, suppressing every
	// AVC (review finding); fail closed when it is queryable and disabled. (2) the
	// LOSS counter: if it climbs during the window the kernel dropped records on
	// buffer overflow, so a zero-denial slice is not trustworthy (review finding).
	en0, lost0, _, auOK0 := auditStatus(r)
	if auOK0 && en0 == 0 {
		return nil, false, runInfo{}, fmt.Errorf("auditing is disabled on the verifier (auditctl -s enabled=0) — cannot observe denials; enable auditing and re-run")
	}
	if _, err := r.Run("sudo systemctl reset-failed " + t.Unit + " 2>/dev/null; true"); err != nil {
		return nil, false, runInfo{}, err
	}
	_, startErr := r.Run(fmt.Sprintf("sudo systemctl restart %s", t.Unit))
	exOK := startErr == nil
	var run runInfo
	if exOK {
		// Capture the label AND the running binary (resolved path + digest) from
		// the SAME MainPID while the service is up.
		run = captureRunInfo(r, t.Unit)
		_, exErr := r.Run("set -e\n" + t.Exercise)
		exOK = exErr == nil
		// TOCTOU: `run` was captured right after restart, BEFORE the scenario. If
		// the exercise restarted or re-exec'd the service into different bytes or
		// an unconfined context, binding the verdict to the pre-exercise capture
		// would attest a process that did not do the work (review finding).
		// Re-capture after the scenario; if a MainPID is still present and its
		// (domain, exe, digest) changed, fail closed. A same-identity restart
		// (new pid, same binary/label/digest) is benign; a clean stop by the
		// scenario (no pid) leaves the pre-capture authoritative.
		if exOK {
			if after := captureRunInfo(r, t.Unit); after.ExePath != "" &&
				(after.ExePath != run.ExePath || after.ExeDigest != run.ExeDigest ||
					labelType(after.Label) != labelType(run.Label)) {
				return nil, false, run, fmt.Errorf(
					"the exercised process changed identity mid-run (before exe=%s sha=%s label=%s; after exe=%s sha=%s label=%s) — the verdict cannot bind a single executed image",
					run.ExePath, run.ExeDigest, run.Label, after.ExePath, after.ExeDigest, after.Label)
			}
		}
	}
	stopErr := func() error { _, e := r.Run(fmt.Sprintf("sudo systemctl stop %s", t.Unit)); return e }()
	// The unit must actually be stopped: a still-running process could keep
	// generating (or hide) records outside our window. Verify inactivity and fail
	// closed rather than discarding the stop error (review finding).
	if act, _ := r.Run(fmt.Sprintf("systemctl is-active %s", t.Unit)); hasLine(act, "active") {
		return nil, exOK, run, fmt.Errorf("unit %s did not stop after the exercise (%s, err=%v) — cannot bound the observation window", t.Unit, strings.TrimSpace(act), stopErr)
	}
	// Drain barrier: the process is dead, so no NEW records are generated; give
	// auditd's backlog a bounded chance to flush pending records to disk before we
	// read, so a late-written AVC is not missed as a false zero-denial (review
	// finding). Each probe is a round-trip, so no sleep is needed. If the backlog
	// is queryable but never drains, FAIL CLOSED rather than read a partial slice.
	backlogDrained := true
	for i := 0; i < 5; i++ {
		_, _, bl, ok := auditStatus(r)
		if !ok || bl <= 0 {
			backlogDrained = true
			break
		}
		backlogDrained = false
	}
	if !backlogDrained {
		return nil, exOK, run, fmt.Errorf("auditd backlog did not drain after the exercise — audit records may still be unwritten; re-run on a less loaded verifier")
	}
	// Fail closed on log rotation/truncation: a new inode or a shrunk file
	// means our byte offset is stale and a plain tail would silently miss AVC
	// records, reporting a false zero-denial pass (review finding).
	post, err := r.Run("sudo stat -c '%s %i' /var/log/audit/audit.log")
	if err != nil {
		return nil, exOK, run, fmt.Errorf("audit log re-stat: %w", err)
	}
	postFields := strings.Fields(strings.TrimSpace(post))
	if len(postFields) != 2 || postFields[1] != startInode {
		return nil, exOK, run, fmt.Errorf("audit log rotated during exercise (inode %s→%v) — re-run", startInode, postFields)
	}
	if sizeShrank(offset, postFields[0]) {
		return nil, exOK, run, fmt.Errorf("audit log truncated during exercise (%s→%s bytes) — re-run", offset, postFields[0])
	}
	// Capture the RAW slice — do not pre-filter with `grep -E '^type=...'`. On a
	// host with auditd name_format set, every record is prefixed with
	// `node=<hostname> `, so an anchored `^type=` silently drops real AVCs and a
	// denied domain looks clean. The parsers below already select AVC/
	// SELINUX_ERR/PATH records (substring match, prefix-tolerant) and ignore the
	// rest. Dropping the `; true` also means a failed `tail` (rotated/again
	// truncated log, permission loss) surfaces as an error instead of an empty
	// "no denials" result (review finding).
	out, err := r.Run(fmt.Sprintf(`sudo tail -c +%s /var/log/audit/audit.log 2>/dev/null`, "$(("+offset+"+1))"))
	if err != nil {
		return nil, exOK, run, fmt.Errorf("reading audit slice: %w", err)
	}
	// Re-stat the inode AFTER the read. The rotation check above happens before
	// a SEPARATE tail command; a rotation in that window would make tail read the
	// NEW file at the stale offset and return an empty slice successfully — a
	// false zero-denial pass (review finding). If the inode changed across the
	// read, our offset is meaningless and the slice cannot be trusted.
	post2, err := r.Run("sudo stat -c '%i' /var/log/audit/audit.log")
	if err != nil {
		return nil, exOK, run, fmt.Errorf("audit log post-read stat: %w", err)
	}
	if strings.TrimSpace(post2) != startInode {
		return nil, exOK, run, fmt.Errorf("audit log rotated during read (inode %s→%s) — re-run", startInode, strings.TrimSpace(post2))
	}
	// If the kernel dropped audit records during the window, the slice we just
	// read may be missing AVCs — a zero-denial result would be a false pass. Only
	// enforced when both snapshots were readable (auditctl present) so a
	// stat/audit-less environment is not spuriously blocked (review finding).
	if _, lost1, _, auOK1 := auditStatus(r); auOK0 && auOK1 && lost0 >= 0 && lost1 > lost0 {
		return nil, exOK, run, fmt.Errorf("kernel audit records were lost during the exercise (lost %d→%d) — the denial set is incomplete; re-run on a less loaded verifier", lost0, lost1)
	}
	for _, te := range avc.ParseTransitionErrors(out) {
		if te.NewType == dom {
			return nil, exOK, run, fmt.Errorf(
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
	return mine, exOK, run, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// captureRunInfo reads the unit's MainPID and returns that process's SELinux
// label plus the resolved path and digest of its running binary, in one shot
// while the service is up. An absent PID yields a zero runInfo.
func captureRunInfo(r vm.Runner, unit string) runInfo {
	out, _ := r.Run(fmt.Sprintf(
		`pid=$(systemctl show -p MainPID --value %s); if [ "$pid" -gt 0 ] 2>/dev/null; then `+
			`printf 'LABEL:%%s\n' "$(ps -o label= -p "$pid")"; `+
			`printf 'EXE:%%s\n' "$(sudo readlink -f /proc/$pid/exe 2>/dev/null)"; `+
			`printf 'EXESHA:%%s\n' "$(sudo sha256sum /proc/$pid/exe 2>/dev/null | awk '{print $1}')"; `+
			`else echo NO_PID; fi`, unit))
	return parseRunInfo(out)
}

// auditStatus parses `auditctl -s` in one call. Its output is space- or
// newline-separated "key value" pairs (older builds use "key=value"). Fields
// absent from the output are returned as -1; ok is false when auditctl cannot be
// queried at all, so callers can skip (best-effort) on a verifier without audit
// tooling while still enforcing when it IS present.
func auditStatus(r vm.Runner) (enabled, lost, backlog int, ok bool) {
	out, err := r.Run("sudo auditctl -s 2>/dev/null")
	if err != nil || strings.TrimSpace(out) == "" {
		return -1, -1, -1, false
	}
	f := strings.Fields(out)
	find := func(key string) int {
		for i, tok := range f {
			if tok == key && i+1 < len(f) {
				if n, e := strconv.Atoi(f[i+1]); e == nil {
					return n
				}
			}
			if strings.HasPrefix(tok, key+"=") {
				if n, e := strconv.Atoi(strings.TrimPrefix(tok, key+"=")); e == nil {
					return n
				}
			}
		}
		return -1
	}
	return find("enabled"), find("lost"), find("backlog"), true
}

// labelType extracts the SELinux type from a user:role:type:level context so a
// confined→unconfined transition is detected even when the binary is unchanged.
func labelType(label string) string {
	parts := strings.Split(strings.TrimSpace(label), ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return strings.TrimSpace(label)
}

// parseRunInfo pulls the LABEL/EXE/EXESHA lines out of the capture command's
// output. NO_PID or a missing line simply leaves that field empty.
func parseRunInfo(out string) runInfo {
	var ri runInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "LABEL:"):
			ri.Label = strings.TrimSpace(strings.TrimPrefix(line, "LABEL:"))
		case strings.HasPrefix(line, "EXE:"):
			ri.ExePath = strings.TrimSpace(strings.TrimPrefix(line, "EXE:"))
		case strings.HasPrefix(line, "EXESHA:"):
			ri.ExeDigest = strings.TrimSpace(strings.TrimPrefix(line, "EXESHA:"))
		}
	}
	return ri
}

// mergeNewRules merges freshly observed rules into the accumulated set,
// returning how many were genuinely new. Rule identity is
// source+target+class+perm: the SOURCE domain is part of the key so a rule for
// one domain never suppresses or absorbs the same target/perm observed for a
// DIFFERENT domain (an entrypoint denial is attributed to init_t, and the
// planned multi-domain split emits several sources) — review finding.
func mergeNewRules(acc *[]policy.AllowRule, fresh []policy.AllowRule) int {
	have := map[string]bool{}
	key := func(r policy.AllowRule, p string) string {
		return r.Source + "/" + r.Target + "/" + r.Class + "/" + p
	}
	for _, r := range *acc {
		for _, p := range r.Perms {
			have[key(r, p)] = true
		}
	}
	added := 0
	for _, r := range fresh {
		var newPerms []string
		for _, p := range r.Perms {
			if !have[key(r, p)] {
				newPerms = append(newPerms, p)
				have[key(r, p)] = true
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

// normalizeRules re-merges accumulated rules by (source, target, class). Source
// is part of the key so rules for different domains are never collapsed into
// one another's permission set (review finding).
func normalizeRules(rules []policy.AllowRule) []policy.AllowRule {
	type key struct{ s, t, c string }
	idx := map[key]int{}
	var out []policy.AllowRule
	for _, r := range rules {
		k := key{r.Source, r.Target, r.Class}
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
		{"no selinux mgmt", fmt.Sprintf("sesearch -A -s %s -t selinux_config_t -p write 2>/dev/null", dom)},
	}
	var out []StaticCheck
	for _, c := range checks {
		res, err := r.Run(c.query)
		trimmed := strings.TrimSpace(res)
		// A sesearch query that fails to execute (bad policy, crashed tool)
		// returns empty output with a non-zero exit. Recording that as an empty
		// result marked the domain "clean" — a fail-open verification hole. Fail
		// the check closed instead so the verdict reflects that verification
		// could not run.
		if err != nil {
			out = append(out, StaticCheck{
				Name: c.name, Query: c.query, Passed: false,
				Detail: "verification query failed to execute (fail-closed): " + trimmed,
			})
			continue
		}
		out = append(out, StaticCheck{Name: c.name, Query: c.query, Passed: trimmed == "", Detail: trimmed})
	}
	out = append(out, permissiveCheck(r, dom))
	return out
}

// permissiveCheck asserts the domain is not in the permissive list. It cannot
// be folded into the sesearch loop: it runs semanage and greps, and grep exits
// non-zero on the SAFE no-match path — so a piped `semanage | grep` conflates a
// clean pass with a semanage failure and fails OPEN (review finding). Instead,
// require semanage itself to succeed, then decide membership in Go: a semanage
// that cannot run is unverifiable, not "not permissive".
func permissiveCheck(r vm.Runner, dom string) StaticCheck {
	c := StaticCheck{Name: "not permissive", Query: "semanage permissive -l (membership of " + dom + ")"}
	out, err := r.Run("sudo semanage permissive -l 2>&1")
	if err != nil {
		c.Passed = false
		c.Detail = "semanage permissive -l failed to run (fail-closed): " + strings.TrimSpace(out)
		return c
	}
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if f == dom {
				c.Passed = false
				c.Detail = dom + " is in the permissive list"
				return c
			}
		}
	}
	c.Passed = true
	return c
}
