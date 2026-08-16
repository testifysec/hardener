// hardener: automated SELinux policy compiler for legacy artifacts.
//
// Usage:
//
//	hardener run --vm <lima-instance> --out <report-dir> <target.yaml>...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/testifysec/hardener/internal/archivista"
	"github.com/testifysec/hardener/internal/conformance"
	"github.com/testifysec/hardener/internal/pipeline"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/signing"
	"github.com/testifysec/hardener/internal/target"
	"github.com/testifysec/hardener/internal/verdict"
	"github.com/testifysec/hardener/internal/vm"
)

// checkConformance applies the supply-chain party contract to a verified run.
//   - second party: observed behavior must stay inside the supplier's
//     declaration; anything undeclared is a supplier finding and fails the run.
//   - first party: observed behavior must match the committed baseline;
//     drift fails the run until a human reviews and updates the baseline.
//   - third party: no counterparty holds a claim; a declared block, if present,
//     is compared for advisory reporting only.
func checkConformance(res *pipeline.Result, t *target.Target, manifestPath string, updateBaseline bool, logf func(string, ...any)) {
	res.Party = t.Party
	// Never persist or compare a baseline for a run that did not fully verify:
	// an enforcement failure can leave FailureReason empty while EnforceOK is
	// false, and --update-baseline would otherwise commit an unverified
	// privilege set (review finding).
	if res.FinalProfile == nil || res.IsFailure() {
		return
	}
	obs := conformance.ExtractObserved(res.FinalProfile, res.FinalRules)

	var decl *profile.Declaration
	baseline := t.Baseline
	switch t.Party {
	case "first":
		if baseline == "" {
			baseline = filepath.Join(filepath.Dir(manifestPath), "baselines", t.Name+".yaml")
		}
		loaded, err := conformance.LoadDeclaration(baseline)
		switch {
		case os.IsNotExist(err) && updateBaseline:
			_ = os.MkdirAll(filepath.Dir(baseline), 0o755)
			if err := conformance.SaveBaseline(baseline, obs); err != nil {
				res.ConformanceFatal = "cannot write baseline: " + err.Error()
				return
			}
			logf("[%s] first-party baseline created: %s", t.Name, baseline)
			return
		case os.IsNotExist(err):
			res.ConformanceFatal = "no committed baseline at " + baseline + " — review the report, then run with --update-baseline to create it"
			return
		case err != nil:
			res.ConformanceFatal = "baseline unreadable: " + err.Error()
			return
		}
		decl = loaded
	case "second":
		decl = t.Declared
	default:
		if t.Declared == nil {
			return
		}
		decl = t.Declared // advisory comparison for third party
	}

	rep := conformance.Compare(decl, obs)
	for _, f := range rep.Undeclared {
		res.ConformanceUndecl = append(res.ConformanceUndecl, f.String())
	}
	res.ConformanceUnexer = rep.Unexercised
	fatal, reason := conformance.Verdict(t.Party, rep)
	if fatal && t.Party == "first" && updateBaseline {
		// A human ran with --update-baseline: that IS the review acceptance.
		if err := conformance.SaveBaseline(baseline, obs); err != nil {
			res.ConformanceFatal = "cannot update baseline: " + err.Error()
			return
		}
		logf("[%s] baseline updated to accept drift: %s", t.Name, baseline)
		return
	}
	if fatal {
		res.ConformanceFatal = reason
		logf("[%s] conformance: %s", t.Name, reason)
	}
}

// Version metadata, stamped by the release pipeline via
// -ldflags "-X main.version=... -X main.gitCommit=... -X main.buildTime=...".
// An unstamped build reports "dev"; the release workflow fails closed on that.
var (
	version   = "dev"
	gitCommit = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Printf("version: %s\ncommit: %s\nbuilt: %s\n", version, gitCommit, buildTime)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: hardener run --vm <lima-instance> --out <dir> <target.yaml>...\n       hardener version")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	vmName := fs.String("vm", "selinux-verifier", "Lima instance name (local verifier)")
	sshTarget := fs.String("ssh", "", "remote verifier over ssh, user@host (RHEL-family, Enforcing, passwordless sudo); overrides --vm")
	sshKey := fs.String("ssh-key", "", "identity file for --ssh")
	outDir := fs.String("out", "reports", "report output directory")
	rounds := fs.Int("rounds", 5, "max permissive observation rounds")
	acceptFlagged := fs.Bool("accept-flagged", false, "auto-apply flagged rules (still reported)")
	updateBaseline := fs.Bool("update-baseline", false, "first-party targets: write the observed behavior as the new baseline")
	signKey := fs.String("sign-key", "", "optional: ed25519 PKCS#8 PEM key; signs each verdict into a DSSE envelope (<target>.verdict.dsse.json)")
	archivistaURL := fs.String("archivista-url", "", "optional: Archivista base URL; uploads the signed envelope (requires --sign-key)")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() == 0 {
		log.Fatal("no target manifests given")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	// Reject inputs whose OUTPUT basename collides before running anything. The
	// report, verdict, and signed envelope are all named from
	// filepath.Base(path), so two manifests at different paths (team-a/app.yaml
	// and team-b/app.yaml) would silently overwrite each other's outputs
	// (review finding).
	seenOut := map[string]string{}
	for _, path := range fs.Args() {
		base := strings.TrimSuffix(filepath.Base(path), ".yaml")
		if prev, ok := seenOut[base]; ok {
			log.Fatalf("output-name collision: %q and %q both write outputs named %q — rename one so their outputs do not overwrite each other", prev, path, base)
		}
		seenOut[base] = path
	}

	var runner vm.Runner = &vm.Lima{Instance: *vmName}
	if *sshTarget != "" {
		runner = &vm.SSH{Target: *sshTarget, KeyPath: *sshKey}
	}
	failures := 0
	for _, path := range fs.Args() {
		t, err := target.Load(path)
		if err != nil {
			log.Printf("SKIP %s: %v", path, err)
			failures++
			continue
		}
		log.Printf("=== %s ===", t.Name)
		res := pipeline.Run(runner, t, pipeline.Options{
			MaxRounds:     *rounds,
			AcceptFlagged: *acceptFlagged,
			Log:           log.Printf,
			// UTC timestamp → a monotonic RPM Release, so rebuilding a policy
			// with changed content never collides with the prior NEVRA.
			Revision: time.Now().UTC().Format("20060102150405"),
		})
		checkConformance(res, t, path, *updateBaseline, log.Printf)
		report := pipeline.RenderReport(res)
		base := strings.TrimSuffix(filepath.Base(path), ".yaml")
		out := filepath.Join(*outDir, base+".md")
		if err := os.WriteFile(out, []byte(report), 0o644); err != nil {
			log.Fatal(err)
		}

		// The verdict as an attestation: an unsigned in-toto statement, ready
		// for the factory's signing rails (cilock run -- hardener run ...).
		var subjects []verdict.Subject
		if res.RPMPath != "" && res.RPMSHA256 != "" {
			subjects = append(subjects, verdict.Subject{Name: verdict.RPMSubjectName(res.RPMPath), SHA256: res.RPMSHA256})
		}
		env := verdict.Env{
			Distro: res.VerifierEnv["distro"], Kernel: res.VerifierEnv["kernel"],
			Mode: res.VerifierEnv["selinuxMode"], PolicyPackage: res.VerifierEnv["policyPackage"],
		}
		st, err := verdict.BuildOrErr(res, env, subjects)
		if err != nil {
			log.Fatalf("build verdict: %v", err)
		}
		stJSON, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		vout := filepath.Join(*outDir, base+".verdict.json")
		if err := os.WriteFile(vout, stJSON, 0o644); err != nil {
			log.Fatal(err)
		}

		// Optional signing and optional upload — both off unless asked for.
		if *signKey != "" {
			env2, err := signing.SignFile(*signKey, "application/vnd.in-toto+json", stJSON)
			if err != nil {
				log.Fatalf("sign verdict: %v", err)
			}
			envJSON, _ := json.MarshalIndent(env2, "", "  ")
			dsseOut := filepath.Join(*outDir, base+".verdict.dsse.json")
			if err := os.WriteFile(dsseOut, envJSON, 0o644); err != nil {
				log.Fatal(err)
			}
			if *archivistaURL != "" {
				gitoid, err := archivista.Upload(*archivistaURL, env2)
				if err != nil {
					log.Fatalf("%v", err)
				}
				log.Printf("[%s] verdict attestation stored: %s (gitoid %s)", t.Name, *archivistaURL, gitoid)
			}
		} else if *archivistaURL != "" {
			log.Fatal("--archivista-url requires --sign-key: unsigned attestations are not worth storing")
		}
		if res.IsFailure() {
			failures++
			why := res.FailureReason
			if why == "" {
				why = res.ConformanceFatal
			}
			if why == "" && len(res.Flags) > 0 && !res.FlagsAccepted {
				why = fmt.Sprintf("%d review-flagged rules not accepted", len(res.Flags))
			}
			if why == "" {
				why = "enforcing verification failed"
			}
			log.Printf("=== %s: FAIL (%s) → %s", t.Name, why, out)
		} else {
			log.Printf("=== %s: PASS → %s", t.Name, out)
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
}
