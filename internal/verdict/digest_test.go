package verdict

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodSHA = "abababababababababababababababababababababababababababababababab"

// A malformed or empty subject digest must fail statement construction — an
// attestation whose subject digest is garbage binds to nothing (review finding).
func TestBuildRejectsMalformedDigest(t *testing.T) {
	r := passingResult()
	// The extra must BE the built RPM (name+digest match), so set RPMPath/RPMSHA256
	// to the malformed value — the digest validation is what we're testing.
	r.RPMPath = "/x/app.rpm"
	r.RPMSHA256 = "ab12"
	_, err := BuildOrErr(r, Env{}, []Subject{{Name: "app.rpm", SHA256: "ab12"}})
	if err == nil {
		t.Fatal("short/malformed digest must be rejected")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error should name the digest problem: %v", err)
	}
}

// A run that produced a policy RPM must carry it as a subject with a valid digest.
func TestBuildRequiresAValidSubject(t *testing.T) {
	r := passingResult()
	// The RPM subject name must match the produced RPM (res.RPMPath basename).
	r.RPMPath = "/home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm"
	r.RPMSHA256 = goodSHA
	st, err := BuildOrErr(r, Env{}, []Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: goodSHA}})
	if err != nil {
		t.Fatalf("valid digest must be accepted: %v", err)
	}
	// Every subject digest in the statement must be 64-hex.
	for _, s := range st.Subject {
		d := s.Digest["sha256"]
		if len(d) != 64 {
			t.Errorf("subject %s has non-64-hex digest %q", s.Name, d)
		}
	}
	// At least one subject must exist (the policy RPM or the entrypoint bytes).
	if len(st.Subject) == 0 {
		t.Error("a PASS statement must bind to at least one artifact")
	}
}

// Round 15: a passing run that produced an RPM MUST bind it as a subject. The
// distributed package (compiled policy + scriptlets) is what gets installed;
// entrypoint digests do not substitute for the RPM subject.
func TestPassingVerdictRequiresRPMSubjectWhenRPMProduced(t *testing.T) {
	r := passingResult()
	r.RPMPath = "/home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm"
	r.RPMSHA256 = goodSHA // the authoritative computed digest
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Fatal("an RPM-producing pass must bind the RPM subject, even with entrypoint digests")
	}
	// The matching RPM subject (name AND digest) satisfies it.
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: goodSHA}}); err != nil {
		t.Fatalf("binding the produced RPM must succeed: %v", err)
	}
	// A differently-named RPM subject does not satisfy the requirement.
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "some-other.rpm", SHA256: goodSHA}}); err == nil {
		t.Fatal("a non-matching RPM subject must not satisfy the RPM-binding requirement")
	}
	// Round 21: a valid-but-WRONG digest under the right name must be rejected —
	// the bound digest must equal the computed package digest.
	wrong := "cd" + goodSHA[2:]
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: wrong}}); err == nil {
		t.Fatal("an RPM subject whose digest differs from the computed package digest must be rejected")
	}
}

// Entrypoint digests supplied by the pipeline become subjects, binding the
// verdict to the exact exercised bytes, not just the generated policy.
func TestBuildBindsEntrypointDigests(t *testing.T) {
	r := passingResult()
	r.RPMPath = "" // isolate entrypoint-byte binding (no RPM claimed)
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA}
	st, err := BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range st.Subject {
		if s.Name == "/usr/sbin/widgetd" && s.Digest["sha256"] == goodSHA {
			found = true
		}
	}
	if !found {
		t.Errorf("entrypoint bytes must be a subject: %+v", st.Subject)
	}
}

// A passing verdict must bind to the exercised artifact (RPM or entrypoint
// bytes), not merely to the generated policy text — otherwise a deploy gate
// trusts a claim tied to nothing it will actually install (review finding).
func TestPassingVerdictRequiresArtifactSubject(t *testing.T) {
	r := passingResult()
	r.RPMPath = ""
	r.EntrypointDigests = nil // only .te/.fc would remain
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Fatal("passing verdict with only policy-text subjects must be rejected")
	}
	// With an entrypoint digest it succeeds.
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA}
	if _, err := BuildOrErr(r, Env{}, nil); err != nil {
		t.Fatalf("entrypoint-bound passing verdict must be accepted: %v", err)
	}
}

// Identical inputs must produce byte-identical statements — a map iteration
// over entrypoint digests would otherwise reorder subjects and change the
// DSSE signature (review finding).
func TestStatementIsDeterministic(t *testing.T) {
	r := passingResult()
	r.RPMPath = "" // determinism of entrypoint-subject ordering; no RPM claimed
	r.EntrypointDigests = map[string]string{
		"/usr/sbin/a": goodSHA, "/usr/sbin/b": goodSHA, "/usr/sbin/c": goodSHA,
		"/usr/sbin/d": goodSHA, "/usr/sbin/e": goodSHA,
	}
	r.EntrypointPaths = []string{"/usr/sbin/a", "/usr/sbin/b", "/usr/sbin/c", "/usr/sbin/d", "/usr/sbin/e"}
	r.ObservedEntrypoints = []string{"/usr/sbin/a"} // MainPID binary; must be in the bound set
	var first []byte
	for i := 0; i < 20; i++ {
		st, err := BuildOrErr(r, Env{Mode: "Enforcing"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(st)
		if first == nil {
			first = raw
		} else if string(raw) != string(first) {
			t.Fatalf("statement bytes differ across builds (non-deterministic subject order)")
		}
	}
}

// Round 16: the verdict must DISCLOSE the unconditional base-interface grants
// (shell/bin exec, /etc & /usr reads, cert access) as review-required — they
// produce no AVCs, so a pass must not silently imply they were minimized.
func TestVerdictDisclosesBaseGrants(t *testing.T) {
	r := passingResult()
	r.RPMPath = ""
	st, err := BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Predicate.Coverage.BaseGrants) == 0 {
		t.Error("verdict must disclose the unconditional base grants")
	}
	found := false
	for _, g := range st.Predicate.Coverage.BaseGrants {
		if g == "corecmd_exec_shell" {
			found = true
		}
	}
	if !found {
		t.Errorf("base grants must include shell execution: %v", st.Predicate.Coverage.BaseGrants)
	}
}

// Round 24: undeclared behavior for a first/second-party artifact must fail
// closed even if the ConformanceFatal summary string was never set (the two
// could disagree and pass).
func TestVerdictFailsOnUndeclaredWithoutFatal(t *testing.T) {
	r := passingResult()
	r.RPMPath = ""
	r.Party = "second"
	r.ConformanceUndecl = []string{"capability setuid"}
	r.ConformanceFatal = "" // inconsistent: undeclared set, fatal empty
	st, err := BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != "fail" {
		t.Errorf("undeclared second-party behavior must fail closed, got %q", st.Predicate.Verdict)
	}
	// A THIRD-party artifact's undeclared behavior stays advisory (not fatal).
	// Set BOTH party fields so BuildOrErr does not reject on a party mismatch —
	// otherwise the zero-value statement passes the assertion vacuously (review
	// finding on the earlier version of this test).
	r.Party = "third"
	r.Target.Party = "third"
	// No extra — the entrypoint digests in passingResult() satisfy the artifact
	// requirement (an unrelated extra is now rejected).
	st, err = BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatalf("third-party build must not error: %v", err)
	}
	if st.Predicate.Verdict == "fail" {
		t.Error("third-party undeclared behavior is advisory, must not fail")
	}
}

// Round 27: the SIGNED party is res.Target.Party, but fail-closed conformance
// used res.Party — a second field that is empty in passingResult(). A "second"
// artifact with undeclared behavior then passed. failureOf must key on the same
// party that gets signed.
func TestVerdictFailsUndeclaredWhenResPartyEmpty(t *testing.T) {
	r := passingResult() // Target.Party="second", res.Party=""
	r.RPMPath = ""
	r.Party = "" // the exact inconsistency: signed says second, res.Party empty
	r.ConformanceUndecl = []string{"capability setuid"}
	st, err := BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != "fail" {
		t.Errorf("second-party undeclared behavior must fail even with empty res.Party, got %q", st.Predicate.Verdict)
	}
	if st.Predicate.Conformance.Party != "second" {
		t.Errorf("conformance party must reflect the signed target party, got %q", st.Predicate.Conformance.Party)
	}
}

// A disagreement between the signed target party and res.Party is a wiring bug
// and must fail construction loudly, not sign one while fail-closing on another.
func TestVerdictRejectsPartyMismatch(t *testing.T) {
	r := passingResult() // Target.Party="second"
	r.RPMPath = ""
	r.Party = "third" // disagrees with the signed target party
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Error("a party mismatch between res.Target.Party and res.Party must fail construction")
	}
}

// Round 36: an unrelated caller-provided extra subject must NOT satisfy the
// exercised-artifact requirement — only exercised entrypoint bytes or the built
// RPM are authoritative. Otherwise any subject with a valid digest yields a pass.
func TestVerdictRejectsUnrelatedExtraWithoutArtifact(t *testing.T) {
	r := passingResult()
	r.RPMPath = ""
	r.EntrypointDigests = nil // no authoritative artifact
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "unrelated", SHA256: goodSHA}}); err == nil {
		t.Error("an unrelated extra subject must not satisfy the artifact requirement")
	}
	// With entrypoint bytes present, the same build succeeds.
	r.EntrypointDigests = map[string]string{"/opt/widget/bin/widgetd": goodSHA}
	r.EntrypointPaths = []string{"/opt/widget/bin/widgetd"}
	r.ObservedEntrypoints = []string{"/opt/widget/bin/widgetd"}
	if _, err := BuildOrErr(r, Env{}, nil); err != nil {
		t.Errorf("exercised entrypoint bytes must satisfy the artifact requirement: %v", err)
	}
}

// Round 44: an unrelated extra (not the built RPM) must be rejected even when an
// authoritative entrypoint artifact exists, and duplicate subject names too.
func TestVerdictRejectsUnrelatedAndDuplicateExtras(t *testing.T) {
	r := passingResult()
	r.RPMPath = "" // no RPM → NO extra is authoritative
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "unrelated.rpm", SHA256: goodSHA}}); err == nil {
		t.Error("an extra with no built RPM must be rejected")
	}
	// With an RPM, an extra whose digest does not match the computed one is rejected.
	r.RPMPath = "/x/widget-selinux-1.0.0-1.el9.noarch.rpm"
	r.RPMSHA256 = goodSHA
	wrong := "cd" + goodSHA[2:]
	if _, err := BuildOrErr(r, Env{}, []Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: wrong}}); err == nil {
		t.Error("an extra whose digest != the computed RPM digest must be rejected")
	}
	// A duplicate RPM subject name is rejected.
	if _, err := BuildOrErr(r, Env{}, []Subject{
		{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: goodSHA},
		{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: goodSHA},
	}); err == nil {
		t.Error("duplicate subject names must be rejected")
	}
}

// The built RPM is the generated SELinux POLICY package, not the application, so
// binding ONLY the RPM leaves the app bytes uncertified — a changed application
// artifact at the same path could reuse the verdict. A passing verdict must bind
// the exercised entrypoint digests even when a correctly-bound RPM is present.
// (review finding — round 53)
func TestPassingVerdictRequiresEntrypointDigestsEvenWithRPM(t *testing.T) {
	r := passingResult()
	r.RPMPath = "/home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm"
	r.RPMSHA256 = goodSHA
	r.EntrypointDigests = nil // policy package present, but NO application bytes bound
	rpmSubject := []Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: goodSHA}}
	if _, err := BuildOrErr(r, Env{}, rpmSubject); err == nil {
		t.Fatal("a pass bound only to the policy RPM (no entrypoint digests) must be rejected")
	}
	// Restoring the entrypoint digests (with the RPM still bound) succeeds.
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA}
	if _, err := BuildOrErr(r, Env{}, rpmSubject); err != nil {
		t.Fatalf("app entrypoints + bound RPM must be accepted: %v", err)
	}
}

// A non-empty EntrypointDigests is not enough: a passing verdict must bind a
// digest for EVERY resolved entrypoint (an omitted one could change without
// invalidating the signature) and must not bind any path outside the resolved
// set. (review finding — round 55)
func TestPassingVerdictValidatesEntrypointSetCompletely(t *testing.T) {
	// Missing: two entrypoints resolved, only one bound → reject.
	r := passingResult()
	r.RPMPath = ""
	r.EntrypointPaths = []string{"/usr/sbin/widgetd", "/usr/sbin/widget-helper"}
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA} // helper omitted
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Error("a resolved entrypoint with no bound digest must be rejected")
	}

	// Extra: a bound path that was never in the resolved set → reject.
	r = passingResult()
	r.RPMPath = ""
	r.EntrypointPaths = []string{"/usr/sbin/widgetd"}
	r.EntrypointDigests = map[string]string{
		"/usr/sbin/widgetd":  goodSHA,
		"/usr/bin/unrelated": goodSHA, // never resolved as an entrypoint
	}
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Error("an entrypoint digest for a path outside the resolved set must be rejected")
	}

	// Exact match of every resolved entrypoint → accept.
	r = passingResult()
	r.RPMPath = ""
	r.EntrypointPaths = []string{"/usr/sbin/widgetd", "/usr/sbin/widget-helper"}
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA, "/usr/sbin/widget-helper": goodSHA}
	if _, err := BuildOrErr(r, Env{}, nil); err != nil {
		t.Errorf("binding every resolved entrypoint must be accepted: %v", err)
	}
}
