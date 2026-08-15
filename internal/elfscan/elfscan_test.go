package elfscan

import (
	"strings"
	"testing"
)

const readelfSample = `Symbol table '.dynsym' contains 195 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND bind@GLIBC_2.17 (2)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND listen@GLIBC_2.17 (2)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setuid@GLIBC_2.17 (2)
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND initgroups@GLIBC_2.17 (2)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fopen64@GLIBC_2.17 (2)
    10: 0000000000000000    32 FUNC    GLOBAL DEFAULT   12 mosquitto_main
    11: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND connect@GLIBC_2.17 (2)
`

func TestParseDynSyms(t *testing.T) {
	syms := ParseDynSyms(readelfSample)
	for _, want := range []string{"bind", "listen", "setuid", "initgroups", "connect"} {
		if !syms[want] {
			t.Errorf("missing imported symbol %q in %v", want, syms)
		}
	}
	if syms["mosquitto_main"] {
		t.Error("defined (non-UND) symbols must not be treated as imports")
	}
}

func TestPredict(t *testing.T) {
	preds := Predict(map[string]bool{
		"bind": true, "listen": true, "setuid": true, "initgroups": true, "connect": true,
	})
	features := map[string]bool{}
	for _, p := range preds {
		features[p.Feature] = true
	}
	for _, want := range []string{"port-bind", "cap-setuid", "cap-setgid", "outbound-connect"} {
		if !features[want] {
			t.Errorf("missing predicted feature %q in %+v", want, preds)
		}
	}
}

// The whole point: features predicted statically but never granted by the
// final policy are coverage gaps in the exercise, not proof of least privilege.
func TestCoverageGaps(t *testing.T) {
	preds := []Prediction{
		{Feature: "port-bind", Reason: "imports bind/listen"},
		{Feature: "cap-setuid", Reason: "imports setuid"},
		{Feature: "outbound-connect", Reason: "imports connect"},
	}
	finalTE := `allow widget_t widget_port_t:tcp_socket name_bind;
allow widget_t widget_t:capability { setgid setuid };`
	gaps := CoverageGaps(preds, finalTE)
	if len(gaps) != 1 || gaps[0].Feature != "outbound-connect" {
		t.Errorf("want exactly the outbound-connect gap, got %+v", gaps)
	}
}

func TestStaticBinaryYieldsNoFalseConfidence(t *testing.T) {
	syms := ParseDynSyms("Symbol table '.dynsym' contains 0 entries:\n")
	if len(syms) != 0 {
		t.Errorf("static binary should produce no imports, got %v", syms)
	}
	if preds := Predict(syms); len(preds) != 0 {
		t.Errorf("no imports must mean no predictions, got %+v", preds)
	}
}

func TestFeatureMarkers(t *testing.T) {
	// Every predictable feature must have a policy marker, or gap detection
	// would report permanent false gaps.
	for f := range featureMarkers {
		if len(featureMarkers[f]) == 0 {
			t.Errorf("feature %q has no policy markers", f)
		}
	}
	for _, p := range Predict(allSymbols()) {
		if _, ok := featureMarkers[p.Feature]; !ok {
			t.Errorf("prediction feature %q has no marker entry", p.Feature)
		}
	}
}

func allSymbols() map[string]bool {
	out := map[string]bool{}
	for sym := range symbolFeatures {
		out[sym] = true
	}
	return out
}

func TestParseHandlesVersionSuffixVariants(t *testing.T) {
	line := `     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setgroups`
	syms := ParseDynSyms("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n" + line + "\n")
	if !syms["setgroups"] {
		t.Errorf("unversioned symbol not parsed: %v", syms)
	}
	if strings.ContainsAny("setgroups", "@") {
		t.Fatal("test sanity")
	}
}
