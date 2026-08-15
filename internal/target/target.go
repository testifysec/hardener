// Package target defines the per-application manifest that drives the pipeline.
package target

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/testifysec/hardener/internal/profile"
)

// Target describes how to obtain, run, and exercise one application in the VM.
type Target struct {
	Name    string `yaml:"name"`
	License string `yaml:"license"` // open-source | proprietary-freely-distributable
	Source  string `yaml:"source"`  // where the artifact comes from (URL / repo)

	// Install is a bash script (run with sudo available) that installs the app.
	Install string `yaml:"install"`
	// Unit is the systemd unit name used to start/stop the app.
	Unit string `yaml:"unit"`
	// UnitFile, when set, is written to /etc/systemd/system/<Unit> before start
	// (for tarball/binary apps that ship no unit).
	UnitFile string `yaml:"unit_file,omitempty"`
	// Setup runs after install and unit placement (users, dirs, config).
	Setup string `yaml:"setup,omitempty"`
	// Exercise is a bash script that drives the app through its scenarios.
	Exercise string `yaml:"exercise"`

	Executables []string             `yaml:"executables"`
	Paths       []profile.PathAccess `yaml:"paths"`
	Ports       []profile.Port       `yaml:"ports,omitempty"`

	// Party is the supply-chain class of the artifact: "first" (our code,
	// baseline-checked), "second" (supplier deliverable, declaration-checked),
	// or "third" (COTS/OSS artifact, observation only). Empty means third.
	Party string `yaml:"party,omitempty"`
	// Declared is the supplier's claimed privilege set (second party).
	Declared *profile.Declaration `yaml:"declared,omitempty"`
	// Baseline is the path to the committed privilege baseline (first party).
	// Defaults to baselines/<name>.yaml relative to the manifest.
	Baseline string `yaml:"baseline,omitempty"`
}

// Load reads and validates a target manifest.
func Load(path string) (*Target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch t.Party {
	case "", "first", "second", "third":
	default:
		return nil, fmt.Errorf("%s: party must be first, second, or third (got %q)", path, t.Party)
	}
	if t.Party == "second" && t.Declared == nil {
		return nil, fmt.Errorf("%s: party: second requires a declared: block (the supplier's privilege declaration)", path)
	}
	for _, missing := range []struct {
		ok  bool
		msg string
	}{
		{t.Name != "", "name"},
		{t.Install != "", "install"},
		{t.Unit != "", "unit"},
		{t.Exercise != "", "exercise"},
		{len(t.Executables) > 0, "executables"},
	} {
		if !missing.ok {
			return nil, fmt.Errorf("%s: missing required field %q", path, missing.msg)
		}
	}
	return &t, nil
}

// Profile builds the initial security profile from the manifest.
func (t *Target) Profile() *profile.Profile {
	return &profile.Profile{
		Name:        t.Name,
		Executables: t.Executables,
		Paths:       t.Paths,
		Ports:       t.Ports,
	}
}
