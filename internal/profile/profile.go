// Package profile defines the security profile: the intermediate representation
// between artifact analysis and any concrete policy backend (SELinux today).
package profile

// PathAccess maps a filesystem regex (file_contexts syntax) to a semantic kind.
type PathAccess struct {
	Path string `yaml:"path"` // file_contexts-style regex, e.g. /var/lib/widget(/.*)?
	Kind string `yaml:"kind"` // conf | var_lib | log | runtime | content | tmp | cache
	// Owned is an explicit operator assertion that this app owns Path even
	// though its directory name does not match the app name at a token boundary
	// (e.g. plex owning /usr/lib/plexmediaserver). It is required — and only
	// honored — when the name heuristic cannot confirm ownership, turning a
	// silent heuristic pass into a reviewable, greppable claim (review finding).
	Owned bool `yaml:"owned,omitempty"`
}

// Port is a listening socket the application needs to bind.
type Port struct {
	Proto string `yaml:"proto"` // tcp | udp
	Port  int    `yaml:"port"`
}

// Declaration is a claimed privilege set for an application, used two ways:
// as a second-party supplier's declared privileges (verified against observed
// behavior — deviations are supplier findings), and as a first-party committed
// baseline (verified against observed behavior — deviations are drift).
type Declaration struct {
	Capabilities []string `yaml:"capabilities,omitempty"`
	Ports        []Port   `yaml:"ports,omitempty"`
	ForeignTypes []string `yaml:"foreign_types,omitempty"`
	// ForeignPortBinds are existing distro port types the app binds
	// (e.g. http_cache_port_t) as opposed to ports newly labeled for it.
	ForeignPortBinds []string `yaml:"foreign_port_binds,omitempty"`
	// BaseGrants are the refpolicy interfaces the base template grants
	// unconditionally (shell exec, /etc read, ...). They produce no AVC, so
	// they are declared here to keep the conformance contract complete.
	BaseGrants []string `yaml:"base_grants,omitempty"`
}

// Profile is the distilled least-privilege description of one artifact.
type Profile struct {
	Name         string       `yaml:"name"`
	Version      string       `yaml:"version,omitempty"`
	Executables  []string     `yaml:"executables"` // literal paths of entrypoint binaries
	Paths        []PathAccess `yaml:"paths"`
	Ports        []Port       `yaml:"ports,omitempty"`
	Capabilities []string     `yaml:"capabilities,omitempty"`
	// Interfaces are extra refpolicy interface calls the app needs
	// (e.g. sysnet_dns_name_resolve), added during refinement.
	Interfaces []string `yaml:"interfaces,omitempty"`
}
