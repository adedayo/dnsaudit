package audit

import (
	"fmt"
	"sort"
	"strings"
)

// Profile names the breadth of an assessment.
type Profile string

// Supported profiles.
const (
	// ProfileQuick is DNS-only and fast: the controls most likely to matter.
	ProfileQuick Profile = "quick"
	// ProfileStandard is the default balance of coverage and cost.
	ProfileStandard Profile = "standard"
	// ProfileEmail concentrates on mail authentication and transport.
	ProfileEmail Profile = "email"
	// ProfileSurface concentrates on externally exploitable exposure.
	ProfileSurface Profile = "surface"
	// ProfileDeep runs everything, including checks with external egress.
	ProfileDeep Profile = "deep"
)

// profileMembers declares which checks belong to which profile.
//
// Membership is data, not logic, so adding a check never requires editing
// profile code — the registry and this table are the only things to touch.
// A nil entry means "every registered check", which is what keeps ProfileDeep
// automatically complete as new checks land.
var profileMembers = map[Profile][]string{
	ProfileQuick:    {"spf", "dmarc", "dnssec", "caa", "mx"},
	ProfileStandard: {"spf", "dmarc", "dkim", "dnssec", "caa", "mx", "mtasts", "nssec", "tlsrpt", "bimi"},
	ProfileEmail:    {"spf", "dmarc", "dkim", "mtasts", "mx", "tlsrpt", "bimi"},
	ProfileSurface:  {"dnssec", "nssec", "caa", "ptr"},
	ProfileDeep:     nil,
}

// profileSummaries describe each profile for help text and the manifest.
var profileSummaries = map[Profile]string{
	ProfileQuick:    "DNS-only essentials: SPF, DMARC, DNSSEC, CAA and MX.",
	ProfileStandard: "Balanced default: the quick set plus DKIM, MTA-STS, TLS-RPT, BIMI and NSEC.",
	ProfileEmail:    "Mail authentication and transport security only.",
	ProfileSurface:  "Externally exploitable exposure and delegation hygiene.",
	ProfileDeep:     "Every registered check, including those requiring egress.",
}

// Profiles returns the supported profile names in a stable order, ascending in
// breadth so that help text reads sensibly.
func Profiles() []string {
	return []string{
		string(ProfileQuick), string(ProfileStandard), string(ProfileEmail),
		string(ProfileSurface), string(ProfileDeep),
	}
}

// ParseProfile validates a profile name.
func ParseProfile(s string) (Profile, error) {
	p := Profile(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := profileMembers[p]; ok {
		return p, nil
	}
	return "", fmt.Errorf("error: unknown profile %q (want one of: %s)",
		s, strings.Join(Profiles(), ", "))
}

// Summary describes the profile.
func (p Profile) Summary() string { return profileSummaries[p] }

// Selection resolves which checks to run.
type Selection struct {
	// Profile is the starting set.
	Profile Profile
	// Only, when non-empty, replaces the profile's membership entirely.
	Only []string
	// Skip removes checks, and is applied last so it always wins.
	Skip []string
	// NoNetwork excludes checks requiring egress beyond DNS.
	NoNetwork bool
}

// Resolve returns the checks to run, in registry order.
//
// An unknown name in Only or Skip is an error rather than a silent no-op. A
// caller who misspells a check name would otherwise believe they had assessed
// something they had not, which is precisely the sort of quiet gap a security
// tool must never introduce.
func (s Selection) Resolve() ([]Check, error) {
	profile := s.Profile
	if profile == "" {
		profile = ProfileStandard
	}
	members, ok := profileMembers[profile]
	if !ok {
		return nil, fmt.Errorf("error: unknown profile %q", profile)
	}

	registered := map[string]Check{}
	for _, c := range Registered() {
		registered[c.Describe().Name] = c
	}

	var wanted []string
	switch {
	case len(s.Only) > 0:
		wanted = s.Only
	case members == nil: // deep: everything registered
		wanted = Names()
	default:
		wanted = members
	}

	if err := validateNames(wanted, registered); err != nil {
		return nil, err
	}
	if err := validateNames(s.Skip, registered); err != nil {
		return nil, err
	}

	skip := map[string]bool{}
	for _, name := range s.Skip {
		skip[name] = true
	}

	selected := make([]string, 0, len(wanted))
	seen := map[string]bool{}
	for _, name := range wanted {
		if skip[name] || seen[name] {
			continue
		}
		// A profile may name a check that is not yet implemented; skip it
		// rather than failing, so profiles can be written ahead of the code.
		check, ok := registered[name]
		if !ok {
			continue
		}
		if s.NoNetwork && check.Describe().ExcludedByNoNetwork() {
			continue
		}
		seen[name] = true
		selected = append(selected, name)
	}
	sort.Strings(selected)

	// Selecting nothing is always a mistake. Running zero checks and reporting
	// a clean result would be the most dangerous outcome this tool could
	// produce, so refuse rather than reassure.
	if len(selected) == 0 {
		return nil, fmt.Errorf(
			"error: no checks selected (profile %q, after --checks/--skip-checks%s)",
			profile, noNetworkNote(s.NoNetwork))
	}

	checks := make([]Check, 0, len(selected))
	for _, name := range selected {
		checks = append(checks, registered[name])
	}
	return checks, nil
}

// noNetworkNote explains, when relevant, that --no-network may be the reason a
// selection came out empty.
func noNetworkNote(noNetwork bool) string {
	if noNetwork {
		return " and --no-network"
	}
	return ""
}

// validateNames rejects names that are neither registered nor known to any
// profile, so that a typo surfaces immediately.
func validateNames(names []string, registered map[string]Check) error {
	for _, name := range names {
		if _, ok := registered[name]; ok {
			continue
		}
		if knownToAProfile(name) {
			continue
		}
		return fmt.Errorf("error: unknown check %q (available: %s)",
			name, strings.Join(Names(), ", "))
	}
	return nil
}

func knownToAProfile(name string) bool {
	for _, members := range profileMembers {
		for _, member := range members {
			if member == name {
				return true
			}
		}
	}
	return false
}
