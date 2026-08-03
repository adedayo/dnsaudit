// Package takeover holds the fingerprint database that identifies which
// third-party service a CNAME points at, and whether an unclaimed name on that
// service can be claimed by somebody else.
//
// The database is embedded data rather than code so that it can be corrected
// and extended without a release: services change their behaviour, and a
// fingerprint that was accurate a year ago may now describe a service that has
// closed the hole. It carries a schema version and a provenance statement for
// the same reason — a reader deciding how much to trust a Critical finding is
// entitled to know where the claim came from.
package takeover

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed fingerprints.json
var fingerprintData []byte

// Status describes what happens when a name on the service is left unclaimed.
type Status string

// The statuses a fingerprint may declare.
const (
	// StatusVulnerable means an unclaimed name can be claimed by anybody.
	StatusVulnerable Status = "vulnerable"
	// StatusEdgeCase means it can be claimed only under conditions that are
	// not observable from DNS — typically a verification token, an account
	// tier, or a race with the previous owner.
	StatusEdgeCase Status = "edge-case"
	// StatusNotVulnerable means the service prevents a third party claiming a
	// name the original owner used.
	StatusNotVulnerable Status = "not-vulnerable"
)

// Fingerprint identifies one service and its takeover behaviour.
type Fingerprint struct {
	// Service is the human-readable provider name.
	Service string `json:"service"`
	// CNAMEPatterns are the suffixes (or exact names) a CNAME target matches.
	CNAMEPatterns []string `json:"cname_patterns"`
	// NXDOMAIN records whether a dangling name leaves the CNAME target
	// unresolvable. When true, DNS alone is sufficient to detect the
	// condition; when false, only an HTTP response distinguishes a claimed
	// name from an unclaimed one.
	NXDOMAIN bool `json:"nxdomain"`
	// HTTPBody are the response fragments that corroborate an unclaimed name.
	HTTPBody []string `json:"http_body"`
	// Status is the takeover behaviour.
	Status Status `json:"status"`
	// Reference cites the source establishing the behaviour.
	Reference string `json:"reference"`
}

// Database is the embedded fingerprint set with its metadata.
type Database struct {
	SchemaVersion int           `json:"schema_version"`
	Updated       string        `json:"updated"`
	Provenance    string        `json:"provenance"`
	Notes         string        `json:"notes"`
	Fingerprints  []Fingerprint `json:"fingerprints"`
}

// SupportedSchemaVersion is the schema this build understands. A database
// declaring anything else is refused rather than interpreted optimistically,
// because a silently misread fingerprint produces confident nonsense at
// Critical severity.
const SupportedSchemaVersion = 1

var (
	loadOnce sync.Once
	loaded   Database
	loadErr  error
)

// Load returns the embedded fingerprint database.
func Load() (Database, error) {
	loadOnce.Do(func() {
		loaded, loadErr = Parse(fingerprintData)
	})
	return loaded, loadErr
}

// Parse reads and validates a fingerprint database.
func Parse(data []byte) (Database, error) {
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return db, fmt.Errorf("error: cannot parse the takeover fingerprint database: %w", err)
	}
	if err := db.Validate(); err != nil {
		return db, err
	}
	return db, nil
}

// Validate enforces the invariants every entry must satisfy.
//
// This runs on the embedded data at load time and is exercised by the tests, so
// a malformed contribution fails the build rather than producing a finding
// nobody can trace to a source.
func (db Database) Validate() error {
	if db.SchemaVersion != SupportedSchemaVersion {
		return fmt.Errorf(
			"error: takeover fingerprint schema version %d is not supported (this build understands %d)",
			db.SchemaVersion, SupportedSchemaVersion)
	}
	if strings.TrimSpace(db.Provenance) == "" {
		return fmt.Errorf("error: the takeover fingerprint database has no provenance statement")
	}
	if len(db.Fingerprints) == 0 {
		return fmt.Errorf("error: the takeover fingerprint database is empty")
	}

	seen := map[string]bool{}
	for _, f := range db.Fingerprints {
		switch {
		case strings.TrimSpace(f.Service) == "":
			return fmt.Errorf("error: a takeover fingerprint has no service name")
		case len(f.CNAMEPatterns) == 0:
			return fmt.Errorf("error: fingerprint %q has no CNAME patterns", f.Service)
		case strings.TrimSpace(f.Reference) == "":
			return fmt.Errorf("error: fingerprint %q cites no reference", f.Service)
		}
		switch f.Status {
		case StatusVulnerable, StatusEdgeCase, StatusNotVulnerable:
		default:
			return fmt.Errorf("error: fingerprint %q has unknown status %q", f.Service, f.Status)
		}
		// A fingerprint that is neither detectable by NXDOMAIN nor by an HTTP
		// body cannot be confirmed at all, so it could only ever produce an
		// unverified guess.
		if !f.NXDOMAIN && len(f.HTTPBody) == 0 {
			return fmt.Errorf(
				"error: fingerprint %q is undetectable: it neither leaves the target unresolvable nor declares an HTTP body",
				f.Service)
		}
		for _, pattern := range f.CNAMEPatterns {
			key := strings.ToLower(strings.TrimSpace(pattern))
			if key == "" {
				return fmt.Errorf("error: fingerprint %q has an empty CNAME pattern", f.Service)
			}
			if seen[key] {
				return fmt.Errorf("error: CNAME pattern %q appears in more than one fingerprint", pattern)
			}
			seen[key] = true
		}
	}
	return nil
}

// Match returns the fingerprint whose pattern the CNAME target matches.
//
// The longest matching pattern wins, so a specific entry is never shadowed by a
// broader one that happens to be listed first.
func (db Database) Match(target string) (Fingerprint, bool) {
	target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if target == "" {
		return Fingerprint{}, false
	}

	var (
		best      Fingerprint
		bestLen   int
		bestFound bool
	)
	for _, f := range db.Fingerprints {
		for _, pattern := range f.CNAMEPatterns {
			p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
			matched := target == strings.TrimPrefix(p, ".") ||
				(strings.HasPrefix(p, ".") && strings.HasSuffix(target, p)) ||
				(!strings.HasPrefix(p, ".") && strings.HasSuffix(target, "."+p))
			if matched && len(p) > bestLen {
				best, bestLen, bestFound = f, len(p), true
			}
		}
	}
	return best, bestFound
}

// Services returns the service names in the database, for `dnsaudit catalogue`
// and the forthcoming capability manifest.
func (db Database) Services() []string {
	names := make([]string, 0, len(db.Fingerprints))
	for _, f := range db.Fingerprints {
		names = append(names, f.Service)
	}
	return names
}
