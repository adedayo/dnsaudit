package finding

import "strings"

// The rename from dnsaudit to vantage re-prefixed every catalogue identifier
// from DNSA- to SURF-. Identifiers are not merely cosmetic: they are written
// into suppression files, baselines and CI policies by users, so changing them
// silently invalidates configuration that was correct the day before.
//
// The aliases below make the old identifiers keep working. They are resolved
// on lookup rather than added to the catalogue map, so that Catalogue(),
// Checks() and the agent-facing manifest continue to report each rule exactly
// once, under its canonical name. The legacy prefix is an accepted input, not
// a second identity.
const (
	// legacyIDPrefix is the identifier prefix used up to and including v1.1.0.
	legacyIDPrefix = "DNSA-"
	// canonicalIDPrefix is the prefix used from the rename onwards.
	canonicalIDPrefix = "SURF-"
)

// CanonicalID maps a legacy DNSA- identifier onto its current SURF- equivalent.
//
// Identifiers that are already canonical are returned unchanged, as are ones
// that do not correspond to any catalogue entry. Echoing unknown input back
// rather than rewriting it keeps any "unknown rule" diagnostic phrased in terms
// of what the caller actually supplied, instead of a string they never typed.
func CanonicalID(id string) string {
	rest, ok := strings.CutPrefix(id, legacyIDPrefix)
	if !ok {
		return id
	}
	candidate := canonicalIDPrefix + rest
	if _, known := catalogue[candidate]; !known {
		return id
	}
	return candidate
}
