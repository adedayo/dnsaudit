package netattr

import "strings"

// regionJurisdictions maps a cloud operator's region identifier to the ISO
// 3166-1 alpha-2 country the region's data centres are in.
//
// This is a mapping of published facts — each operator documents where its
// regions are — rather than a geolocation guess about an address. That
// distinction is what makes it usable: an IP geolocation database is a
// probabilistic claim about where a machine is, whereas "eu-west-1 is Ireland"
// is a statement the operator makes itself and contracts on.
//
// The map is deliberately incomplete, and its incompleteness is safe. An
// unknown region yields an empty jurisdiction, and the rule that uses it
// declines to report rather than assuming. Guessing a country from a region
// name's prefix — that anything beginning "eu-" is inside the EU, say — would
// be wrong for the UK and Switzerland in exactly the cases a data-residency
// question is being asked about.
var regionJurisdictions = map[string]string{
	// ------------------------------------------- Amazon Web Services (AWS) ---
	"us-east-1": "US", "us-east-2": "US", "us-west-1": "US", "us-west-2": "US",
	"us-gov-east-1": "US", "us-gov-west-1": "US",
	"ca-central-1": "CA", "ca-west-1": "CA",
	"sa-east-1": "BR",
	"eu-west-1": "IE", "eu-west-2": "GB", "eu-west-3": "FR",
	"eu-central-1": "DE", "eu-central-2": "CH",
	"eu-north-1": "SE", "eu-south-1": "IT", "eu-south-2": "ES",
	"me-south-1": "BH", "me-central-1": "AE",
	"il-central-1": "IL",
	"af-south-1":   "ZA",
	"ap-east-1":    "HK",
	"ap-south-1":   "IN", "ap-south-2": "IN",
	"ap-northeast-1": "JP", "ap-northeast-3": "JP",
	"ap-northeast-2": "KR",
	"ap-southeast-1": "SG", "ap-southeast-2": "AU", "ap-southeast-4": "AU",
	"ap-southeast-3": "ID", "ap-southeast-5": "MY", "ap-southeast-7": "TH",
	"cn-north-1": "CN", "cn-northwest-1": "CN",
	"mx-central-1": "MX",

	// ------------------------------------------------------- Google Cloud ---
	// Google publishes a "scope" that is either a region or a zone; zones are
	// the region name with a trailing letter, which normaliseRegion strips.
	"us-central1": "US", "us-east4": "US", "us-east5": "US", "us-east7": "US",
	"us-south1": "US", "us-west3": "US", "us-west4": "US",
	"northamerica-northeast1": "CA", "northamerica-northeast2": "CA",
	"northamerica-south1": "MX",
	"southamerica-east1":  "BR", "southamerica-west1": "CL",
	"europe-west1": "BE", "europe-west2": "GB", "europe-west3": "DE",
	"europe-west4": "NL", "europe-west6": "CH", "europe-west8": "IT",
	"europe-west9": "FR", "europe-west10": "DE", "europe-west12": "IT",
	"europe-north1": "FI", "europe-north2": "SE",
	"europe-central2": "PL", "europe-southwest1": "ES",
	"asia-east1": "TW", "asia-east2": "HK",
	"asia-northeast1": "JP", "asia-northeast2": "JP", "asia-northeast3": "KR",
	"asia-south1": "IN", "asia-south2": "IN",
	"asia-southeast1": "SG", "asia-southeast2": "ID",
	"australia-southeast1": "AU", "australia-southeast2": "AU",
	"me-west1": "IL", "me-central1": "QA", "me-central2": "SA",
	"africa-south1": "ZA",
}

// JurisdictionOf returns the ISO 3166-1 alpha-2 country for a region
// identifier, or the empty string when it is not known.
func JurisdictionOf(region string) string {
	return regionJurisdictions[normaliseRegion(region)]
}

// normaliseRegion trims a Google Cloud zone down to its region.
//
// Google's published scope is sometimes "europe-west2-a" — a zone — and
// sometimes "europe-west2". The zone suffix is a single letter after a final
// hyphen; an AWS region such as "eu-west-2" ends in a digit and is left alone.
func normaliseRegion(region string) string {
	region = strings.ToLower(strings.TrimSpace(region))
	if i := strings.LastIndex(region, "-"); i > 0 && len(region)-i == 2 {
		if c := region[i+1]; c >= 'a' && c <= 'z' {
			return region[:i]
		}
	}
	return region
}
