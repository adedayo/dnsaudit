package finding

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Entry is the canonical definition of a finding: its identity, default
// severity, and — critically — the remediation guidance and references.
//
// Keeping remediation in a version-controlled catalogue rather than generating
// it at the point of use means advice is reviewed once, cited to a standard,
// and identical for every consumer. It is also what allows an AI agent to
// explain a finding without inventing security guidance.
type Entry struct {
	ID          string
	Check       string
	Title       string
	Severity    Severity
	Confidence  Confidence
	Description string
	Remediation string
	References  []string
	Tags        []string
}

// idPattern constrains catalogue identifiers to DNSA-<CHECK>-<NNN>.
var idPattern = regexp.MustCompile(`^DNSA-[A-Z0-9]+-[0-9]{3}$`)

// rfc6376KeyRecord is the DKIM key-record section, cited by every DKIM key
// finding. Naming it once means a mistyped fragment cannot send a reader to the
// wrong part of the specification for some findings but not others.
const rfc6376KeyRecord = "https://www.rfc-editor.org/rfc/rfc6376#section-3.6.1"

// Compliance tags applied to catalogue entries.
const (
	TagNCSCMailCheck = "ncsc-mailcheck"
	TagCISControls   = "cis-controls"
	TagNIST80081     = "nist-800-81"
	TagPCIDSS        = "pci-dss"
	TagEmailAuth     = "email-authentication"
	TagTransport     = "transport-security"
	TagPKI           = "pki"
	TagReputation    = "reputation"
	TagResilience    = "resilience"
)

// catalogue holds every finding dnsaudit can raise, keyed by ID.
//
// Entries are added as the rules that raise them are implemented. Specs 011 to
// 013 define further rules; those IDs are reserved by the spec but are only
// added here once the implementing code exists, so that `dnsaudit catalogue`
// never advertises a check the tool cannot actually perform.
var catalogue = index([]Entry{
	// ---------------------------------------------------------------- SPF ---
	{
		ID:         "DNSA-SPF-001",
		Check:      "spf",
		Title:      "No SPF record published",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "The domain publishes no SPF record, so receiving mail servers have no " +
			"authoritative list of hosts permitted to send on its behalf. Anyone may send mail " +
			"claiming to originate from this domain and it will not fail SPF.",
		Remediation: "Publish a TXT record at the domain apex enumerating your legitimate senders, " +
			"ending in a terminal mechanism. Start with `v=spf1 include:<provider> ~all` while you " +
			"confirm the sender list, then tighten to `-all`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-002",
		Check:      "spf",
		Title:      "Multiple SPF records published",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "More than one TXT record beginning with `v=spf1` was found. RFC 7208 requires " +
			"receivers to return PermError in this case, so SPF evaluation fails entirely and the " +
			"protection you believe is in place is not applied.",
		Remediation: "Merge the records into a single TXT record. Multiple `include:` mechanisms may " +
			"coexist within one record; multiple records may not.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-4.5"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-003",
		Check:      "spf",
		Title:      "SPF record has a neutral or missing terminal mechanism",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The record ends in `?all`, or has no terminal `all` mechanism at all. Either way " +
			"unauthorised senders receive a neutral result, which receivers treat much as if no SPF " +
			"record existed.",
		Remediation: "Replace `?all` with `-all` (or `~all` during rollout) so that hosts outside the " +
			"published set produce a fail or softfail.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.1"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-004",
		Check:      "spf",
		Title:      "SPF record permits all senders (+all)",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Description: "The record terminates in `+all`, which explicitly authorises every host on the " +
			"internet to send mail as this domain. This is worse than publishing no record, because " +
			"it actively vouches for spoofed mail.",
		Remediation: "Replace `+all` with `-all` immediately, after confirming your legitimate senders " +
			"are enumerated by the preceding mechanisms.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.1"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-005",
		Check:      "spf",
		Title:      "SPF record uses softfail (~all) rather than fail (-all)",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The record terminates in `~all`. Mail from unauthorised hosts is marked but " +
			"generally still delivered. This is the correct setting during rollout, but leaves " +
			"spoofed mail reaching recipients if left in place indefinitely.",
		Remediation: "Once DMARC aggregate reports confirm all legitimate senders are covered, tighten " +
			"the terminal mechanism to `-all`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.1"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-008",
		Check:      "spf",
		Title:      "SPF record uses the deprecated ptr mechanism",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The record contains a `ptr` mechanism. RFC 7208 deprecates it: it is slow, " +
			"imposes load on reverse DNS, and some receivers ignore or penalise it.",
		Remediation: "Remove the `ptr` mechanism and enumerate senders with `ip4`, `ip6`, `a`, `mx` or " +
			"`include` instead.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.5"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-SPF-006",
		Check:      "spf",
		Title:      "SPF evaluation exceeds the ten-lookup limit",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "Evaluating the record requires more than the ten DNS lookups RFC 7208 permits. " +
			"Receivers return PermError once the limit is passed, so SPF fails open: the record is " +
			"published, appears correct, and protects nothing. This is invisible to anyone simply " +
			"reading the record.",
		Remediation: "Reduce the number of `include`, `a`, `mx`, `exists` and `redirect` terms. Flatten " +
			"rarely-changing includes into explicit `ip4`/`ip6` ranges, and remove providers you no " +
			"longer send through. Re-run this check to confirm the count is at or below ten.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-SPF-007",
		Check:      "spf",
		Title:      "SPF evaluation exceeds the two void-lookup limit",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "More than two of the record's lookups returned no records at all. RFC 7208 " +
			"allows receivers to return PermError beyond two such void lookups, and they generally " +
			"indicate a sender that has been decommissioned without the record being updated.",
		Remediation: "Remove the mechanisms whose targets no longer resolve. The evidence lists the " +
			"names that returned nothing.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-SPF-009",
		Check:      "spf",
		Title:      "SPF include target publishes no usable record",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "An `include` or `redirect` names a domain that does not resolve, or that " +
			"publishes no SPF record. RFC 7208 makes this a PermError, so the whole evaluation can " +
			"fail rather than merely skipping the offending term.",
		Remediation: "Correct or remove the named term. A provider that has been decommissioned should " +
			"be removed rather than left in place.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.2"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-SPF-010",
		Check:      "spf",
		Title:      "SPF record exceeds recommended length limits",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "A single TXT string exceeds 255 octets, or the record as a whole exceeds 512 " +
			"octets. Over-long records are split inconsistently by DNS interfaces and can push a " +
			"response beyond the size some resolvers will accept over UDP.",
		Remediation: "Shorten the record — usually by consolidating address ranges or removing unused " +
			"senders — or split long values into correctly concatenated 255-octet TXT strings.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-3.3"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-SPF-011",
		Check:      "spf",
		Title:      "SPF record authorises an overly broad address range",
		Severity:   SeverityMedium,
		Confidence: ConfidenceMedium,
		Description: "The record authorises an IP range wider than a /16 (IPv4) or /32 (IPv6). Any host " +
			"within that range — including systems you do not control, such as other tenants of a " +
			"shared hosting provider — can send authenticated mail as this domain.",
		Remediation: "Narrow the range to the specific addresses your mail infrastructure uses, or " +
			"replace it with an `include:` of your provider's maintained SPF record.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.6"},
		Tags:       []string{TagEmailAuth},
	},

	// -------------------------------------------------------------- DMARC ---
	{
		ID:         "DNSA-DMARC-001",
		Check:      "dmarc",
		Title:      "No DMARC record published",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "No `v=DMARC1` record was found at `_dmarc.<domain>`. Without DMARC, SPF and DKIM " +
			"results are advisory only: receivers have no instruction on what to do with mail that " +
			"fails authentication, and you receive no reporting on abuse of your domain.",
		Remediation: "Publish `v=DMARC1; p=none; rua=mailto:<your-address>` to begin monitoring, then " +
			"progress to `p=quarantine` and `p=reject` as reports confirm legitimate senders pass.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-002",
		Check:      "dmarc",
		Title:      "DMARC policy is monitoring only (p=none)",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The policy is `p=none`, so receivers take no action on mail that fails " +
			"authentication. This provides visibility but no protection against spoofing.",
		Remediation: "Use the aggregate reports to confirm your legitimate senders align, then move to " +
			"`p=quarantine` and ultimately `p=reject`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.3"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-003",
		Check:      "dmarc",
		Title:      "DMARC policy is applied to only a subset of mail (pct<100)",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The `pct` tag limits policy application to a fraction of failing messages, so " +
			"the remainder is delivered unchanged. This is a rollout aid, not an end state.",
		Remediation: "Once confident in the policy, remove the `pct` tag or set it to 100.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.3"},
		Tags:        []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-004",
		Check:      "dmarc",
		Title:      "Subdomain policy is weaker than the domain policy",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The `sp` tag is weaker than `p`, so subdomains are less protected than the " +
			"organisational domain. Attackers routinely spoof subdomains precisely because they are " +
			"often overlooked.",
		Remediation: "Set `sp` to match `p`, or remove the `sp` tag so subdomains inherit the domain " +
			"policy.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.3"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-005",
		Check:      "dmarc",
		Title:      "No DMARC aggregate reporting address (rua)",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The record has no `rua` tag, so no aggregate reports are sent. You have no " +
			"visibility of who is sending mail as your domain, and no evidence base for tightening " +
			"the policy safely.",
		Remediation: "Add `rua=mailto:<address>` — ideally a dedicated mailbox or a DMARC reporting " +
			"service — and review the reports before enforcing.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-7.1"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-006",
		Check:      "dmarc",
		Title:      "External reporting destination lacks an authorisation record",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "A `rua` or `ruf` destination lies outside the domain, but the destination has " +
			"not published the authorisation record RFC 7489 requires at " +
			"`<domain>._report._dmarc.<destination>`. Conforming receivers will not send reports " +
			"there. The failure is entirely silent: the record looks correct, and the absence of " +
			"reports is easily mistaken for an absence of abuse.",
		Remediation: "Publish `v=DMARC1` at `<your-domain>._report._dmarc.<destination>` in the " +
			"destination's zone, or ask your reporting provider to do so.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-7.1"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-007",
		Check:      "dmarc",
		Title:      "Multiple DMARC records published",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "More than one `v=DMARC1` record was found. RFC 7489 requires receivers to ignore " +
			"the policy entirely when this happens, so the domain is left unprotected.",
		Remediation: "Remove all but one DMARC TXT record at `_dmarc.<domain>`.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.6.3"},
		Tags:        []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-008",
		Check:      "dmarc",
		Title:      "DMARC record is syntactically invalid",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "The record could not be parsed as valid DMARC — for example a missing or " +
			"misplaced `p` tag, or an unrecognised policy value. Receivers will discard it, leaving " +
			"the domain unprotected despite a record being present.",
		Remediation: "Correct the record syntax. The `v=DMARC1` tag must come first and `p` must be " +
			"the second tag, with a value of `none`, `quarantine` or `reject`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.4"},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DMARC-009",
		Check:      "dmarc",
		Title:      "DMARC policy is inherited from the organisational domain",
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Description: "This name publishes no DMARC record of its own. Receivers fall back to the " +
			"organisational domain's policy, as RFC 7489 specifies, so the name is covered — but by " +
			"a policy defined elsewhere, which may be changed or tightened without reference to " +
			"this subdomain.",
		Remediation: "No action is required if the inherited policy is intended. Publish a record at " +
			"`_dmarc.<subdomain>`, or set `sp` on the organisational domain, to control the policy " +
			"explicitly.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7489#section-6.6.3"},
		Tags:       []string{TagEmailAuth},
	},

	// --------------------------------------------------------------- DKIM ---
	{
		ID:         "DNSA-DKIM-001",
		Check:      "dkim",
		Title:      "No DKIM key found",
		Severity:   SeverityMedium,
		Confidence: ConfidenceLow,
		Description: "No usable DKIM key record was found for the supplied selector, or for any of " +
			"the selectors commonly used by mail providers. Without DKIM, mail cannot be " +
			"cryptographically attributed to the domain and survives neither forwarding nor " +
			"DMARC alignment when SPF breaks.",
		Remediation: "Enable DKIM signing at your mail provider and publish the key it gives you at " +
			"`<selector>._domainkey.<domain>`. If you already sign with a selector that is not " +
			"widely used, re-run the check with `-s <selector>`.",
		References: []string{rfc6376KeyRecord},
		Tags:       []string{TagEmailAuth, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DKIM-002",
		Check:      "dkim",
		Title:      "DKIM RSA key is shorter than 1024 bits",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "The published RSA key is below 1024 bits. Keys of this size are factorable by a " +
			"well-resourced attacker, who could then sign mail that passes DKIM and DMARC as though " +
			"it came from you.",
		Remediation: "Generate a replacement key of at least 2048 bits, publish it under a new " +
			"selector, switch signing to it, and remove the old record once no mail signed with it " +
			"remains in flight.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8301#section-3.2"},
		Tags:       []string{TagEmailAuth, TagPKI, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-DKIM-003",
		Check:      "dkim",
		Title:      "DKIM RSA key is only 1024 bits",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The published RSA key is exactly 1024 bits. RFC 8301 sets 1024 as the floor and " +
			"2048 as the expectation; 1024-bit keys are no longer considered durable.",
		Remediation: "Rotate to a 2048-bit key under a new selector.",
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8301#section-3.2"},
		Tags:        []string{TagEmailAuth, TagPKI},
	},
	{
		ID:         "DNSA-DKIM-004",
		Check:      "dkim",
		Title:      "DKIM key is revoked (empty p=)",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The record has an empty `p=` tag, which RFC 6376 defines as revocation. Any mail " +
			"still signed with this selector will fail DKIM verification.",
		Remediation: "If the selector is retired, remove the record once no signed mail remains in " +
			"flight. If it is still in use, republish the correct public key.",
		References: []string{rfc6376KeyRecord},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-DKIM-005",
		Check:      "dkim",
		Title:      "DKIM selector is in test mode (t=y)",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The `t=y` flag tells receivers to treat signatures from this selector as " +
			"experimental and not to penalise unsigned or failing mail. Left in place after " +
			"rollout, it quietly removes the protection DKIM is meant to provide.",
		Remediation: "Remove the `t=y` flag once signing is verified in production.",
		References:  []string{rfc6376KeyRecord},
		Tags:        []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-DKIM-006",
		Check:      "dkim",
		Title:      "DKIM key record is malformed",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The record could not be parsed as a DKIM key: the `p=` tag is absent, its " +
			"base64 is invalid, or the encoded key is not a well-formed public key. Receivers will " +
			"be unable to verify signatures made with this selector.",
		Remediation: "Republish the key exactly as issued by your mail provider, taking care that " +
			"long values split across TXT strings are concatenated without inserted whitespace.",
		References: []string{rfc6376KeyRecord},
		Tags:       []string{TagEmailAuth},
	},

	// -------------------------------------------------------------- TLSRPT ---
	{
		ID:         "DNSA-TLSRPT-001",
		Check:      "tlsrpt",
		Title:      "No TLS-RPT record published",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "No `v=TLSRPTv1` record was found at `_smtp._tls.<domain>`. Sending servers " +
			"therefore have nowhere to report failures to negotiate TLS with your mail exchangers, " +
			"so downgrade attacks and expired certificates can go unnoticed indefinitely.",
		Remediation: "Publish `v=TLSRPTv1; rua=mailto:<address>` at `_smtp._tls.<domain>` and review " +
			"the daily reports alongside your MTA-STS or DANE policy.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8460#section-3"},
		Tags:       []string{TagTransport, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-TLSRPT-002",
		Check:      "tlsrpt",
		Title:      "TLS-RPT record is malformed or has no reporting destination",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "A TLS-RPT record is present but unusable: the `rua` tag is missing, empty, or " +
			"specifies a scheme other than `mailto:` or `https:`. No reports will be delivered, so " +
			"the record gives a false impression of visibility.",
		Remediation: "Correct the record to `v=TLSRPTv1; rua=mailto:<address>`, using a comma to " +
			"separate multiple destinations.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8460#section-3"},
		Tags:       []string{TagTransport},
	},
	{
		ID:         "DNSA-MX-001",
		Check:      "mx",
		Title:      "MX host does not resolve",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "A published mail exchanger has no A or AAAA record. Senders cannot connect to " +
			"it, so mail is delayed while it is retried and is lost entirely if no other exchanger " +
			"accepts it. A typo in an MX host is invisible until mail starts failing.",
		Remediation: "Correct the MX hostname, or publish the missing address record for it. Remove " +
			"exchangers that are no longer in service.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc5321#section-5.1"},
		Tags:       []string{TagEmailAuth, TagResilience},
	},
	{
		ID:         "DNSA-MX-002",
		Check:      "mx",
		Title:      "MX record points at a CNAME",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "An MX record names a host that is itself a CNAME alias. RFC 2181 prohibits " +
			"this: the target of an MX record must be a hostname with an address record. Behaviour " +
			"varies between senders, so delivery may work in testing and fail in production.",
		Remediation: "Point the MX record at a hostname that has A or AAAA records directly, rather " +
			"than at an alias.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc2181#section-10.3"},
		Tags:       []string{TagEmailAuth, TagResilience},
	},
	{
		ID:         "DNSA-MX-003",
		Check:      "mx",
		Title:      "Non-mail domain does not publish a null MX",
		Severity:   SeverityLow,
		Confidence: ConfidenceMedium,
		Description: "The domain publishes no mail exchangers but does not declare that fact. RFC " +
			"7505 defines a null MX (`0 .`) to state explicitly that a domain accepts no mail. " +
			"Without it, senders fall back to the address record and queue undeliverable mail for " +
			"days rather than rejecting it immediately.",
		Remediation: "Publish `0 .` as the sole MX record for domains that neither send nor receive " +
			"mail, alongside a restrictive SPF record.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc7505"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-MX-004",
		Check:      "mx",
		Title:      "Only one mail exchanger is published",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "A single MX record leaves no redundancy: if that host is unreachable, inbound " +
			"mail is deferred until senders give up. Note that a single hostname may still resolve " +
			"to a resilient pool of addresses, so this is worth confirming rather than assuming.",
		Remediation: "Publish at least one secondary mail exchanger at a higher preference value, " +
			"ideally on separate infrastructure.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc5321#section-5.1"},
		Tags:       []string{TagResilience},
	},
	{
		ID:         "DNSA-CAA-001",
		Check:      "caa",
		Title:      "No CAA record at the domain or any ancestor",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "No CAA record was found at the domain or any ancestor up to the public suffix. " +
			"Any certification authority may therefore issue certificates for this domain, so a " +
			"single compromised or deceived CA anywhere in the world is enough to mint a trusted " +
			"certificate for it.",
		Remediation: "Publish a CAA record naming the CAs you actually use, for example " +
			"`0 issue \"letsencrypt.org\"`. Include every CA in use, or issuance will start failing.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8659#section-3"},
		Tags:       []string{TagPKI},
	},
	{
		ID:         "DNSA-CAA-002",
		Check:      "caa",
		Title:      "CAA policy restricts issuance but not wildcard issuance",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The policy contains `issue` but no `issuewild`. Under RFC 8659 an absent " +
			"`issuewild` means wildcard issuance falls back to the `issue` policy, which is usually " +
			"intended — but if the intent was to forbid wildcards, that is not what is published.",
		Remediation: "Add an explicit `issuewild` property. Use `0 issuewild \";\"` to forbid " +
			"wildcard certificates entirely, or name the permitted CAs.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8659#section-4.3"},
		Tags:       []string{TagPKI},
	},
	{
		ID:         "DNSA-CAA-003",
		Check:      "caa",
		Title:      "CAA policy has no iodef reporting address",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The policy defines no `iodef` property, so when a CA refuses an unauthorised " +
			"issuance request nobody is told. Those refusals are exactly the signal that someone is " +
			"attempting to obtain a certificate for your domain.",
		Remediation: "Add an `iodef` property pointing at a monitored address, for example " +
			"`0 iodef \"mailto:security@example.com\"`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8659#section-4.4"},
		Tags:       []string{TagPKI},
	},
	{
		ID:         "DNSA-CAA-004",
		Check:      "caa",
		Title:      "CAA record sets the critical flag on an unrecognised tag",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "A CAA record sets the issuer critical flag on a property tag that is not " +
			"recognised. RFC 8659 requires a CA that does not understand a critical property to " +
			"refuse issuance, so this can block all certificate issuance for the domain.",
		Remediation: "Correct the property tag, or clear the critical flag if the property is " +
			"advisory. Recognised tags are `issue`, `issuewild` and `iodef`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8659#section-4.1"},
		Tags:       []string{TagPKI},
	},
	{
		ID:         "DNSA-CAA-005",
		Check:      "caa",
		Title:      "CAA policy is inherited from an ancestor domain",
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Description: "The domain publishes no CAA record of its own; the policy in force was found " +
			"at an ancestor by the tree-climbing algorithm. This is valid and often intended, but " +
			"means the policy is controlled elsewhere and may change without notice.",
		Remediation: "No action is required. Publish a CAA record at this name if it needs a policy " +
			"independent of its parent.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8659#section-3"},
		Tags:       []string{TagPKI},
	},
	{
		ID:         "DNSA-MTASTS-001",
		Check:      "mtasts",
		Title:      "No MTA-STS policy published",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "No `_mta-sts` TXT record was found. Without MTA-STS, SMTP connections to this " +
			"domain's mail exchangers fall back to opportunistic TLS, which an attacker positioned " +
			"in the network path can strip — downgrading mail to plaintext with no warning to " +
			"either party.",
		Remediation: "Publish `v=STSv1; id=<timestamp>` at `_mta-sts.<domain>` and serve a policy " +
			"file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`, starting in testing mode.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.1"},
		Tags:       []string{TagTransport, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-MTASTS-002",
		Check:      "mtasts",
		Title:      "MTA-STS policy file is unreachable",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "The `_mta-sts` TXT record advertises a policy, but the policy file could not be " +
			"retrieved from `https://mta-sts.<domain>/.well-known/mta-sts.txt`. Senders that cannot " +
			"fetch the policy have nothing to enforce, so the domain has the appearance of MTA-STS " +
			"protection without the substance.",
		Remediation: "Serve the policy file over HTTPS at the required path with a valid certificate. " +
			"RFC 8461 forbids redirects, so the resource must be served directly.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.3"},
		Tags:       []string{TagTransport, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-MTASTS-003",
		Check:      "mtasts",
		Title:      "MTA-STS policy is in testing mode",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The policy specifies `mode: testing`. Senders report failures but still deliver " +
			"mail over an unauthenticated connection, so a downgrade attack succeeds exactly as it " +
			"would with no policy at all. Testing mode is the correct starting point, but is often " +
			"left in place indefinitely.",
		Remediation: "Once TLS-RPT reports show no failures for your legitimate senders, change the " +
			"policy to `mode: enforce`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.2"},
		Tags:       []string{TagTransport, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-MTASTS-004",
		Check:      "mtasts",
		Title:      "MTA-STS policy mode is none",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "The policy specifies `mode: none`, which instructs senders to disregard any " +
			"previously cached policy. This is the correct way to withdraw MTA-STS, but if the " +
			"withdrawal was not deliberate the domain is left with no transport protection.",
		Remediation: "Set `mode: enforce` if MTA-STS is intended. If it is being withdrawn " +
			"deliberately, remove the TXT record once caches have expired.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.2"},
		Tags:       []string{TagTransport},
	},
	{
		ID:         "DNSA-MTASTS-005",
		Check:      "mtasts",
		Title:      "MTA-STS policy does not cover the published mail exchangers",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "One or more hosts in the domain's MX record set do not match any `mx` pattern " +
			"in the policy. Under an enforcing policy, senders must refuse to deliver to an " +
			"unlisted exchanger, so mail routed there will bounce.",
		Remediation: "Add an `mx` entry for every published mail exchanger. A leading `*.` wildcard " +
			"matches exactly one label, so `*.example.com` does not match `a.b.example.com`.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-4.1"},
		Tags:       []string{TagTransport, TagNCSCMailCheck},
	},
	{
		ID:         "DNSA-MTASTS-006",
		Check:      "mtasts",
		Title:      "MTA-STS policy id does not match the TXT record",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The `id` in the TXT record differs from the one in the policy file. Senders key " +
			"their cache on the TXT `id`, so a mismatch means an updated policy may not be fetched " +
			"when it changes, leaving senders enforcing a stale version.",
		Remediation: "Update the `id` in the TXT record whenever the policy file changes, and keep " +
			"the two values identical.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.1"},
		Tags:       []string{TagTransport},
	},
	{
		ID:         "DNSA-MTASTS-007",
		Check:      "mtasts",
		Title:      "MTA-STS policy max_age is below the recommended minimum",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The policy's `max_age` is shorter than one day. A short lifetime narrows the " +
			"window in which a cached policy protects senders, so an attacker who can block policy " +
			"retrieval need only do so briefly before the protection lapses.",
		Remediation: "Raise `max_age` to at least 86400 seconds; RFC 8461 suggests a value on the " +
			"order of weeks for established policies.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.2"},
		Tags:       []string{TagTransport},
	},
	{
		ID:         "DNSA-MTASTS-008",
		Check:      "mtasts",
		Title:      "MTA-STS policy is served with an invalid certificate",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Description: "The policy host's TLS certificate did not validate. RFC 8461 requires senders " +
			"to reject a policy that is not served over a validated HTTPS connection, so the policy " +
			"is inert — and the failure looks identical to the domain simply having no policy.",
		Remediation: "Install a certificate valid for `mta-sts.<domain>` from a publicly trusted CA, " +
			"and ensure the full chain is served.",
		References: []string{"https://www.rfc-editor.org/rfc/rfc8461#section-3.3"},
		Tags:       []string{TagTransport, TagPKI},
	},
	{
		ID:         "DNSA-BIMI-001",
		Check:      "bimi",
		Title:      "BIMI record published without an enforcing DMARC policy",
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Description: "A BIMI record is published, but DMARC is not enforcing (`p=none`, or absent). " +
			"BIMI requires an enforcing policy, so no mailbox provider will display the logo. The " +
			"investment in BIMI is therefore delivering nothing.",
		Remediation: "Move the DMARC policy to `p=quarantine` or `p=reject` once aggregate reports " +
			"confirm legitimate mail passes.",
		References: []string{"https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/"},
		Tags:       []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-BIMI-002",
		Check:      "bimi",
		Title:      "BIMI logo location is missing or not HTTPS",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Description: "The `l=` tag is absent, empty, or does not use HTTPS. Mailbox providers " +
			"retrieve the logo over HTTPS only, so the record cannot produce a displayed indicator.",
		Remediation: "Set `l=` to an HTTPS URL serving the logo as SVG Tiny Portable/Secure.",
		References:  []string{"https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/"},
		Tags:        []string{TagEmailAuth},
	},
	{
		ID:         "DNSA-BIMI-003",
		Check:      "bimi",
		Title:      "BIMI record has no Verified Mark Certificate",
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Description: "The record has no `a=` tag naming a Verified Mark Certificate. Several major " +
			"mailbox providers, including Gmail and Apple Mail, require a VMC before displaying a " +
			"logo, so the indicator will not appear for a large share of recipients.",
		Remediation: "Obtain a Verified Mark Certificate from an authorised issuer and publish its " +
			"HTTPS location in the `a=` tag.",
		References: []string{"https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/"},
		Tags:       []string{TagEmailAuth},
	},
})

// index converts the declarative slice above into a lookup map, panicking on
// malformed input. This runs at package initialisation, so a catalogue defect
// fails every test rather than lurking until a user hits the affected rule.
func index(entries []Entry) map[string]Entry {
	byID := make(map[string]Entry, len(entries))
	for _, e := range entries {
		if _, dup := byID[e.ID]; dup {
			panic(fmt.Sprintf("finding: duplicate catalogue ID %q", e.ID))
		}
		byID[e.ID] = e
	}
	return byID
}

// Lookup returns the catalogue entry for an ID.
func Lookup(id string) (Entry, bool) {
	e, ok := catalogue[id]
	return e, ok
}

// Catalogue returns every entry, sorted by ID, for `dnsaudit catalogue` and the
// agent-facing manifest.
func Catalogue() []Entry {
	entries := make([]Entry, 0, len(catalogue))
	for _, e := range catalogue {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// CatalogueForCheck returns the entries belonging to a single check.
func CatalogueForCheck(check string) []Entry {
	var entries []Entry
	for _, e := range Catalogue() {
		if strings.EqualFold(e.Check, check) {
			entries = append(entries, e)
		}
	}
	return entries
}

// Checks returns the sorted set of check names represented in the catalogue.
func Checks() []string {
	seen := map[string]bool{}
	var names []string
	for _, e := range catalogue {
		if !seen[e.Check] {
			seen[e.Check] = true
			names = append(names, e.Check)
		}
	}
	sort.Strings(names)
	return names
}

// ValidateCatalogue checks the invariants the specification requires of every
// entry. It is exported so that the catalogue integrity test, and any future
// contributor tooling, share one definition of correctness.
func ValidateCatalogue() error {
	for _, e := range Catalogue() {
		switch {
		case !idPattern.MatchString(e.ID):
			return fmt.Errorf("error: malformed catalogue ID %q (want DNSA-<CHECK>-<NNN>)", e.ID)
		case strings.TrimSpace(e.Check) == "":
			return fmt.Errorf("error: catalogue entry %s has no check name", e.ID)
		case strings.TrimSpace(e.Title) == "":
			return fmt.Errorf("error: catalogue entry %s has no title", e.ID)
		case strings.TrimSpace(e.Description) == "":
			return fmt.Errorf("error: catalogue entry %s has no description", e.ID)
		case strings.TrimSpace(e.Remediation) == "":
			return fmt.Errorf("error: catalogue entry %s has no remediation guidance", e.ID)
		case len(e.References) == 0:
			return fmt.Errorf("error: catalogue entry %s has no references", e.ID)
		case !e.Severity.Valid():
			return fmt.Errorf("error: catalogue entry %s has an invalid severity", e.ID)
		case !e.Confidence.Valid():
			return fmt.Errorf("error: catalogue entry %s has an invalid confidence", e.ID)
		}
		// The ID's check segment must agree with the Check field, so that
		// filtering by check and filtering by ID prefix never disagree.
		segment := strings.Split(e.ID, "-")[1]
		if !strings.EqualFold(segment, strings.ReplaceAll(e.Check, "-", "")) {
			return fmt.Errorf("error: catalogue entry %s does not match its check %q", e.ID, e.Check)
		}
	}
	return nil
}
